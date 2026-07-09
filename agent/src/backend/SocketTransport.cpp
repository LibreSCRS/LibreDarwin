// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// macOS AgentTransport backend over the App-Group AF_UNIX socket. One serial GCD
// queue is the loop: the accept source, every per-connection read/write source,
// and all AgentTransport calls (post-marshaled by the core) run on it, so
// transport state needs no locks. The agent SELF-BINDS the socket (D7);
// launch_activate_socket is an optional inherited-fd fallback.
#include <LibreSCRS/Darwin/backend/SocketTransport.h>

#include <LibreSCRS/Agent/backend/Logging.h>

#include <launch.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <utility>

namespace LibreSCRS::Darwin {
namespace {

namespace log = Agent::log;

void makeNonBlockingCloexec(int fd) noexcept
{
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// SO_NOSIGPIPE: writing to a peer-closed socket must return EPIPE, NOT raise
// SIGPIPE (whose default action would terminate the daemon). Per-fd and NOT
// inherited across accept(), so it is set on the listen fd AND every accepted
// fd; main() also installs a process-wide SIG_IGN as a belt-and-suspenders.
void setNoSigPipe(int fd) noexcept
{
    int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
}

std::expected<wire::UniqueFd, std::string> bindContainerSocket(const std::string& path)
{
    if (path.size() >= sizeof(sockaddr_un{}.sun_path)) {
        return std::unexpected(std::format("socket path exceeds sun_path limit ({} bytes)", path.size()));
    }
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
    ::unlink(path.c_str()); // remove a stale socket

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return std::unexpected(std::format("socket(): {}", std::strerror(errno)));
    }
    wire::UniqueFd owned(fd);
    makeNonBlockingCloexec(fd);
    setNoSigPipe(fd);

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        return std::unexpected(std::format("bind({}): {}", path, std::strerror(errno)));
    }
    ::chmod(path.c_str(), 0600);
    if (::listen(fd, 16) != 0) {
        return std::unexpected(std::format("listen(): {}", std::strerror(errno)));
    }
    return owned;
}

std::optional<wire::UniqueFd> inheritActivatedSocket(const std::string& name)
{
    int* fds = nullptr;
    size_t count = 0;
    if (launch_activate_socket(name.c_str(), &fds, &count) != 0 || count == 0 || fds == nullptr) {
        if (fds != nullptr) {
            free(fds);
        }
        return std::nullopt;
    }
    wire::UniqueFd owned(fds[0]);
    for (size_t i = 1; i < count; ++i) {
        ::close(fds[i]);
    }
    free(fds);
    makeNonBlockingCloexec(owned.get());
    return owned;
}

} // namespace

SocketTransport::SendState SocketTransport::trySendFrame(int fd, OutFrame& f)
{
    // Guard the fixed ancillary buffer (sized for kMaxFrameFds) against an
    // over-count outbound frame before writing into it — a stack overflow
    // otherwise. Fail the send CLOSED; the caller drops the connection.
    if (f.fds.size() > wire::kMaxFrameFds) {
        return SendState::Error;
    }
    while (f.sent < f.bytes.size()) {
        ssize_t w = -1;
        if (!f.ancillarySent && !f.fds.empty()) {
            iovec iov{};
            iov.iov_base = f.bytes.data() + f.sent;
            iov.iov_len = f.bytes.size() - f.sent;
            alignas(struct cmsghdr) std::array<std::uint8_t, CMSG_SPACE(sizeof(int) * wire::kMaxFrameFds)> control{};
            msghdr msg{};
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            const std::size_t bytes = sizeof(int) * f.fds.size();
            msg.msg_control = control.data();
            msg.msg_controllen = CMSG_SPACE(bytes);
            cmsghdr* c = CMSG_FIRSTHDR(&msg);
            c->cmsg_level = SOL_SOCKET;
            c->cmsg_type = SCM_RIGHTS;
            c->cmsg_len = CMSG_LEN(bytes);
            int* dst = reinterpret_cast<int*>(CMSG_DATA(c));
            for (std::size_t i = 0; i < f.fds.size(); ++i) {
                dst[i] = f.fds[i].get();
            }
            w = ::sendmsg(fd, &msg, 0);
        } else {
            w = ::write(fd, f.bytes.data() + f.sent, f.bytes.size() - f.sent);
        }
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return SendState::WouldBlock;
            }
            return SendState::Error;
        }
        if (!f.ancillarySent) {
            f.ancillarySent = true; // fds ride exactly the first send
        }
        f.sent += static_cast<std::size_t>(w);
    }
    f.fds.clear(); // sent + duped into the peer; drop our copies
    return SendState::Sent;
}

std::expected<std::unique_ptr<SocketTransport>, std::string>
SocketTransport::create(std::string socketPath, std::optional<std::string> socketActivationName)
{
    wire::UniqueFd listenFd;
    bool ownsSocketFile = true;

    if (socketActivationName) {
        if (auto activated = inheritActivatedSocket(*socketActivationName)) {
            listenFd = std::move(*activated);
            ownsSocketFile = false; // launchd owns the socket file
        }
    }
    if (!listenFd) {
        auto bound = bindContainerSocket(socketPath);
        if (!bound) {
            return std::unexpected(bound.error());
        }
        listenFd = std::move(*bound);
    }

    dispatch_queue_t queue = dispatch_queue_create("rs.librescrs.agent.transport", DISPATCH_QUEUE_SERIAL);
    // Private ctor; make_unique cannot see it.
    std::unique_ptr<SocketTransport> t(
        new SocketTransport(queue, std::move(listenFd), std::move(socketPath), ownsSocketFile));
    t->installAcceptSource();
    return t;
}

SocketTransport::SocketTransport(dispatch_queue_t queue, wire::UniqueFd listenFd, std::string socketPath,
                                 bool ownsSocketFile)
    : m_queue(queue), m_listenFd(std::move(listenFd)), m_socketPath(std::move(socketPath)),
      m_ownsSocketFile(ownsSocketFile)
{}

SocketTransport::~SocketTransport()
{
    if (m_queue == nullptr) {
        return;
    }
    // Quiesce on the loop: dispatch_sync serializes with any in-flight source
    // handler, then cancels every source so none fires again. Must NOT be called
    // from within a loop handler (the daemon destroys after stopping the run
    // loop; tests destroy from the main thread) — that would deadlock.
    dispatch_sync(m_queue, ^{
      if (m_acceptSource != nullptr) {
          dispatch_source_cancel(m_acceptSource);
          dispatch_release(m_acceptSource);
          m_acceptSource = nullptr;
      }
      for (auto& [id, conn] : m_connections) {
          if (conn->readSource != nullptr) {
              dispatch_source_cancel(conn->readSource);
              dispatch_release(conn->readSource);
              conn->readSource = nullptr;
          }
          if (conn->writeSource != nullptr) {
              dispatch_source_cancel(conn->writeSource);
              dispatch_release(conn->writeSource);
              conn->writeSource = nullptr;
          }
      }
      m_connections.clear();
    });

    if (m_ownsSocketFile && !m_socketPath.empty()) {
        ::unlink(m_socketPath.c_str());
    }
    dispatch_release(m_queue);
    m_queue = nullptr;
}

void SocketTransport::setRequestSink(RequestSink sink)
{
    m_sink = std::move(sink);
}

void SocketTransport::installAcceptSource()
{
    m_acceptSource =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, static_cast<uintptr_t>(m_listenFd.get()), 0, m_queue);
    dispatch_source_set_event_handler(m_acceptSource, ^{
      this->onAcceptReady();
    });
    dispatch_resume(m_acceptSource);
}

void SocketTransport::onAcceptReady()
{
    for (;;) {
        const int c = ::accept(m_listenFd.get(), nullptr, nullptr);
        if (c < 0) {
            if (errno == EINTR) {
                continue;
            }
            break; // EAGAIN: drained
        }
        acceptOne(c);
    }
}

void SocketTransport::acceptOne(int connFd)
{
    wire::UniqueFd fd(connFd);
    makeNonBlockingCloexec(connFd);
    setNoSigPipe(connFd);

    auto creds = capturePeerCredentials(connFd);
    if (!creds) {
        log::warn("transport: rejecting connection with unidentifiable peer");
        return; // fail closed; fd closed by UniqueFd
    }

    const std::uint64_t id = m_nextConnId++;
    auto conn = std::make_unique<Connection>();
    conn->id = id;
    // Transfer the fd into a shared_ptr with a closing deleter (see Connection::fd).
    conn->fd = std::shared_ptr<int>(new int(fd.release()), [](int* p) {
        if (*p >= 0) {
            ::close(*p);
        }
        delete p;
    });
    conn->caller = Agent::CallerToken(std::format("conn:{}", id));
    conn->creds = *creds;

    conn->readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, static_cast<uintptr_t>(*conn->fd), 0, m_queue);
    dispatch_source_set_event_handler(conn->readSource, ^{
      this->onReadReady(id);
    });
    // The cancel handler co-owns the fd so it stays open until GCD has fully
    // deregistered this source; the fd closes when the last source's handler drops
    // its share (Apple's required fd-source teardown discipline).
    std::shared_ptr<int> readFdRef = conn->fd;
    dispatch_source_set_cancel_handler(conn->readSource, ^{
      (void)readFdRef;
    });
    dispatch_resume(conn->readSource);

    m_connections.emplace(id, std::move(conn));
    log::infof("transport: client connected ({}, {})", m_connections[id]->caller.str(), creds->label());
}

void SocketTransport::onReadReady(std::uint64_t connId)
{
    const auto it = m_connections.find(connId);
    if (it == m_connections.end()) {
        return;
    }
    Connection& conn = *it->second;
    // Capture the caller BEFORE dispatching frames: m_sink replies synchronously
    // (sendTo -> flushWrites), and a send failure closes + erases this connection,
    // leaving `conn` dangling. pump() can also yield multiple frames per call, so a
    // mid-loop close must not be dereferenced on the next iteration.
    const Agent::CallerToken caller = conn.caller;
    wire::PumpResult pumped = conn.reassembler.pump(*conn.fd);

    for (auto& frame : pumped.frames) {
        auto env = wire::parseRequest(frame.body);
        if (!env) {
            log::warn("transport: malformed request; dropping connection");
            closeConnection(connId);
            return; // conn is gone
        }
        // The connection may have been closed by a prior frame's synchronous
        // reply-send failure; stop touching it.
        if (m_connections.find(connId) == m_connections.end()) {
            return;
        }
        if (m_sink) {
            Inbound in;
            in.caller = caller;
            in.connId = connId;
            in.request = std::move(*env);
            in.fds = std::move(frame.fds);
            m_sink(std::move(in));
        }
    }
    if (pumped.status != wire::PumpStatus::Ok) {
        closeConnection(connId);
    }
}

void SocketTransport::closeConnection(std::uint64_t connId)
{
    const auto it = m_connections.find(connId);
    if (it == m_connections.end()) {
        return;
    }
    const Agent::CallerToken caller = it->second->caller;
    if (it->second->readSource != nullptr) {
        dispatch_source_cancel(it->second->readSource);
        dispatch_release(it->second->readSource);
        it->second->readSource = nullptr;
    }
    if (it->second->writeSource != nullptr) {
        dispatch_source_cancel(it->second->writeSource);
        dispatch_release(it->second->writeSource);
        it->second->writeSource = nullptr;
    }
    m_connections.erase(it); // drops this connection's fd share; the source cancel
                             // handlers close the fd once GCD finishes their teardown

    // Client-liveness fan-out, in registration order (the contract:
    // OperationManager auto-cancel, then Pkcs11Broker lease revoke).
    for (auto& handler : m_disconnectHandlers) {
        handler(caller);
    }
}

void SocketTransport::enqueueSend(Connection& conn, std::vector<std::uint8_t> framed, std::vector<wire::UniqueFd> fds)
{
    OutFrame f;
    f.bytes = std::move(framed);
    f.fds = std::move(fds);
    conn.outQueue.push_back(std::move(f));
    flushWrites(conn);
}

void SocketTransport::flushWrites(Connection& conn)
{
    while (!conn.outQueue.empty()) {
        const SendState s = trySendFrame(*conn.fd, conn.outQueue.front());
        if (s == SendState::WouldBlock) {
            if (conn.writeSource == nullptr) {
                const std::uint64_t id = conn.id;
                conn.writeSource =
                    dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE, static_cast<uintptr_t>(*conn.fd), 0, m_queue);
                dispatch_source_set_event_handler(conn.writeSource, ^{
                  const auto it = this->m_connections.find(id);
                  if (it != this->m_connections.end()) {
                      this->flushWrites(*it->second);
                  }
                });
                // Co-own the fd (see acceptOne): the write source must not outlive
                // the fd's validity, and the fd must not close before this source's
                // cancellation completes.
                std::shared_ptr<int> writeFdRef = conn.fd;
                dispatch_source_set_cancel_handler(conn.writeSource, ^{
                  (void)writeFdRef;
                });
                dispatch_resume(conn.writeSource);
            }
            return; // wait for write-readiness
        }
        if (s == SendState::Error) {
            closeConnection(conn.id);
            return; // conn gone
        }
        conn.outQueue.pop_front(); // Sent
    }
    // Drained: tear down the (backpressure-only) write source if it exists.
    if (conn.writeSource != nullptr) {
        dispatch_source_cancel(conn.writeSource);
        dispatch_release(conn.writeSource);
        conn.writeSource = nullptr;
    }
}

void SocketTransport::sendTo(std::uint64_t connId, const wire::CborValue& message, std::vector<wire::UniqueFd> fds)
{
    const auto it = m_connections.find(connId);
    if (it == m_connections.end()) {
        return;
    }
    auto framed = wire::encodeFrame(message.encode(), static_cast<std::uint32_t>(fds.size()));
    enqueueSend(*it->second, std::move(framed), std::move(fds));
}

void SocketTransport::broadcast(const wire::CborValue& event)
{
    const auto framed = wire::encodeFrame(event.encode(), 0);
    // Snapshot the connection ids FIRST: a failed send inside enqueueSend closes +
    // erases the connection (flushWrites -> closeConnection -> m_connections.erase),
    // which would invalidate a live range-for iterator. sendTo re-finds by id and
    // no-ops a vanished connection.
    std::vector<std::uint64_t> ids;
    ids.reserve(m_connections.size());
    for (const auto& [id, conn] : m_connections) {
        ids.push_back(id);
    }
    for (const std::uint64_t id : ids) {
        const auto it = m_connections.find(id);
        if (it != m_connections.end()) {
            enqueueSend(*it->second, framed, {});
        }
    }
}

std::string SocketTransport::handleFor(Agent::ObjectId id)
{
    const auto it = m_idToHandle.find(id.value());
    if (it != m_idToHandle.end()) {
        return it->second;
    }
    std::string handle = std::format("obj/{}", m_nextHandle++);
    m_idToHandle.emplace(id.value(), handle);
    m_handleToId.emplace(handle, id.value());
    return handle;
}

void SocketTransport::publishReader(const Agent::ReaderState& reader)
{
    wire::ReaderState r;
    r.handle = handleFor(reader.id);
    r.name = reader.name;
    r.hasCard = reader.hasCard;
    if (reader.card.valid()) {
        r.card = handleFor(reader.card);
    }
    m_readers[r.handle] = r;
    broadcast(wire::toCbor(wire::ReaderAdded{r}));
}

void SocketTransport::publishCard(const Agent::CardState& card)
{
    wire::CardState c;
    c.handle = handleFor(card.id);
    c.reader = handleFor(card.reader);
    c.caps = card.capabilities;
    c.preAuth = card.preReadAuth;
    m_cards[c.handle] = c;

    CardRouting routing;
    routing.cardId = card.id;
    routing.readerId = card.reader;
    if (const auto rit = m_readers.find(c.reader); rit != m_readers.end()) {
        routing.readerName = rit->second.name;
    }
    // The cache key is the per-insertion card ObjectId (stringified), NOT the wire
    // handle: the typed-op deps, the broker card-op seams, and the CardKeyTracker
    // removal scrub must all agree on it, and the tracker only has the ObjectId.
    routing.cardKey = std::to_string(card.id.value());
    routing.caps = card.capabilities;
    routing.preAuth = card.preReadAuth;
    m_cardRouting[c.handle] = std::move(routing);

    broadcast(wire::toCbor(wire::CardAdded{c}));
}

void SocketTransport::withdraw(Agent::ObjectId object)
{
    const auto it = m_idToHandle.find(object.value());
    if (it == m_idToHandle.end()) {
        return;
    }
    const std::string handle = it->second;
    if (m_readers.erase(handle) > 0) {
        broadcast(wire::toCbor(wire::ReaderRemoved{handle}));
    } else if (m_cards.erase(handle) > 0) {
        m_cardRouting.erase(handle);
        broadcast(wire::toCbor(wire::CardRemoved{handle}));
    }
    m_idToHandle.erase(it);
    m_handleToId.erase(handle);
}

void SocketTransport::updateProperties(Agent::ObjectId reader, const Agent::PropertyDelta& delta)
{
    const auto handleIt = m_idToHandle.find(reader.value());
    if (handleIt == m_idToHandle.end()) {
        return;
    }
    const auto readerIt = m_readers.find(handleIt->second);
    if (readerIt == m_readers.end()) {
        return;
    }
    readerIt->second.hasCard = delta.hasCard;
    readerIt->second.card =
        delta.hasCard && delta.card.valid() ? std::optional<std::string>(handleFor(delta.card)) : std::nullopt;

    std::map<std::string, wire::CborValue> props;
    props.emplace("hasCard", wire::CborValue(delta.hasCard));
    if (readerIt->second.card) {
        props.emplace("card", wire::CborValue(*readerIt->second.card));
    }
    broadcast(wire::toCbor(wire::PropertyChanged{readerIt->first, "Reader1", std::move(props)}));
}

void SocketTransport::post(std::function<void()> fn)
{
    dispatch_async(m_queue, ^{
      if (!m_loopQuiesced) {
          fn();
      }
    });
}

void SocketTransport::postAfter(std::chrono::microseconds delay, std::function<void()> fn)
{
    const dispatch_time_t when = dispatch_time(DISPATCH_TIME_NOW, static_cast<int64_t>(delay.count()) * 1000);
    dispatch_after(when, m_queue, ^{
      if (!m_loopQuiesced) {
          fn();
      }
    });
}

void SocketTransport::quiesceLoop()
{
    // Set the drop-flag AND sever every frontend-bound edge the transport's own
    // sources drive, all on the loop so no source event can reach the frontend
    // after this returns. Called at teardown BEFORE the frontend is destroyed:
    //  - m_loopQuiesced drops posted/postAfter continuations (worker marshals);
    //  - clearing m_sink stops onReadReady -> frontend->dispatch();
    //  - clearing m_disconnectHandlers stops closeConnection -> the frontend +
    //    core client-disconnect callbacks.
    // The private serial queue keeps servicing its read/accept sources after the
    // CFRunLoop stops, so guarding post() alone is insufficient; these are the
    // synchronous paths.
    dispatch_sync(m_queue, ^{
      m_loopQuiesced = true;
      m_sink = nullptr;
      m_disconnectHandlers.clear();
    });
}

void SocketTransport::onClientDisconnect(std::function<void(Agent::CallerToken)> handler)
{
    m_disconnectHandlers.push_back(std::move(handler));
}

wire::StateReply SocketTransport::currentState() const
{
    wire::StateReply state;
    for (const auto& [handle, reader] : m_readers) {
        state.readers.push_back(reader);
    }
    for (const auto& [handle, card] : m_cards) {
        state.cards.push_back(card);
    }
    return state;
}

std::optional<SocketTransport::CardRouting> SocketTransport::cardRouting(const std::string& cardHandle) const
{
    const auto it = m_cardRouting.find(cardHandle);
    if (it == m_cardRouting.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<SocketTransport::ReaderCardInfo> SocketTransport::readerCard(const std::string& readerHandle) const
{
    const auto rit = m_readers.find(readerHandle);
    if (rit == m_readers.end()) {
        return std::nullopt;
    }
    const auto idIt = m_handleToId.find(readerHandle);
    if (idIt == m_handleToId.end()) {
        return std::nullopt;
    }
    ReaderCardInfo info;
    info.readerId = Agent::ObjectId{idIt->second};
    info.readerName = rit->second.name;
    // cardKey is the present card's ObjectId (stringified) — the same per-insertion
    // key the CardRouting + CardKeyTracker use — or empty when no card is present.
    if (rit->second.card) {
        const auto cardIdIt = m_handleToId.find(*rit->second.card);
        if (cardIdIt != m_handleToId.end()) {
            info.cardKey = std::to_string(cardIdIt->second);
        }
    }
    return info;
}

void SocketTransport::broadcastConfigChanged(const std::string& key)
{
    broadcast(wire::toCbor(wire::ConfigChanged{key}));
}

void SocketTransport::broadcastQuiesced(wire::QuiesceReason reason)
{
    broadcast(wire::toCbor(wire::AgentQuiesced{reason}));
}

std::optional<PeerCredentials> SocketTransport::credentialsFor(const Agent::CallerToken& caller) const
{
    for (const auto& [id, conn] : m_connections) {
        if (conn->caller == caller) {
            return conn->creds;
        }
    }
    return std::nullopt;
}

} // namespace LibreSCRS::Darwin
