// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Prompter socket server, event-driven on GCD dispatch sources. Peer-
// authenticates the agent at accept (fail-closed "unauthorized"), then serves
// one RequestSecret / CancelCurrent per connection; the blocking provider call
// runs on a concurrent worker queue so a cross-connection CancelCurrent is
// dispatched while a modal is up.
#include "PrompterServer.h"

#include <LibreSCRS/Darwin/backend/wire/Framing.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <format>
#include <type_traits>
#include <utility>
#include <variant>

namespace LibreSCRS::Darwin {
namespace {

wire::PromptReply unauthorizedReply()
{
    wire::PromptReply r;
    r.status = wire::PromptReplyStatus::Unauthorized;
    r.userMessage = "caller is not the agent";
    return r;
}

void makeNonBlockingCloexec(int fd) noexcept
{
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void clearNonBlocking(int fd) noexcept
{
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

// Writing to a peer-closed socket must return EPIPE, not raise SIGPIPE (the
// prompter has no process-wide SIG_IGN like the daemon).
void setNoSigPipe(int fd) noexcept
{
    int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
}

// Exhaustiveness guard for the PrompterRequest visit below: instantiated only
// inside a discarded if-constexpr branch, so it fires ONLY if a future
// PrompterRequest alternative reaches the final else without an explicit arm
// above it (compile-break honesty in place of an else-arm assumption).
template <class>
inline constexpr bool always_false_v = false;

} // namespace

PrompterServer::PrompterServer(std::string socketPath, SecretProvider provider, MultiSecretProvider multiProvider,
                               CancelHandler cancel, PeerAuthorized peerAuth)
    : m_socketPath(std::move(socketPath)), m_provider(std::move(provider)), m_multiProvider(std::move(multiProvider)),
      m_cancel(std::move(cancel)), m_peerAuth(std::move(peerAuth))
{}

PrompterServer::~PrompterServer()
{
    stop();
    if (m_worker != nullptr) {
        dispatch_release(m_worker);
        m_worker = nullptr;
    }
    if (m_queue != nullptr) {
        dispatch_release(m_queue);
        m_queue = nullptr;
    }
}

std::expected<void, std::string> PrompterServer::start()
{
    if (m_started) {
        return {};
    }
    if (m_socketPath.size() >= sizeof(sockaddr_un{}.sun_path)) {
        return std::unexpected(std::format("prompter socket path exceeds sun_path limit"));
    }
    ::unlink(m_socketPath.c_str()); // remove a stale socket
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return std::unexpected(std::format("socket(): {}", std::strerror(errno)));
    }
    m_listen = wire::UniqueFd(fd);
    makeNonBlockingCloexec(fd);
    setNoSigPipe(fd);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, m_socketPath.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        return std::unexpected(std::format("bind(): {}", std::strerror(errno)));
    }
    ::chmod(m_socketPath.c_str(), 0600);
    if (::listen(fd, 8) != 0) {
        return std::unexpected(std::format("listen(): {}", std::strerror(errno)));
    }

    if (m_queue == nullptr) {
        m_queue = dispatch_queue_create("rs.librescrs.prompter", DISPATCH_QUEUE_SERIAL);
    }
    if (m_worker == nullptr) {
        m_worker = dispatch_queue_create("rs.librescrs.prompter.worker", DISPATCH_QUEUE_CONCURRENT);
    }
    m_acceptSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, static_cast<uintptr_t>(fd), 0, m_queue);
    dispatch_source_set_event_handler(m_acceptSource, ^{
      this->onAcceptReady();
    });
    dispatch_resume(m_acceptSource);
    m_started = true;
    return {};
}

void PrompterServer::stop() noexcept
{
    if (!m_started) {
        return;
    }
    m_started = false;
    // Cancel every source on the loop, then barrier once more so the enqueued
    // cancellation handlers have run before the listen fd closes (Apple's
    // fd-source teardown discipline; per-connection fds are co-owned by their
    // cancel handlers and close themselves). No blocking accept() to wake ->
    // no join() -> stop() cannot hang on a pending modal.
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
      }
      m_connections.clear();
    });
    dispatch_sync(m_queue, ^{
                  });
    m_listen.reset();
    if (!m_socketPath.empty()) {
        ::unlink(m_socketPath.c_str());
    }
}

void PrompterServer::onAcceptReady()
{
    for (;;) {
        const int c = ::accept(m_listen.get(), nullptr, nullptr);
        if (c < 0) {
            if (errno == EINTR) {
                continue;
            }
            break; // EWOULDBLOCK: drained
        }
        acceptOne(c);
    }
}

void PrompterServer::acceptOne(int connFd)
{
    wire::UniqueFd fd(connFd);
    makeNonBlockingCloexec(connFd);
    setNoSigPipe(connFd);

    // Peer-auth BEFORE reading anything: only the agent may drive the prompter
    // (Prompter1 "unauthorized"). The rejection is a tiny frame on a fresh
    // socket; best-effort, then the fd closes.
    const auto creds = capturePeerCredentials(connFd);
    if (!creds || !m_peerAuth(*creds)) {
        wire::PromptReply rejection = unauthorizedReply();
        wire::sendPromptReplyScrubbed(connFd, rejection);
        return; // fail closed; fd closed by UniqueFd
    }

    const std::uint64_t id = m_nextConnId++;
    auto conn = std::make_unique<Connection>();
    conn->id = id;
    conn->fd = std::shared_ptr<int>(new int(fd.release()), [](int* p) {
        if (*p >= 0) {
            ::close(*p);
        }
        delete p;
    });
    conn->readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, static_cast<uintptr_t>(*conn->fd), 0, m_queue);
    dispatch_source_set_event_handler(conn->readSource, ^{
      this->onReadReady(id);
    });
    // The cancel handler co-owns the fd so it stays open until GCD has fully
    // deregistered the source (mirror of SocketTransport).
    std::shared_ptr<int> readFdRef = conn->fd;
    dispatch_source_set_cancel_handler(conn->readSource, ^{
      (void)readFdRef;
    });
    dispatch_resume(conn->readSource);
    m_connections.emplace(id, std::move(conn));
}

void PrompterServer::onReadReady(std::uint64_t connId)
{
    const auto it = m_connections.find(connId);
    if (it == m_connections.end()) {
        return;
    }
    Connection& conn = *it->second;
    wire::PumpResult pumped = conn.reassembler.pump(*conn.fd);
    if (pumped.frames.empty()) {
        if (pumped.status != wire::PumpStatus::Ok) {
            closeConnection(connId); // EOF / protocol error before a request
        }
        return;
    }

    // One request per connection: detach the fd share for the reply path and
    // retire the read side before dispatching anything.
    std::shared_ptr<int> fd = conn.fd;
    wire::Frame frame = std::move(pumped.frames.front());
    closeConnection(connId); // cancels the read source; `conn` is gone

    auto parsed = wire::parsePrompterRequest(frame.body);
    if (!parsed.has_value()) {
        return; // malformed; fail closed — the detached fd share drops here
    }

    // Fail-closed dispatch totality: EVERY PrompterRequest alternative has an
    // explicit if-constexpr arm; a wire alternative added without one breaks
    // the compile (static_assert below) instead of throwing
    // bad_variant_access at runtime.
    std::visit(
        [this, &fd](auto&& msg) {
            using T = std::decay_t<decltype(msg)>;
            if constexpr (std::is_same_v<T, wire::PromptCancel>) {
                // Inline on the serial queue — which a modal never blocks (the
                // modal blocks the worker + main queues), so a cross-connection
                // cancel can always dismiss it. The handler dispatches
                // abortModal asynchronously. CancelCurrent has no reply.
                m_cancel();
            } else if constexpr (std::is_same_v<T, wire::PromptRequest>) {
                // The blocking provider call (dispatch_sync(main) + runModal)
                // runs on the concurrent worker. The block holds its own copies
                // (provider, request, fd share) and never touches `this`, so a
                // stop()/destruction while the modal is up cannot dangle; the
                // reply is sent + scrubbed on the worker and the fd closes with
                // its last share. The fd turns blocking for the send: the read
                // side is retired, and a reply near the 8 KiB cap may not fit
                // the socket buffer in one non-blocking write.
                const wire::PromptRequest req = std::move(msg);
                const SecretProvider provider = m_provider;
                const std::shared_ptr<int> connFd = fd;
                dispatch_async(m_worker, ^{
                  wire::PromptReply reply = provider(req);
                  clearNonBlocking(*connFd);
                  wire::sendPromptReplyScrubbed(*connFd, reply);
                });
            } else if constexpr (std::is_same_v<T, wire::RequestSecrets>) {
                // Same worker discipline as PromptRequest: the change modal
                // blocks identically, and the reply — BOTH secrets inline —
                // goes out through the scrubbing multi overload.
                const wire::RequestSecrets req = std::move(msg);
                const MultiSecretProvider provider = m_multiProvider;
                const std::shared_ptr<int> connFd = fd;
                dispatch_async(m_worker, ^{
                  wire::MultiPromptReply reply = provider(req);
                  clearNonBlocking(*connFd);
                  wire::sendPromptReplyScrubbed(*connFd, reply);
                });
            } else {
                static_assert(always_false_v<T>, "PrompterServer::onReadReady: unhandled PrompterRequest arm");
            }
        },
        std::move(*parsed));
}

void PrompterServer::closeConnection(std::uint64_t connId)
{
    const auto it = m_connections.find(connId);
    if (it == m_connections.end()) {
        return;
    }
    if (it->second->readSource != nullptr) {
        dispatch_source_cancel(it->second->readSource);
        dispatch_release(it->second->readSource);
        it->second->readSource = nullptr;
    }
    m_connections.erase(it);
}

} // namespace LibreSCRS::Darwin
