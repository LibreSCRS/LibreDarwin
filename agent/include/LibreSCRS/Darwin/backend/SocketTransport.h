// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/PeerIdentity.h>
#include <LibreSCRS/Darwin/backend/SocketPathIdentity.h>
#include <LibreSCRS/Agent/wire/FrameReassembler.h>
#include <LibreSCRS/Agent/wire/Messages.h>
#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <LibreSCRS/Agent/backend/AgentTransport.h>
#include <LibreSCRS/Auth/AuthRequirement.h> // LibreSCRS::Auth::PreReadAuthMethod (CardRouting::preAuth)

#include <dispatch/dispatch.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace LibreSCRS::Darwin {

// macOS AgentTransport backend: the client membrane + its GCD loop over the
// App-Group `0600` AF_UNIX socket. It owns the CBOR framing, the SCM_RIGHTS
// fd-passing, peer identity, the ObjectId<->wire-handle mapping, and the
// published presence snapshot; the neutral core never touches wire paths. The
// Linux twin is LibreLinux's D-Bus ObjectManager + sd-event backend; here it is
// GCD dispatch sources on one serial queue (the loop). The agent SELF-BINDS
// the container socket (SMAppService can't template a per-user SockPathName);
// launch_activate_socket is an optional inherited-fd fallback.
//
// THREADING: everything that touches transport state runs on the single serial
// dispatch queue (the loop). Cross-thread entry is only via post()/postAfter()
// (thread-safe dispatch_async/after). The core's presence updates arrive
// post-marshaled, so publish*/withdraw/updateProperties, the inbound sink, and
// sendTo all run on the loop with no additional locking.
class SocketTransport final : public Agent::AgentTransport
{
public:
    // One inbound request delivered to the frontend, with the fds that
    // accompanied it (Sign's inputFd) and the connection to reply on.
    struct Inbound
    {
        Agent::CallerToken caller;
        std::uint64_t connId{0};
        Agent::Wire::RequestEnvelope request;
        std::vector<Agent::Wire::UniqueFd> fds;
    };
    using RequestSink = std::function<void(Inbound&&)>;

    // Bind the container socket at `socketPath` (0600, sun_path-guarded,
    // unlink-stale, cleanup-on-exit), or inherit a launchd-activated fd when
    // `socketActivationName` is set and available. On success the loop + accept
    // source are installed (driven by the process CFRunLoop / dispatch main).
    [[nodiscard]] static std::expected<std::unique_ptr<SocketTransport>, std::string>
    create(std::string socketPath, std::optional<std::string> socketActivationName = std::nullopt);

    // Serve an already-listening socket whose FILE this process does not own
    // (the launchd-activated fd create() inherits). launchd owns that path, so
    // no replaced-path guard is installed and the file is never unlinked here:
    // binding a fresh socket over it would sever the activation.
    [[nodiscard]] static std::unique_ptr<SocketTransport> adoptInherited(Agent::Wire::UniqueFd listenFd,
                                                                         std::string socketPath);

    ~SocketTransport() override;
    SocketTransport(const SocketTransport&) = delete;
    SocketTransport& operator=(const SocketTransport&) = delete;

    // Wire the inbound sink (the SocketFrontend). Called once at startup.
    void setRequestSink(RequestSink sink);

    // Routing facts for a card, resolved from a card wire handle carried in a
    // request. The frontend uses these to gate the op (caps/preAuth) and to
    // address OperationManager::publish (readerId + readerName) + the caches
    // (cardKey == the card wire handle). nullopt if the handle is unknown.
    struct CardRouting
    {
        Agent::ObjectId cardId;
        Agent::ObjectId readerId;
        std::string readerName;
        std::string cardKey; // == the card wire handle (opaque per-insertion key)
        std::uint32_t caps{0};
        // The core's OWN vocabulary (LibreSCRS::Auth::PreReadAuthMethod), not the
        // wire mirror: CardRouting is Darwin-local routing bookkeeping, built and
        // consumed straight from Agent::CardState::preReadAuth, and never itself
        // crosses the CBOR wire (wire::CardState::preAuth is the encoded form).
        LibreSCRS::Auth::PreReadAuthMethod preAuth{LibreSCRS::Auth::PreReadAuthMethod::None};
    };
    [[nodiscard]] std::optional<CardRouting> cardRouting(const std::string& cardHandle) const;

    // Routing facts for a reader wire handle (the reader-addressed Pkcs11/CertDer
    // requests + the AgentCore ResolveReaderCard/ResolveCardKey seams). The
    // cardKey is the card currently in the reader, or empty when none is present.
    struct ReaderCardInfo
    {
        Agent::ObjectId readerId;
        std::string readerName;
        std::string cardKey; // the present card's wire handle, or empty
    };
    [[nodiscard]] std::optional<ReaderCardInfo> readerCard(const std::string& readerHandle) const;

    // The presence roster the reader-identity seams read (AgentCoreSeams.h):
    // every published reader's PC/SC name, index-aligned with the per-insertion
    // key of the card it holds -- the stringified card ObjectId that CardRouting
    // and the CardKeyTracker use -- or empty for an empty slot. The key comes
    // from the CARD objects (each names its reader), so it is present the moment
    // publishCard returns and gone the moment the card is withdrawn, independent
    // of the reader's HasCard/Card property flip that follows both.
    //
    // ANY thread: the one presence read that is not loop-affine, because the
    // prompt gate stamps a dialog from a reader WORKER thread. It returns a copy
    // of a snapshot the loop rebuilds on every presence change, under its own
    // mutex, so a worker never walks the loop-owned maps.
    struct PresenceRoster
    {
        std::vector<std::string> readerNames;
        std::vector<std::string> cardKeys;
    };
    [[nodiscard]] PresenceRoster presenceRoster() const;

    // Send one CBOR message to a specific connection, optionally taking ownership
    // of fds to pass via SCM_RIGHTS. Loop-thread only (the sink runs there).
    void sendTo(std::uint64_t connId, const Agent::Wire::CborValue& message,
                std::vector<Agent::Wire::UniqueFd> fds = {});

    // The current presence snapshot for a GetState reply. Loop-thread only.
    [[nodiscard]] Agent::Wire::StateReply currentState() const;

    // Broadcast a Config1.Changed event to every connection (the frontend's
    // emitConfigChanged path); there is no per-connection subscription
    // filtering in this version. Loop-thread only.
    void broadcastConfigChanged(const std::string& key);

    // Broadcast an AgentQuiesced event (system sleep / screen lock / user switch /
    // shutdown) so clients render "card suspended" rather than a bare removal.
    // Loop-thread only (wrap in post() from another thread).
    void broadcastQuiesced(Agent::Wire::QuiesceReason reason);

    // Update the published card-state's cardType and broadcast a
    // PropertyChanged carrying the full new value -- the post-read
    // authoritative update (IdentityReadFlow resolving CardData::cardType via
    // ReadIdentity or a GetPhoto cache miss). A no-op if @p cardHandle was
    // withdrawn meanwhile, or if the value did not actually change. Loop-thread
    // only (wrap in post() from another thread -- SocketFrontend's
    // onCardType callback does exactly that).
    void updateCardType(const std::string& cardHandle, const std::string& cardType);

    // Resolve a live CallerToken to its captured peer credentials (for the
    // Authorizer's SecTask check). Loop-thread only; nullopt if the connection
    // is gone.
    [[nodiscard]] std::optional<PeerCredentials> credentialsFor(const Agent::CallerToken& caller) const;

    // The serial loop queue (for the daemon to target other work at the loop).
    [[nodiscard]] dispatch_queue_t loopQueue() const noexcept
    {
        return m_queue;
    }

    // Quiesce the loop at teardown, BEFORE the frontend is destroyed: drops every
    // subsequently-run posted/postAfter block AND severs the frontend-bound inbound
    // edges (the request sink + the client-disconnect handlers) so no transport
    // source event can invoke a frontend callback after the frontend is freed.
    void quiesceLoop();

    // Test hook: shrink the first-frame (slow-loris) watchdog window. Call
    // before any client connects; production keeps the 30 s default.
    void setFirstFrameTimeoutForTest(std::chrono::microseconds timeout) noexcept
    {
        m_firstFrameTimeout = timeout;
    }

    // Test hook: shorten the replaced-path guard's check interval (production
    // keeps 10 s). Takes effect at once, from any thread but the loop.
    void setPathGuardIntervalForTest(std::chrono::microseconds interval);

    // Test hook: how many accept-source cancel handlers found the listen fd
    // already closed (or no longer this listener). Must stay 0: the fd may
    // close only inside that handler. Shared so a test can read it after the
    // transport is destroyed (teardown cancels the source too).
    [[nodiscard]] std::shared_ptr<const std::atomic<std::uint32_t>> closedListenFdAtCancelForTest() const noexcept
    {
        return m_closedListenFdAtCancel;
    }

    // --- AgentTransport ----------------------------------------------------
    void publishReader(const Agent::ReaderState& reader) override;
    void publishCard(const Agent::CardState& card) override;
    void withdraw(Agent::ObjectId object) override;
    void updateProperties(Agent::ObjectId reader, const Agent::PropertyDelta& delta) override;
    void post(std::function<void()> fn) override;
    void postAfter(std::chrono::microseconds delay, std::function<void()> fn) override;
    void onClientDisconnect(std::function<void(Agent::CallerToken)> handler) override;

private:
    // Rebuild the roster snapshot from m_readers / m_cards / m_cardRouting. Loop
    // thread; called at the end of every presence mutation.
    void rebuildRoster();

    struct OutFrame
    {
        std::vector<std::uint8_t> bytes;        // full framed bytes (header + body)
        std::vector<Agent::Wire::UniqueFd> fds; // owned; sent via SCM_RIGHTS on the first sendmsg
        std::size_t sent{0};
        bool ancillarySent{false};
    };

    struct Connection
    {
        std::uint64_t id{0};
        // The socket fd is held in a shared_ptr with a closing deleter so BOTH the
        // read and write dispatch sources' cancel handlers co-own it: the fd is
        // closed only after GCD has fully torn down every source monitoring it
        // (Apple requires an fd-source cancel handler; closing the fd before
        // cancellation completes races the kevent dereg). Never null after accept.
        std::shared_ptr<int> fd;
        Agent::CallerToken caller;
        PeerCredentials creds;
        Agent::Wire::FrameReassembler reassembler;
        dispatch_source_t readSource{nullptr};
        dispatch_source_t writeSource{nullptr};
        // Slow-loris guard: armed on accept, cancelled on the first complete
        // frame; fires -> the connection is reaped. A timer SOURCE (not
        // dispatch_after) so closeConnection/teardown can cancel it — a pending
        // dispatch_after block would outlive the transport.
        dispatch_source_t firstFrameTimer{nullptr};
        bool sawFirstFrame{false};
        bool writeSourceResumed{false};
        std::deque<OutFrame> outQueue;
        // Sum of every currently-queued OutFrame::bytes.size(): incremented in
        // enqueueSend before push_back, decremented in flushWrites alongside
        // pop_front, and zeroed in closeConnection. Checked against
        // kMaxQueuedBytesPerConnection / kMaxQueuedFrames on every enqueue so a
        // peer that never reads (or reads slower than it is published to) gets
        // its connection closed instead of growing this queue forever.
        std::size_t queuedBytes{0};
    };

    enum class SendState : std::uint8_t { Sent, WouldBlock, Error };
    [[nodiscard]] static SendState trySendFrame(int fd, OutFrame& f);

    SocketTransport(dispatch_queue_t queue, Agent::Wire::UniqueFd listenFd, std::string socketPath, bool ownsSocketFile,
                    std::optional<SocketPathIdentity> listenIdentity);
    void installAcceptSource();
    // Replaced-path guard (own socket file only): on every accept and on a
    // timer, compare what the path names with the inode this process bound.
    // On a mismatch the accept source is cancelled; its cancel handler closes
    // the listen fd and binds again. Loop thread.
    void installPathGuard();
    void checkSocketPath();
    void cancelAcceptSource();
    void onAcceptSourceCancelled();
    void rebindListenSocket();
    void onAcceptReady();
    void acceptOne(int connFd);
    void onReadReady(std::uint64_t connId);
    void closeConnection(std::uint64_t connId);
    void armFirstFrameTimer(Connection& conn);
    void onFirstFrameTimeout(std::uint64_t connId);
    static void cancelFirstFrameTimer(Connection& conn) noexcept;
    void enqueueSend(Connection& conn, std::vector<std::uint8_t> framed, std::vector<Agent::Wire::UniqueFd> fds);
    void flushWrites(Connection& conn);
    void broadcast(const Agent::Wire::CborValue& event);

    // ObjectId <-> opaque wire handle. The handle is a stable per-insertion
    // string ("obj/<n>"), the same shape for readers and cards; NEVER a
    // fingerprint.
    [[nodiscard]] std::string handleFor(Agent::ObjectId id);

    dispatch_queue_t m_queue{nullptr};
    Agent::Wire::UniqueFd m_listenFd;
    std::string m_socketPath;
    bool m_ownsSocketFile{false};
    dispatch_source_t m_acceptSource{nullptr};
    // The listen fd is closed ONLY in the accept source's cancel handler
    // (closing it first races GCD's kevent teardown). Every installed accept
    // source enters this group and its cancel handler leaves it, so the
    // destructor waits for the last handler before `this` goes away.
    dispatch_group_t m_acceptTeardown{nullptr};
    // Inode the path named right after our bind(); nullopt while unbound.
    std::optional<SocketPathIdentity> m_listenIdentity;
    dispatch_source_t m_pathGuardTimer{nullptr};
    std::chrono::microseconds m_pathGuardInterval{std::chrono::seconds(10)};
    bool m_rebindPending{false}; // replacement seen; bind again until it succeeds
    bool m_stopping{false};      // destructor started: cancel handlers must not bind
    // The listener as it was when its accept source's cancel was requested;
    // nullopt there already means it had been closed early.
    std::optional<ListenSocketObject> m_cancelledListener;
    std::shared_ptr<std::atomic<std::uint32_t>> m_closedListenFdAtCancel{
        std::make_shared<std::atomic<std::uint32_t>>(0)};

    RequestSink m_sink;
    bool m_loopQuiesced{false}; // set by quiesceLoop(); drops late posted blocks
    std::vector<std::function<void(Agent::CallerToken)>> m_disconnectHandlers;

    std::uint64_t m_nextConnId{1};
    std::uint64_t m_nextHandle{1};
    std::map<std::uint64_t, std::unique_ptr<Connection>> m_connections;
    std::chrono::microseconds m_firstFrameTimeout{std::chrono::seconds(30)};

    // Published presence snapshot, keyed by wire handle.
    std::map<std::string, Agent::Wire::ReaderState> m_readers;
    std::map<std::string, Agent::Wire::CardState> m_cards;
    // Card routing (readerId/readerName/caps/preAuth), keyed by card wire handle.
    // Populated alongside m_cards in publishCard; consumed by cardRouting().
    std::map<std::string, CardRouting> m_cardRouting;
    // The roster snapshot presenceRoster() copies out: rebuilt by the loop
    // (rebuildRoster) after every publish / withdraw, read from any thread
    // under m_rosterMutex.
    mutable std::mutex m_rosterMutex;
    PresenceRoster m_roster;
    // ObjectId -> handle for withdraw / updateProperties, and the reverse for the
    // request path (a request carries a wire handle; the seams need the ObjectId).
    std::map<std::uint64_t, std::string> m_idToHandle;
    std::map<std::string, std::uint64_t> m_handleToId;
};

} // namespace LibreSCRS::Darwin
