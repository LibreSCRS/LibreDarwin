// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/PeerIdentity.h>
#include <LibreSCRS/Darwin/backend/SingleInstanceLock.h>
#include <LibreSCRS/Darwin/backend/SocketPathIdentity.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <LibreSCRS/Agent/wire/FrameReassembler.h>
#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <dispatch/dispatch.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>

namespace LibreSCRS::Darwin {

// The agent-owned prompter's socket server: it binds the private 0600
// prompter.sock, PEER-AUTHENTICATES that the connecting client is the agent
// (fail-closed "unauthorized" otherwise — a same-uid process must not be able
// to drive the credential window and harvest a secret), and dispatches each
// RequestSecret to an injected SecretProvider (the AppKit window), each
// RequestSecrets to a MultiSecretProvider (the change panel) and each
// CancelCurrent to a CancelHandler with the id it addresses. LM-free (links
// wire-core only); the providers + peer-auth are seams so the server logic is
// unit-testable without a display or real code signing.
//
// Event-driven on GCD dispatch sources (mirroring the agent SocketTransport):
// one serial queue hosts the accept source, every per-connection read source,
// and the connection registry; the BLOCKING provider call — it raises a panel
// on the main thread and then waits on that panel's own semaphore — runs on a
// separate concurrent worker queue. A CancelCurrent arriving on a second
// connection is therefore read and dispatched WHILE a panel raised by a first
// connection is still up: the wait blocks ONLY the worker thread that asked
// for it, never the serial queue and never the main queue, which goes on
// running the run loop the panels are drawn by. One request is served per
// connection; the reply is sent + scrubbed on the worker and the fd closes
// with its last co-owning share.
class PrompterServer
{
public:
    // Show the credential window for `req`, return the outcome. Called on the
    // concurrent worker queue; the window impl marshals UI to the main thread.
    using SecretProvider = std::function<wire::PromptReply(const wire::PromptRequest& req)>;
    // Show the multi-secret change window for `req` (RequestSecrets, kind
    // "change_pin"), return the outcome. Same worker-queue calling convention
    // as SecretProvider.
    using MultiSecretProvider = std::function<wire::MultiPromptReply(const wire::RequestSecrets& req)>;
    // Dismiss the window @p promptId names (CancelCurrent). Called inline on
    // the serial queue; must not block (the window impl marshals the dismissal
    // to the main queue asynchronously and returns at once). An empty id is an
    // unaddressed dismissal from a caller that knows no id.
    using CancelHandler = std::function<void(const std::string& promptId)>;
    // Ask the human to confirm a non-card action (ConfirmAction). Same
    // worker-queue calling convention as the secret providers: it blocks until
    // the human answers, so it must never run on the serial queue that serves
    // every connection.
    using ConfirmProvider = std::function<wire::ConfirmReply(const wire::ConfirmAction& req)>;
    // Close every window still standing (Reset) and return how many. Run on
    // the concurrent worker queue like every other request-shaped call, even
    // though the real implementation (PromptWindow::dismissAll) is fast and
    // documented safe from any thread: keeping every provider off the serial
    // queue is the one invariant to hold, not "this call happens to be quick".
    // Reset therefore shares the SAME worker queue whose threads the standing
    // prompts already occupy -- the right tradeoff, because calling it inline
    // on the serial queue would instead park THAT queue's accept/read
    // processing for every other connection behind dismissAll()'s own
    // main-queue round trip; bounded only by how many threads GCD is willing
    // to grow the queue to for concurrently blocked work, not by anything
    // this server imposes.
    using ResetHandler = std::function<std::uint32_t()>;
    // Is this connecting peer the agent? (real impl: SecTask signing-id match).
    using PeerAuthorized = std::function<bool(const PeerCredentials&)>;

    PrompterServer(std::string socketPath, SecretProvider provider, MultiSecretProvider multiProvider,
                   CancelHandler cancel, ConfirmProvider confirm, ResetHandler reset, PeerAuthorized peerAuth);
    ~PrompterServer();
    PrompterServer(const PrompterServer&) = delete;
    PrompterServer& operator=(const PrompterServer&) = delete;

    // Take the path's instance lock (SingleInstanceLock), then bind the socket
    // (0600, sun_path-guarded, unlink-stale) + arm the accept source. Another
    // prompter holding the lock is ServerStartError::AnotherInstance, and
    // nothing at the path has been touched; the lock is held until stop().
    [[nodiscard]] std::expected<void, ServerStartError> start();

    // Cancel the accept + connection sources and quiesce the serial queue.
    // Returns promptly even while a provider call is still blocked waiting on
    // its panel: that call finishes on its own detached fd share and never
    // touches the server again (no blocking accept() to wake -> no join()
    // hang).
    // Idempotent; start() may be called again afterwards.
    void stop() noexcept;

    // Where the server reports what it did on its own (a replaced socket path
    // and the bind that answers it). Set before start(); unset = silent. The
    // prompter links no logging facade, so its host supplies one.
    void setWarn(std::function<void(const std::string&)> warn);

    // Test hook: shorten the replaced-path guard's check interval (production
    // keeps 10 s). Set before start().
    void setPathGuardIntervalForTest(std::chrono::microseconds interval) noexcept
    {
        m_pathGuardInterval = interval;
    }

    // Test hook: how many accept-source cancel handlers found the listen fd
    // already closed (or no longer this listener). Must stay 0: the fd may
    // close only inside that handler. Read after stop().
    [[nodiscard]] std::shared_ptr<const std::atomic<std::uint32_t>> closedListenFdAtCancelForTest() const noexcept
    {
        return m_closedListenFdAtCancel;
    }

private:
    struct Connection
    {
        std::uint64_t id{0};
        // Co-owned by the read source's cancel handler and (after dispatch)
        // the worker block, so the fd outlives GCD's kevent teardown and the
        // reply send (the SocketTransport::Connection::fd discipline).
        std::shared_ptr<int> fd;
        Agent::Wire::FrameReassembler reassembler;
        dispatch_source_t readSource{nullptr};
    };

    void onAcceptReady();
    void acceptOne(int connFd);
    void onReadReady(std::uint64_t connId);
    void closeConnection(std::uint64_t connId);
    // Bind + listen the socket file and record its inode; loop thread or start().
    [[nodiscard]] std::expected<void, std::string> bindListenSocket();
    void installAcceptSource();
    void installPathGuard();
    // Replaced-path guard: on every accept and on a timer, compare what the
    // path names with the inode we bound; on a mismatch cancel the accept
    // source, whose cancel handler closes the listen fd and binds again.
    void checkSocketPath();
    void cancelAcceptSource();
    void onAcceptSourceCancelled();
    void rebindListenSocket();
    void warn(const std::string& message) const;

    std::string m_socketPath;
    SecretProvider m_provider;
    MultiSecretProvider m_multiProvider;
    CancelHandler m_cancel;
    ConfirmProvider m_confirmProvider;
    ResetHandler m_reset;
    PeerAuthorized m_peerAuth;
    Agent::Wire::UniqueFd m_listen;
    dispatch_queue_t m_queue{nullptr};  // serial: accept + reads + registry
    dispatch_queue_t m_worker{nullptr}; // concurrent: blocking provider calls
    dispatch_source_t m_acceptSource{nullptr};
    // The listen fd is closed ONLY in the accept source's cancel handler;
    // every installed accept source enters this group and its cancel handler
    // leaves it, so stop() waits for the last handler before returning.
    dispatch_group_t m_acceptTeardown{nullptr};
    std::optional<SocketPathIdentity> m_listenIdentity; // nullopt while unbound
    // Held from start() to stop(); released there only after the socket file
    // is removed, so a successor's fresh file cannot be the one removed.
    std::optional<SingleInstanceLock> m_instanceLock;
    dispatch_source_t m_pathGuardTimer{nullptr};
    std::chrono::microseconds m_pathGuardInterval{std::chrono::seconds(10)};
    bool m_rebindPending{false}; // replacement seen; bind again until it succeeds
    bool m_stopping{false};      // stop() started: cancel handlers must not bind
    // The listener as it was when its accept source's cancel was requested;
    // nullopt there already means it had been closed early.
    std::optional<ListenSocketObject> m_cancelledListener;
    std::shared_ptr<std::atomic<std::uint32_t>> m_closedListenFdAtCancel{
        std::make_shared<std::atomic<std::uint32_t>>(0)};
    std::function<void(const std::string&)> m_warn;
    std::uint64_t m_nextConnId{1};
    std::map<std::uint64_t, std::unique_ptr<Connection>> m_connections;
    bool m_started{false};
};

} // namespace LibreSCRS::Darwin
