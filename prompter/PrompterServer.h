// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/PeerIdentity.h>
#include <LibreSCRS/Darwin/backend/wire/FrameReassembler.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>
#include <LibreSCRS/Darwin/backend/wire/UniqueFd.h>

#include <dispatch/dispatch.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <string>

namespace LibreSCRS::Darwin {

// The agent-owned prompter's socket server: it binds the private 0600
// prompter.sock, PEER-AUTHENTICATES that the connecting client is the agent
// (fail-closed "unauthorized" otherwise — a same-uid process must not be able
// to drive the credential window and harvest a secret), and dispatches each
// RequestSecret to an injected SecretProvider (the AppKit window), each
// RequestSecrets to a MultiSecretProvider (the change modal) and each
// CancelCurrent to a CancelHandler. LM-free (links wire-core only); the
// providers + peer-auth are seams so the server logic is unit-testable without
// a display or real code signing.
//
// Event-driven on GCD dispatch sources (mirroring the agent SocketTransport):
// one serial queue hosts the accept source, every per-connection read source,
// and the connection registry; the BLOCKING provider call (the modal) runs on
// a separate concurrent worker queue. A CancelCurrent arriving on a
// second connection is therefore read and dispatched WHILE a modal raised by a
// first connection is still up — the modal blocks the worker and the main
// queue, never the serial queue. One request is served per connection; the
// reply is sent + scrubbed on the worker and the fd closes with its last
// co-owning share.
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
    // Dismiss whatever modal is currently up (CancelCurrent). Called inline on
    // the serial queue; must not block (the window impl dispatches abortModal
    // asynchronously to the main queue).
    using CancelHandler = std::function<void()>;
    // Is this connecting peer the agent? (real impl: SecTask signing-id match).
    using PeerAuthorized = std::function<bool(const PeerCredentials&)>;

    PrompterServer(std::string socketPath, SecretProvider provider, MultiSecretProvider multiProvider,
                   CancelHandler cancel, PeerAuthorized peerAuth);
    ~PrompterServer();
    PrompterServer(const PrompterServer&) = delete;
    PrompterServer& operator=(const PrompterServer&) = delete;

    // Bind the socket (0600, sun_path-guarded, unlink-stale) + arm the accept
    // source. Returns an error string on bind failure.
    [[nodiscard]] std::expected<void, std::string> start();

    // Cancel the accept + connection sources and quiesce the serial queue.
    // Returns promptly even while a provider call is still blocked inside a
    // modal: that call finishes on its own detached fd share and never touches
    // the server again (no blocking accept() to wake -> no join() hang).
    // Idempotent; start() may be called again afterwards.
    void stop() noexcept;

private:
    struct Connection
    {
        std::uint64_t id{0};
        // Co-owned by the read source's cancel handler and (after dispatch)
        // the worker block, so the fd outlives GCD's kevent teardown and the
        // reply send (the SocketTransport::Connection::fd discipline).
        std::shared_ptr<int> fd;
        wire::FrameReassembler reassembler;
        dispatch_source_t readSource{nullptr};
    };

    void onAcceptReady();
    void acceptOne(int connFd);
    void onReadReady(std::uint64_t connId);
    void closeConnection(std::uint64_t connId);

    std::string m_socketPath;
    SecretProvider m_provider;
    MultiSecretProvider m_multiProvider;
    CancelHandler m_cancel;
    PeerAuthorized m_peerAuth;
    wire::UniqueFd m_listen;
    dispatch_queue_t m_queue{nullptr};  // serial: accept + reads + registry
    dispatch_queue_t m_worker{nullptr}; // concurrent: blocking provider calls
    dispatch_source_t m_acceptSource{nullptr};
    std::uint64_t m_nextConnId{1};
    std::map<std::uint64_t, std::unique_ptr<Connection>> m_connections;
    bool m_started{false};
};

} // namespace LibreSCRS::Darwin
