// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/PeerIdentity.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>
#include <LibreSCRS/Darwin/backend/wire/UniqueFd.h>

#include <atomic>
#include <expected>
#include <functional>
#include <string>
#include <thread>

namespace LibreSCRS::Darwin {

// The agent-owned prompter's socket server: it binds the private 0600
// prompter.sock, PEER-AUTHENTICATES that the connecting client is the agent
// (fail-closed "unauthorized" otherwise — a same-uid process must not be able to
// drive the credential window and harvest a secret), and dispatches each
// RequestSecret to an injected SecretProvider (the AppKit window) / CancelCurrent
// to a CancelHandler. LM-free (links wire-core only); the provider + peer-auth
// are seams so the server logic is unit-testable without a display or real code
// signing.
class PrompterServer
{
public:
    // Show the credential window for `req`, return the outcome. Called on the
    // accept thread; the window impl marshals UI to the main thread.
    using SecretProvider = std::function<wire::PromptReply(const wire::PromptRequest& req)>;
    // Dismiss whatever modal is currently up (CancelCurrent).
    using CancelHandler = std::function<void()>;
    // Is this connecting peer the agent? (real impl: SecTask signing-id match).
    using PeerAuthorized = std::function<bool(const PeerCredentials&)>;

    PrompterServer(std::string socketPath, SecretProvider provider, CancelHandler cancel, PeerAuthorized peerAuth);
    ~PrompterServer();
    PrompterServer(const PrompterServer&) = delete;
    PrompterServer& operator=(const PrompterServer&) = delete;

    // Bind the socket (0600, sun_path-guarded, unlink-stale) + start the blocking
    // accept thread. Returns an error string on bind failure.
    [[nodiscard]] std::expected<void, std::string> start();
    void stop() noexcept;

    // Peer-auth + serve one request on an already-connected fd. The accept loop
    // calls this per connection; tests drive it directly over a socketpair.
    void handleConnection(int connFd);

private:
    void acceptLoop();

    std::string m_socketPath;
    SecretProvider m_provider;
    CancelHandler m_cancel;
    PeerAuthorized m_peerAuth;
    wire::UniqueFd m_listen;
    std::atomic<bool> m_stop{false};
    std::thread m_thread;
};

} // namespace LibreSCRS::Darwin
