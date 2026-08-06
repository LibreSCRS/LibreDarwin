// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h> // PromptKind

#include <LibreSCRS/Agent/backend/PromptTypes.h>        // PromptOptions, PromptResult, PinChangePromptResult
#include <LibreSCRS/Agent/backend/PrompterClientBase.h> // Operations::PrompterClientBase

#include <functional>
#include <string>

namespace LibreSCRS::Darwin {

// macOS PrompterClientBase backend: forwards PIN / CAN / MRZ requests to the
// agent-owned secure credential window (librescrs-prompter) over the private
// 0600 prompter.sock. The secret returns INLINE over the local socket, is
// scrubbed straight into a cleansing Secure::String, and the transfer buffer is
// zeroed — it NEVER transits a client. The window shows the platform-derived
// (SecCode) requester so the user authorizes a NAMED caller. Same contract as
// the Linux pinentry-kde prompter. The prompter authenticates that WE are the
// agent (peer-auth) before serving.
//
// requestX runs on a per-reader worker (off the main actor); the blocking
// request/reply over prompter.sock is fine there. cancel() opens a separate
// connection and sends CancelCurrent so an in-flight prompt on another
// connection returns Cancelled (mirrors the Linux cross-connection dismiss).
class MacPrompterClient final : public Agent::Operations::PrompterClientBase
{
public:
    // Verifies the process SERVING a freshly-connected prompter socket BEFORE
    // any request is sent or any reply is trusted: a same-uid process that
    // unlinks and re-binds prompter.sock must not be able to feed the agent a
    // secret of its choosing (every wrong PIN presented to the card burns a
    // retry counter). Empty (the default) verifies the prompter's code-signing
    // identity — signing id + App-Group entitlement, the shared PeerCodeSigning
    // gate, symmetric to the prompter authenticating the agent at accept.
    // Tests (and the composition root's explicit development opt-out for
    // unsigned local builds) inject a permissive one.
    using PeerVerifier = std::function<bool(int connectedFd)>;

    explicit MacPrompterClient(std::string prompterSocketPath, PeerVerifier peerVerifier = {});
    ~MacPrompterClient() override;

    [[nodiscard]] Agent::PromptResult requestPin(const Agent::PromptOptions& options) override;
    [[nodiscard]] Agent::PromptResult requestCan(const Agent::PromptOptions& options) override;
    [[nodiscard]] Agent::PromptResult requestMrz(const Agent::PromptOptions& options) override;
    // Two-secret change prompt: current + new PIN captured in ONE modal (the
    // confirm re-entry never leaves the prompter). Both secrets return inline
    // and are scrubbed into cleansing Secure::Strings exactly like the
    // single-secret path.
    [[nodiscard]] Agent::PinChangePromptResult requestPinChange(const Agent::PromptOptions& options) override;

    // Ask the human to confirm a non-card action. Deliberately NOT on
    // PrompterClientBase: that interface is shared with the Linux agent, where
    // consent is polkit's job. Returns Error (fail closed) if the prompter is
    // unreachable, unresponsive or answers something this build cannot read.
    [[nodiscard]] wire::ConfirmReply requestConfirmation(const wire::ConfirmAction& action);
    void cancel() noexcept override;

private:
    [[nodiscard]] Agent::PromptResult request(wire::PromptKind kind, const Agent::PromptOptions& options);
    std::string m_socketPath;
    PeerVerifier m_peerVerifier;
};

} // namespace LibreSCRS::Darwin
