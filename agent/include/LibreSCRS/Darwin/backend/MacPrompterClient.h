// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/PromptTypes.h>        // PromptOptions, PromptResult
#include <LibreSCRS/Agent/backend/PrompterClientBase.h> // Operations::PrompterClientBase

namespace LibreSCRS::Darwin {

// macOS PrompterClientBase backend: forwards PIN / CAN / MRZ requests to the
// agent-owned secure credential window (prompter/). The secret returns as a
// cleansing Secure::String and NEVER transits a client — the same contract as
// the Linux pinentry-kde prompter. The window shows the platform-derived client
// identity (from the peer SecCode) so the user authorizes a NAMED requester.
//
// TODO(P1b) implement-macos-backend: IPC to the credential window, cancel()
// dismissing the current modal, and the CAN/MRZ surfaces the system PIN sheet
// cannot provide (why protected-auth-path is agent-owned here).
class MacPrompterClient final : public Agent::Operations::PrompterClientBase
{
public:
    MacPrompterClient();
    ~MacPrompterClient() override;

    [[nodiscard]] Agent::Operations::PromptResult requestPin(const Agent::Operations::PromptOptions& options) override;
    [[nodiscard]] Agent::Operations::PromptResult requestCan(const Agent::Operations::PromptOptions& options) override;
    [[nodiscard]] Agent::Operations::PromptResult requestMrz(const Agent::Operations::PromptOptions& options) override;
    void cancel() noexcept override;
};

} // namespace LibreSCRS::Darwin
