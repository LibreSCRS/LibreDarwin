// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SKELETON — stub (TODO P1b: implement-macos-backend). requestX return values
// are value-initialized placeholders; P1b returns real PromptResult status +
// Secure::String from the credential window.
#include <LibreSCRS/Darwin/backend/MacPrompterClient.h>

namespace LibreSCRS::Darwin {

MacPrompterClient::MacPrompterClient() = default;
MacPrompterClient::~MacPrompterClient() = default;

Agent::Operations::PromptResult MacPrompterClient::requestPin(const Agent::Operations::PromptOptions&)
{
    // TODO(P1b): IPC to the agent-owned credential window; return the entered PIN.
    return {};
}

Agent::Operations::PromptResult MacPrompterClient::requestCan(const Agent::Operations::PromptOptions&)
{
    // TODO(P1b): CAN surface (the system PIN sheet cannot render CAN).
    return {};
}

Agent::Operations::PromptResult MacPrompterClient::requestMrz(const Agent::Operations::PromptOptions&)
{
    // TODO(P1b): MRZ (ICAO 9303) surface.
    return {};
}

void MacPrompterClient::cancel() noexcept
{
    // TODO(P1b): dismiss the current modal (wired by OperationBase::requestCancel).
}

} // namespace LibreSCRS::Darwin
