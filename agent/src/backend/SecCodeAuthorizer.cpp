// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SKELETON — stub (TODO P1b: implement-macos-backend).
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>

namespace LibreSCRS::Darwin {

SecCodeAuthorizer::SecCodeAuthorizer() = default;
SecCodeAuthorizer::~SecCodeAuthorizer() = default;

bool SecCodeAuthorizer::authorize(std::string_view /*actionId*/, const Agent::CallerToken& /*caller*/)
{
    // TODO(P1b): resolve caller audit_token -> SecCode, check the Designated
    // Requirement + config/MDM allow-list, enforce the C7 first-op rate limit.
    // Default-allow placeholder until the policy lands.
    return true;
}

} // namespace LibreSCRS::Darwin
