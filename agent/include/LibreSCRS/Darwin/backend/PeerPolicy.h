// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief The identities the two ends of the private prompter socket require of
///        each other, in one place.
///
/// Both are compiled in. Neither end reads an override from the environment:
/// `launchctl setenv` reaches every job the user's launchd starts, so a variable
/// that renamed the expected peer or switched the check off would be a switch any
/// process running as the user could flip.

#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h>

#include <functional>
#include <string>

namespace LibreSCRS::Darwin {

/// @brief What the prompter requires of the process connecting to prompter.sock:
///        the agent's signing identifier and the App-Group entitlement.
[[nodiscard]] inline ExpectedPeerIdentity expectedAgentIdentity()
{
    return ExpectedPeerIdentity{.signingId = std::string(kAgentSigningId), .appGroup = std::string(kAppGroup)};
}

/// @brief What the agent requires of the process serving prompter.sock: the
///        prompter's signing identifier and the App-Group entitlement.
[[nodiscard]] inline ExpectedPeerIdentity expectedPrompterIdentity()
{
    return ExpectedPeerIdentity{.signingId = std::string(kPrompterSigningId), .appGroup = std::string(kAppGroup)};
}

/// @brief The check the agent runs on a freshly connected prompter socket before
///        any request is sent or any reply is trusted.
///
/// Verifies the serving peer against @ref expectedPrompterIdentity. There is no
/// opt-out: a same-uid process that unlinks and re-binds prompter.sock must not
/// be able to feed the agent a secret of its choosing, since every wrong PIN
/// presented to a card burns a retry counter.
///
/// @return A verifier taking the connected descriptor; `false` means refuse.
[[nodiscard]] std::function<bool(int connectedFd)> makeDefaultPrompterVerifier();

} // namespace LibreSCRS::Darwin
