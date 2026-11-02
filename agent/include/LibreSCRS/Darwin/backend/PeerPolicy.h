// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief The identity the agent requires of the process serving prompter.sock.
///
/// The other direction -- what the prompter and the PKCS#11 module require of
/// the agent -- is LibreAgent's `expectedAgentIdentity()`, the same one every
/// client of agent.sock holds the agent to. Both are compiled in, and so is the
/// team id their designated requirement names (`configuredTeamId()`). Neither
/// end reads an override from the environment: `launchctl setenv` reaches every
/// job the user's launchd starts, so a variable that renamed the expected peer
/// or switched the check off would be a switch any process running as the user
/// could flip.

#include <LibreSCRS/Agent/wire/darwin/PeerCodeSigning.h>

#include <functional>
#include <string>

namespace LibreSCRS::Darwin {

/// @brief What the agent requires of the process serving prompter.sock: the
///        prompter's signing identifier, the App-Group entitlement, and -- when
///        a team id is configured -- the designated requirement.
[[nodiscard]] inline Agent::Wire::Darwin::ExpectedPeerIdentity expectedPrompterIdentity()
{
    namespace Peer = Agent::Wire::Darwin;
    return Peer::ExpectedPeerIdentity{.signingId = std::string(Peer::kPrompterSigningId),
                                      .appGroup = Peer::appGroup(),
                                      .teamId = Peer::configuredTeamId()};
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
