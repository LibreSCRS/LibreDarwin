// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The one platform fact the shared PKCS#11 module needs on macOS: where the
// agent listens, and who must be listening there. Both are compiled in; nothing
// is read from the environment of the application that loaded the module.
#include <LibreSCRS/Agent/pkcs11/AgentClientFactory.h>
#include <LibreSCRS/Agent/pkcs11/SocketAgentClient.h>
#include <LibreSCRS/Darwin/backend/AppGroupPaths.h>
#include <LibreSCRS/Darwin/backend/PeerPolicy.h>

#include <memory>

namespace LibreSCRS::Pkcs11Agent {

std::unique_ptr<AgentClient> makeAgentClient()
{
    // The same identity the app and its token extension hold the agent to.
    return std::make_unique<SocketAgentClient>(Darwin::agentSocketPath().string(), SocketTimeouts{}, [](int fd) {
        return Darwin::verifyConnectedPeer(fd, Darwin::expectedAgentIdentity());
    });
}

} // namespace LibreSCRS::Pkcs11Agent
