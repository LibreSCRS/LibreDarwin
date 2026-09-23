// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Darwin/backend/PeerPolicy.h>

namespace LibreSCRS::Darwin {

std::function<bool(int connectedFd)> makeDefaultPrompterVerifier()
{
    return
        [expected = expectedPrompterIdentity()](int connectedFd) { return verifyConnectedPeer(connectedFd, expected); };
}

} // namespace LibreSCRS::Darwin
