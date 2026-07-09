// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Peer identity capture via LOCAL_PEERTOKEN -> audit_token. This is the
// non-spoofable, TOCTOU-safe basis for the Authorizer's SecTask check (Task 6).
#include <LibreSCRS/Darwin/backend/PeerIdentity.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <cstring>
#include <format>

namespace LibreSCRS::Darwin {

std::string PeerCredentials::label() const
{
    return std::format("pid:{}/gen:{}", pid, pidVersion);
}

std::optional<PeerCredentials> capturePeerCredentials(int connFd) noexcept
{
    audit_token_t token{};
    socklen_t len = sizeof(token);
    if (::getsockopt(connFd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0 || len != sizeof(token)) {
        return std::nullopt; // fail closed
    }
    PeerCredentials creds;
    creds.auditToken = token;
    creds.pid = audit_token_to_pid(token);
    creds.pidVersion = audit_token_to_pidversion(token);
    return creds;
}

} // namespace LibreSCRS::Darwin
