// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <bsm/libbsm.h> // audit_token_t + audit_token_to_pid / _pidversion

#include <cstdint>
#include <optional>
#include <string>

namespace LibreSCRS::Darwin {

// Non-spoofable peer credentials captured from an accepted AF_UNIX socket via
// getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN) (macOS 10.15+). The audit_token is
// TOCTOU-safe — it carries the pid AND the pidversion, so a reused pid is
// distinguishable — and is exactly what the SecCodeAuthorizer turns into a
// SecTask (SecTaskCreateWithAuditToken). Prefer this over getpeereid/getpid,
// which are pid-reuse-racy and carry no code-signing identity.
struct PeerCredentials
{
    audit_token_t auditToken{};
    pid_t pid{-1};
    std::uint32_t pidVersion{0};

    // Stable, reuse-immune label for logs / diagnostics ("pid:<pid>/gen:<ver>").
    // This is NOT the CallerToken — the transport mints a per-connection
    // CallerToken and maps it back to these credentials for the authorizer.
    [[nodiscard]] std::string label() const;
};

// Capture the connected peer's credentials from an accepted socket fd. Returns
// nullopt on failure (fail closed — never default-trust an unidentifiable peer).
[[nodiscard]] std::optional<PeerCredentials> capturePeerCredentials(int connFd) noexcept;

} // namespace LibreSCRS::Darwin
