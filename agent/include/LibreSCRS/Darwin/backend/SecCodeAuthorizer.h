// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/Authorizer.h>

#include <string_view>

namespace LibreSCRS::Darwin {

// macOS Authorizer backend: the authorization-of-the-CLIENT policy gate (distinct
// from authentication-TO-the-card, which is the PIN). The Linux twin routes the
// decision through polkit; macOS has no polkit, so this resolves the connecting
// peer's code-signing identity from its audit_token (captured by SocketTransport
// via LOCAL_PEERTOKEN) via the PUBLIC SecTaskCreateWithAuditToken (TOCTOU-safe)
// -> signing identifier / Team ID + entitlements, checked against a config/MDM
// allow-list. (No fully-public API builds a SecCodeRef from an audit token:
// SecCodeCreateWithAuditToken AND kSecGuestAttributeAudit are SPI; the public
// PID attribute is TOCTOU-racy. The browser-loaded facade's peer is the BROWSER's
// Team ID, so the facade path is default-allowed, not gated by our Team ID.)
// Default-allow (PIN-as-consent is the human
// presence proof), site-restrictable.
//
// TODO(P1b) implement-macos-backend: resolve the CallerToken -> SecCode DR,
// evaluate the config/MDM policy, and enforce the C7 first-op rate limit
// (5 prompt-raising first-ops / 60 s per caller, exponential backoff 2 s->60 s,
// RateLimited fail-closed) shared with the Card1.Sign throttle.
class SecCodeAuthorizer final : public Agent::Authorizer
{
public:
    SecCodeAuthorizer();
    ~SecCodeAuthorizer() override;

    [[nodiscard]] bool authorize(std::string_view actionId, const Agent::CallerToken& caller) override;
};

} // namespace LibreSCRS::Darwin
