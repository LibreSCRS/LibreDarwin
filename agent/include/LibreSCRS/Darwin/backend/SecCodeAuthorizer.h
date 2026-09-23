// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h>
#include <LibreSCRS/Darwin/backend/PeerIdentity.h>

#include <LibreSCRS/Agent/backend/Authorizer.h>

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Darwin {

// macOS Authorizer backend: the authorization-of-the-CLIENT policy gate (distinct
// from authentication-TO-the-card, which is the PIN). The Linux twin routes the
// decision through polkit; macOS has no polkit, so this resolves the connecting
// peer's code-signing identity from its audit_token via the PUBLIC,
// TOCTOU-safe SecTaskCreateWithAuditToken -> signing identifier + app-group
// entitlement, and checks the Policy allow-lists injected by the composition
// root. NOTE: no configuration source feeds the Policy today — the daemon
// constructs it with empty allow-lists, so the posture below runs entirely on
// its defaults.
//
// Posture: the four default actions (configure / sign / pkcs11.login /
// credentials.manage) are DEFAULT-ALLOW (the signing PIN is the human-presence
// proof; the core rate-limiter caps abuse) unless a site allow-list is
// configured. The trust tier (configure.trust) with an empty list adds no
// narrowing: the boundary there is the device-owner confirmation the frontend
// requires before it applies the write. Unknown actions are denied. A peer
// that cannot be identified is denied (fail closed).
//
// What an allow-list proves, and what it does not: the signing identifier and
// the app-group entitlement are both CLAIMED by the peer's own signature, and
// an ad-hoc signed binary can claim both. Until the peer's designated
// requirement is checked against our Team ID, an allow-list narrows honest
// callers and stops no one who signs a binary to match. Every allow-list still
// requires the app-group entitlement, and fails closed without it, because that
// is the most the public SecTask path can ask for.
//
// The per-caller first-op rate limit is NOT here: it is the neutral core's RateLimiter,
// keyed on the CallerToken the transport mints. This gate does identity only.
class SecCodeAuthorizer final : public Agent::Authorizer
{
public:
    // Resolves a live CallerToken to its captured peer credentials (the
    // transport's credentialsFor). Injected so the gate stays testable.
    using CredentialsResolver = std::function<std::optional<PeerCredentials>(const Agent::CallerToken&)>;

    // The code-signing facts read from a peer's audit_token (the shared
    // SecTask resolution in PeerCodeSigning.h).
    using PeerAuth = PeerCodeSigning;
    // Resolves a peer's SecTask facts. Default = real SecTask; a fake is injected
    // in tests (the test binary has no meaningful signing identity).
    using AuthResolver = std::function<PeerAuth(const PeerCredentials&)>;

    struct Policy
    {
        // Signing identifiers allowed to change TRUST-tier config
        // (TsaUrls/TslSources). Empty => no narrowing; the device-owner
        // confirmation the frontend requires is the boundary.
        std::vector<std::string> trustTierSigningIds;
        // Optional site allow-list for the DEFAULT actions. Empty => default-allow
        // (PIN-as-consent). Non-empty => restrict to these signing identifiers.
        std::vector<std::string> allowedSigningIds;
        // If set, every allow-list decision ALSO requires the peer to carry this
        // app-group entitlement -- claimed by the peer's signature, like the
        // signing identifier. e.g. "group.org.librescrs.LibreMac".
        std::optional<std::string> requiredAppGroup;
    };

    SecCodeAuthorizer(CredentialsResolver credentials, Policy policy);
    ~SecCodeAuthorizer() override;

    [[nodiscard]] Agent::AuthorizationOutcome authorize(std::string_view actionId,
                                                        const Agent::CallerToken& caller) override;

    // Test seam: override the SecTask resolution with a fake.
    void setAuthResolverForTest(AuthResolver resolver);

private:
    CredentialsResolver m_credentials;
    Policy m_policy;
    AuthResolver m_authResolver; // default: real SecTask
};

} // namespace LibreSCRS::Darwin
