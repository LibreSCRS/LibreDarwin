// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
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
// entitlement, and checks a config/MDM allow-list.
//
// Posture (design §4.1): the three default actions (configure / sign /
// pkcs11.login) are DEFAULT-ALLOW (the signing PIN is the human-presence proof;
// the core rate-limiter caps abuse) unless a site allow-list is configured. The
// trust tier (configure.trust) is allow-list-gated (empty list => denied to all;
// trust config is then file-seeded only, mirroring the Linux DefaultAuthorizer
// fallback). Unknown actions are denied. A peer that cannot be identified is
// denied (fail closed). Where an allow-list applies, an optional required
// app-group entitlement binds it to our Team ID (Apple provisions app groups per
// Team ID), so a self-signed binary cannot claim a listed signing id + our group
// -- stronger than a signing-identifier string alone.
//
// The C7 first-op rate limit is NOT here: it is the neutral core's RateLimiter,
// keyed on the CallerToken the transport mints. This gate does identity only.
class SecCodeAuthorizer final : public Agent::Authorizer
{
public:
    // Resolves a live CallerToken to its captured peer credentials (the
    // transport's credentialsFor). Injected so the gate stays testable.
    using CredentialsResolver = std::function<std::optional<PeerCredentials>(const Agent::CallerToken&)>;

    // The code-signing facts read from a peer's audit_token.
    struct PeerAuth
    {
        std::optional<std::string> signingId; // SecTaskCopySigningIdentifier (nullopt if unsigned)
        std::vector<std::string> appGroups;   // com.apple.security.application-groups
    };
    // Resolves a peer's SecTask facts. Default = real SecTask; a fake is injected
    // in tests (the test binary has no meaningful signing identity).
    using AuthResolver = std::function<PeerAuth(const PeerCredentials&)>;

    struct Policy
    {
        // Signing identifiers allowed to change TRUST-tier config
        // (TsaUrls/TslSources). Empty => nobody (file-seeded trust only).
        std::vector<std::string> trustTierSigningIds;
        // Optional site allow-list for the DEFAULT actions. Empty => default-allow
        // (PIN-as-consent). Non-empty => restrict to these signing identifiers.
        std::vector<std::string> allowedSigningIds;
        // If set, every allow-list decision ALSO requires the peer to carry this
        // app-group entitlement (Team-ID-bound). e.g. "group.org.librescrs.LibreMac".
        std::optional<std::string> requiredAppGroup;
    };

    SecCodeAuthorizer(CredentialsResolver credentials, Policy policy);
    ~SecCodeAuthorizer() override;

    [[nodiscard]] bool authorize(std::string_view actionId, const Agent::CallerToken& caller) override;

    // Test seam: override the SecTask resolution with a fake.
    void setAuthResolverForTest(AuthResolver resolver);

private:
    CredentialsResolver m_credentials;
    Policy m_policy;
    AuthResolver m_authResolver; // default: real SecTask
};

} // namespace LibreSCRS::Darwin
