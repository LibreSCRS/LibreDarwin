// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// macOS client-authorization gate. Resolves the peer's code-signing identity
// from its audit_token (public SecTaskCreateWithAuditToken, TOCTOU-safe; the
// designated requirement too when a Team ID is configured) and evaluates the
// allow-list. Default-allow for the PIN-gated actions; allow-list
// for the trust tier; fail-closed on an unidentifiable peer.
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>

#include <LibreSCRS/Agent/backend/Logging.h>

#include <algorithm>
#include <utility>

namespace LibreSCRS::Darwin {
namespace {

namespace log = Agent::log;

bool contains(const std::vector<std::string>& list, const std::string& v)
{
    return std::find(list.begin(), list.end(), v) != list.end();
}

} // namespace

SecCodeAuthorizer::SecCodeAuthorizer(CredentialsResolver credentials, Policy policy)
    : m_credentials(std::move(credentials)), m_policy(std::move(policy)),
      m_authResolver(
          [teamId = m_policy.teamId](const PeerCredentials& creds) { return resolvePeerCodeSigning(creds, teamId); })
{}

SecCodeAuthorizer::~SecCodeAuthorizer() = default;

void SecCodeAuthorizer::setAuthResolverForTest(AuthResolver resolver)
{
    m_authResolver = std::move(resolver);
}

Agent::AuthorizationOutcome SecCodeAuthorizer::authorize(std::string_view actionId, const Agent::CallerToken& caller)
{
    const bool isDefault = actionId == Agent::kActionConfigure || actionId == Agent::kActionSign ||
                           actionId == Agent::kActionPkcs11Login || actionId == Agent::kActionCredentialsManage;
    const bool isTrust = actionId == Agent::kActionConfigureTrust;
    if (!isDefault && !isTrust) {
        return Agent::AuthorizationOutcome::Denied; // unknown action -> deny
    }

    const auto creds = m_credentials(caller);
    if (!creds) {
        log::warnf("authz: denying {} - unidentifiable peer", actionId);
        return Agent::AuthorizationOutcome::Denied; // fail closed
    }
    const PeerAuth peer = m_authResolver(*creds);

    // A signing-identifier match is claimable by an ad-hoc-signed binary, and so
    // is the app-group entitlement: the SecTask path reports what the peer's own
    // signature claims. An allow-list is honoured ONLY together with the
    // app-group requirement, and one configured without a requiredAppGroup fails
    // closed. What neither proves is who signed the peer. With a Team ID in the
    // policy that is proved too: the shared resolution checks the peer's code,
    // reached by its audit token through public Security API, against the
    // designated requirement (anchor apple + our Team ID as the leaf OU), and an
    // allow-list then demands that it held. Without a Team ID a determined
    // ad-hoc spoofer is a documented residual; the default posture -- empty
    // allow-lists, PIN-as-consent -- does not rest on either.
    const auto signingIdAllowed = [&](const std::vector<std::string>& list) {
        if (!m_policy.requiredAppGroup) {
            log::warnf("authz: denying {} - allow-list configured without a requiredAppGroup binding", actionId);
            return false;
        }
        if (m_policy.teamId && peer.designatedRequirementValid != true) {
            log::warnf("authz: denying {} - peer does not satisfy the designated requirement", actionId);
            return false;
        }
        return peer.signingId && contains(list, *peer.signingId) &&
               contains(peer.appGroups, *m_policy.requiredAppGroup);
    };

    if (isTrust) {
        // An empty list means no narrowing is configured, NOT "deny
        // everything": the boundary for this tier is the human confirmation
        // the frontend requires before it applies the write. A configured list
        // is an ADDITIONAL narrowing on top of that, meaningful once the peer's
        // designated requirement is checked against a Team ID. And-ing the two
        // unconditionally would leave the tier sealed exactly as before, only
        // after bothering the user first.
        if (m_policy.trustTierSigningIds.empty()) {
            return Agent::AuthorizationOutcome::Granted;
        }
        return signingIdAllowed(m_policy.trustTierSigningIds) ? Agent::AuthorizationOutcome::Granted
                                                              : Agent::AuthorizationOutcome::Denied;
    }
    // Default action: default-allow unless a site allow-list is configured.
    if (m_policy.allowedSigningIds.empty()) {
        return Agent::AuthorizationOutcome::Granted;
    }
    return signingIdAllowed(m_policy.allowedSigningIds) ? Agent::AuthorizationOutcome::Granted
                                                        : Agent::AuthorizationOutcome::Denied;
}

} // namespace LibreSCRS::Darwin
