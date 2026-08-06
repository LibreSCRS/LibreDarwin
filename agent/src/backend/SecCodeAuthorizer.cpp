// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// macOS client-authorization gate. Resolves the peer's code-signing identity
// from its audit_token (public SecTaskCreateWithAuditToken, TOCTOU-safe) and
// evaluates the allow-list. Default-allow for the PIN-gated actions; allow-list
// for the trust tier; fail-closed on an unidentifiable peer.
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>

#include <LibreSCRS/Agent/backend/Logging.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecTask.h>

#include <algorithm>
#include <cstring>
#include <utility>

namespace LibreSCRS::Darwin {
namespace {

namespace log = Agent::log;

std::optional<std::string> cfStringToStd(CFStringRef s)
{
    if (s == nullptr) {
        return std::nullopt;
    }
    if (const char* fast = CFStringGetCStringPtr(s, kCFStringEncodingUTF8)) {
        return std::string(fast);
    }
    const CFIndex len = CFStringGetLength(s);
    const CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string out(static_cast<std::size_t>(max), '\0');
    if (CFStringGetCString(s, out.data(), max, kCFStringEncodingUTF8) == false) {
        return std::nullopt;
    }
    out.resize(std::strlen(out.c_str()));
    return out;
}

// Real SecTask resolution: audit_token -> signing identifier + app groups.
SecCodeAuthorizer::PeerAuth resolveWithSecTask(const PeerCredentials& creds)
{
    SecCodeAuthorizer::PeerAuth out;
    SecTaskRef task = SecTaskCreateWithAuditToken(nullptr, creds.auditToken);
    if (task == nullptr) {
        return out; // unidentifiable -> empty (denied where an allow-list applies)
    }

    CFErrorRef err = nullptr;
    if (CFStringRef sid = SecTaskCopySigningIdentifier(task, &err)) {
        out.signingId = cfStringToStd(sid);
        CFRelease(sid);
    }
    if (err != nullptr) {
        CFRelease(err);
        err = nullptr;
    }

    CFStringRef key = CFSTR("com.apple.security.application-groups");
    if (CFTypeRef value = SecTaskCopyValueForEntitlement(task, key, &err)) {
        if (CFGetTypeID(value) == CFArrayGetTypeID()) {
            auto array = static_cast<CFArrayRef>(value);
            const CFIndex n = CFArrayGetCount(array);
            for (CFIndex i = 0; i < n; ++i) {
                auto item = static_cast<CFStringRef>(CFArrayGetValueAtIndex(array, i));
                if (CFGetTypeID(item) == CFStringGetTypeID()) {
                    if (auto g = cfStringToStd(item)) {
                        out.appGroups.push_back(std::move(*g));
                    }
                }
            }
        }
        CFRelease(value);
    }
    if (err != nullptr) {
        CFRelease(err);
    }
    CFRelease(task);
    return out;
}

bool contains(const std::vector<std::string>& list, const std::string& v)
{
    return std::find(list.begin(), list.end(), v) != list.end();
}

} // namespace

SecCodeAuthorizer::SecCodeAuthorizer(CredentialsResolver credentials, Policy policy)
    : m_credentials(std::move(credentials)), m_policy(std::move(policy)), m_authResolver(&resolveWithSecTask)
{}

SecCodeAuthorizer::~SecCodeAuthorizer() = default;

void SecCodeAuthorizer::setAuthResolverForTest(AuthResolver resolver)
{
    m_authResolver = std::move(resolver);
}

bool SecCodeAuthorizer::authorize(std::string_view actionId, const Agent::CallerToken& caller)
{
    const bool isDefault = actionId == Agent::kActionConfigure || actionId == Agent::kActionSign ||
                           actionId == Agent::kActionPkcs11Login || actionId == Agent::kActionCredentialsManage;
    const bool isTrust = actionId == Agent::kActionConfigureTrust;
    if (!isDefault && !isTrust) {
        return false; // unknown action -> deny
    }

    const auto creds = m_credentials(caller);
    if (!creds) {
        log::warnf("authz: denying {} - unidentifiable peer", actionId);
        return false; // fail closed
    }
    const PeerAuth peer = m_authResolver(*creds);

    // A bare signing-identifier match is claimable by an ad-hoc-signed binary, so
    // it is NOT an authentication boundary on its own. An allow-list is therefore
    // honoured ONLY when it is also bound to the app-group entitlement (Apple
    // provisions app groups per Team ID). If an allow-list is configured without a
    // requiredAppGroup, the gate cannot be a real boundary -> fail closed.
    // NOTE: the fully-robust bind is SecCode validity vs a designated
    // requirement (anchor apple + Team OU), which needs the SPI
    // SecCodeCreateWithAuditToken; the public SecTask path reports claimed identity
    // only. The app-group requirement is the strongest PUBLIC-API hardening; a
    // determined ad-hoc spoofer remains a documented residual (default posture —
    // empty allow-list + PIN-as-consent — is unaffected).
    const auto signingIdAllowed = [&](const std::vector<std::string>& list) {
        if (!m_policy.requiredAppGroup) {
            log::warnf("authz: denying {} - allow-list configured without a requiredAppGroup binding", actionId);
            return false;
        }
        return peer.signingId && contains(list, *peer.signingId) &&
               contains(peer.appGroups, *m_policy.requiredAppGroup);
    };

    if (isTrust) {
        // An empty list means no narrowing is configured, NOT "deny
        // everything": the boundary for this tier is the human confirmation
        // the frontend requires before it applies the write. A configured list
        // is an ADDITIONAL narrowing on top of that, for the day a Team ID
        // exists. And-ing the two unconditionally would leave the tier sealed
        // exactly as before, only after bothering the user first.
        if (m_policy.trustTierSigningIds.empty()) {
            return true;
        }
        return signingIdAllowed(m_policy.trustTierSigningIds);
    }
    // Default action: default-allow unless a site allow-list is configured.
    if (m_policy.allowedSigningIds.empty()) {
        return true;
    }
    return signingIdAllowed(m_policy.allowedSigningIds);
}

} // namespace LibreSCRS::Darwin
