// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The client-authorization gate policy. The SecTask resolution is faked (the
// test binary has no meaningful code-signing identity); the real SecTask path is
// exercised by the hardware gate. Default-allow for PIN-gated actions, allow-list
// for the trust tier, app-group binding, fail-closed on an unidentifiable peer.
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>

#include <LibreSCRS/Agent/backend/Authorizer.h> // kAction* ids

#include <gtest/gtest.h>

using namespace LibreSCRS::Darwin;
namespace Agent = ::LibreSCRS::Agent;

namespace {

PeerCredentials fakeCreds()
{
    PeerCredentials c;
    c.pid = 4242;
    c.pidVersion = 1;
    return c;
}

// Build an authorizer whose credential + SecTask resolution are faked.
SecCodeAuthorizer make(SecCodeAuthorizer::Policy policy, SecCodeAuthorizer::PeerAuth peer, bool identifiable = true)
{
    SecCodeAuthorizer authz(
        [identifiable](const Agent::CallerToken&) -> std::optional<PeerCredentials> {
            return identifiable ? std::optional<PeerCredentials>(fakeCreds()) : std::nullopt;
        },
        std::move(policy));
    authz.setAuthResolverForTest([peer](const PeerCredentials&) { return peer; });
    return authz;
}

const Agent::CallerToken kCaller{"conn:1"};

TEST(SecCodeAuthorizer, DefaultActionsAllowedByDefault)
{
    auto authz = make({}, {}); // empty policy, unsigned peer
    EXPECT_TRUE(authz.authorize(Agent::kActionConfigure, kCaller));
    EXPECT_TRUE(authz.authorize(Agent::kActionSign, kCaller));
    EXPECT_TRUE(authz.authorize(Agent::kActionPkcs11Login, kCaller));
    EXPECT_TRUE(authz.authorize(Agent::kActionCredentialsManage, kCaller));
}

TEST(SecCodeAuthorizer, UnknownActionDenied)
{
    auto authz = make({}, {});
    EXPECT_FALSE(authz.authorize("org.librescrs.agent.nonsense", kCaller));
}

TEST(SecCodeAuthorizer, TrustTierDeniedWithEmptyAllowList)
{
    SecCodeAuthorizer::PeerAuth peer{std::string("org.librescrs.LibreMac"), {}};
    auto authz = make({}, peer); // no trustTierSigningIds
    EXPECT_FALSE(authz.authorize(Agent::kActionConfigureTrust, kCaller));
}

TEST(SecCodeAuthorizer, TrustTierAllowedForListedSigningId)
{
    SecCodeAuthorizer::Policy policy;
    policy.trustTierSigningIds = {"org.librescrs.LibreMac"};
    policy.requiredAppGroup = "group.org.librescrs.LibreMac"; // allow-list must be group-bound
    SecCodeAuthorizer::PeerAuth peer{std::string("org.librescrs.LibreMac"), {"group.org.librescrs.LibreMac"}};
    auto authz = make(policy, peer);
    EXPECT_TRUE(authz.authorize(Agent::kActionConfigureTrust, kCaller));
}

TEST(SecCodeAuthorizer, AllowListWithoutRequiredAppGroupFailsClosed)
{
    // A bare signing-identifier allow-list (no app-group binding) is spoofable by
    // an ad-hoc-signed binary, so it must fail closed rather than honour the claim.
    SecCodeAuthorizer::Policy trust;
    trust.trustTierSigningIds = {"org.librescrs.LibreMac"};
    auto a1 = make(trust, SecCodeAuthorizer::PeerAuth{std::string("org.librescrs.LibreMac"), {}});
    EXPECT_FALSE(a1.authorize(Agent::kActionConfigureTrust, kCaller));

    SecCodeAuthorizer::Policy dflt;
    dflt.allowedSigningIds = {"org.librescrs.LibreMac"};
    auto a2 = make(dflt, SecCodeAuthorizer::PeerAuth{std::string("org.librescrs.LibreMac"), {}});
    EXPECT_FALSE(a2.authorize(Agent::kActionSign, kCaller));
}

TEST(SecCodeAuthorizer, TrustTierDeniedForUnlistedOrUnsignedPeer)
{
    SecCodeAuthorizer::Policy policy;
    policy.trustTierSigningIds = {"org.librescrs.LibreMac"};
    // Unlisted signing id.
    auto a1 = make(policy, SecCodeAuthorizer::PeerAuth{std::string("com.evil.app"), {}});
    EXPECT_FALSE(a1.authorize(Agent::kActionConfigureTrust, kCaller));
    // Unsigned peer (no signing id).
    auto a2 = make(policy, SecCodeAuthorizer::PeerAuth{std::nullopt, {}});
    EXPECT_FALSE(a2.authorize(Agent::kActionConfigureTrust, kCaller));
}

TEST(SecCodeAuthorizer, DefaultActionAllowListRestricts)
{
    SecCodeAuthorizer::Policy policy;
    policy.allowedSigningIds = {"org.librescrs.LibreMac"};
    policy.requiredAppGroup = "group.org.librescrs.LibreMac"; // allow-list must be group-bound
    auto allowed = make(
        policy, SecCodeAuthorizer::PeerAuth{std::string("org.librescrs.LibreMac"), {"group.org.librescrs.LibreMac"}});
    EXPECT_TRUE(allowed.authorize(Agent::kActionSign, kCaller));
    auto denied =
        make(policy, SecCodeAuthorizer::PeerAuth{std::string("com.evil.app"), {"group.org.librescrs.LibreMac"}});
    EXPECT_FALSE(denied.authorize(Agent::kActionSign, kCaller));
}

TEST(SecCodeAuthorizer, RequiredAppGroupBindsTheAllowList)
{
    SecCodeAuthorizer::Policy policy;
    policy.trustTierSigningIds = {"org.librescrs.LibreMac"};
    policy.requiredAppGroup = "group.org.librescrs.LibreMac";
    // Matching signing id but WITHOUT the app group -> denied (a self-signed
    // binary could claim the id but not our Team-ID-bound group).
    auto without = make(policy, SecCodeAuthorizer::PeerAuth{std::string("org.librescrs.LibreMac"), {}});
    EXPECT_FALSE(without.authorize(Agent::kActionConfigureTrust, kCaller));
    // With the app group -> allowed.
    auto with = make(
        policy, SecCodeAuthorizer::PeerAuth{std::string("org.librescrs.LibreMac"), {"group.org.librescrs.LibreMac"}});
    EXPECT_TRUE(with.authorize(Agent::kActionConfigureTrust, kCaller));
}

TEST(SecCodeAuthorizer, UnidentifiablePeerFailsClosed)
{
    auto authz = make({}, {}, /*identifiable=*/false);
    EXPECT_FALSE(authz.authorize(Agent::kActionSign, kCaller)); // even a default action
    EXPECT_FALSE(authz.authorize(Agent::kActionConfigureTrust, kCaller));
}

} // namespace
