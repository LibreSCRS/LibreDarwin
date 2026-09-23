// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The shared expected-peer policy both ends of the private prompter socket
// enforce (and the SecCodeAuthorizer's allow-list builds on): signing-id match
// alone is NEVER enough — the App-Group entitlement must also be present, and
// an unsigned/unidentifiable peer always fails closed. Both are claimed by the
// peer's own signature, so this is the policy, not an authentication. The
// real SecTask resolution is exercised by the hardware gate (this test binary
// has no meaningful code-signing identity).
#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h>

#include <gtest/gtest.h>

#include <string>

using namespace LibreSCRS::Darwin;

namespace {

const ExpectedPeerIdentity kExpectedAgent{std::string(kAgentSigningId), std::string(kAppGroup)};

TEST(PeerCodeSigning, MatchingSigningIdAndAppGroupPasses)
{
    PeerCodeSigning peer{std::string(kAgentSigningId), {std::string(kAppGroup)}};
    EXPECT_TRUE(matchesExpectedPeer(peer, kExpectedAgent));
}

TEST(PeerCodeSigning, ExtraAppGroupsDoNotHideTheRequiredOne)
{
    PeerCodeSigning peer{std::string(kAgentSigningId), {"group.example.other", std::string(kAppGroup)}};
    EXPECT_TRUE(matchesExpectedPeer(peer, kExpectedAgent));
}

TEST(PeerCodeSigning, WrongSigningIdFailsEvenWithTheAppGroup)
{
    PeerCodeSigning peer{std::string("com.evil.app"), {std::string(kAppGroup)}};
    EXPECT_FALSE(matchesExpectedPeer(peer, kExpectedAgent));
}

TEST(PeerCodeSigning, SigningIdAloneWithoutTheAppGroupFails)
{
    // The policy requires both claims. Neither authenticates: an ad-hoc-signed
    // binary can claim the app group as easily as the signing identifier.
    PeerCodeSigning peer{std::string(kAgentSigningId), {}};
    EXPECT_FALSE(matchesExpectedPeer(peer, kExpectedAgent));
}

TEST(PeerCodeSigning, UnsignedPeerFailsClosed)
{
    PeerCodeSigning peer{std::nullopt, {std::string(kAppGroup)}};
    EXPECT_FALSE(matchesExpectedPeer(peer, kExpectedAgent));
}

TEST(PeerCodeSigning, UnidentifiablePeerResolvesEmptyAndFailsClosed)
{
    // resolvePeerCodeSigning on a default (zero) audit token: whatever SecTask
    // reports for it, the resulting facts must NOT match our expected agent.
    PeerCredentials creds;
    EXPECT_FALSE(matchesExpectedPeer(resolvePeerCodeSigning(creds), kExpectedAgent));
}

} // namespace
