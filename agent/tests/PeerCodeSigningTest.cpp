// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The shared expected-peer policy both ends of the private prompter socket
// enforce (and the SecCodeAuthorizer's allow-list builds on): signing-id match
// alone is NEVER enough — the App-Group entitlement must also be present, and
// an unsigned/unidentifiable peer always fails closed. Both are claimed by the
// peer's own signature, so this is the policy, not an authentication. With a
// team id configured the policy also demands the peer's designated requirement,
// which is what does authenticate. The real SecTask resolution is exercised by
// the hardware gate; the designated-requirement path is exercised here against
// this test binary, which no team signed, so the positive half waits for a
// Developer ID build.
#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h>

#include <gtest/gtest.h>

#include <mach/mach.h>

#include <optional>
#include <string>

using namespace LibreSCRS::Darwin;

namespace {

const ExpectedPeerIdentity kExpectedAgent{std::string(kAgentSigningId), appGroup()};

TEST(PeerCodeSigning, MatchingSigningIdAndAppGroupPasses)
{
    PeerCodeSigning peer{std::string(kAgentSigningId), {appGroup()}};
    EXPECT_TRUE(matchesExpectedPeer(peer, kExpectedAgent));
}

TEST(PeerCodeSigning, ExtraAppGroupsDoNotHideTheRequiredOne)
{
    PeerCodeSigning peer{std::string(kAgentSigningId), {"group.example.other", appGroup()}};
    EXPECT_TRUE(matchesExpectedPeer(peer, kExpectedAgent));
}

TEST(PeerCodeSigning, WrongSigningIdFailsEvenWithTheAppGroup)
{
    PeerCodeSigning peer{std::string("com.evil.app"), {appGroup()}};
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
    PeerCodeSigning peer{std::nullopt, {appGroup()}};
    EXPECT_FALSE(matchesExpectedPeer(peer, kExpectedAgent));
}

TEST(PeerCodeSigning, UnidentifiablePeerResolvesEmptyAndFailsClosed)
{
    // resolvePeerCodeSigning on a default (zero) audit token: whatever SecTask
    // reports for it, the resulting facts must NOT match our expected agent.
    PeerCredentials creds;
    EXPECT_FALSE(matchesExpectedPeer(resolvePeerCodeSigning(creds, std::nullopt), kExpectedAgent));
}

const ExpectedPeerIdentity kExpectedTeamAgent{std::string(kAgentSigningId), appGroup(), "ABCDE12345"};

PeerCodeSigning claimingAgent(std::optional<bool> designatedRequirementValid)
{
    return PeerCodeSigning{std::string(kAgentSigningId), {appGroup()}, designatedRequirementValid};
}

TEST(PeerCodeSigning, TeamIdRequiresDesignatedRequirement)
{
    // The two claims match, but with a team id configured they are not enough:
    // an ad-hoc binary can make both. Only a designated requirement that held
    // lets the peer through; one that was never evaluated counts as failed.
    EXPECT_FALSE(matchesExpectedPeer(claimingAgent(std::nullopt), kExpectedTeamAgent));
    EXPECT_FALSE(matchesExpectedPeer(claimingAgent(false), kExpectedTeamAgent));
    EXPECT_TRUE(matchesExpectedPeer(claimingAgent(true), kExpectedTeamAgent));
}

TEST(PeerCodeSigning, TeamIdDoesNotReplaceTheClaimedIdentity)
{
    PeerCodeSigning wrongId{std::string("com.evil.app"), {appGroup()}, true};
    EXPECT_FALSE(matchesExpectedPeer(wrongId, kExpectedTeamAgent));
    PeerCodeSigning noGroup{std::string(kAgentSigningId), {}, true};
    EXPECT_FALSE(matchesExpectedPeer(noGroup, kExpectedTeamAgent));
}

TEST(PeerCodeSigning, WithoutTeamIdTheDesignatedRequirementIsNotConsulted)
{
    // Empty team id = the behaviour before the check existed.
    EXPECT_TRUE(matchesExpectedPeer(claimingAgent(std::nullopt), kExpectedAgent));
    EXPECT_TRUE(matchesExpectedPeer(claimingAgent(false), kExpectedAgent));
}

TEST(PeerCodeSigning, AppGroupIsNamedAfterTheTeam)
{
    // Spelled out here rather than built from a shared constant, so the test
    // does not share the rule it checks.
    EXPECT_EQ(appGroupFor(""), "group.org.librescrs.LibreMac");
    EXPECT_EQ(appGroupFor("ABCDE12345"), "ABCDE12345.org.librescrs.LibreMac");
}

TEST(PeerCodeSigning, DesignatedRequirementNamesTheTeamAndTheIdentifier)
{
    EXPECT_EQ(designatedRequirementFor("ABCDE12345", kAgentSigningId),
              std::optional<std::string>("anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\" "
                                         "and identifier \"org.librescrs.agent\""));
}

TEST(PeerCodeSigning, DesignatedRequirementRefusesTextThatCouldRewriteIt)
{
    // Both strings are pasted into the requirement language. A quote or a space
    // in either would let the text add a clause of its own, so neither is
    // escaped: anything outside the plain alphabet is refused.
    EXPECT_FALSE(designatedRequirementFor("", kAgentSigningId));
    EXPECT_FALSE(designatedRequirementFor("ABCDE12345", ""));
    EXPECT_FALSE(designatedRequirementFor("ABC\" or true", kAgentSigningId));
    EXPECT_FALSE(designatedRequirementFor("ABCDE12345", "org.librescrs.agent\" or identifier \"x"));
    EXPECT_FALSE(designatedRequirementFor("ABCDE 12345", kAgentSigningId));
}

PeerCredentials ownCredentials()
{
    PeerCredentials creds;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    EXPECT_EQ(task_info(mach_task_self(), TASK_AUDIT_TOKEN, reinterpret_cast<task_info_t>(&creds.auditToken), &count),
              KERN_SUCCESS);
    return creds;
}

TEST(PeerCodeSigning, ResolveEvaluatesTheRequirementOnlyWhenATeamIdIsGiven)
{
    // This process as its own peer: no team signed the test binary, so the
    // requirement is evaluated and fails. Without a team id it is not evaluated.
    const PeerCredentials creds = ownCredentials();
    EXPECT_EQ(resolvePeerCodeSigning(creds, std::nullopt).designatedRequirementValid, std::nullopt);
    EXPECT_EQ(resolvePeerCodeSigning(creds, std::string("ABCDE12345")).designatedRequirementValid,
              std::optional<bool>(false));
}

TEST(PeerCodeSigning, UnsignedByTheTeamSelfFailsTheRequirement)
{
    // The start-up self-check on a binary the team did not sign: it must say no,
    // so a mis-signed build refuses to start instead of being refused by its peer.
    EXPECT_FALSE(selfSatisfiesDesignatedRequirement("ABCDE12345", kAgentSigningId));
}

TEST(SignatureMatchesBuild, NeedsTheGroupAlways)
{
    EXPECT_TRUE(signatureMatchesBuild(true, "group.org.librescrs.LibreMac", {"group.org.librescrs.LibreMac"}));
    EXPECT_TRUE(signatureMatchesBuild(true, "ABCDE12345.org.librescrs.LibreMac",
                                      {"group.example.other", "ABCDE12345.org.librescrs.LibreMac"}));
    // Built for a team, signed into the team-less group (or the other way
    // round): the agent would serve a container its clients never look in.
    EXPECT_FALSE(signatureMatchesBuild(true, "ABCDE12345.org.librescrs.LibreMac", {"group.org.librescrs.LibreMac"}));
    EXPECT_FALSE(signatureMatchesBuild(true, "group.org.librescrs.LibreMac", {"ABCDE12345.org.librescrs.LibreMac"}));
    EXPECT_FALSE(
        signatureMatchesBuild(true, "ABCDE12345.org.librescrs.LibreMac", {"VWXYZ67890.org.librescrs.LibreMac"}));
    EXPECT_FALSE(signatureMatchesBuild(true, "group.org.librescrs.LibreMac", {}));
    // The group is right but the team's designated requirement does not hold.
    EXPECT_FALSE(signatureMatchesBuild(false, "group.org.librescrs.LibreMac", {"group.org.librescrs.LibreMac"}));
}

TEST(SignatureMatchesBuild, UnentitledTestBinaryDoesNotMatch)
{
    // The linker-signed test binary carries no App Group at all, so it fails
    // the group whether or not the build names a team.
    // In a build with no team, red if reading this process's groups is stubbed
    // to report the build's.
    EXPECT_FALSE(selfMatchesBuild(kAgentSigningId));
}

} // namespace
