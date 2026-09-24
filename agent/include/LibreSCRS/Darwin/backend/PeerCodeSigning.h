// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/PeerIdentity.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Darwin {

// The code-signing facts read from a peer's audit_token via the PUBLIC,
// TOCTOU-safe SecTaskCreateWithAuditToken, plus -- when a team id is configured
// -- whether the peer's code satisfies our designated requirement. ONE
// resolution path shared by the agent's client-authorization gate
// (SecCodeAuthorizer) and both ends of the private prompter socket, so the
// SecTask and SecCode logic exists exactly once.
struct PeerCodeSigning
{
    std::optional<std::string> signingId; // SecTaskCopySigningIdentifier (nullopt if unsigned)
    std::vector<std::string> appGroups;   // com.apple.security.application-groups
    // nullopt: not evaluated (no team id). false: evaluated and failed, or the
    // peer's code could not be reached. true: SecCodeCheckValidity held.
    std::optional<bool> designatedRequirementValid{};
};

// The identity ONE specific trusted peer must present: its code-signing
// identifier plus an App-Group entitlement. Both are CLAIMED by the peer's own
// signature, and an ad-hoc signed binary can claim both. With a team id the
// peer must also satisfy the designated requirement "anchor apple generic,
// leaf OU = team id, identifier = its signing id", which only a binary our
// team signed can; that is the check that says who signed it. Without one, a
// match keeps our binaries from talking to a stranger by accident, not to one
// that signs itself to match.
struct ExpectedPeerIdentity
{
    std::string signingId;
    std::string appGroup;
    std::optional<std::string> teamId{}; // nullopt: no designated-requirement check
};

// Canonical identities of the two agent-owned binaries (their embedded
// CFBundleIdentifier, which codesign uses as the default signing identifier)
// and the App Group both are provisioned into.
inline constexpr std::string_view kAgentSigningId = "org.librescrs.agent";
inline constexpr std::string_view kPrompterSigningId = "org.librescrs.prompter";
inline constexpr std::string_view kAppGroup = "group.org.librescrs.LibreMac";

// The team id this build was configured with (the LIBRESCRS_TEAM_ID CMake cache
// value, compiled in). nullopt when it is empty, which keeps the checks as they
// were before the designated requirement existed. Never read from the
// environment: a variable could switch the check off for every job launchd starts.
[[nodiscard]] std::optional<std::string> configuredTeamId();

// The designated requirement text for `signingId` signed by `teamId`, or nullopt
// when either is empty or carries anything but letters, digits and (for the
// identifier) '.', '-', '_' -- both are pasted into the requirement language, so
// a quote or a space could add a clause.
[[nodiscard]] std::optional<std::string> designatedRequirementFor(std::string_view teamId, std::string_view signingId);

// Resolve a peer's SecTask facts. An unidentifiable peer yields an empty
// result (no signing id, no groups) — callers fail closed on it. With a team id,
// also evaluate the designated requirement against the peer's code (reached by
// its audit token, public API) for the signing id SecTask reported.
[[nodiscard]] PeerCodeSigning resolvePeerCodeSigning(const PeerCredentials& creds,
                                                     const std::optional<std::string>& teamId);

// Policy: does `peer` present `expected` (signing-identifier match AND the
// app-group entitlement, AND the designated requirement when `expected` names a
// team id)? Pure, so it is unit-testable without real signing.
[[nodiscard]] bool matchesExpectedPeer(const PeerCodeSigning& peer, const ExpectedPeerIdentity& expected);

// Capture + resolve + match in one step on a CONNECTED AF_UNIX fd
// (LOCAL_PEERTOKEN reports the peer from either end, so a CLIENT can verify
// the process serving the socket it just connected to). Fails closed when the
// peer cannot be captured or resolved.
[[nodiscard]] bool verifyConnectedPeer(int connectedFd, const ExpectedPeerIdentity& expected);

// Does THIS process's code satisfy the designated requirement for `signingId`
// signed by `teamId`?
[[nodiscard]] bool selfSatisfiesDesignatedRequirement(std::string_view teamId, std::string_view signingId);

// The start-up self-check: true when no team id is configured, otherwise whether
// this process satisfies the requirement its peers will hold it to. A build that
// names a team id but was signed by someone else would otherwise start and be
// refused by every peer with nothing to say why.
[[nodiscard]] bool selfMatchesConfiguredTeam(std::string_view selfSigningId);

} // namespace LibreSCRS::Darwin
