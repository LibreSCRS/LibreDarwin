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
// TOCTOU-safe SecTaskCreateWithAuditToken. ONE resolution path shared by the
// agent's client-authorization gate (SecCodeAuthorizer) and both ends of the
// private prompter socket, so the SecTask logic exists exactly once.
struct PeerCodeSigning
{
    std::optional<std::string> signingId; // SecTaskCopySigningIdentifier (nullopt if unsigned)
    std::vector<std::string> appGroups;   // com.apple.security.application-groups
};

// The identity ONE specific trusted peer must present: its code-signing
// identifier plus an App-Group entitlement. Apple provisions app groups per
// Team ID, so the group requirement binds the (claimable) signing identifier
// to our Team ID — the strongest PUBLIC-API binding; the SecCode/designated-
// requirement residual is documented in SecCodeAuthorizer.cpp.
struct ExpectedPeerIdentity
{
    std::string signingId;
    std::string appGroup;
};

// Canonical identities of the two agent-owned binaries (their embedded
// CFBundleIdentifier, which codesign uses as the default signing identifier)
// and the App Group both are provisioned into.
inline constexpr std::string_view kAgentSigningId = "org.librescrs.agent";
inline constexpr std::string_view kPrompterSigningId = "org.librescrs.prompter";
inline constexpr std::string_view kAppGroup = "group.org.librescrs.LibreMac";

// Resolve a peer's SecTask facts. An unidentifiable peer yields an empty
// result (no signing id, no groups) — callers fail closed on it.
[[nodiscard]] PeerCodeSigning resolvePeerCodeSigning(const PeerCredentials& creds);

// Policy: does `peer` present `expected` (signing-identifier match AND the
// app-group entitlement)? Pure, so it is unit-testable without real signing.
[[nodiscard]] bool matchesExpectedPeer(const PeerCodeSigning& peer, const ExpectedPeerIdentity& expected);

// Capture + resolve + match in one step on a CONNECTED AF_UNIX fd
// (LOCAL_PEERTOKEN reports the peer from either end, so a CLIENT can verify
// the process serving the socket it just connected to). Fails closed when the
// peer cannot be captured or resolved.
[[nodiscard]] bool verifyConnectedPeer(int connectedFd, const ExpectedPeerIdentity& expected);

} // namespace LibreSCRS::Darwin
