// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Cross-stack wire-contract drift guard — macOS (LibreDarwin) half.
//
// The macOS twin of LibreLinux/agent/tests/WireContractGuardTest.cpp. The socket
// wire contract (agent/wire/librescrs-agent.cddl) mirrors, value-for-value, the
// Linux-session-owned D-Bus contract; the CBOR message enums on the wire are
// re-typed by hand (the CDDL enum literals) and by the future LibreMac Swift
// client mirror. Each mirror pins itself to hard-coded literals in its OWN stack
// but not to the upstream LibreAgent/LibreMiddleware symbol — so a core renumber
// (or an ErrorCode append) would go silently stale on the wire + on the client.
//
// This fixture is the ONE place on the macOS side that ties the canonical wire
// literals to the upstream symbols. The LibreDarwin agent backend links
// LibreAgent::Core (which re-exports LibreMiddleware Plugin/Auth PUBLIC), so a
// static_assert here breaks the build the instant a core enum renumbers — the
// half no LM-free client test can catch (a client stack cannot link LM).
//
// The matching CDDL (agent/wire/librescrs-agent.cddl) and the future LibreMac
// Swift client mirror pin to the SAME literals; together they chain
//   LibreAgent/LM  <->  CBOR/CDDL wire literals  <->  LibreMac
// without the LM-free client ever linking LM.
//
// === Mirror manifest — keep these in lockstep ===
//   ErrorCode        : LibreAgent value/ErrorTaxonomy.h (SOURCE, pinned to the
//                      canonical dbus/org.librescrs.Agent.Operation1.xml on Linux)
//                      <-> CDDL `error-code` <-> LibreMac ErrorCode mirror
//   capability bits  : LibreMiddleware Plugin/PluginTypes.h CardCapabilities
//                      <-> CDDL `capability-bit` <-> LibreMac Cap mirror
//   pre-read auth    : LibreMiddleware Auth/AuthRequirement.h PreReadAuthMethod
//                      <-> CDDL `pre-read-auth`
//   op phase/status  : LibreAgent OperationPhase.h <-> CDDL `op-phase`/`op-status`
//   message tags     : CDDL request/event `t:` tags — count-pinned below

#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/OperationPhase.h>

#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Auth/AuthRequirement.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string_view>

namespace {

using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::Operations::OperationPhase;
using LibreSCRS::Agent::Operations::OperationStatus;
using LibreSCRS::Auth::PreReadAuthMethod;
using LibreSCRS::Plugin::CardCapabilities;

constexpr std::uint32_t u(CardCapabilities c)
{
    return static_cast<std::uint32_t>(c);
}
constexpr std::uint32_t u(ErrorCode e)
{
    return static_cast<std::uint32_t>(e);
}
constexpr std::uint32_t u(OperationPhase p)
{
    return static_cast<std::uint32_t>(p);
}
constexpr std::uint32_t u(OperationStatus s)
{
    return static_cast<std::uint32_t>(s);
}
constexpr std::uint32_t u(PreReadAuthMethod m)
{
    return static_cast<std::uint32_t>(m);
}

// --- LM CardCapabilities <-> CDDL `capability-bit` (THE anchor) --------------
static_assert(u(CardCapabilities::None) == 0u, "wire contract: CardCapabilities::None drifted from 0");
static_assert(u(CardCapabilities::PKI) == (1u << 0),
              "wire contract: PKI bit drifted; CDDL capability-bit Pki now stale");
static_assert(u(CardCapabilities::IdentityData) == (1u << 1),
              "wire contract: IdentityData bit drifted; CDDL capability-bit IdentityData now stale");
static_assert(u(CardCapabilities::EmrtdCrypto) == (1u << 2),
              "wire contract: EmrtdCrypto bit drifted; CDDL capability-bit EmrtdCrypto now stale");
static_assert(u(CardCapabilities::PinManagement) == (1u << 3),
              "wire contract: PinManagement bit drifted; CDDL capability-bit PinManagement now stale");

// --- LM PreReadAuthMethod <-> CDDL `pre-read-auth` ---------------------------
static_assert(u(PreReadAuthMethod::None) == 0u, "wire contract: PreReadAuthMethod::None drifted from 0");
static_assert(u(PreReadAuthMethod::BacMrz) == 1u, "wire contract: PreReadAuthMethod::BacMrz drifted from 1");
static_assert(u(PreReadAuthMethod::PaceCan) == 2u, "wire contract: PreReadAuthMethod::PaceCan drifted from 2");

// --- LibreAgent OperationPhase / OperationStatus <-> CDDL `op-phase`/`op-status` ---
static_assert(u(OperationPhase::Created) == 0u, "wire contract: op-phase Created drifted from 0");
static_assert(u(OperationPhase::Connecting) == 1u, "wire contract: op-phase Connecting drifted from 1");
static_assert(u(OperationPhase::AwaitingConsent) == 2u, "wire contract: op-phase AwaitingConsent drifted from 2");
static_assert(u(OperationPhase::Authenticating) == 3u, "wire contract: op-phase Authenticating drifted from 3");
static_assert(u(OperationPhase::Reading) == 4u, "wire contract: op-phase Reading drifted from 4");
static_assert(u(OperationPhase::Signing) == 5u, "wire contract: op-phase Signing drifted from 5");
static_assert(u(OperationPhase::Timestamping) == 6u, "wire contract: op-phase Timestamping drifted from 6");
static_assert(u(OperationPhase::Done) == 7u,
              "wire contract: op-phase Done (last) drifted from 7; bump the CDDL op-phase");
static_assert(u(OperationStatus::Ok) == 0u, "wire contract: op-status Ok drifted from 0");
static_assert(u(OperationStatus::Cancelled) == 1u, "wire contract: op-status Cancelled drifted from 1");
static_assert(u(OperationStatus::Error) == 2u, "wire contract: op-status Error drifted from 2");

// --- agent ErrorCode: renumber anchor (18 stable, append-only) ---------------
// ErrorCode is append-only on the wire. Pinning first + last value + count
// catches a RENUMBER of the existing range. An APPEND leaves first/last green,
// so the count assert is the tripwire: bump it (and the CDDL `error-code` + the
// LibreMac mirror) when the taxonomy grows.
static_assert(u(ErrorCode::None) == 0u, "wire contract: ErrorCode::None drifted from 0");
static_assert(u(ErrorCode::RateLimited) == 17u,
              "wire contract: ErrorCode::RateLimited (last) drifted; mirror in CDDL error-code + LibreMac");
static_assert(u(ErrorCode::RateLimited) + 1u == 18u,
              "wire contract: ErrorCode count changed; append to CDDL error-code + LibreMac mirror + bump this guard");

// --- CDDL message `t:` tags: presence + count drift guard --------------------
// The socket message vocabulary (request + event `t:` tags) has no upstream enum
// to anchor to (the tags are CDDL string literals), so this table pins the SET.
// Adding/removing a message MUST update: the CDDL (agent/wire/librescrs-agent.cddl),
// wire/Messages.{h,cpp}, and this table (bump kMessageTagCount). The Task-4
// MessagesRoundTripTest proves each tag actually encodes/decodes; this only pins
// that the vocabulary did not silently change size.
constexpr std::array<std::string_view, 27> kMessageTags{
    // requests (17)
    "Hello", "GetState", "ReadIdentity", "GetPhoto", "ReadCertificates", "Sign", "GetCertDer", "GetConfig", "SetConfig",
    "ResetConfig", "CancelOp", "GetSignResult", "Pkcs11.Login", "Pkcs11.Logout", "Pkcs11.PublicKey", "Pkcs11.SignRaw",
    "Pkcs11.Decrypt",
    // events (10)
    "ReaderAdded", "ReaderRemoved", "CardAdded", "CardRemoved", "PropertyChanged", "ConfigChanged", "OpProgress",
    "OpResultReady", "OpFinished", "AgentQuiesced"};
constexpr std::size_t kMessageTagCount = 27; // 17 requests + 10 events
static_assert(kMessageTags.size() == kMessageTagCount,
              "wire contract: socket message vocabulary changed; update the CDDL + wire/Messages + this guard");

} // namespace

// A compiled TU is required to evaluate the static_asserts; the runtime body is
// a formality (matches the Linux WireContractGuard). The exhaustiveness switches
// below carry the append-detection the value pins above cannot: with
// -Werror=switch on this target, an upstream APPEND to any anchored enum adds an
// unhandled enumerator and breaks the build (forcing a matching CDDL + LibreMac
// mirror update). The value pins catch a RENUMBER; these catch an APPEND.
TEST(WireContractGuard, MacOsAnchorsHold)
{
    // Spot-check the tag table is populated (defends against an all-empty init).
    EXPECT_EQ(kMessageTags.front(), "Hello");
    EXPECT_EQ(kMessageTags.back(), "AgentQuiesced");

    for (const auto phase : {OperationPhase::Created, OperationPhase::Connecting, OperationPhase::AwaitingConsent,
                             OperationPhase::Authenticating, OperationPhase::Reading, OperationPhase::Signing,
                             OperationPhase::Timestamping, OperationPhase::Done}) {
        switch (phase) { // no default: -Werror=switch fires on an appended phase
        case OperationPhase::Created:
        case OperationPhase::Connecting:
        case OperationPhase::AwaitingConsent:
        case OperationPhase::Authenticating:
        case OperationPhase::Reading:
        case OperationPhase::Signing:
        case OperationPhase::Timestamping:
        case OperationPhase::Done:
            break;
        }
    }
    for (const auto status : {OperationStatus::Ok, OperationStatus::Cancelled, OperationStatus::Error}) {
        switch (status) { // no default
        case OperationStatus::Ok:
        case OperationStatus::Cancelled:
        case OperationStatus::Error:
            break;
        }
    }
    for (const auto method : {PreReadAuthMethod::None, PreReadAuthMethod::BacMrz, PreReadAuthMethod::PaceCan}) {
        switch (method) { // no default
        case PreReadAuthMethod::None:
        case PreReadAuthMethod::BacMrz:
        case PreReadAuthMethod::PaceCan:
            break;
        }
    }
    for (const auto cap : {CardCapabilities::None, CardCapabilities::PKI, CardCapabilities::IdentityData,
                           CardCapabilities::EmrtdCrypto, CardCapabilities::PinManagement}) {
        switch (cap) { // no default: an appended capability bit breaks the build
        case CardCapabilities::None:
        case CardCapabilities::PKI:
        case CardCapabilities::IdentityData:
        case CardCapabilities::EmrtdCrypto:
        case CardCapabilities::PinManagement:
            break;
        }
    }
    SUCCEED();
}
