// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Cross-stack wire-contract drift guard.
//
// The socket wire contract (agent/wire/librescrs-agent.cddl) mirrors, value-for-
// value, the canonical D-Bus agent surface; the CBOR message enums on the wire
// are re-typed by hand as CDDL literals, and again by the Swift client. Each
// mirror pins itself to hard-coded literals in its OWN stack but not to the
// upstream enum — so a renumber (or an append) would go silently stale on the
// wire and on the client.
//
// This fixture is the one place that ties those wire literals back to the
// upstream symbols. The agent backend links LibreAgent::Core (which re-exports
// the LibreMiddleware Plugin/Auth types), so a static_assert here breaks the
// build the instant a core enum renumbers — the half no client-side test can
// catch, because a client stack cannot link the middleware.
//
// === Mirror manifest — keep these in lockstep ===
//   ErrorCode        : LibreSCRS/Agent/value/ErrorTaxonomy.h (SOURCE)
//                      <-> CDDL `error-code` <-> the Swift client's ErrorCode
//   capability bits  : LibreSCRS/Plugin/PluginTypes.h CardCapabilities
//                      <-> CDDL `capability-bit` <-> the Swift client's Cap
//   pre-read auth    : LibreSCRS/Auth/AuthRequirement.h PreReadAuthMethod
//                      <-> CDDL `pre-read-auth`
//   op phase/status  : LibreSCRS/Agent/OperationPhase.h
//                      <-> CDDL `op-phase`/`op-status`
//   message tags     : CDDL request/event `t:` tags — count-pinned below

#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/OperationPhase.h>

#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Auth/AuthRequirement.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

// --- agent ErrorCode <-> CDDL `error-code` (THE anchor) ----------------------
// Canonical wire name per enumerator. NO default case: with -Werror=switch on
// this target an appended enumerator is a compile error until it is named here,
// and the runtime comparison below then fails until the CDDL enumerates it too.
constexpr const char* wireNameFor(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::None:
        return "None";
    case ErrorCode::CardRemoved:
        return "CardRemoved";
    case ErrorCode::CredentialWrong:
        return "CredentialWrong";
    case ErrorCode::CredentialBlocked:
        return "CredentialBlocked";
    case ErrorCode::CommunicationError:
        return "CommunicationError";
    case ErrorCode::ParseError:
        return "ParseError";
    case ErrorCode::UnsupportedCard:
        return "UnsupportedCard";
    case ErrorCode::AuthFailed:
        return "AuthFailed";
    case ErrorCode::PrompterError:
        return "PrompterError";
    case ErrorCode::CapabilityMissing:
        return "CapabilityMissing";
    case ErrorCode::WatchdogTimeout:
        return "WatchdogTimeout";
    case ErrorCode::KeyNotFound:
        return "KeyNotFound";
    case ErrorCode::KeyAmbiguous:
        return "KeyAmbiguous";
    case ErrorCode::CertExpiredBlocked:
        return "CertExpiredBlocked";
    case ErrorCode::ChainIncomplete:
        return "ChainIncomplete";
    case ErrorCode::TsaUnreachable:
        return "TsaUnreachable";
    case ErrorCode::SigningEngineError:
        return "SigningEngineError";
    case ErrorCode::RateLimited:
        return "RateLimited";
    case ErrorCode::EngineUnavailable:
        return "EngineUnavailable";
    }
    return nullptr; // not a taxonomy value (used to probe past the end)
}

// Size derived from the switch itself (values outside it fall through to
// nullptr), so the count tracks the switch automatically and no separate
// constant can go stale — the failure mode of the count pin this replaced.
constexpr std::uint32_t taxonomyCount() noexcept
{
    std::uint32_t count = 0;
    while (wireNameFor(static_cast<ErrorCode>(count)) != nullptr) {
        ++count;
    }
    return count;
}

constexpr std::uint32_t kTaxonomyCount = taxonomyCount();
static_assert(u(ErrorCode::None) == 0u, "wire contract: ErrorCode::None drifted from 0");
static_assert(kTaxonomyCount >= 19u, "the taxonomy is append-only; it can only grow");

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

std::string slurp(const char* path)
{
    std::ifstream in(path);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

// Extracts the `Name: <value>` pairs of the CDDL `error-code = &( ... )` group.
// CDDL comments run from ';' to end of line and are stripped first so a commented
// value can never be mistaken for a live one.
std::vector<std::pair<std::uint32_t, std::string>> parseCddlErrorCode(const std::string& cddl)
{
    std::vector<std::pair<std::uint32_t, std::string>> entries;
    const std::size_t start = cddl.find("error-code");
    if (start == std::string::npos) {
        return entries;
    }
    const std::size_t open = cddl.find('(', start);
    const std::size_t close = cddl.find(')', open);
    if (open == std::string::npos || close == std::string::npos) {
        return entries;
    }

    std::string block = cddl.substr(open + 1, close - open - 1);
    std::istringstream lines(block);
    std::string line;
    std::string stripped;
    while (std::getline(lines, line)) {
        stripped += line.substr(0, line.find(';'));
        stripped += '\n';
    }

    const std::regex entryRe(R"(([A-Za-z][A-Za-z0-9]*)\s*:\s*(\d+))");
    for (auto it = std::sregex_iterator(stripped.begin(), stripped.end(), entryRe); it != std::sregex_iterator();
         ++it) {
        entries.emplace_back(static_cast<std::uint32_t>(std::stoul((*it)[2].str())), (*it)[1].str());
    }
    return entries;
}

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

// The CDDL is the wire contract of record and the Swift client mirrors it by
// hand; neither links LM, so this is the only place they can be tied back to the
// upstream taxonomy. wireNameFor()'s switch makes an APPEND a compile error, and
// this test makes a stale CDDL a test failure: a code the CDDL omits still
// reaches the wire, where a hand mirror that lacks it fails the decode closed.
TEST(WireContractGuard, CddlErrorCodeMatchesAgentEnumValueForValue)
{
    const std::string cddl = slurp(LIBREDARWIN_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto entries = parseCddlErrorCode(cddl);
    ASSERT_FALSE(entries.empty()) << "could not locate the `error-code = &( ... )` group in librescrs-agent.cddl — "
                                     "if it was reformatted, keep the `Name: <value>` entries this guard parses";

    EXPECT_EQ(entries.size(), kTaxonomyCount)
        << "the CDDL enumerates " << entries.size() << " error codes but the agent ErrorCode enum has "
        << kTaxonomyCount << " — the CDDL is the macOS wire contract of record, keep the two identical (append-only). "
        << "A code the CDDL omits still reaches the wire and fails the Swift client's decode closed";

    const std::size_t common = std::min<std::size_t>(entries.size(), kTaxonomyCount);
    for (std::size_t i = 0; i < common; ++i) {
        EXPECT_EQ(entries[i].first, static_cast<std::uint32_t>(i))
            << "the CDDL error-code group is not contiguous at entry " << i
            << " — the taxonomy is append-only from 0, never renumbered";
        EXPECT_EQ(entries[i].second, wireNameFor(static_cast<ErrorCode>(i)))
            << "the CDDL names error-code " << i << " '" << entries[i].second << "' but the agent enum calls it '"
            << wireNameFor(static_cast<ErrorCode>(i)) << "'";
    }
}
