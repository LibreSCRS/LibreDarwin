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
//   sync errors      : LibreSCRS/Darwin/backend/wire/Messages.h SyncError
//                      <-> CDDL `sync-error` (compared as a SET; name-carried)
//   cred outcome     : LibreSCRS/Agent/value/CredentialRecord.h CredentialOutcome
//                      <-> CDDL `cred-outcome`
//   cred record vocab: LibreSCRS/Plugin/PinStatusEntry.h PinKind/PinState/
//                      UnblockStyle/PinRecovery (via CredentialRecord.h detail::
//                      *Token) <-> CDDL `cred-kind`/`cred-state`/`unblock-style`/
//                      `cred-recovery`
//   cred record keys : CredentialRecord.h field names <-> CDDL `cred-record` keys
//   cred verbs       : CDDL `cred-verb` string literals (no upstream enum)

#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h>
#include <LibreSCRS/Agent/OperationPhase.h>

#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Auth/AuthRequirement.h>

#include <LibreSCRS/Darwin/backend/wire/Messages.h>

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

using LibreSCRS::Agent::CredentialOutcome;
using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::Operations::OperationPhase;
using LibreSCRS::Agent::Operations::OperationStatus;
using LibreSCRS::Auth::PreReadAuthMethod;
using LibreSCRS::Darwin::wire::SyncError;
using LibreSCRS::Darwin::wire::syncErrorName;
using LibreSCRS::Plugin::CardCapabilities;
using LibreSCRS::Plugin::PinKind;
using LibreSCRS::Plugin::PinRecovery;
using LibreSCRS::Plugin::PinState;
using LibreSCRS::Plugin::UnblockStyle;

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
constexpr std::uint32_t u(CredentialOutcome o)
{
    return static_cast<std::uint32_t>(o);
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
    case ErrorCode::InvalidDocument:
        return "InvalidDocument";
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

// --- LibreDarwin wire::SyncError <-> CDDL `sync-error` ------------------------
// Named synchronous-method errors. Order is NOT wire-significant (the wire
// carries the NAME), so the runtime guard compares the CDDL group and this enum
// as SETS. This local switch mirrors the shipping wire::syncErrorName(): with
// -Werror=switch on this target an APPENDED SyncError member is a compile error
// here until it is named (and the CDDL enumerates it).
//
// SyncError::UnknownCredential / ::InvalidRequest are the credential-management
// members of wire::SyncError; they are named below like every other enumerator,
// so this switch (and the CDDL `sync-error` group) must be extended in lockstep
// with any future append to wire::SyncError.
constexpr const char* syncErrorWireName(SyncError e) noexcept
{
    switch (e) {
    case SyncError::UnknownCard:
        return "UnknownCard";
    case SyncError::KeyNotFound:
        return "KeyNotFound";
    case SyncError::NotAuthorized:
        return "NotAuthorized";
    case SyncError::UserNotLoggedIn:
        return "UserNotLoggedIn";
    case SyncError::UnknownConfigKey:
        return "UnknownConfigKey";
    case SyncError::ReadOnlyConfig:
        return "ReadOnlyConfig";
    case SyncError::InvalidConfigValue:
        return "InvalidConfigValue";
    case SyncError::UnsupportedProtocol:
        return "UnsupportedProtocol";
    case SyncError::AuthFailed:
        return "AuthFailed";
    case SyncError::CommunicationError:
        return "CommunicationError";
    case SyncError::NotSupported:
        return "NotSupported";
    case SyncError::UnsupportedOnThisCard:
        return "UnsupportedOnThisCard";
    case SyncError::UnsupportedSignatureParameter:
        return "UnsupportedSignatureParameter";
    case SyncError::InputTooLarge:
        return "InputTooLarge";
    case SyncError::RateLimited:
        return "RateLimited";
    case SyncError::UnknownCredential: // appended for credential management
        return "UnknownCredential";
    case SyncError::InvalidRequest: // appended for credential management
        return "InvalidRequest";
    }
    return nullptr; // not a SyncError value (used to probe past the end for the count)
}
constexpr std::uint32_t syncErrorCount() noexcept
{
    std::uint32_t count = 0;
    while (syncErrorWireName(static_cast<SyncError>(count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(syncErrorCount() >= 15u, "the sync-error vocabulary is append-only; it can only grow");

// --- LibreAgent CredentialOutcome <-> CDDL `cred-outcome` ---------------------
// Mutation outcome vocabulary. The CDDL group is authored in enum order, so the
// runtime guard compares value-for-value (append-only, like error-code). No
// default case: -Werror=switch breaks the build on an appended member.
constexpr const char* credOutcomeToken(CredentialOutcome o) noexcept
{
    switch (o) {
    case CredentialOutcome::Unspecified:
        return "unspecified";
    case CredentialOutcome::Ok:
        return "ok";
    case CredentialOutcome::UserCancelled:
        return "userCancelled";
    case CredentialOutcome::MissingFields:
        return "missingFields";
    case CredentialOutcome::InvalidPin:
        return "invalidPin";
    case CredentialOutcome::Blocked:
        return "blocked";
    case CredentialOutcome::PluginError:
        return "pluginError";
    case CredentialOutcome::Unsupported:
        return "unsupported";
    case CredentialOutcome::KeyActivationFailed:
        return "keyActivationFailed";
    case CredentialOutcome::CardRemoved:
        return "cardRemoved";
    }
    return nullptr;
}
constexpr std::uint32_t credOutcomeCount() noexcept
{
    std::uint32_t count = 0;
    while (credOutcomeToken(static_cast<CredentialOutcome>(count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(u(CredentialOutcome::Unspecified) == 0u, "wire contract: CredentialOutcome::Unspecified drifted from 0");
static_assert(credOutcomeCount() == 10u,
              "wire contract: cred-outcome has 10 tokens; update the CDDL + this switch together");

// --- LM credential-record vocab <-> CDDL record token groups -----------------
// Local exhaustive switches (append-guarded, no default) for the four enum-
// valued record fields, each pinned at runtime against the shipping
// detail::credential*Token helper the list flow emits. Order is NOT wire-
// significant here (cred-kind deliberately lists "unknown" LAST while the enum
// lists it FIRST), so the runtime guard set-compares each CDDL group.
constexpr const char* credKindToken(PinKind k) noexcept
{
    switch (k) {
    case PinKind::Unknown:
        return "unknown";
    case PinKind::UserPin:
        return "user";
    case PinKind::SignPin:
        return "sign";
    case PinKind::Puk:
        return "puk";
    case PinKind::Can:
        return "can";
    }
    return nullptr;
}
constexpr const char* credStateToken(PinState s) noexcept
{
    switch (s) {
    case PinState::Unknown:
        return "unknown";
    case PinState::Transport:
        return "transport";
    case PinState::Operational:
        return "operational";
    case PinState::NeedsChange:
        return "needsChange";
    case PinState::Blocked:
        return "blocked";
    }
    return nullptr;
}
constexpr const char* unblockStyleToken(UnblockStyle st) noexcept
{
    switch (st) {
    case UnblockStyle::Unknown:
        return "unknown";
    case UnblockStyle::ResetOnly:
        return "resetOnly";
    case UnblockStyle::SetsNewPin:
        return "setsNewPin";
    case UnblockStyle::UnblockAndChange:
        return "unblockAndChange";
    }
    return nullptr;
}
constexpr const char* credRecoveryToken(PinRecovery r) noexcept
{
    switch (r) {
    case PinRecovery::Unknown:
        return "unknown";
    case PinRecovery::HolderViaPuk:
        return "holderViaPuk";
    case PinRecovery::IssuerProcess:
        return "issuerProcess";
    case PinRecovery::None:
        return "none";
    }
    return nullptr;
}
constexpr std::uint32_t credKindCount() noexcept
{
    std::uint32_t count = 0;
    while (credKindToken(static_cast<PinKind>(count)) != nullptr) {
        ++count;
    }
    return count;
}
constexpr std::uint32_t credStateCount() noexcept
{
    std::uint32_t count = 0;
    while (credStateToken(static_cast<PinState>(count)) != nullptr) {
        ++count;
    }
    return count;
}
constexpr std::uint32_t unblockStyleCount() noexcept
{
    std::uint32_t count = 0;
    while (unblockStyleToken(static_cast<UnblockStyle>(count)) != nullptr) {
        ++count;
    }
    return count;
}
constexpr std::uint32_t credRecoveryCount() noexcept
{
    std::uint32_t count = 0;
    while (credRecoveryToken(static_cast<PinRecovery>(count)) != nullptr) {
        ++count;
    }
    return count;
}
static_assert(credKindCount() == 5u, "wire contract: cred-kind has 5 tokens");
static_assert(credStateCount() == 5u, "wire contract: cred-state has 5 tokens");
static_assert(unblockStyleCount() == 4u, "wire contract: unblock-style has 4 tokens");
static_assert(credRecoveryCount() == 4u, "wire contract: cred-recovery has 4 tokens");

// --- CDDL `cred-verb` string literals (no upstream enum — pinned as a set) ----
constexpr std::array<std::string_view, 3> kCredVerbs{"change", "unblock", "activate_pin"};
static_assert(kCredVerbs.size() == 3u, "wire contract: cred-verb has 3 tokens");

// --- CDDL `cred-record` map keys (camelCase; == CredentialRecord field names) -
// The full ordered key set, shared with the codec test's cred-record
// expectations. NOTE: this is 23 keys — CredentialRecord has 23 fields and the
// D-Bus a{sv} lists 23 keys.
constexpr std::array<std::string_view, 23> kCredRecordKeys{"id",
                                                           "label",
                                                           "kind",
                                                           "state",
                                                           "retriesLeft",
                                                           "retriesMax",
                                                           "usesLeft",
                                                           "usesMax",
                                                           "unblocksLeft",
                                                           "minLength",
                                                           "maxLength",
                                                           "canChange",
                                                           "unblockable",
                                                           "unblockStyle",
                                                           "activatable",
                                                           "keyActivationPending",
                                                           "keyActivatable",
                                                           "recovery",
                                                           "probeSafe",
                                                           "blockedGuidanceKey",
                                                           "blockedGuidanceFallback",
                                                           "keyActivationGuidanceKey",
                                                           "keyActivationGuidanceFallback"};
static_assert(kCredRecordKeys.size() == 23u, "wire contract: cred-record has 23 keys");

// --- CDDL message `t:` tags: presence + count drift guard --------------------
// The socket message vocabulary (request + event `t:` tags) has no upstream enum
// to anchor to (the tags are CDDL string literals), so this table pins the SET.
// Adding/removing a message MUST update: the CDDL (agent/wire/librescrs-agent.cddl),
// wire/Messages.{h,cpp}, and this table (bump kMessageTagCount). The
// MessagesRoundTripTest proves each tag actually encodes/decodes; this only pins
// that the vocabulary did not silently change size.
constexpr std::array<std::string_view, 30> kMessageTags{
    // requests (20)
    "Hello", "GetState", "ReadIdentity", "GetPhoto", "ReadCertificates", "Sign", "GetCertDer", "GetConfig", "SetConfig",
    "ResetConfig", "CancelOp", "GetSignResult", "Pkcs11.Login", "Pkcs11.Logout", "Pkcs11.PublicKey", "Pkcs11.SignRaw",
    "Pkcs11.Decrypt", "ListCredentials", "ManagePin", "ActivateSigningKey",
    // events (10)
    "ReaderAdded", "ReaderRemoved", "CardAdded", "CardRemoved", "PropertyChanged", "ConfigChanged", "OpProgress",
    "OpResultReady", "OpFinished", "AgentQuiesced"};
constexpr std::size_t kMessageTagCount = 30; // 20 requests + 10 events
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

// Right-hand side of a top-level CDDL rule `<ruleName> = ...`, comment-stripped
// and joined across continuation lines up to (but excluding) the next top-level
// `name = ...` definition. Empty if the rule is not found. Slurps the credential
// vocabulary groups the way parseCddlErrorCode slurps error-code.
std::string cddlRuleRhs(const std::string& cddl, const std::string& ruleName)
{
    std::istringstream lines(cddl);
    std::string line;
    std::string rhs;
    bool capturing = false;
    const std::regex defRe(R"(^\s*([A-Za-z][A-Za-z0-9-]*)\s*=)");
    while (std::getline(lines, line)) {
        const std::string stripped = line.substr(0, line.find(';'));
        std::smatch match;
        const bool isDef = std::regex_search(stripped, match, defRe);
        if (capturing) {
            if (isDef) {
                break; // the next rule begins; the captured rule is complete
            }
            rhs += ' ';
            rhs += stripped;
            continue;
        }
        if (isDef && match[1].str() == ruleName) {
            capturing = true;
            rhs += stripped.substr(stripped.find('=') + 1);
        }
    }
    return rhs;
}

// The quoted string literals of a CDDL string-alternation RHS ("a" / "b" / ...),
// in source order.
std::vector<std::string> cddlQuotedTokens(const std::string& rhs)
{
    std::vector<std::string> tokens;
    // Custom `rx` delimiter: the pattern itself contains the `)"` sequence, which
    // would prematurely close a default-delimiter raw string.
    const std::regex quoted(R"rx("([^"]*)")rx");
    for (auto it = std::sregex_iterator(rhs.begin(), rhs.end(), quoted); it != std::sregex_iterator(); ++it) {
        tokens.push_back((*it)[1].str());
    }
    return tokens;
}

// The map key names of a CDDL map-group RHS `{ key: type, ? key: type, ... }`,
// in declaration order. The `?` optional markers and the value types are
// ignored — only identifiers immediately followed by ':' are keys (the camelCase
// keys never contain '-', so the hyphenated type refs are not matched).
std::vector<std::string> cddlMapKeys(const std::string& rhs)
{
    std::vector<std::string> keys;
    const std::regex keyRe(R"(([A-Za-z][A-Za-z0-9]*)\s*:)");
    for (auto it = std::sregex_iterator(rhs.begin(), rhs.end(), keyRe); it != std::sregex_iterator(); ++it) {
        keys.push_back((*it)[1].str());
    }
    return keys;
}

// Sorted-set equality of two token lists, with a labeled failure. Order-
// insensitive: for the record vocab groups (and sync-error) the wire carries the
// NAME, so only the SET of tokens is contractually pinned.
void expectSameTokenSet(std::vector<std::string> cddlTokens, std::vector<std::string> enumTokens,
                        std::string_view group)
{
    std::sort(cddlTokens.begin(), cddlTokens.end());
    std::sort(enumTokens.begin(), enumTokens.end());
    EXPECT_EQ(cddlTokens, enumTokens) << "the CDDL `" << group << "` group and its upstream enum drifted";
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

// The CDDL `sync-error` names mirror wire::SyncError, compared as a SET (the wire
// carries the name, so order is not significant). The syncErrorWireName() switch
// makes an APPEND a compile error; this makes a stale CDDL a test failure and
// pins the guard's expectation to the shipping wire::syncErrorName() so the two
// appended names actually reach the wire.
TEST(WireContractGuard, CddlSyncErrorMatchesWireEnum)
{
    const std::string cddl = slurp(LIBREDARWIN_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto cddlTokens = cddlQuotedTokens(cddlRuleRhs(cddl, "sync-error"));
    ASSERT_FALSE(cddlTokens.empty()) << "could not locate the `sync-error = ...` group in librescrs-agent.cddl";
    EXPECT_EQ(cddlTokens.size(), syncErrorCount()) << "the CDDL `sync-error` group enumerates " << cddlTokens.size()
                                                   << " names but wire::SyncError has " << syncErrorCount();

    std::vector<std::string> enumTokens;
    for (std::uint32_t i = 0; i < syncErrorCount(); ++i) {
        const auto e = static_cast<SyncError>(i);
        enumTokens.emplace_back(syncErrorWireName(e));
        EXPECT_EQ(syncErrorName(e), std::string_view(syncErrorWireName(e)))
            << "wire::syncErrorName() disagrees with the guard at SyncError " << i;
    }
    expectSameTokenSet(cddlTokens, enumTokens, "sync-error");
}

// The CDDL `cred-outcome` group mirrors LibreAgent CredentialOutcome value-for-
// value (both authored in enum order, append-only).
TEST(WireContractGuard, CddlCredentialOutcomeMatchesAgentEnum)
{
    const std::string cddl = slurp(LIBREDARWIN_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto tokens = cddlQuotedTokens(cddlRuleRhs(cddl, "cred-outcome"));
    ASSERT_EQ(tokens.size(), credOutcomeCount()) << "the CDDL `cred-outcome` group has " << tokens.size()
                                                 << " tokens but CredentialOutcome has " << credOutcomeCount();
    for (std::uint32_t i = 0; i < credOutcomeCount(); ++i) {
        EXPECT_EQ(tokens[i], credOutcomeToken(static_cast<CredentialOutcome>(i)))
            << "cred-outcome token " << i << " drifted from CredentialOutcome";
    }
}

// The CDDL `cred-verb` closed set matches the three management verbs. No upstream
// enum — the verbs are wire string literals, pinned here (and by the credential
// codec tests).
TEST(WireContractGuard, CddlCredentialVerbsMatchTokens)
{
    const std::string cddl = slurp(LIBREDARWIN_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto tokens = cddlQuotedTokens(cddlRuleRhs(cddl, "cred-verb"));
    ASSERT_EQ(tokens.size(), kCredVerbs.size()) << "the CDDL `cred-verb` group changed size";
    for (std::size_t i = 0; i < kCredVerbs.size(); ++i) {
        EXPECT_EQ(tokens[i], kCredVerbs[i]) << "cred-verb token " << i << " drifted";
    }
}

// The four enum-valued record vocabularies (kind/state/unblock-style/recovery)
// match the shipping detail::credential*Token helpers, and the CDDL groups match
// them as SETS (cred-kind's source order deliberately differs from the enum's).
TEST(WireContractGuard, CddlCredentialRecordVocabMatchesAgentHelpers)
{
    namespace detail = LibreSCRS::Agent::detail;
    const std::string cddl = slurp(LIBREDARWIN_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    std::vector<std::string> kinds;
    for (std::uint32_t i = 0; i < credKindCount(); ++i) {
        const auto k = static_cast<PinKind>(i);
        EXPECT_EQ(std::string(credKindToken(k)), detail::credentialKindToken(k)) << "cred-kind helper drift at " << i;
        kinds.emplace_back(credKindToken(k));
    }
    expectSameTokenSet(cddlQuotedTokens(cddlRuleRhs(cddl, "cred-kind")), kinds, "cred-kind");

    std::vector<std::string> states;
    for (std::uint32_t i = 0; i < credStateCount(); ++i) {
        const auto s = static_cast<PinState>(i);
        EXPECT_EQ(std::string(credStateToken(s)), detail::credentialStateToken(s))
            << "cred-state helper drift at " << i;
        states.emplace_back(credStateToken(s));
    }
    expectSameTokenSet(cddlQuotedTokens(cddlRuleRhs(cddl, "cred-state")), states, "cred-state");

    std::vector<std::string> styles;
    for (std::uint32_t i = 0; i < unblockStyleCount(); ++i) {
        const auto st = static_cast<UnblockStyle>(i);
        EXPECT_EQ(std::string(unblockStyleToken(st)), detail::unblockStyleToken(st))
            << "unblock-style helper drift at " << i;
        styles.emplace_back(unblockStyleToken(st));
    }
    expectSameTokenSet(cddlQuotedTokens(cddlRuleRhs(cddl, "unblock-style")), styles, "unblock-style");

    std::vector<std::string> recoveries;
    for (std::uint32_t i = 0; i < credRecoveryCount(); ++i) {
        const auto r = static_cast<PinRecovery>(i);
        EXPECT_EQ(std::string(credRecoveryToken(r)), detail::recoveryToken(r)) << "cred-recovery helper drift at " << i;
        recoveries.emplace_back(credRecoveryToken(r));
    }
    expectSameTokenSet(cddlQuotedTokens(cddlRuleRhs(cddl, "cred-recovery")), recoveries, "cred-recovery");
}

// The CDDL `cred-record` map keys match the credential-record contract key set
// (camelCase, in declaration order). Shared with the credential codec test
// expectations.
TEST(WireContractGuard, CddlCredentialRecordKeysMatchContract)
{
    const std::string cddl = slurp(LIBREDARWIN_WIRE_CDDL);
    ASSERT_FALSE(cddl.empty()) << "wire CDDL source path not wired";

    const auto keys = cddlMapKeys(cddlRuleRhs(cddl, "cred-record"));
    ASSERT_EQ(keys.size(), kCredRecordKeys.size()) << "the CDDL `cred-record` group has " << keys.size()
                                                   << " keys but the contract fixes " << kCredRecordKeys.size();
    for (std::size_t i = 0; i < kCredRecordKeys.size(); ++i) {
        EXPECT_EQ(keys[i], kCredRecordKeys[i]) << "cred-record key " << i << " drifted";
    }
}
