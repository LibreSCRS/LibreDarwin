// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/wire/Cbor.h>

#include <LibreSCRS/Agent/OperationPhase.h>      // OperationPhase, OperationStatus
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h> // ErrorCode
#include <LibreSCRS/Auth/AuthRequirement.h>      // PreReadAuthMethod

#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

// Typed message model over the reconciled CDDL (agent/wire/librescrs-agent.cddl).
// The agent is a SERVER: it PARSES inbound requests (untrusted -> strict) and
// BUILDS outbound replies + events (trusted, from core results). The value enums
// are the upstream core enums so the WireContractGuard anchoring holds; the two
// socket-only vocabularies (SyncError names, QuiesceReason) are declared here.

namespace LibreSCRS::Darwin::wire {

using LibreSCRS::Agent::ErrorCode;
using LibreSCRS::Agent::Operations::OperationPhase;
using LibreSCRS::Agent::Operations::OperationStatus;
using LibreSCRS::Auth::PreReadAuthMethod;

// Why a request could not be modeled from its CBOR (distinct from CborError,
// which is the byte-level decode failure). All fail closed.
enum class WireError : std::uint8_t {
    NotDecodable,   // the frame body was not canonical CBOR
    NotAMap,        // top-level item is not a map
    MissingField,   // a required field is absent
    WrongType,      // a field has the wrong CBOR type
    NoTag,          // no `t` discriminator
    UnknownMessage, // `t` is not a known request tag
    BadEnum,        // an enum-valued field is out of range
    BadConfigKey,   // a config key outside the settable / known set
};

// Socket-only lifecycle vocabulary (no core enum — AgentQuiesced is macOS-specific).
enum class QuiesceReason : std::uint8_t { SystemSleep = 0, ScreenLocked = 1, SessionInactive = 2, Shutdown = 3 };

// Named synchronous-method errors (D-Bus Error.* names). Distinct from the async
// numeric ErrorCode. Order is not wire-significant (the wire carries the name).
enum class SyncError : std::uint8_t {
    UnknownCard,
    KeyNotFound,
    NotAuthorized,
    UserNotLoggedIn,
    UnknownConfigKey,
    ReadOnlyConfig,
    InvalidConfigValue,
    UnsupportedProtocol,
    AuthFailed,
    CommunicationError,
    NotSupported,
    UnsupportedOnThisCard,
    UnsupportedSignatureParameter,
    InputTooLarge,
    RateLimited,
};

// The wire name for a SyncError (== the CDDL literal). Never empty.
[[nodiscard]] std::string_view syncErrorName(SyncError e) noexcept;

// ---- shared sub-types --------------------------------------------------------

// Card1.Sign options. format/level/packaging required; the rest optional.
struct SignOpts
{
    std::string format;
    std::string level;
    std::string packaging;
    std::optional<bool> allowExpired;
    std::optional<std::string> displayName;
    std::optional<std::string> reason;
    std::optional<std::string> location;
    bool operator==(const SignOpts&) const = default;
};

struct ReaderState
{
    std::string handle;
    std::string name;
    bool hasCard{false};
    std::optional<std::string> card;
    bool operator==(const ReaderState&) const = default;
};

struct CardState
{
    std::string handle;
    std::string reader;
    std::uint32_t caps{0}; // capabilities bitmask (CardCapabilities bits)
    PreReadAuthMethod preAuth{PreReadAuthMethod::None};
    bool operator==(const CardState&) const = default;
};

// One grouped field cell (labelKey, labelFallback, value) — the Certificates1
// (ssv) shape (value is always a UTF-8 string on the cert surface).
struct CertField
{
    std::string labelKey;
    std::string labelFallback;
    std::string value;
    bool operator==(const CertField&) const = default;
};

struct CertInfo
{
    std::string certId;
    bool signingCapable{false};
    std::map<std::string, std::map<std::string, CertField>> fields; // group -> field -> cell
    std::uint32_t keyUsageBits{0};
    std::vector<std::string> ekus;
    std::vector<std::string> chainSubjectCns;
    std::uint32_t trustStatus{0};
    bool operator==(const CertInfo&) const = default;
};

struct SignMeta
{
    std::string format;
    std::string level;
    bool tsaUsed{false};
    bool chainComplete{false};
    bool operator==(const SignMeta&) const = default;
};

// ---- requests (client -> agent) ---------------------------------------------

struct Hello
{
    std::uint64_t proto{0};
    std::optional<std::string> client;
    bool operator==(const Hello&) const = default;
};
struct GetState
{
    bool operator==(const GetState&) const = default;
};
struct ReadIdentity
{
    std::string card;
    bool operator==(const ReadIdentity&) const = default;
};
struct GetPhoto
{
    std::string card;
    bool operator==(const GetPhoto&) const = default;
};
struct ReadCertificates
{
    std::string card;
    bool operator==(const ReadCertificates&) const = default;
};
struct Sign
{
    std::string card;
    std::string cert;
    std::uint64_t inFd{0}; // fd-index into the frame's SCM_RIGHTS vector
    SignOpts opts;
    bool operator==(const Sign&) const = default;
};
struct GetCertDer
{
    std::string reader;
    std::string cert;
    bool operator==(const GetCertDer&) const = default;
};
struct GetConfig
{
    bool operator==(const GetConfig&) const = default;
};
struct SetConfig
{
    std::string key; // a settable-config-key
    CborValue value; // `any`
    bool operator==(const SetConfig&) const = default;
};
struct ResetConfig
{
    std::string key; // a config-key
    bool operator==(const ResetConfig&) const = default;
};
struct CancelOp
{
    std::uint64_t op{0};
    bool operator==(const CancelOp&) const = default;
};
struct GetSignResult
{
    std::uint64_t op{0};
    bool operator==(const GetSignResult&) const = default;
};
struct PkLogin
{
    std::string reader;
    bool operator==(const PkLogin&) const = default;
};
struct PkLogout
{
    std::string reader;
    bool operator==(const PkLogout&) const = default;
};
struct PkPublicKey
{
    std::string reader;
    std::string cert;
    bool operator==(const PkPublicKey&) const = default;
};
struct PkSignRaw
{
    std::string reader;
    std::string cert;
    std::vector<std::uint8_t> data;
    bool operator==(const PkSignRaw&) const = default;
};
struct PkDecrypt
{
    std::string reader;
    std::string cert;
    std::vector<std::uint8_t> data;
    bool operator==(const PkDecrypt&) const = default;
};

using Request =
    std::variant<Hello, GetState, ReadIdentity, GetPhoto, ReadCertificates, Sign, GetCertDer, GetConfig, SetConfig,
                 ResetConfig, CancelOp, GetSignResult, PkLogin, PkLogout, PkPublicKey, PkSignRaw, PkDecrypt>;

struct RequestEnvelope
{
    std::uint64_t req{0};
    Request body;
    bool operator==(const RequestEnvelope&) const = default;
};

// Parse one request frame body: canonical-decode the CBOR, require a map with a
// `req` id + a known `t` tag, and strictly model the body. Fail closed.
[[nodiscard]] std::expected<RequestEnvelope, WireError> parseRequest(std::span<const std::uint8_t> body);

// Round-trip helper (tests + symmetry): encode a request envelope to a CBOR map.
[[nodiscard]] CborValue toCbor(const RequestEnvelope& env);

// ---- reply arms (agent -> client) -------------------------------------------

struct HelloAck
{
    std::string agentVer;
    std::vector<std::string> features;
};
struct OpStarted
{
    std::uint64_t op{0};
};
struct StateReply
{
    std::vector<ReaderState> readers;
    std::vector<CardState> cards;
};
struct CertListReply
{
    std::vector<CertInfo> certs;
};
struct CertDerReply
{
    std::vector<std::uint8_t> der;
};
// Pkcs11.PublicKey: RSA served (n/e); EC reserved (crv/x/y) — not produced in v0.1.
struct RsaPublicKey
{
    std::vector<std::uint8_t> n;
    std::vector<std::uint8_t> e;
};
struct EcPublicKey
{
    std::string crv;
    std::vector<std::uint8_t> x;
    std::vector<std::uint8_t> y;
};
using PublicKeyReply = std::variant<RsaPublicKey, EcPublicKey>;
struct ConfigReply
{
    std::map<std::string, CborValue> entries; // config-key -> any
};
struct AckReply
{};
struct RawSignatureReply
{
    std::vector<std::uint8_t> sig;
};

struct ErrInfo
{
    std::variant<ErrorCode, SyncError> code; // async numeric OR sync named
    std::optional<std::string> msgKey;
    std::optional<std::string> msgFallback;
};

// ---- op-result payloads (OpResultReady / GetSignResult) ----------------------

struct IdentityField
{
    std::string labelKey;
    std::string labelFallback;
    std::string type;                                           // "text" | "date" | "binary"
    std::variant<std::string, std::vector<std::uint8_t>> value; // tstr for text/date, bstr for binary
};
struct IdentityResult
{
    std::map<std::string, std::map<std::string, IdentityField>> fields; // group -> field -> cell
};
struct PhotoItem
{
    std::string key; // "group:field"
    std::uint64_t fd{0};
};
struct PhotoResult
{
    std::vector<PhotoItem> photos;
};
struct CertListResult
{
    std::vector<CertInfo> certs;
};
struct SignResult
{
    std::uint64_t artifact{0}; // fd-index
    SignMeta meta;
};
using OpResult = std::variant<IdentityResult, PhotoResult, CertListResult, SignResult>;

// Build a full reply CBOR map ({t:"Reply", req, <arm keys>}) for each arm, or an
// error reply ({t:"Reply", req, err:{...}}).
[[nodiscard]] CborValue makeReply(std::uint64_t req, const HelloAck&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const OpStarted&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const StateReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const CertListReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const CertDerReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const PublicKeyReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const ConfigReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const AckReply&);
[[nodiscard]] CborValue makeReply(std::uint64_t req, const RawSignatureReply&);
[[nodiscard]] CborValue makeSignRecoveryReply(std::uint64_t req, const SignResult&); // sign-recovery arm
[[nodiscard]] CborValue makeErrorReply(std::uint64_t req, const ErrInfo&);

// ---- events (agent -> client, unsolicited) ----------------------------------

struct ReaderAdded
{
    ReaderState reader;
};
struct ReaderRemoved
{
    std::string handle;
};
struct CardAdded
{
    CardState card;
};
struct CardRemoved
{
    std::string handle;
};
struct PropertyChanged
{
    std::string handle;
    std::string iface;
    std::map<std::string, CborValue> props;
};
struct ConfigChanged
{
    std::string key;
};
struct OpProgress
{
    std::uint64_t op{0};
    OperationPhase phase{OperationPhase::Created};
    std::optional<double> progress;
    std::optional<bool> indeterminate;
    std::optional<std::uint64_t> watchdogSecs;
};
struct OpResultReady
{
    std::uint64_t op{0};
    OpResult result;
};
struct OpFinished
{
    std::uint64_t op{0};
    OperationStatus status{OperationStatus::Ok};
    ErrorCode code{ErrorCode::None};
    std::string msgKey;
    std::string msgFallback;
};
struct AgentQuiesced
{
    QuiesceReason reason{QuiesceReason::SystemSleep};
};

[[nodiscard]] CborValue toCbor(const ReaderAdded&);
[[nodiscard]] CborValue toCbor(const ReaderRemoved&);
[[nodiscard]] CborValue toCbor(const CardAdded&);
[[nodiscard]] CborValue toCbor(const CardRemoved&);
[[nodiscard]] CborValue toCbor(const PropertyChanged&);
[[nodiscard]] CborValue toCbor(const ConfigChanged&);
[[nodiscard]] CborValue toCbor(const OpProgress&);
[[nodiscard]] CborValue toCbor(const OpResultReady&);
[[nodiscard]] CborValue toCbor(const OpFinished&);
[[nodiscard]] CborValue toCbor(const AgentQuiesced&);

} // namespace LibreSCRS::Darwin::wire
