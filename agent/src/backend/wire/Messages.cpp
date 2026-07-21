// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Typed message (de)serialization over the Cbor seam. parseRequest is the
// untrusted inbound path (canonical-decode, then strict field modeling, fail
// closed); the toCbor / makeReply builders are the trusted outbound path.
#include <LibreSCRS/Darwin/backend/wire/Messages.h>

#include <utility>

namespace LibreSCRS::Darwin::wire {
namespace {

using Map = CborValue::Map;
using Array = CborValue::Array;
using Bytes = CborValue::Bytes;

// --- strict field accessors (required) ---------------------------------------
std::expected<std::string, WireError> fText(const Map& m, std::string_view k)
{
    const auto it = m.find(k);
    if (it == m.end()) {
        return std::unexpected(WireError::MissingField);
    }
    const auto* t = it->second.asText();
    if (t == nullptr) {
        return std::unexpected(WireError::WrongType);
    }
    return *t;
}
std::expected<std::uint64_t, WireError> fUint(const Map& m, std::string_view k)
{
    const auto it = m.find(k);
    if (it == m.end()) {
        return std::unexpected(WireError::MissingField);
    }
    const auto v = it->second.asUInt();
    if (!v) {
        return std::unexpected(WireError::WrongType);
    }
    return *v;
}
std::expected<Bytes, WireError> fBytes(const Map& m, std::string_view k)
{
    const auto it = m.find(k);
    if (it == m.end()) {
        return std::unexpected(WireError::MissingField);
    }
    const auto* b = it->second.asBytes();
    if (b == nullptr) {
        return std::unexpected(WireError::WrongType);
    }
    return *b;
}

// --- strict field accessors (optional: absent => nullopt, wrong type => error) -
std::expected<std::optional<std::string>, WireError> fOptText(const Map& m, std::string_view k)
{
    const auto it = m.find(k);
    if (it == m.end()) {
        return std::optional<std::string>{};
    }
    const auto* t = it->second.asText();
    if (t == nullptr) {
        return std::unexpected(WireError::WrongType);
    }
    return std::optional<std::string>{*t};
}
std::expected<std::optional<bool>, WireError> fOptBool(const Map& m, std::string_view k)
{
    const auto it = m.find(k);
    if (it == m.end()) {
        return std::optional<bool>{};
    }
    const auto v = it->second.asBool();
    if (!v) {
        return std::unexpected(WireError::WrongType);
    }
    return std::optional<bool>{*v};
}

std::expected<SignOpts, WireError> parseSignOpts(const CborValue& v)
{
    const auto* m = v.asMap();
    if (m == nullptr) {
        return std::unexpected(WireError::WrongType);
    }
    auto format = fText(*m, "format");
    if (!format) {
        return std::unexpected(format.error());
    }
    auto level = fText(*m, "level");
    if (!level) {
        return std::unexpected(level.error());
    }
    auto packaging = fText(*m, "packaging");
    if (!packaging) {
        return std::unexpected(packaging.error());
    }
    auto allowExpired = fOptBool(*m, "allowExpired");
    if (!allowExpired) {
        return std::unexpected(allowExpired.error());
    }
    auto displayName = fOptText(*m, "displayName");
    if (!displayName) {
        return std::unexpected(displayName.error());
    }
    auto reason = fOptText(*m, "reason");
    if (!reason) {
        return std::unexpected(reason.error());
    }
    auto location = fOptText(*m, "location");
    if (!location) {
        return std::unexpected(location.error());
    }
    return SignOpts{std::move(*format),      std::move(*level),  std::move(*packaging), *allowExpired,
                    std::move(*displayName), std::move(*reason), std::move(*location)};
}

// --- outbound sub-type encoders ----------------------------------------------
CborValue arrOfText(const std::vector<std::string>& v)
{
    Array a;
    a.reserve(v.size());
    for (const auto& s : v) {
        a.push_back(CborValue(s));
    }
    return CborValue(std::move(a));
}

CborValue encodeSignOpts(const SignOpts& o)
{
    Map m;
    m.emplace("format", CborValue(o.format));
    m.emplace("level", CborValue(o.level));
    m.emplace("packaging", CborValue(o.packaging));
    if (o.allowExpired) {
        m.emplace("allowExpired", CborValue(*o.allowExpired));
    }
    if (o.displayName) {
        m.emplace("displayName", CborValue(*o.displayName));
    }
    if (o.reason) {
        m.emplace("reason", CborValue(*o.reason));
    }
    if (o.location) {
        m.emplace("location", CborValue(*o.location));
    }
    return CborValue(std::move(m));
}

CborValue encodeReaderState(const ReaderState& r)
{
    Map m;
    m.emplace("handle", CborValue(r.handle));
    m.emplace("name", CborValue(r.name));
    m.emplace("hasCard", CborValue(r.hasCard));
    if (r.card) {
        m.emplace("card", CborValue(*r.card));
    }
    return CborValue(std::move(m));
}

CborValue encodeCardState(const CardState& c)
{
    Map m;
    m.emplace("handle", CborValue(c.handle));
    m.emplace("reader", CborValue(c.reader));
    m.emplace("caps", CborValue::uint(c.caps));
    m.emplace("preAuth", CborValue::uint(static_cast<std::uint64_t>(c.preAuth)));
    return CborValue(std::move(m));
}

CborValue encodeCertInfo(const CertInfo& ci)
{
    Map groups;
    for (const auto& [group, cells] : ci.fields) {
        Map inner;
        for (const auto& [key, cell] : cells) {
            Array tuple; // cert-field = [labelKey, labelFallback, value]
            tuple.push_back(CborValue(cell.labelKey));
            tuple.push_back(CborValue(cell.labelFallback));
            tuple.push_back(CborValue(cell.value));
            inner.emplace(key, CborValue(std::move(tuple)));
        }
        groups.emplace(group, CborValue(std::move(inner)));
    }
    Map m;
    m.emplace("certId", CborValue(ci.certId));
    m.emplace("signingCapable", CborValue(ci.signingCapable));
    m.emplace("fields", CborValue(std::move(groups)));
    m.emplace("keyUsageBits", CborValue::uint(ci.keyUsageBits));
    m.emplace("ekus", arrOfText(ci.ekus));
    m.emplace("chainSubjectCns", arrOfText(ci.chainSubjectCns));
    m.emplace("trustStatus", CborValue::uint(ci.trustStatus));
    return CborValue(std::move(m));
}

CborValue encodeSignMeta(const SignMeta& s)
{
    Map m;
    m.emplace("format", CborValue(s.format));
    m.emplace("level", CborValue(s.level));
    m.emplace("tsaUsed", CborValue(s.tsaUsed));
    m.emplace("chainComplete", CborValue(s.chainComplete));
    return CborValue(std::move(m));
}

// CredentialOutcome -> its camelCase wire token. Exhaustive switch, NO default:
// with -Werror=switch an appended outcome is a compile error until it is named
// here. The agent only ENCODES outcomes (the client decodes them fail-closed).
const char* credOutcomeToken(LibreSCRS::Agent::CredentialOutcome o) noexcept
{
    using LibreSCRS::Agent::CredentialOutcome;
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
    return "unspecified"; // unreachable (all enumerators handled)
}

// cred-result = { outcome, ? retriesLeft, blocked, ? pinActivated, ? keyActivated }.
// Optional numeric/bool keys are OMITTED when nullopt; `blocked` is always written.
CborValue encodeCredResult(const LibreSCRS::Agent::CredentialOpResult& r)
{
    Map m;
    m.emplace("outcome", CborValue(credOutcomeToken(r.outcome)));
    if (r.retriesLeft) {
        m.emplace("retriesLeft", CborValue::uint(static_cast<std::uint64_t>(*r.retriesLeft)));
    }
    m.emplace("blocked", CborValue(r.blocked));
    if (r.pinActivated) {
        m.emplace("pinActivated", CborValue(*r.pinActivated));
    }
    if (r.keyActivated) {
        m.emplace("keyActivated", CborValue(*r.keyActivated));
    }
    return CborValue(std::move(m));
}

// cred-record: 22 camelCase keys mirroring CredentialRecord. The four enum-valued
// fields (kind/state/unblockStyle/recovery) are already token STRINGS on the
// record (produced upstream via detail::*Token), written verbatim. Optional
// numeric + guidance keys are OMITTED when nullopt; booleans are always written.
CborValue encodeCredRecord(const LibreSCRS::Agent::CredentialRecord& rec)
{
    Map m;
    m.emplace("id", CborValue(rec.id));
    m.emplace("label", CborValue(rec.label));
    m.emplace("kind", CborValue(rec.kind));
    m.emplace("state", CborValue(rec.state));
    if (rec.retriesLeft) {
        m.emplace("retriesLeft", CborValue::uint(static_cast<std::uint64_t>(*rec.retriesLeft)));
    }
    if (rec.retriesMax) {
        m.emplace("retriesMax", CborValue::uint(static_cast<std::uint64_t>(*rec.retriesMax)));
    }
    if (rec.usesLeft) {
        m.emplace("usesLeft", CborValue::uint(static_cast<std::uint64_t>(*rec.usesLeft)));
    }
    if (rec.unblocksLeft) {
        m.emplace("unblocksLeft", CborValue::uint(static_cast<std::uint64_t>(*rec.unblocksLeft)));
    }
    if (rec.minLength) {
        m.emplace("minLength", CborValue::uint(static_cast<std::uint64_t>(*rec.minLength)));
    }
    if (rec.maxLength) {
        m.emplace("maxLength", CborValue::uint(static_cast<std::uint64_t>(*rec.maxLength)));
    }
    m.emplace("canChange", CborValue(rec.canChange));
    m.emplace("unblockable", CborValue(rec.unblockable));
    m.emplace("unblockStyle", CborValue(rec.unblockStyle));
    m.emplace("activatable", CborValue(rec.activatable));
    m.emplace("keyActivationPending", CborValue(rec.keyActivationPending));
    m.emplace("keyActivatable", CborValue(rec.keyActivatable));
    m.emplace("recovery", CborValue(rec.recovery));
    m.emplace("probeSafe", CborValue(rec.probeSafe));
    if (rec.blockedGuidanceKey) {
        m.emplace("blockedGuidanceKey", CborValue(*rec.blockedGuidanceKey));
    }
    if (rec.blockedGuidanceFallback) {
        m.emplace("blockedGuidanceFallback", CborValue(*rec.blockedGuidanceFallback));
    }
    if (rec.keyActivationGuidanceKey) {
        m.emplace("keyActivationGuidanceKey", CborValue(*rec.keyActivationGuidanceKey));
    }
    if (rec.keyActivationGuidanceFallback) {
        m.emplace("keyActivationGuidanceFallback", CborValue(*rec.keyActivationGuidanceFallback));
    }
    return CborValue(std::move(m));
}

CborValue encodeOpResult(const OpResult& r)
{
    return std::visit(
        [](const auto& arm) -> CborValue {
            using T = std::decay_t<decltype(arm)>;
            Map m;
            if constexpr (std::is_same_v<T, IdentityResult>) {
                m.emplace("kind", CborValue("Identity"));
                Map groups;
                for (const auto& [group, cells] : arm.fields) {
                    Map inner;
                    for (const auto& [key, cell] : cells) {
                        Array tuple; // id-field = [labelKey, labelFallback, type, value]
                        tuple.push_back(CborValue(cell.labelKey));
                        tuple.push_back(CborValue(cell.labelFallback));
                        tuple.push_back(CborValue(cell.type));
                        if (std::holds_alternative<std::string>(cell.value)) {
                            tuple.push_back(CborValue(std::get<std::string>(cell.value)));
                        } else {
                            tuple.push_back(CborValue(std::get<Bytes>(cell.value)));
                        }
                        inner.emplace(key, CborValue(std::move(tuple)));
                    }
                    groups.emplace(group, CborValue(std::move(inner)));
                }
                m.emplace("fields", CborValue(std::move(groups)));
            } else if constexpr (std::is_same_v<T, PhotoResult>) {
                m.emplace("kind", CborValue("Photo"));
                Array photos;
                for (const auto& p : arm.photos) {
                    Map pm;
                    pm.emplace("key", CborValue(p.key));
                    pm.emplace("fd", CborValue::uint(p.fd));
                    photos.push_back(CborValue(std::move(pm)));
                }
                m.emplace("photos", CborValue(std::move(photos)));
            } else if constexpr (std::is_same_v<T, CertListResult>) {
                m.emplace("kind", CborValue("Certificates"));
                Array certs;
                for (const auto& c : arm.certs) {
                    certs.push_back(encodeCertInfo(c));
                }
                m.emplace("certs", CborValue(std::move(certs)));
            } else if constexpr (std::is_same_v<T, SignResult>) {
                m.emplace("kind", CborValue("Sign"));
                m.emplace("artifact", CborValue::uint(arm.artifact));
                m.emplace("meta", encodeSignMeta(arm.meta));
            } else { // CredentialsResult
                m.emplace("kind", CborValue("Credentials"));
                m.emplace("result", encodeCredResult(arm.result));
                Array records;
                records.reserve(arm.records.size());
                for (const auto& rec : arm.records) {
                    records.push_back(encodeCredRecord(rec));
                }
                m.emplace("records", CborValue(std::move(records)));
            }
            return CborValue(std::move(m));
        },
        r);
}

// --- outbound request encoders (round-trip symmetry) -------------------------
CborValue encodeRequestBody(const Request& body)
{
    return std::visit(
        [](const auto& r) -> CborValue {
            using T = std::decay_t<decltype(r)>;
            Map m;
            if constexpr (std::is_same_v<T, Hello>) {
                m.emplace("t", CborValue("Hello"));
                m.emplace("proto", CborValue::uint(r.proto));
                if (r.client) {
                    m.emplace("client", CborValue(*r.client));
                }
            } else if constexpr (std::is_same_v<T, GetState>) {
                m.emplace("t", CborValue("GetState"));
            } else if constexpr (std::is_same_v<T, ReadIdentity>) {
                m.emplace("t", CborValue("ReadIdentity"));
                m.emplace("card", CborValue(r.card));
            } else if constexpr (std::is_same_v<T, GetPhoto>) {
                m.emplace("t", CborValue("GetPhoto"));
                m.emplace("card", CborValue(r.card));
            } else if constexpr (std::is_same_v<T, ReadCertificates>) {
                m.emplace("t", CborValue("ReadCertificates"));
                m.emplace("card", CborValue(r.card));
            } else if constexpr (std::is_same_v<T, Sign>) {
                m.emplace("t", CborValue("Sign"));
                m.emplace("card", CborValue(r.card));
                m.emplace("cert", CborValue(r.cert));
                m.emplace("in", CborValue::uint(r.inFd));
                m.emplace("opts", encodeSignOpts(r.opts));
            } else if constexpr (std::is_same_v<T, GetCertDer>) {
                m.emplace("t", CborValue("GetCertDer"));
                m.emplace("reader", CborValue(r.reader));
                m.emplace("cert", CborValue(r.cert));
            } else if constexpr (std::is_same_v<T, GetConfig>) {
                m.emplace("t", CborValue("GetConfig"));
            } else if constexpr (std::is_same_v<T, SetConfig>) {
                m.emplace("t", CborValue("SetConfig"));
                m.emplace("key", CborValue(r.key));
                m.emplace("value", r.value);
            } else if constexpr (std::is_same_v<T, ResetConfig>) {
                m.emplace("t", CborValue("ResetConfig"));
                m.emplace("key", CborValue(r.key));
            } else if constexpr (std::is_same_v<T, CancelOp>) {
                m.emplace("t", CborValue("CancelOp"));
                m.emplace("op", CborValue::uint(r.op));
            } else if constexpr (std::is_same_v<T, GetSignResult>) {
                m.emplace("t", CborValue("GetSignResult"));
                m.emplace("op", CborValue::uint(r.op));
            } else if constexpr (std::is_same_v<T, PkLogin>) {
                m.emplace("t", CborValue("Pkcs11.Login"));
                m.emplace("reader", CborValue(r.reader));
            } else if constexpr (std::is_same_v<T, PkLogout>) {
                m.emplace("t", CborValue("Pkcs11.Logout"));
                m.emplace("reader", CborValue(r.reader));
            } else if constexpr (std::is_same_v<T, PkPublicKey>) {
                m.emplace("t", CborValue("Pkcs11.PublicKey"));
                m.emplace("reader", CborValue(r.reader));
                m.emplace("cert", CborValue(r.cert));
            } else if constexpr (std::is_same_v<T, PkSignRaw>) {
                m.emplace("t", CborValue("Pkcs11.SignRaw"));
                m.emplace("reader", CborValue(r.reader));
                m.emplace("cert", CborValue(r.cert));
                m.emplace("data", CborValue(r.data));
            } else if constexpr (std::is_same_v<T, PkDecrypt>) {
                m.emplace("t", CborValue("Pkcs11.Decrypt"));
                m.emplace("reader", CborValue(r.reader));
                m.emplace("cert", CborValue(r.cert));
                m.emplace("data", CborValue(r.data));
            } else if constexpr (std::is_same_v<T, ListCredentials>) {
                m.emplace("t", CborValue("ListCredentials"));
                m.emplace("card", CborValue(r.card));
            } else if constexpr (std::is_same_v<T, ManagePin>) {
                m.emplace("t", CborValue("ManagePin"));
                m.emplace("card", CborValue(r.card));
                m.emplace("pinId", CborValue(r.pinId));
                m.emplace("verb", CborValue(r.verb));
                if (r.activateKey) {
                    m.emplace("activateKey", CborValue(*r.activateKey));
                }
            } else { // ActivateSigningKey
                m.emplace("t", CborValue("ActivateSigningKey"));
                m.emplace("card", CborValue(r.card));
            }
            return CborValue(std::move(m));
        },
        body);
}

// Reply envelope helper: start from {t:"Reply", req} and merge the arm's keys.
CborValue makeReplyBase(std::uint64_t req)
{
    Map m;
    m.emplace("t", CborValue("Reply"));
    m.emplace("req", CborValue::uint(req));
    return CborValue(std::move(m));
}

} // namespace

std::string_view syncErrorName(SyncError e) noexcept
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
    case SyncError::UnknownCredential:
        return "UnknownCredential";
    case SyncError::InvalidRequest:
        return "InvalidRequest";
    }
    return "UnknownCard"; // unreachable (all enumerators handled)
}

std::expected<RequestEnvelope, WireError> parseRequest(std::span<const std::uint8_t> body)
{
    const auto decoded = decode(body);
    if (!decoded) {
        return std::unexpected(WireError::NotDecodable);
    }
    const auto* m = decoded->asMap();
    if (m == nullptr) {
        return std::unexpected(WireError::NotAMap);
    }
    const auto req = fUint(*m, "req");
    if (!req) {
        return std::unexpected(req.error());
    }
    const auto tag = fText(*m, "t");
    if (!tag) {
        return std::unexpected(tag.error() == WireError::MissingField ? WireError::NoTag : tag.error());
    }

    RequestEnvelope env;
    env.req = *req;
    const std::string& t = *tag;

    // A small helper to model a single required-string-field request.
    const auto oneString = [&](std::string_view key) -> std::expected<std::string, WireError> {
        return fText(*m, key);
    };

    if (t == "Hello") {
        auto proto = fUint(*m, "proto");
        if (!proto) {
            return std::unexpected(proto.error());
        }
        auto client = fOptText(*m, "client");
        if (!client) {
            return std::unexpected(client.error());
        }
        env.body = Hello{*proto, std::move(*client)};
    } else if (t == "GetState") {
        env.body = GetState{};
    } else if (t == "ReadIdentity") {
        auto card = oneString("card");
        if (!card) {
            return std::unexpected(card.error());
        }
        env.body = ReadIdentity{std::move(*card)};
    } else if (t == "GetPhoto") {
        auto card = oneString("card");
        if (!card) {
            return std::unexpected(card.error());
        }
        env.body = GetPhoto{std::move(*card)};
    } else if (t == "ReadCertificates") {
        auto card = oneString("card");
        if (!card) {
            return std::unexpected(card.error());
        }
        env.body = ReadCertificates{std::move(*card)};
    } else if (t == "Sign") {
        auto card = fText(*m, "card");
        if (!card) {
            return std::unexpected(card.error());
        }
        auto cert = fText(*m, "cert");
        if (!cert) {
            return std::unexpected(cert.error());
        }
        auto inFd = fUint(*m, "in");
        if (!inFd) {
            return std::unexpected(inFd.error());
        }
        const auto optsIt = m->find("opts");
        if (optsIt == m->end()) {
            return std::unexpected(WireError::MissingField);
        }
        auto opts = parseSignOpts(optsIt->second);
        if (!opts) {
            return std::unexpected(opts.error());
        }
        env.body = Sign{std::move(*card), std::move(*cert), *inFd, std::move(*opts)};
    } else if (t == "GetCertDer") {
        auto reader = fText(*m, "reader");
        if (!reader) {
            return std::unexpected(reader.error());
        }
        auto cert = fText(*m, "cert");
        if (!cert) {
            return std::unexpected(cert.error());
        }
        env.body = GetCertDer{std::move(*reader), std::move(*cert)};
    } else if (t == "GetConfig") {
        env.body = GetConfig{};
    } else if (t == "SetConfig") {
        auto key = fText(*m, "key");
        if (!key) {
            return std::unexpected(key.error());
        }
        const auto valueIt = m->find("value");
        if (valueIt == m->end()) {
            return std::unexpected(WireError::MissingField);
        }
        env.body = SetConfig{std::move(*key), valueIt->second};
    } else if (t == "ResetConfig") {
        auto key = oneString("key");
        if (!key) {
            return std::unexpected(key.error());
        }
        env.body = ResetConfig{std::move(*key)};
    } else if (t == "CancelOp") {
        auto op = fUint(*m, "op");
        if (!op) {
            return std::unexpected(op.error());
        }
        env.body = CancelOp{*op};
    } else if (t == "GetSignResult") {
        auto op = fUint(*m, "op");
        if (!op) {
            return std::unexpected(op.error());
        }
        env.body = GetSignResult{*op};
    } else if (t == "Pkcs11.Login") {
        auto reader = oneString("reader");
        if (!reader) {
            return std::unexpected(reader.error());
        }
        env.body = PkLogin{std::move(*reader)};
    } else if (t == "Pkcs11.Logout") {
        auto reader = oneString("reader");
        if (!reader) {
            return std::unexpected(reader.error());
        }
        env.body = PkLogout{std::move(*reader)};
    } else if (t == "Pkcs11.PublicKey") {
        auto reader = fText(*m, "reader");
        if (!reader) {
            return std::unexpected(reader.error());
        }
        auto cert = fText(*m, "cert");
        if (!cert) {
            return std::unexpected(cert.error());
        }
        env.body = PkPublicKey{std::move(*reader), std::move(*cert)};
    } else if (t == "Pkcs11.SignRaw" || t == "Pkcs11.Decrypt") {
        auto reader = fText(*m, "reader");
        if (!reader) {
            return std::unexpected(reader.error());
        }
        auto cert = fText(*m, "cert");
        if (!cert) {
            return std::unexpected(cert.error());
        }
        auto data = fBytes(*m, "data");
        if (!data) {
            return std::unexpected(data.error());
        }
        if (t == "Pkcs11.SignRaw") {
            env.body = PkSignRaw{std::move(*reader), std::move(*cert), std::move(*data)};
        } else {
            env.body = PkDecrypt{std::move(*reader), std::move(*cert), std::move(*data)};
        }
    } else if (t == "ListCredentials") {
        auto card = oneString("card");
        if (!card) {
            return std::unexpected(card.error());
        }
        env.body = ListCredentials{std::move(*card)};
    } else if (t == "ManagePin") {
        // pinId/verb are strings; the verb is validated against the closed
        // cred-verb set (and the activateKey/verb combination) at the frontend
        // entry gate, not here — the parser only models the shape, fail closed.
        auto card = fText(*m, "card");
        if (!card) {
            return std::unexpected(card.error());
        }
        auto pinId = fText(*m, "pinId");
        if (!pinId) {
            return std::unexpected(pinId.error());
        }
        auto verb = fText(*m, "verb");
        if (!verb) {
            return std::unexpected(verb.error());
        }
        auto activateKey = fOptBool(*m, "activateKey");
        if (!activateKey) {
            return std::unexpected(activateKey.error());
        }
        env.body = ManagePin{std::move(*card), std::move(*pinId), std::move(*verb), *activateKey};
    } else if (t == "ActivateSigningKey") {
        auto card = oneString("card");
        if (!card) {
            return std::unexpected(card.error());
        }
        env.body = ActivateSigningKey{std::move(*card)};
    } else {
        return std::unexpected(WireError::UnknownMessage);
    }
    return env;
}

CborValue toCbor(const RequestEnvelope& env)
{
    CborValue bodyCbor = encodeRequestBody(env.body);
    Map m = *bodyCbor.asMap(); // copy the body's keys
    m.emplace("req", CborValue::uint(env.req));
    return CborValue(std::move(m));
}

// ---- reply builders ----------------------------------------------------------
namespace {
void mergeInto(CborValue& reply, Map arm)
{
    // reply is guaranteed a Map (makeReplyBase); merge the arm's keys.
    auto base = *reply.asMap();
    for (auto& [k, v] : arm) {
        base.emplace(k, std::move(v));
    }
    reply = CborValue(std::move(base));
}
} // namespace

CborValue makeReply(std::uint64_t req, const HelloAck& a)
{
    CborValue reply = makeReplyBase(req);
    Map arm;
    arm.emplace("kind", CborValue("HelloAck"));
    arm.emplace("agentVer", CborValue(a.agentVer));
    arm.emplace("features", arrOfText(a.features));
    mergeInto(reply, std::move(arm));
    return reply;
}

CborValue makeReply(std::uint64_t req, const OpStarted& o)
{
    CborValue reply = makeReplyBase(req);
    Map arm;
    arm.emplace("op", CborValue::uint(o.op));
    mergeInto(reply, std::move(arm));
    return reply;
}

CborValue makeReply(std::uint64_t req, const StateReply& s)
{
    CborValue reply = makeReplyBase(req);
    Array readers;
    for (const auto& r : s.readers) {
        readers.push_back(encodeReaderState(r));
    }
    Array cards;
    for (const auto& c : s.cards) {
        cards.push_back(encodeCardState(c));
    }
    Map arm;
    arm.emplace("readers", CborValue(std::move(readers)));
    arm.emplace("cards", CborValue(std::move(cards)));
    mergeInto(reply, std::move(arm));
    return reply;
}

CborValue makeReply(std::uint64_t req, const CertListReply& c)
{
    CborValue reply = makeReplyBase(req);
    Array certs;
    for (const auto& ci : c.certs) {
        certs.push_back(encodeCertInfo(ci));
    }
    Map arm;
    arm.emplace("certs", CborValue(std::move(certs)));
    mergeInto(reply, std::move(arm));
    return reply;
}

CborValue makeReply(std::uint64_t req, const CertDerReply& c)
{
    CborValue reply = makeReplyBase(req);
    Map arm;
    arm.emplace("der", CborValue(c.der));
    mergeInto(reply, std::move(arm));
    return reply;
}

CborValue makeReply(std::uint64_t req, const PublicKeyReply& pk)
{
    CborValue reply = makeReplyBase(req);
    Map arm;
    if (std::holds_alternative<RsaPublicKey>(pk)) {
        const auto& rsa = std::get<RsaPublicKey>(pk);
        arm.emplace("kty", CborValue("RSA"));
        arm.emplace("n", CborValue(rsa.n));
        arm.emplace("e", CborValue(rsa.e));
    } else {
        const auto& ec = std::get<EcPublicKey>(pk);
        arm.emplace("kty", CborValue("EC"));
        arm.emplace("crv", CborValue(ec.crv));
        arm.emplace("x", CborValue(ec.x));
        arm.emplace("y", CborValue(ec.y));
    }
    mergeInto(reply, std::move(arm));
    return reply;
}

CborValue makeReply(std::uint64_t req, const ConfigReply& c)
{
    CborValue reply = makeReplyBase(req);
    Map entries;
    for (const auto& [k, v] : c.entries) {
        entries.emplace(k, v);
    }
    Map arm;
    arm.emplace("entries", CborValue(std::move(entries)));
    mergeInto(reply, std::move(arm));
    return reply;
}

CborValue makeReply(std::uint64_t req, const AckReply&)
{
    CborValue reply = makeReplyBase(req);
    Map arm;
    arm.emplace("ok", CborValue(true));
    mergeInto(reply, std::move(arm));
    return reply;
}

CborValue makeReply(std::uint64_t req, const RawSignatureReply& r)
{
    CborValue reply = makeReplyBase(req);
    Map arm;
    arm.emplace("sig", CborValue(r.sig));
    mergeInto(reply, std::move(arm));
    return reply;
}

CborValue makeSignRecoveryReply(std::uint64_t req, const SignResult& sr)
{
    CborValue reply = makeReplyBase(req);
    Map arm;
    arm.emplace("result", encodeOpResult(OpResult{sr}));
    mergeInto(reply, std::move(arm));
    return reply;
}

CborValue makeErrorReply(std::uint64_t req, const ErrInfo& e)
{
    CborValue reply = makeReplyBase(req);
    Map err;
    if (std::holds_alternative<ErrorCode>(e.code)) {
        err.emplace("code", CborValue::uint(static_cast<std::uint64_t>(std::get<ErrorCode>(e.code))));
    } else {
        err.emplace("name", CborValue(std::string(syncErrorName(std::get<SyncError>(e.code)))));
    }
    if (e.msgKey) {
        err.emplace("msgKey", CborValue(*e.msgKey));
    }
    if (e.msgFallback) {
        err.emplace("msgFallback", CborValue(*e.msgFallback));
    }
    Map arm;
    arm.emplace("err", CborValue(std::move(err)));
    mergeInto(reply, std::move(arm));
    return reply;
}

// ---- event builders ----------------------------------------------------------
CborValue toCbor(const ReaderAdded& e)
{
    Map m;
    m.emplace("t", CborValue("ReaderAdded"));
    m.emplace("reader", encodeReaderState(e.reader));
    return CborValue(std::move(m));
}
CborValue toCbor(const ReaderRemoved& e)
{
    Map m;
    m.emplace("t", CborValue("ReaderRemoved"));
    m.emplace("handle", CborValue(e.handle));
    return CborValue(std::move(m));
}
CborValue toCbor(const CardAdded& e)
{
    Map m;
    m.emplace("t", CborValue("CardAdded"));
    m.emplace("card", encodeCardState(e.card));
    return CborValue(std::move(m));
}
CborValue toCbor(const CardRemoved& e)
{
    Map m;
    m.emplace("t", CborValue("CardRemoved"));
    m.emplace("handle", CborValue(e.handle));
    return CborValue(std::move(m));
}
CborValue toCbor(const PropertyChanged& e)
{
    Map props;
    for (const auto& [k, v] : e.props) {
        props.emplace(k, v);
    }
    Map m;
    m.emplace("t", CborValue("PropertyChanged"));
    m.emplace("handle", CborValue(e.handle));
    m.emplace("iface", CborValue(e.iface));
    m.emplace("props", CborValue(std::move(props)));
    return CborValue(std::move(m));
}
CborValue toCbor(const ConfigChanged& e)
{
    Map m;
    m.emplace("t", CborValue("ConfigChanged"));
    m.emplace("key", CborValue(e.key));
    return CborValue(std::move(m));
}
CborValue toCbor(const OpProgress& e)
{
    Map m;
    m.emplace("t", CborValue("OpProgress"));
    m.emplace("op", CborValue::uint(e.op));
    m.emplace("phase", CborValue::uint(static_cast<std::uint64_t>(e.phase)));
    if (e.progress) {
        m.emplace("progress", CborValue(*e.progress));
    }
    if (e.indeterminate) {
        m.emplace("indeterminate", CborValue(*e.indeterminate));
    }
    if (e.watchdogSecs) {
        m.emplace("watchdogSecs", CborValue::uint(*e.watchdogSecs));
    }
    return CborValue(std::move(m));
}
CborValue toCbor(const OpResultReady& e)
{
    Map m;
    m.emplace("t", CborValue("OpResultReady"));
    m.emplace("op", CborValue::uint(e.op));
    m.emplace("result", encodeOpResult(e.result));
    return CborValue(std::move(m));
}
CborValue toCbor(const OpFinished& e)
{
    Map m;
    m.emplace("t", CborValue("OpFinished"));
    m.emplace("op", CborValue::uint(e.op));
    m.emplace("status", CborValue::uint(static_cast<std::uint64_t>(e.status)));
    m.emplace("code", CborValue::uint(static_cast<std::uint64_t>(e.code)));
    m.emplace("msgKey", CborValue(e.msgKey));
    m.emplace("msgFallback", CborValue(e.msgFallback));
    return CborValue(std::move(m));
}
CborValue toCbor(const AgentQuiesced& e)
{
    Map m;
    m.emplace("t", CborValue("AgentQuiesced"));
    m.emplace("reason", CborValue::uint(static_cast<std::uint64_t>(e.reason)));
    return CborValue(std::move(m));
}

} // namespace LibreSCRS::Darwin::wire
