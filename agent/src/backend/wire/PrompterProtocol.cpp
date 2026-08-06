// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The private agent<->prompter CBOR protocol over the Cbor seam. Strict decode
// (fail closed) for both directions; every secret-bearing buffer this layer
// creates is zeroed before it dies.
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <LibreSCRS/Agent/wire/Framing.h>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace LibreSCRS::Darwin::wire {

// Pulled in unqualified for this TU: the codec/framing primitives now live in
// the shared LibreAgent::Wire library; PromptKind/PromptRequest/etc. above stay
// Darwin-local (the private agent<->prompter protocol never left this repo).
using LibreSCRS::Agent::Wire::decode;
using LibreSCRS::Agent::Wire::secureZero;
using LibreSCRS::Agent::Wire::sendFrame;

namespace {

using Map = CborValue::Map;
using Array = CborValue::Array;

std::string_view kindName(PromptKind k)
{
    switch (k) {
    case PromptKind::Pin:
        return "pin";
    case PromptKind::Can:
        return "can";
    case PromptKind::Mrz:
        return "mrz";
    }
    return "pin";
}

std::string_view statusName(PromptReplyStatus s)
{
    switch (s) {
    case PromptReplyStatus::Ok:
        return "ok";
    case PromptReplyStatus::Cancelled:
        return "cancelled";
    case PromptReplyStatus::Error:
        return "error";
    case PromptReplyStatus::Unauthorized:
        return "unauthorized";
    }
    return "error";
}

std::optional<PromptReplyStatus> statusFromName(std::string_view s)
{
    if (s == "ok") {
        return PromptReplyStatus::Ok;
    }
    if (s == "cancelled") {
        return PromptReplyStatus::Cancelled;
    }
    if (s == "error") {
        return PromptReplyStatus::Error;
    }
    if (s == "unauthorized") {
        return PromptReplyStatus::Unauthorized;
    }
    return std::nullopt;
}

std::expected<const Map*, PrompterParseError> topMap(const std::span<const std::uint8_t> body,
                                                     std::optional<CborValue>& hold)
{
    auto decoded = decode(body);
    if (!decoded) {
        return std::unexpected(PrompterParseError::NotDecodable);
    }
    hold = std::move(*decoded);
    const auto* m = hold->asMap();
    if (m == nullptr) {
        return std::unexpected(PrompterParseError::NotAMap);
    }
    return m;
}

std::optional<std::string> optText(const Map& m, std::string_view k)
{
    const auto it = m.find(k);
    if (it == m.end()) {
        return std::string{};
    }
    const auto* t = it->second.asText();
    return t ? std::optional<std::string>(*t) : std::nullopt;
}

std::optional<std::uint64_t> optUint(const Map& m, std::string_view k)
{
    const auto it = m.find(k);
    if (it == m.end()) {
        return std::uint64_t{0};
    }
    return it->second.asUInt();
}

// The UNTRUSTED `artifacts` (batch-sign only) option: absent on every prompt
// that is not a batch sign (an older agent predating this key must not break
// either), so a missing entry degrades to an empty list, same tolerance as
// optText/optUint above. A PRESENT value must be an array of tstr like every
// other array-of-string on this wire — a type mismatch fails closed
// (nullopt), it is not silently dropped.
std::optional<std::vector<std::string>> optStringArray(const Map& m, std::string_view k)
{
    const auto it = m.find(k);
    if (it == m.end()) {
        return std::vector<std::string>{};
    }
    const auto* arr = it->second.asArray();
    if (arr == nullptr) {
        return std::nullopt;
    }
    std::vector<std::string> out;
    out.reserve(arr->size());
    for (const auto& item : *arr) {
        const auto* s = item.asText();
        if (s == nullptr) {
            return std::nullopt;
        }
        out.push_back(*s);
    }
    return out;
}

// The display metadata shared by both secret-request messages (all optional
// on the wire; nullopt only on a type mismatch).
struct DisplayFields
{
    std::string title;
    std::string description;
    std::string requester;
    std::string artifact;
};

std::optional<DisplayFields> optDisplayFields(const Map& m)
{
    auto title = optText(m, "title");
    auto description = optText(m, "description");
    auto requester = optText(m, "requester");
    auto artifact = optText(m, "artifact");
    if (!title || !description || !requester || !artifact) {
        return std::nullopt;
    }
    return DisplayFields{std::move(*title), std::move(*description), std::move(*requester), std::move(*artifact)};
}

// Required byte-string field carrying one inbound secret; enforces the
// per-secret kMaxSecretBytes cap BEFORE copying (an oversized secret is never
// duplicated by this layer).
std::expected<std::vector<std::uint8_t>, PrompterParseError> requiredSecret(const Map& m, std::string_view key)
{
    const auto it = m.find(key);
    if (it == m.end() || it->second.asBytes() == nullptr) {
        return std::unexpected(PrompterParseError::MissingField);
    }
    const auto& bytes = *it->second.asBytes();
    if (bytes.size() > kMaxSecretBytes) {
        return std::unexpected(PrompterParseError::SecretTooLarge);
    }
    return bytes;
}

// Zero a decoded reply tree when it goes out of scope: it holds the plaintext
// secret(s) for Ok replies, so EVERY parse exit (success, cap reject,
// malformed) must scrub it — after the reply copies are taken.
struct HoldScrub
{
    std::optional<CborValue>& hold;
    ~HoldScrub()
    {
        if (hold) {
            hold->scrub();
        }
    }
};

// The shared encode-send-zero core of every prompter reply send: encode one
// reply message, best-effort send the frame, then zero the CBOR tree copy and
// the encoded frame body. Send failures are swallowed (the peer just times
// out); the zeroing always runs. The caller zeroes the reply struct's own
// secret vector(s) afterwards.
template <typename Reply>
void sendReplyAndZeroWire(int connFd, const Reply& reply) noexcept
{
    try {
        CborValue msg = toCbor(reply);
        std::vector<std::uint8_t> body = msg.encode();
        static_cast<void>(sendFrame(connFd, body));
        secureZero(body);
        msg.scrub();
    } catch (...) {
        // Encode/send allocation failed: nothing (or a partial frame) went out;
        // the peer times out. Fall through — the caller's secret scrub still
        // runs.
    }
}

} // namespace

CborValue toCbor(const PromptRequest& r)
{
    Map m;
    m.emplace("t", CborValue("RequestSecret"));
    m.emplace("kind", CborValue(std::string(kindName(r.kind))));
    if (!r.title.empty()) {
        m.emplace("title", CborValue(r.title));
    }
    if (!r.description.empty()) {
        m.emplace("description", CborValue(r.description));
    }
    if (!r.requester.empty()) {
        m.emplace("requester", CborValue(r.requester));
    }
    if (!r.artifact.empty()) {
        m.emplace("artifact", CborValue(r.artifact));
    }
    if (r.minLength != 0) {
        m.emplace("minLength", CborValue::uint(r.minLength));
    }
    if (r.maxLength != 0) {
        m.emplace("maxLength", CborValue::uint(r.maxLength));
    }
    if (!r.artifacts.empty()) {
        Array arr;
        arr.reserve(r.artifacts.size());
        for (const auto& a : r.artifacts) {
            arr.push_back(CborValue(a));
        }
        m.emplace("artifacts", CborValue(std::move(arr)));
    }
    if (r.attempt != 0) {
        m.emplace("attempt", CborValue::uint(r.attempt));
    }
    if (!r.lastError.empty()) {
        m.emplace("lastError", CborValue(r.lastError));
    }
    return CborValue(std::move(m));
}

CborValue toCbor(const PromptCancel&)
{
    Map m;
    m.emplace("t", CborValue("CancelCurrent"));
    return CborValue(std::move(m));
}

CborValue toCbor(const RequestSecrets& r)
{
    Map m;
    m.emplace("t", CborValue("RequestSecrets"));
    m.emplace("kind", CborValue(r.kind));
    if (!r.title.empty()) {
        m.emplace("title", CborValue(r.title));
    }
    if (!r.description.empty()) {
        m.emplace("description", CborValue(r.description));
    }
    if (!r.requester.empty()) {
        m.emplace("requester", CborValue(r.requester));
    }
    if (!r.artifact.empty()) {
        m.emplace("artifact", CborValue(r.artifact));
    }
    if (r.primaryMinLength != 0) {
        m.emplace("primaryMinLength", CborValue::uint(r.primaryMinLength));
    }
    if (r.primaryMaxLength != 0) {
        m.emplace("primaryMaxLength", CborValue::uint(r.primaryMaxLength));
    }
    if (r.newMinLength != 0) {
        m.emplace("newMinLength", CborValue::uint(r.newMinLength));
    }
    if (r.newMaxLength != 0) {
        m.emplace("newMaxLength", CborValue::uint(r.newMaxLength));
    }
    return CborValue(std::move(m));
}

CborValue toCbor(const ConfirmAction& r)
{
    Map m;
    m.emplace("t", CborValue("ConfirmAction"));
    m.emplace("kind", CborValue(r.kind));
    if (!r.title.empty()) {
        m.emplace("title", CborValue(r.title));
    }
    if (!r.description.empty()) {
        m.emplace("description", CborValue(r.description));
    }
    if (!r.requester.empty()) {
        m.emplace("requester", CborValue(r.requester));
    }
    if (!r.artifact.empty()) {
        m.emplace("artifact", CborValue(r.artifact));
    }
    return CborValue(std::move(m));
}

CborValue toCbor(const ConfirmReply& r)
{
    Map m;
    m.emplace("t", CborValue("Confirm"));
    m.emplace("status", CborValue(std::string(statusName(r.status))));
    if (!r.userMessage.empty()) {
        m.emplace("userMessage", CborValue(r.userMessage));
    }
    return CborValue(std::move(m));
}

CborValue toCbor(const PromptReply& r)
{
    Map m;
    m.emplace("t", CborValue("Secret"));
    m.emplace("status", CborValue(std::string(statusName(r.status))));
    if (r.status == PromptReplyStatus::Ok) {
        m.emplace("secret", CborValue(r.secret));
    }
    if (!r.userMessage.empty()) {
        m.emplace("userMessage", CborValue(r.userMessage));
    }
    return CborValue(std::move(m));
}

CborValue toCbor(const MultiPromptReply& r)
{
    Map m;
    m.emplace("t", CborValue("Secrets"));
    m.emplace("status", CborValue(std::string(statusName(r.status))));
    if (r.status == PromptReplyStatus::Ok) {
        m.emplace("primary", CborValue(r.primary));
        m.emplace("secondary", CborValue(r.secondary));
    }
    if (!r.userMessage.empty()) {
        m.emplace("userMessage", CborValue(r.userMessage));
    }
    return CborValue(std::move(m));
}

std::expected<PrompterRequest, PrompterParseError> parsePrompterRequest(std::span<const std::uint8_t> body)
{
    std::optional<CborValue> hold;
    auto mapRes = topMap(body, hold);
    if (!mapRes) {
        return std::unexpected(mapRes.error());
    }
    const Map& m = **mapRes;

    const auto tIt = m.find("t");
    if (tIt == m.end() || tIt->second.asText() == nullptr) {
        return std::unexpected(PrompterParseError::MissingField);
    }
    const std::string& t = *tIt->second.asText();

    if (t == "CancelCurrent") {
        return PrompterRequest{PromptCancel{}};
    }

    // Both secret requests carry a "kind" discriminator: a closed enum for the
    // single-secret prompt, an open flow name for the multi-secret one.
    const auto kindIt = m.find("kind");

    if (t == "RequestSecrets") {
        if (kindIt == m.end() || kindIt->second.asText() == nullptr) {
            return std::unexpected(PrompterParseError::MissingField);
        }
        RequestSecrets r;
        r.kind = *kindIt->second.asText();
        auto display = optDisplayFields(m);
        const auto priMin = optUint(m, "primaryMinLength");
        const auto priMax = optUint(m, "primaryMaxLength");
        const auto newMin = optUint(m, "newMinLength");
        const auto newMax = optUint(m, "newMaxLength");
        if (!display || !priMin || !priMax || !newMin || !newMax) {
            return std::unexpected(PrompterParseError::WrongType);
        }
        r.title = std::move(display->title);
        r.description = std::move(display->description);
        r.requester = std::move(display->requester);
        r.artifact = std::move(display->artifact);
        r.primaryMinLength = static_cast<std::uint32_t>(*priMin);
        r.primaryMaxLength = static_cast<std::uint32_t>(*priMax);
        r.newMinLength = static_cast<std::uint32_t>(*newMin);
        r.newMaxLength = static_cast<std::uint32_t>(*newMax);
        return PrompterRequest{std::move(r)};
    }
    if (t == "ConfirmAction") {
        if (kindIt == m.end() || kindIt->second.asText() == nullptr) {
            return std::unexpected(PrompterParseError::MissingField);
        }
        ConfirmAction r;
        r.kind = *kindIt->second.asText();
        auto display = optDisplayFields(m);
        if (!display) {
            return std::unexpected(PrompterParseError::WrongType);
        }
        r.title = std::move(display->title);
        r.description = std::move(display->description);
        r.requester = std::move(display->requester);
        r.artifact = std::move(display->artifact);
        return PrompterRequest{std::move(r)};
    }
    if (t != "RequestSecret") {
        return std::unexpected(PrompterParseError::UnknownMessage);
    }

    if (kindIt == m.end() || kindIt->second.asText() == nullptr) {
        return std::unexpected(PrompterParseError::MissingField);
    }
    const std::string& kindStr = *kindIt->second.asText();
    PromptRequest r;
    if (kindStr == "pin") {
        r.kind = PromptKind::Pin;
    } else if (kindStr == "can") {
        r.kind = PromptKind::Can;
    } else if (kindStr == "mrz") {
        r.kind = PromptKind::Mrz;
    } else {
        return std::unexpected(PrompterParseError::BadEnum);
    }

    auto display = optDisplayFields(m);
    const auto minLen = optUint(m, "minLength");
    const auto maxLen = optUint(m, "maxLength");
    auto artifacts = optStringArray(m, "artifacts");
    // Retry context: absent on the first-ever prompt for a card (an older
    // agent predating this key must not break either) -- optUint/optText
    // already default a missing key to 0/"" the same way minLength/title do;
    // a PRESENT-but-mistyped value fails the whole request closed like every
    // other field here.
    const auto attempt = optUint(m, "attempt");
    const auto lastError = optText(m, "lastError");
    if (!display || !minLen || !maxLen || !artifacts || !attempt || !lastError) {
        return std::unexpected(PrompterParseError::WrongType);
    }
    r.title = std::move(display->title);
    r.description = std::move(display->description);
    r.requester = std::move(display->requester);
    r.artifact = std::move(display->artifact);
    r.minLength = static_cast<std::uint32_t>(*minLen);
    r.maxLength = static_cast<std::uint32_t>(*maxLen);
    r.artifacts = std::move(*artifacts);
    r.attempt = static_cast<std::uint32_t>(*attempt);
    r.lastError = std::move(*lastError);
    return PrompterRequest{std::move(r)};
}

std::expected<PromptReply, PrompterParseError> parsePromptReply(std::span<const std::uint8_t> body)
{
    std::optional<CborValue> hold;
    auto mapRes = topMap(body, hold);
    if (!mapRes) {
        return std::unexpected(mapRes.error());
    }
    // The decoded tree holds the plaintext secret for Ok replies; the guard
    // zeroes it on EVERY exit, after the copy below.
    const HoldScrub scrubGuard{hold};
    const Map& m = **mapRes;

    const auto statusIt = m.find("status");
    if (statusIt == m.end() || statusIt->second.asText() == nullptr) {
        return std::unexpected(PrompterParseError::MissingField);
    }
    const auto status = statusFromName(*statusIt->second.asText());
    if (!status) {
        return std::unexpected(PrompterParseError::BadEnum);
    }
    PromptReply reply;
    reply.status = *status;

    if (reply.status == PromptReplyStatus::Ok) {
        auto secret = requiredSecret(m, "secret");
        if (!secret) {
            return std::unexpected(secret.error());
        }
        reply.secret = std::move(*secret);
    }
    const auto msg = optText(m, "userMessage");
    if (!msg) {
        secureZero(reply.secret); // the extracted copy must not die unscrubbed
        return std::unexpected(PrompterParseError::WrongType);
    }
    reply.userMessage = std::move(*msg);
    return reply;
}

std::expected<ConfirmReply, PrompterParseError> parseConfirmReply(std::span<const std::uint8_t> body)
{
    std::optional<CborValue> hold;
    auto mapRes = topMap(body, hold);
    if (!mapRes) {
        return std::unexpected(mapRes.error());
    }
    // This reply has no secret of its own, but the bytes handed in are not
    // this side's to trust, and decoding has already copied whatever they
    // carried. So the tree is zeroed on every exit exactly like the
    // secret-bearing parsers do.
    const HoldScrub scrubGuard{hold};
    const Map& m = **mapRes;

    // A message carrying a secret is not a confirmation. Refusing it here is
    // what makes "this path cannot transport a secret" a property of the path
    // rather than a description of the struct: without it, such a message
    // would parse cleanly and its secret would be silently dropped.
    if (m.contains("secret") || m.contains("primary") || m.contains("secondary")) {
        return std::unexpected(PrompterParseError::UnknownMessage);
    }

    const auto statusIt = m.find("status");
    if (statusIt == m.end() || statusIt->second.asText() == nullptr) {
        return std::unexpected(PrompterParseError::MissingField);
    }
    const auto status = statusFromName(*statusIt->second.asText());
    if (!status) {
        return std::unexpected(PrompterParseError::BadEnum);
    }
    const auto msg = optText(m, "userMessage");
    if (!msg) {
        return std::unexpected(PrompterParseError::WrongType);
    }
    ConfirmReply reply;
    reply.status = *status;
    reply.userMessage = std::move(*msg);
    return reply;
}

std::expected<MultiPromptReply, PrompterParseError> parseMultiPromptReply(std::span<const std::uint8_t> body)
{
    std::optional<CborValue> hold;
    auto mapRes = topMap(body, hold);
    if (!mapRes) {
        return std::unexpected(mapRes.error());
    }
    // The decoded tree holds BOTH plaintext secrets for Ok replies; the guard
    // zeroes it on EVERY exit, after the copies below.
    const HoldScrub scrubGuard{hold};
    const Map& m = **mapRes;

    const auto statusIt = m.find("status");
    if (statusIt == m.end() || statusIt->second.asText() == nullptr) {
        return std::unexpected(PrompterParseError::MissingField);
    }
    const auto status = statusFromName(*statusIt->second.asText());
    if (!status) {
        return std::unexpected(PrompterParseError::BadEnum);
    }
    MultiPromptReply reply;
    reply.status = *status;

    if (reply.status == PromptReplyStatus::Ok) {
        auto primary = requiredSecret(m, "primary");
        if (!primary) {
            return std::unexpected(primary.error());
        }
        auto secondary = requiredSecret(m, "secondary");
        if (!secondary) {
            secureZero(*primary); // the sibling copy must not die unscrubbed
            return std::unexpected(secondary.error());
        }
        reply.primary = std::move(*primary);
        reply.secondary = std::move(*secondary);
    }
    const auto msg = optText(m, "userMessage");
    if (!msg) {
        secureZero(reply.primary); // the extracted copies must not die unscrubbed
        secureZero(reply.secondary);
        return std::unexpected(PrompterParseError::WrongType);
    }
    reply.userMessage = std::move(*msg);
    return reply;
}

void sendPromptReplyScrubbed(int connFd, PromptReply& reply) noexcept
{
    sendReplyAndZeroWire(connFd, reply);
    secureZero(reply.secret);
}

void sendConfirmReply(int connFd, const ConfirmReply& reply) noexcept
{
    // The wire buffers are zeroed by the shared core anyway; there is simply
    // no secret in the struct to zero after it.
    sendReplyAndZeroWire(connFd, reply);
}

void sendPromptReplyScrubbed(int connFd, MultiPromptReply& reply) noexcept
{
    sendReplyAndZeroWire(connFd, reply);
    secureZero(reply.primary);
    secureZero(reply.secondary);
}

namespace {

// Make one untrusted display name safe to drop into a single line of the prompt
// window: every control character (newlines included) becomes a space so the
// name cannot forge extra lines, and the result is elided on a UTF-8 boundary so
// it stays valid UTF-8 (nsstr rejects malformed input) and bounded in length.
std::string neutralizeDisplayName(std::string name)
{
    constexpr std::size_t kMaxBytes = 128;
    for (char& c : name) {
        const auto u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f) {
            c = ' ';
        }
    }
    // The Cocoa text engine also honours the multi-byte Unicode separators as
    // mandatory line breaks (U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR,
    // U+0085 NEXT LINE), which the byte-wise pass above cannot catch; collapse
    // each to one space so they cannot forge extra lines either.
    for (const std::string_view sep : {"\xE2\x80\xA8", "\xE2\x80\xA9", "\xC2\x85"}) {
        for (std::size_t pos = 0; (pos = name.find(sep, pos)) != std::string::npos; ++pos) {
            name.replace(pos, sep.size(), " ");
        }
    }
    if (name.size() > kMaxBytes) {
        std::size_t cut = kMaxBytes;
        while (cut > 0 && (static_cast<unsigned char>(name[cut]) & 0xC0) == 0x80) {
            --cut; // do not split a multi-byte code point
        }
        name.resize(cut);
        name += "\xE2\x80\xA6"; // U+2026 HORIZONTAL ELLIPSIS
    }
    return name;
}

} // namespace

std::string formatUntrustedArtifactList(const std::vector<std::string>& names, std::size_t maxItems)
{
    if (names.empty()) {
        return {};
    }
    std::string out = "Documents (as named by the requesting app):";
    const std::size_t shown = (maxItems == 0) ? names.size() : std::min(names.size(), maxItems);
    for (std::size_t i = 0; i < shown; ++i) {
        out += "\n  \xE2\x80\xA2 "; // U+2022 BULLET
        out += neutralizeDisplayName(names[i]);
    }
    if (names.size() > shown) {
        out += "\n  (+" + std::to_string(names.size() - shown) + " more)";
    }
    return out;
}

} // namespace LibreSCRS::Darwin::wire
