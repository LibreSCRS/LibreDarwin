// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The private agent<->prompter CBOR protocol over the Cbor seam. Strict decode
// (fail closed) for both directions.
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <optional>
#include <string_view>
#include <utility>

namespace LibreSCRS::Darwin::wire {
namespace {

using Map = CborValue::Map;

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
    return CborValue(std::move(m));
}

CborValue toCbor(const PromptCancel&)
{
    Map m;
    m.emplace("t", CborValue("CancelCurrent"));
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
    if (t != "RequestSecret") {
        return std::unexpected(PrompterParseError::UnknownMessage);
    }

    const auto kindIt = m.find("kind");
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

    const auto title = optText(m, "title");
    const auto description = optText(m, "description");
    const auto requester = optText(m, "requester");
    const auto artifact = optText(m, "artifact");
    const auto minLen = optUint(m, "minLength");
    const auto maxLen = optUint(m, "maxLength");
    if (!title || !description || !requester || !artifact || !minLen || !maxLen) {
        return std::unexpected(PrompterParseError::WrongType);
    }
    r.title = std::move(*title);
    r.description = std::move(*description);
    r.requester = std::move(*requester);
    r.artifact = std::move(*artifact);
    r.minLength = static_cast<std::uint32_t>(*minLen);
    r.maxLength = static_cast<std::uint32_t>(*maxLen);
    return PrompterRequest{std::move(r)};
}

std::expected<PromptReply, PrompterParseError> parsePromptReply(std::span<const std::uint8_t> body)
{
    std::optional<CborValue> hold;
    auto mapRes = topMap(body, hold);
    if (!mapRes) {
        return std::unexpected(mapRes.error());
    }
    const Map& m = **mapRes;

    const auto statusIt = m.find("status");
    if (statusIt == m.end() || statusIt->second.asText() == nullptr) {
        return std::unexpected(PrompterParseError::MissingField);
    }
    const std::string& statusStr = *statusIt->second.asText();
    PromptReply reply;
    if (statusStr == "ok") {
        reply.status = PromptReplyStatus::Ok;
    } else if (statusStr == "cancelled") {
        reply.status = PromptReplyStatus::Cancelled;
    } else if (statusStr == "error") {
        reply.status = PromptReplyStatus::Error;
    } else if (statusStr == "unauthorized") {
        reply.status = PromptReplyStatus::Unauthorized;
    } else {
        return std::unexpected(PrompterParseError::BadEnum);
    }

    if (reply.status == PromptReplyStatus::Ok) {
        const auto secretIt = m.find("secret");
        if (secretIt == m.end() || secretIt->second.asBytes() == nullptr) {
            return std::unexpected(PrompterParseError::MissingField);
        }
        reply.secret = *secretIt->second.asBytes();
    }
    const auto msg = optText(m, "userMessage");
    if (!msg) {
        return std::unexpected(PrompterParseError::WrongType);
    }
    reply.userMessage = std::move(*msg);
    return reply;
}

} // namespace LibreSCRS::Darwin::wire
