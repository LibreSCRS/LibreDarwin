// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// CborValue codec over QCBOR. Encoding is RFC 8949 §4.2 core
// deterministic: QCBOR preferred serialization (shortest ints, definite
// lengths, preferred floats) + CanonicalKeyLess map ordering. Decoding is
// strict + bounded (depth/item caps) with a re-encode-and-compare canonical
// check that fails closed on any non-canonical input.
#include <LibreSCRS/Darwin/backend/wire/Cbor.h>

#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>

#include <algorithm>

namespace LibreSCRS::Darwin::wire {
namespace {

UsefulBufC bufOf(std::string_view s) noexcept
{
    return UsefulBufC{s.data(), s.size()};
}
UsefulBufC bufOf(std::span<const std::uint8_t> b) noexcept
{
    return UsefulBufC{b.data(), b.size()};
}

void encodeValue(QCBOREncodeContext* ctx, const CborValue& v)
{
    switch (v.type()) {
    case CborType::Null:
        QCBOREncode_AddNULL(ctx);
        break;
    case CborType::Bool:
        QCBOREncode_AddBool(ctx, *v.asBool());
        break;
    case CborType::UInt:
        QCBOREncode_AddUInt64(ctx, *v.asUInt());
        break;
    case CborType::Int:
        QCBOREncode_AddInt64(ctx, *v.asInt());
        break;
    case CborType::Double:
        QCBOREncode_AddDouble(ctx, *v.asDouble());
        break;
    case CborType::Text:
        QCBOREncode_AddText(ctx, bufOf(*v.asText()));
        break;
    case CborType::Bytes:
        QCBOREncode_AddBytes(ctx, bufOf(*v.asBytes()));
        break;
    case CborType::Array:
        QCBOREncode_OpenArray(ctx);
        for (const auto& e : *v.asArray()) {
            encodeValue(ctx, e);
        }
        QCBOREncode_CloseArray(ctx);
        break;
    case CborType::Map:
        QCBOREncode_OpenMap(ctx);
        // std::map<..., CanonicalKeyLess> iterates in canonical §4.2 order. Each
        // entry is a label (AddText) immediately followed by its value — exactly
        // how QCBOR's *ToMap helpers pair a key with a value under the hood.
        for (const auto& [key, val] : *v.asMap()) {
            QCBOREncode_AddText(ctx, bufOf(key));
            encodeValue(ctx, val);
        }
        QCBOREncode_CloseMap(ctx);
        break;
    }
}

std::expected<CborValue, CborError> readValue(QCBORDecodeContext* ctx, const QCBORItem& item, std::size_t depth,
                                              std::size_t& budget)
{
    if (depth > kMaxCborDepth) {
        return std::unexpected(CborError::TooDeep);
    }
    if (budget == 0) {
        return std::unexpected(CborError::TooManyItems);
    }
    --budget;

    switch (item.uDataType) {
    case QCBOR_TYPE_INT64:
        return CborValue(static_cast<std::int64_t>(item.val.int64));
    case QCBOR_TYPE_UINT64:
        return CborValue(static_cast<std::uint64_t>(item.val.uint64));
    case QCBOR_TYPE_TRUE:
        return CborValue(true);
    case QCBOR_TYPE_FALSE:
        return CborValue(false);
    case QCBOR_TYPE_NULL:
        return CborValue(nullptr);
    case QCBOR_TYPE_DOUBLE:
        // With preferred float enabled (default), QCBOR returns every float as a
        // double in dfnum; QCBOR_TYPE_FLOAT does not occur.
        return CborValue(static_cast<double>(item.val.dfnum));
    case QCBOR_TYPE_TEXT_STRING:
        return CborValue(std::string(static_cast<const char*>(item.val.string.ptr), item.val.string.len));
    case QCBOR_TYPE_BYTE_STRING: {
        const auto* p = static_cast<const std::uint8_t*>(item.val.string.ptr);
        return CborValue(CborValue::Bytes(p, p + item.val.string.len));
    }
    case QCBOR_TYPE_ARRAY: {
        if (item.val.uCount == QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH) {
            return std::unexpected(CborError::NotCanonical); // indefinite length
        }
        CborValue::Array arr;
        const std::uint16_t count = item.val.uCount;
        // Reserve only what the item budget can actually admit — `count` is
        // attacker-controlled (up to 65534), so reserving it outright would
        // sidestep kMaxCborItems and allow a large transient allocation from a
        // tiny body. The read loop below is still budget-gated per element.
        arr.reserve(std::min<std::size_t>(count, budget));
        for (std::uint16_t i = 0; i < count; ++i) {
            QCBORItem child;
            if (QCBORDecode_GetNext(ctx, &child) != QCBOR_SUCCESS) {
                return std::unexpected(CborError::Malformed);
            }
            auto child_value = readValue(ctx, child, depth + 1, budget);
            if (!child_value) {
                return child_value;
            }
            arr.push_back(std::move(*child_value));
        }
        return CborValue(std::move(arr));
    }
    case QCBOR_TYPE_MAP: {
        if (item.val.uCount == QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH) {
            return std::unexpected(CborError::NotCanonical); // indefinite length
        }
        CborValue::Map map;
        const std::uint16_t count = item.val.uCount;
        for (std::uint16_t i = 0; i < count; ++i) {
            QCBORItem child;
            if (QCBORDecode_GetNext(ctx, &child) != QCBOR_SUCCESS) {
                return std::unexpected(CborError::Malformed);
            }
            // Every wire map key on this contract is a text string.
            if (child.uLabelType != QCBOR_TYPE_TEXT_STRING) {
                return std::unexpected(CborError::UnsupportedType);
            }
            std::string key(static_cast<const char*>(child.label.string.ptr), child.label.string.len);
            auto child_value = readValue(ctx, child, depth + 1, budget);
            if (!child_value) {
                return child_value;
            }
            if (!map.emplace(std::move(key), std::move(*child_value)).second) {
                return std::unexpected(CborError::NotCanonical); // duplicate key
            }
        }
        return CborValue(std::move(map));
    }
    default:
        return std::unexpected(CborError::UnsupportedType);
    }
}

} // namespace

std::optional<bool> CborValue::asBool() const noexcept
{
    if (const auto* p = std::get_if<bool>(&m_v)) {
        return *p;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> CborValue::asUInt() const noexcept
{
    if (const auto* p = std::get_if<std::uint64_t>(&m_v)) {
        return *p;
    }
    // Non-negative Int is also a valid unsigned (integers are normalized to Int
    // when they fit; see the uint ctor).
    if (const auto* p = std::get_if<std::int64_t>(&m_v); p && *p >= 0) {
        return static_cast<std::uint64_t>(*p);
    }
    return std::nullopt;
}

std::optional<std::int64_t> CborValue::asInt() const noexcept
{
    if (const auto* p = std::get_if<std::int64_t>(&m_v)) {
        return *p;
    }
    return std::nullopt;
}

std::optional<double> CborValue::asDouble() const noexcept
{
    if (const auto* p = std::get_if<double>(&m_v)) {
        return *p;
    }
    return std::nullopt;
}

const std::string* CborValue::asText() const noexcept
{
    return std::get_if<std::string>(&m_v);
}

const CborValue::Bytes* CborValue::asBytes() const noexcept
{
    return std::get_if<Bytes>(&m_v);
}

const CborValue::Array* CborValue::asArray() const noexcept
{
    return std::get_if<Array>(&m_v);
}

const CborValue::Map* CborValue::asMap() const noexcept
{
    return std::get_if<Map>(&m_v);
}

const CborValue* CborValue::find(std::string_view key) const noexcept
{
    const auto* map = asMap();
    if (map == nullptr) {
        return nullptr;
    }
    const auto it = map->find(key);
    return it == map->end() ? nullptr : &it->second;
}

std::vector<std::uint8_t> CborValue::encode() const
{
    // Pass 1: size calculation.
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, SizeCalculateUsefulBuf);
    encodeValue(&ctx, *this);
    std::size_t size = 0;
    if (QCBOREncode_FinishGetSize(&ctx, &size) != QCBOR_SUCCESS) {
        return {};
    }
    // Pass 2: real encode into the sized buffer.
    std::vector<std::uint8_t> out(size);
    QCBOREncode_Init(&ctx, UsefulBuf{out.data(), out.size()});
    encodeValue(&ctx, *this);
    UsefulBufC encoded;
    if (QCBOREncode_Finish(&ctx, &encoded) != QCBOR_SUCCESS) {
        return {};
    }
    out.resize(encoded.len);
    return out;
}

std::expected<CborValue, CborError> decode(std::span<const std::uint8_t> bytes)
{
    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, bufOf(bytes), QCBOR_DECODE_MODE_NORMAL);

    QCBORItem item;
    if (QCBORDecode_GetNext(&ctx, &item) != QCBOR_SUCCESS) {
        return std::unexpected(CborError::Malformed);
    }
    std::size_t budget = kMaxCborItems;
    auto value = readValue(&ctx, item, 0, budget);
    if (!value) {
        return value;
    }
    // No trailing bytes; the whole input is exactly one top-level item.
    if (QCBORDecode_Finish(&ctx) != QCBOR_SUCCESS) {
        return std::unexpected(CborError::TrailingBytes);
    }
    // Malleability guard: the input must equal our canonical re-encoding. The
    // re-encode is a full frame copy — for secret-bearing frames (prompter
    // replies) it holds the plaintext, so zero it before it dies.
    std::vector<std::uint8_t> canonical = value->encode();
    const bool matches =
        canonical.size() == bytes.size() && std::equal(canonical.begin(), canonical.end(), bytes.begin());
    secureZero(canonical);
    if (!matches) {
        return std::unexpected(CborError::NotCanonical);
    }
    return value;
}

void CborValue::scrub() noexcept
{
    if (auto* text = std::get_if<std::string>(&m_v)) {
        secureZero({reinterpret_cast<std::uint8_t*>(text->data()), text->size()});
    } else if (auto* bytes = std::get_if<Bytes>(&m_v)) {
        secureZero({bytes->data(), bytes->size()});
    } else if (auto* arr = std::get_if<Array>(&m_v)) {
        for (auto& v : *arr) {
            v.scrub();
        }
    } else if (auto* map = std::get_if<Map>(&m_v)) {
        for (auto& [key, v] : *map) {
            v.scrub();
        }
    }
}

void secureZero(std::span<std::uint8_t> bytes) noexcept
{
    volatile std::uint8_t* p = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        p[i] = 0;
    }
}

} // namespace LibreSCRS::Darwin::wire
