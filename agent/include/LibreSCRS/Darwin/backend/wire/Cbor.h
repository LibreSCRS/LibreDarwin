// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

// The CBOR value seam over the vendored QCBOR codec (plan D1). No caller sees
// QCBOR; the Messages layer (Task 4) marshals typed structs to/from CborValue.
//
// Encoding is RFC 8949 §4.2 CORE DETERMINISTIC: QCBOR preferred serialization
// (shortest-form integers, definite lengths, preferred floats) plus canonical
// map-key ordering enforced by CanonicalKeyLess. Every wire map key on this
// contract is a text string, and for text strings the §4.2 bytewise order of the
// encoded keys is IDENTICAL to (length ascending, then content bytewise): the
// CBOR text-string length header is strictly monotonic in length (0x60..0x77,
// then 0x78/0x79/0x7a/0x7b with big-endian length bytes), so a shorter key always
// encodes to a lexicographically-smaller prefix — exactly CanonicalKeyLess, for
// keys of ANY length.
//
// Decoding is strict + bounded (untrusted input, incl. the browser facade):
// depth + item-count caps, and a re-encode-and-compare canonical check that
// rejects non-canonical input (unsorted keys, non-shortest integers,
// indefinite-length items, duplicate keys) fail-closed.

namespace LibreSCRS::Darwin::wire {

// RFC 8949 §4.2 order for the text-string keys on this wire: shorter keys first,
// then bytewise lexicographic content. This is exactly the §4.2 bytewise order of
// the fully-encoded keys for text strings of ANY length, because the CBOR
// text-string length header is monotonic in length.
struct CanonicalKeyLess
{
    using is_transparent = void;
    [[nodiscard]] bool operator()(std::string_view a, std::string_view b) const noexcept
    {
        if (a.size() != b.size()) {
            return a.size() < b.size();
        }
        return a < b;
    }
};

enum class CborType : std::uint8_t { Null, Bool, UInt, Int, Double, Text, Bytes, Array, Map };

enum class CborError : std::uint8_t {
    Malformed,       // QCBOR could not decode the bytes
    NotCanonical,    // decoded, but the bytes were not RFC 8949 §4.2 canonical
    TooDeep,         // nesting exceeded the depth cap
    TooManyItems,    // item count exceeded the cap
    TrailingBytes,   // extra bytes after a complete top-level item
    UnsupportedType, // a CBOR major type outside our closed subset
};

class CborValue
{
public:
    using Bytes = std::vector<std::uint8_t>;
    using Array = std::vector<CborValue>;
    using Map = std::map<std::string, CborValue, CanonicalKeyLess>;

    CborValue() noexcept : m_v(nullptr) {}
    CborValue(std::nullptr_t) noexcept : m_v(nullptr) {}
    CborValue(bool b) noexcept : m_v(b) {}
    // Non-negative integers that fit in int64 are normalized to Int so a value
    // constructed from a uint compares equal to the same value after a
    // decode round-trip (CBOR encodes both identically as major-0; QCBOR decodes
    // them back as INT64). UInt storage is reserved for values > INT64_MAX.
    CborValue(std::uint64_t u) noexcept
    {
        if (u <= static_cast<std::uint64_t>(INT64_MAX)) {
            m_v = static_cast<std::int64_t>(u);
        } else {
            m_v = u;
        }
    }
    CborValue(std::int64_t i) noexcept : m_v(i) {}
    CborValue(double d) noexcept : m_v(d) {}
    CborValue(std::string text) : m_v(std::move(text)) {}
    CborValue(const char* text) : m_v(std::string(text)) {}
    CborValue(Bytes bytes) : m_v(std::move(bytes)) {}
    CborValue(Array arr) : m_v(std::move(arr)) {}
    CborValue(Map map) : m_v(std::move(map)) {}

    // Explicit small-integer convenience for call sites (avoids ambiguous {}).
    static CborValue uint(std::uint64_t u) noexcept
    {
        return CborValue(u);
    }

    [[nodiscard]] CborType type() const noexcept
    {
        return static_cast<CborType>(m_v.index());
    }
    [[nodiscard]] bool isNull() const noexcept
    {
        return type() == CborType::Null;
    }

    // Typed accessors: std::nullopt when the stored type differs. UInt/Int are
    // NOT auto-converted — the caller asks for the exact wire type.
    [[nodiscard]] std::optional<bool> asBool() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t> asUInt() const noexcept;
    [[nodiscard]] std::optional<std::int64_t> asInt() const noexcept;
    [[nodiscard]] std::optional<double> asDouble() const noexcept;
    [[nodiscard]] const std::string* asText() const noexcept;
    [[nodiscard]] const Bytes* asBytes() const noexcept;
    [[nodiscard]] const Array* asArray() const noexcept;
    [[nodiscard]] const Map* asMap() const noexcept;

    // Convenience map lookup: nullptr when not a map or key absent.
    [[nodiscard]] const CborValue* find(std::string_view key) const noexcept;

    bool operator==(const CborValue&) const = default;

    // Canonical (RFC 8949 §4.2) encoding.
    [[nodiscard]] std::vector<std::uint8_t> encode() const;

    // Zero every text/byte-string payload in this tree in place, recursing
    // through arrays and maps (map KEYS are wire field names, not secrets, and
    // stay intact). For secret-bearing frames (prompter replies): no decoded
    // plaintext copy may outlive its use.
    void scrub() noexcept;

private:
    std::variant<std::nullptr_t, bool, std::uint64_t, std::int64_t, double, std::string, Bytes, Array, Map> m_v;
};

// Strict, bounded, canonical-checked decode of one complete top-level item.
// Rejects trailing bytes, non-canonical encodings, and over-deep / over-large
// inputs fail-closed.
[[nodiscard]] std::expected<CborValue, CborError> decode(std::span<const std::uint8_t> bytes);

// Guaranteed zeroization for secret-bearing buffers: volatile writes the
// optimizer may not elide as dead stores (unlike a plain fill before free).
void secureZero(std::span<std::uint8_t> bytes) noexcept;

// Caps applied by decode() (also the encode side stays well within them).
inline constexpr std::size_t kMaxCborDepth = 16;
inline constexpr std::size_t kMaxCborItems = 4096;

} // namespace LibreSCRS::Darwin::wire
