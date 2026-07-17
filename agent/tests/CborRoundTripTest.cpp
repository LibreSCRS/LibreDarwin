// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Byte-stable canonical CBOR round-trips + fail-closed rejection of
// non-canonical / malformed input (the untrusted-parser contract).
#include <LibreSCRS/Darwin/backend/wire/Cbor.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

using LibreSCRS::Darwin::wire::CborError;
using LibreSCRS::Darwin::wire::CborValue;
using LibreSCRS::Darwin::wire::decode;

namespace {

// encode -> decode -> value-equal AND encode(decoded) byte-equal to encode(v).
void expectStableRoundTrip(const CborValue& v)
{
    const std::vector<std::uint8_t> bytes = v.encode();
    const auto decoded = decode(bytes);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, v);
    EXPECT_EQ(decoded->encode(), bytes); // byte-stable
}

TEST(CborRoundTrip, Scalars)
{
    expectStableRoundTrip(CborValue(nullptr));
    expectStableRoundTrip(CborValue(true));
    expectStableRoundTrip(CborValue(false));
    expectStableRoundTrip(CborValue::uint(0));
    expectStableRoundTrip(CborValue::uint(23));
    expectStableRoundTrip(CborValue::uint(1000000));
    expectStableRoundTrip(CborValue(static_cast<std::int64_t>(-17)));
    expectStableRoundTrip(CborValue(std::string("Hello")));
    expectStableRoundTrip(CborValue(std::string{}));
    expectStableRoundTrip(CborValue(CborValue::Bytes{0xDE, 0xAD, 0xBE, 0xEF}));
    expectStableRoundTrip(CborValue(1.5));
}

TEST(CborRoundTrip, NestedMapAndArray)
{
    CborValue::Map inner;
    inner.emplace("given_name", CborValue(std::string("Ana")));
    inner.emplace("age", CborValue::uint(42));

    CborValue::Array certs;
    certs.push_back(CborValue(std::string("certA")));
    certs.push_back(CborValue(std::string("certB")));

    CborValue::Map root;
    root.emplace("t", CborValue(std::string("ReadIdentity")));
    root.emplace("req", CborValue::uint(7));
    root.emplace("fields", CborValue(std::move(inner)));
    root.emplace("certs", CborValue(std::move(certs)));

    expectStableRoundTrip(CborValue(std::move(root)));
}

TEST(CborRoundTrip, MapKeyOrderIsCanonicalRegardlessOfInsertionOrder)
{
    CborValue::Map a;
    a.emplace("bb", CborValue::uint(2));
    a.emplace("a", CborValue::uint(1));
    a.emplace("ccc", CborValue::uint(3));

    CborValue::Map b;
    b.emplace("ccc", CborValue::uint(3));
    b.emplace("a", CborValue::uint(1));
    b.emplace("bb", CborValue::uint(2));

    // Same entries -> identical canonical bytes (shorter keys first, then bytewise).
    EXPECT_EQ(CborValue(std::move(a)).encode(), CborValue(std::move(b)).encode());
}

TEST(CborRoundTrip, RejectsNonShortestInteger)
{
    // 0 encoded as a 1-byte-follows uint (0x18 0x00) instead of 0x00.
    const std::vector<std::uint8_t> nonShortest{0x18, 0x00};
    const auto r = decode(nonShortest);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::NotCanonical);
}

TEST(CborRoundTrip, RejectsIndefiniteLengthArray)
{
    // 0x9f ... 0xff = indefinite-length array [1].
    const std::vector<std::uint8_t> indefinite{0x9f, 0x01, 0xff};
    const auto r = decode(indefinite);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::NotCanonical);
}

TEST(CborRoundTrip, RejectsUnsortedMapKeys)
{
    // map(2){ "b":1, "a":2 } — keys out of canonical order.
    const std::vector<std::uint8_t> unsorted{0xa2, 0x61, 'b', 0x01, 0x61, 'a', 0x02};
    const auto r = decode(unsorted);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::NotCanonical);
}

TEST(CborRoundTrip, RejectsDuplicateMapKeys)
{
    // map(2){ "a":1, "a":2 }.
    const std::vector<std::uint8_t> dup{0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02};
    const auto r = decode(dup);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::NotCanonical);
}

TEST(CborRoundTrip, RejectsTrailingBytes)
{
    std::vector<std::uint8_t> bytes = CborValue::uint(1).encode(); // {0x01}
    bytes.push_back(0x02);                                         // trailing
    const auto r = decode(bytes);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::TrailingBytes);
}

TEST(CborRoundTrip, EncodesFloatInShortestPreferredForm)
{
    // RFC 8949 §4.2 preferred float: 1.5 MUST encode as CBOR float16
    // (0xf9 0x3e 0x00), not float32/64. Locks QCBOR v1.6.1 preferred
    // serialization (a regression / QCBOR bump that stops shortening would break
    // the "§4.2 canonical" guarantee for the only wire float, op-progress).
    const std::vector<std::uint8_t> half{0xf9, 0x3e, 0x00};
    EXPECT_EQ(CborValue(1.5).encode(), half);
}

TEST(CborRoundTrip, RejectsNonShortestFloat)
{
    // 1.5 as float64 (0xfb 3ff8000000000000) is non-canonical -> rejected by the
    // re-encode-and-compare guard (our canonical form is the shortest float16).
    const std::vector<std::uint8_t> asDouble{0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const auto r = decode(asDouble);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), CborError::NotCanonical);
}

TEST(CborRoundTrip, MalformedInputNeverCrashes)
{
    // A spread of malformed byte strings must each return an error, never crash.
    const std::vector<std::vector<std::uint8_t>> corpus{
        {}, {0xff}, {0xa1}, {0x9f}, {0x1b, 0x00}, {0x62, 'a'}, {0x82, 0x01}, {0xa2, 0x61, 'a', 0x01}};
    for (const auto& bytes : corpus) {
        const auto r = decode(bytes);
        EXPECT_FALSE(r.has_value());
    }
}

} // namespace
