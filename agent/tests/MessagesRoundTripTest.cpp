// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Every request round-trips through the typed model and the canonical CBOR wire
// (parseRequest(encode(toCbor(env))) == env). Reply/event builders produce the
// reconciled shapes. Malformed / unknown requests fail closed.
#include <LibreSCRS/Darwin/backend/wire/Messages.h>

#include <gtest/gtest.h>

using namespace LibreSCRS::Darwin::wire;

namespace {

// Encode an envelope to canonical frame bytes, then parse it back.
std::expected<RequestEnvelope, WireError> roundTrip(const RequestEnvelope& env)
{
    const std::vector<std::uint8_t> bytes = toCbor(env).encode();
    return parseRequest(bytes);
}

void expectStable(const RequestEnvelope& env)
{
    const auto parsed = roundTrip(env);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, env);
    // Byte-stable: re-encoding the parsed envelope reproduces the same bytes.
    EXPECT_EQ(toCbor(*parsed).encode(), toCbor(env).encode());
}

TEST(MessagesRoundTrip, EveryRequestType)
{
    expectStable({1, Hello{1, std::nullopt}});
    expectStable({2, Hello{1, std::string("LibreMac/0.1")}});
    expectStable({3, GetState{}});
    expectStable({4, ReadIdentity{"reader/0:card/0"}});
    expectStable({5, GetPhoto{"reader/0:card/0"}});
    expectStable({6, ReadCertificates{"reader/0:card/0"}});
    expectStable({7, Sign{"card/0", "abc123", 0,
                          SignOpts{"pades", "b-lt", "enveloped", true, std::string("Doc"), std::string("why"),
                                   std::string("Belgrade")}}});
    expectStable({8, Sign{"card/0", "abc123", 2,
                          SignOpts{"auto", "b-b", "auto", std::nullopt, std::nullopt, std::nullopt, std::nullopt}}});
    expectStable({9, GetCertDer{"reader/0", "certid"}});
    expectStable({10, GetConfig{}});
    expectStable({11, SetConfig{"DefaultLevel", CborValue(std::string("b-t"))}});
    expectStable({12, ResetConfig{"TsaUrls"}});
    expectStable({13, CancelOp{42}});
    expectStable({14, GetSignResult{42}});
    expectStable({15, PkLogin{"reader/0"}});
    expectStable({16, PkLogout{"reader/0"}});
    expectStable({17, PkPublicKey{"reader/0", "certid"}});
    expectStable({18, PkSignRaw{"reader/0", "certid", {0xDE, 0xAD}}});
    expectStable({19, PkDecrypt{"reader/0", "certid", {0xBE, 0xEF}}});
}

TEST(MessagesRoundTrip, SetConfigCarriesAnyValue)
{
    // The `value` field is `any` — an array here — and survives round-trip.
    CborValue::Array tsl;
    tsl.push_back(CborValue(std::string("https://example/tl.xml")));
    expectStable({20, SetConfig{"TsaUrls", CborValue(std::move(tsl))}});
}

TEST(MessagesRoundTrip, RejectsUnknownTag)
{
    CborValue::Map m;
    m.emplace("t", CborValue("Nope"));
    m.emplace("req", CborValue::uint(1));
    const auto r = parseRequest(CborValue(std::move(m)).encode());
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), WireError::UnknownMessage);
}

TEST(MessagesRoundTrip, RejectsMissingTag)
{
    CborValue::Map m;
    m.emplace("req", CborValue::uint(1));
    const auto r = parseRequest(CborValue(std::move(m)).encode());
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), WireError::NoTag);
}

TEST(MessagesRoundTrip, RejectsMissingRequiredField)
{
    CborValue::Map m;
    m.emplace("t", CborValue("ReadIdentity")); // no "card"
    m.emplace("req", CborValue::uint(1));
    const auto r = parseRequest(CborValue(std::move(m)).encode());
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), WireError::MissingField);
}

TEST(MessagesRoundTrip, RejectsWrongFieldType)
{
    CborValue::Map m;
    m.emplace("t", CborValue("CancelOp"));
    m.emplace("req", CborValue::uint(1));
    m.emplace("op", CborValue(std::string("not-a-number")));
    const auto r = parseRequest(CborValue(std::move(m)).encode());
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), WireError::WrongType);
}

TEST(MessagesRoundTrip, RejectsNonCanonicalOrGarbageBytes)
{
    const std::vector<std::uint8_t> garbage{0xff, 0x00, 0x9f};
    const auto r = parseRequest(garbage);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), WireError::NotDecodable);
}

TEST(MessagesRoundTrip, RejectsNonMapTopLevel)
{
    const auto r = parseRequest(CborValue::uint(7).encode());
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), WireError::NotAMap);
}

// --- reply / event shape checks (agent builds these; the client decodes) -----

TEST(MessagesRoundTrip, ErrorReplyCarriesNumericOrNamedError)
{
    const auto numeric = makeErrorReply(5, ErrInfo{ErrorCode::CardRemoved, std::nullopt, std::nullopt});
    const auto* nm = numeric.find("err");
    ASSERT_NE(nm, nullptr);
    ASSERT_NE(nm->find("code"), nullptr);
    EXPECT_EQ(nm->find("code")->asUInt(), static_cast<std::uint64_t>(ErrorCode::CardRemoved));
    EXPECT_EQ(numeric.find("req")->asUInt(), 5u);

    const auto named = makeErrorReply(6, ErrInfo{SyncError::UnknownCard, std::string("k"), std::string("f")});
    const auto* nmd = named.find("err");
    ASSERT_NE(nmd, nullptr);
    ASSERT_NE(nmd->find("name"), nullptr);
    EXPECT_EQ(*nmd->find("name")->asText(), "UnknownCard");
    EXPECT_EQ(nmd->find("code"), nullptr); // one or the other, never both
}

TEST(MessagesRoundTrip, SignResultEventCarriesFdIndexNotBytes)
{
    OpResultReady ev{9, SignResult{0, SignMeta{"pades", "b-lta", true, false}}};
    const CborValue c = toCbor(ev);
    EXPECT_EQ(*c.find("t")->asText(), "OpResultReady");
    const auto* result = c.find("result");
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(*result->find("kind")->asText(), "Sign");
    // artifact is an fd-index (uint), never inline bytes.
    ASSERT_NE(result->find("artifact"), nullptr);
    EXPECT_TRUE(result->find("artifact")->asUInt().has_value());
}

TEST(MessagesRoundTrip, EveryEventEncodesWithItsTag)
{
    EXPECT_EQ(*toCbor(ReaderAdded{ReaderState{"r", "n", false, std::nullopt}}).find("t")->asText(), "ReaderAdded");
    EXPECT_EQ(*toCbor(ReaderRemoved{"r"}).find("t")->asText(), "ReaderRemoved");
    EXPECT_EQ(*toCbor(CardAdded{CardState{"c", "r", 0x3, PreReadAuthMethod::PaceCan}}).find("t")->asText(),
              "CardAdded");
    EXPECT_EQ(*toCbor(CardRemoved{"c"}).find("t")->asText(), "CardRemoved");
    EXPECT_EQ(*toCbor(ConfigChanged{"DefaultLevel"}).find("t")->asText(), "ConfigChanged");
    EXPECT_EQ(
        *toCbor(OpProgress{1, OperationPhase::Signing, std::nullopt, std::nullopt, std::nullopt}).find("t")->asText(),
        "OpProgress");
    EXPECT_EQ(*toCbor(OpFinished{1, OperationStatus::Ok, ErrorCode::None, "", ""}).find("t")->asText(), "OpFinished");
    EXPECT_EQ(*toCbor(AgentQuiesced{QuiesceReason::SystemSleep}).find("t")->asText(), "AgentQuiesced");
}

} // namespace
