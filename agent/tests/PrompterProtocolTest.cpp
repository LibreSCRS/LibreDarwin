// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The agent<->prompter CBOR protocol round-trips both directions; malformed /
// unknown inputs fail closed.
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <gtest/gtest.h>

using namespace LibreSCRS::Darwin::wire;

namespace {

PromptRequest roundTripRequest(const PromptRequest& r)
{
    const auto bytes = toCbor(r).encode();
    auto parsed = parsePrompterRequest(bytes);
    EXPECT_TRUE(parsed.has_value());
    return std::get<PromptRequest>(*parsed);
}

TEST(PrompterProtocol, RequestRoundTrips)
{
    EXPECT_EQ(roundTripRequest(PromptRequest{PromptKind::Pin, "Title", "Desc", "LibreMac", "doc.pdf", 4, 12}),
              (PromptRequest{PromptKind::Pin, "Title", "Desc", "LibreMac", "doc.pdf", 4, 12}));
    EXPECT_EQ(roundTripRequest(PromptRequest{PromptKind::Can, {}, {}, {}, {}, 6, 6}).kind, PromptKind::Can);
    EXPECT_EQ(roundTripRequest(PromptRequest{PromptKind::Mrz, {}, {}, {}, {}, 0, 0}).kind, PromptKind::Mrz);
}

TEST(PrompterProtocol, CancelParsesAsCancelVariant)
{
    const auto bytes = toCbor(PromptCancel{}).encode();
    auto parsed = parsePrompterRequest(bytes);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(std::holds_alternative<PromptCancel>(*parsed));
}

TEST(PrompterProtocol, ReplyRoundTrips)
{
    for (const auto st : {PromptReplyStatus::Cancelled, PromptReplyStatus::Error, PromptReplyStatus::Unauthorized}) {
        PromptReply r;
        r.status = st;
        r.userMessage = "msg";
        auto parsed = parsePromptReply(toCbor(r).encode());
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(parsed->status, st);
        EXPECT_EQ(parsed->userMessage, "msg");
        EXPECT_TRUE(parsed->secret.empty());
    }
    PromptReply ok;
    ok.status = PromptReplyStatus::Ok;
    ok.secret = {'0', '0', '0', '0'};
    auto parsed = parsePromptReply(toCbor(ok).encode());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, PromptReplyStatus::Ok);
    EXPECT_EQ(parsed->secret, (std::vector<std::uint8_t>{'0', '0', '0', '0'}));
}

TEST(PrompterProtocol, RejectsGarbageAndUnknown)
{
    EXPECT_FALSE(parsePrompterRequest(std::vector<std::uint8_t>{0xff}).has_value());
    // Unknown message tag.
    CborValue::Map m;
    m.emplace("t", CborValue("Nope"));
    EXPECT_EQ(parsePrompterRequest(CborValue(std::move(m)).encode()).error(), PrompterParseError::UnknownMessage);
    // Bad kind enum.
    CborValue::Map bad;
    bad.emplace("t", CborValue("RequestSecret"));
    bad.emplace("kind", CborValue("fingerprint"));
    EXPECT_EQ(parsePrompterRequest(CborValue(std::move(bad)).encode()).error(), PrompterParseError::BadEnum);
    // Ok reply without a secret.
    CborValue::Map noSecret;
    noSecret.emplace("t", CborValue("Secret"));
    noSecret.emplace("status", CborValue("ok"));
    EXPECT_EQ(parsePromptReply(CborValue(std::move(noSecret)).encode()).error(), PrompterParseError::MissingField);
}

} // namespace
