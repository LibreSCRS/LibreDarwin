// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The agent<->prompter CBOR protocol round-trips both directions; malformed /
// unknown inputs fail closed. Secret hygiene: the 8 KiB inbound cap and the
// scrub-after-send path are exercised over a real socketpair.
#include <LibreSCRS/Darwin/backend/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <vector>

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

TEST(PrompterProtocol, RejectsOversizedSecretFailClosed)
{
    PromptReply oversized;
    oversized.status = PromptReplyStatus::Ok;
    oversized.secret.assign(kMaxSecretBytes + 1, 0x41);
    EXPECT_EQ(parsePromptReply(toCbor(oversized).encode()).error(), PrompterParseError::SecretTooLarge);

    // The bound itself is accepted (mirrors the Linux kMaxSecretBytes cap).
    PromptReply atCap;
    atCap.status = PromptReplyStatus::Ok;
    atCap.secret.assign(kMaxSecretBytes, 0x41);
    auto parsed = parsePromptReply(toCbor(atCap).encode());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->secret.size(), kMaxSecretBytes);
}

TEST(PrompterProtocol, ScrubZeroesEveryNestedPayload)
{
    CborValue::Map inner;
    inner.emplace("secret", CborValue(CborValue::Bytes{'1', '2', '3', '4'}));
    CborValue::Map top;
    top.emplace("t", CborValue("Secret"));
    top.emplace("nested", CborValue(std::move(inner)));
    top.emplace("list", CborValue(CborValue::Array{CborValue("pin-text")}));
    CborValue v(std::move(top));

    v.scrub();

    const auto* nested = v.find("nested");
    ASSERT_NE(nested, nullptr);
    const auto* bytes = nested->find("secret")->asBytes();
    ASSERT_NE(bytes, nullptr);
    EXPECT_TRUE(std::all_of(bytes->begin(), bytes->end(), [](std::uint8_t b) { return b == 0; }));
    const auto* text = v.find("t")->asText();
    ASSERT_NE(text, nullptr);
    EXPECT_TRUE(std::all_of(text->begin(), text->end(), [](char c) { return c == '\0'; }));
    const auto* arr = v.find("list")->asArray();
    ASSERT_NE(arr, nullptr);
    const auto* item = (*arr)[0].asText();
    ASSERT_NE(item, nullptr);
    EXPECT_TRUE(std::all_of(item->begin(), item->end(), [](char c) { return c == '\0'; }));
}

TEST(PrompterProtocol, SendReplyScrubsAfterDelivery)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    PromptReply reply;
    reply.status = PromptReplyStatus::Ok;
    reply.secret = {'7', '7', '7', '7'};
    reply.userMessage = "";
    sendPromptReplyScrubbed(sv[0], reply);

    // Sender-side copies are zeroed the moment the frame went out...
    EXPECT_TRUE(std::all_of(reply.secret.begin(), reply.secret.end(), [](std::uint8_t b) { return b == 0; }));

    // ...while the peer received the intact secret.
    auto frame = recvFrame(sv[1]);
    ASSERT_TRUE(frame.has_value());
    auto parsed = parsePromptReply(frame->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, PromptReplyStatus::Ok);
    EXPECT_EQ(parsed->secret, (std::vector<std::uint8_t>{'7', '7', '7', '7'}));

    ::close(sv[0]);
    ::close(sv[1]);
}

} // namespace
