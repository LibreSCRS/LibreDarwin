// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The agent<->prompter CBOR protocol round-trips both directions; malformed /
// unknown inputs fail closed. Secret hygiene: the 8 KiB inbound cap and the
// scrub-after-send path are exercised over a real socketpair — for the single
// secret and for the two-secret change flow (RequestSecrets / MultiPromptReply).
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <vector>

using namespace LibreSCRS::Darwin::wire;
// The codec/framing primitives (decode/sendFrame/recvFrame/CborValue/etc.) now
// live in the shared LibreAgent::Wire library; PromptKind/PromptRequest/etc.
// above stay Darwin-local.
using namespace LibreSCRS::Agent::Wire;

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

// --- multi-secret change prompt (RequestSecrets / MultiPromptReply) ----------

TEST(PrompterProtocol, RequestSecretsRoundTripsAllFields)
{
    // The four per-role bounds are pairwise distinct so a key mix-up between
    // primary*/new* (or min/max) cannot round-trip cleanly.
    const RequestSecrets sent{"change_pin", "Change PIN", "Desc", "LibreMac", "ID card", 4, 8, 6, 12};
    auto parsed = parsePrompterRequest(toCbor(sent).encode());
    ASSERT_TRUE(parsed.has_value());
    ASSERT_TRUE(std::holds_alternative<RequestSecrets>(*parsed));
    EXPECT_EQ(std::get<RequestSecrets>(*parsed), sent);
}

TEST(PrompterProtocol, RequestSecretsOmitsZeroBoundsLikePromptRequest)
{
    const RequestSecrets bare{"change_pin", {}, {}, {}, {}, 0, 0, 0, 0};
    const auto bytes = toCbor(bare).encode();
    const auto tree = decode(bytes);
    ASSERT_TRUE(tree.has_value());
    for (const auto* key : {"primaryMinLength", "primaryMaxLength", "newMinLength", "newMaxLength"}) {
        EXPECT_EQ(tree->find(key), nullptr) << key << " must be omitted when zero";
    }
    auto parsed = parsePrompterRequest(bytes);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(std::get<RequestSecrets>(*parsed), bare);
}

TEST(PrompterProtocol, RequestSecretsWithoutKindFailsClosed)
{
    CborValue::Map m;
    m.emplace("t", CborValue("RequestSecrets"));
    EXPECT_EQ(parsePrompterRequest(CborValue(std::move(m)).encode()).error(), PrompterParseError::MissingField);
}

TEST(PrompterProtocol, MultiReplyRoundTrips)
{
    for (const auto st : {PromptReplyStatus::Cancelled, PromptReplyStatus::Error, PromptReplyStatus::Unauthorized}) {
        MultiPromptReply r;
        r.status = st;
        r.userMessage = "msg";
        auto parsed = parseMultiPromptReply(toCbor(r).encode());
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(parsed->status, st);
        EXPECT_EQ(parsed->userMessage, "msg");
        EXPECT_TRUE(parsed->primary.empty());
        EXPECT_TRUE(parsed->secondary.empty());
    }
    MultiPromptReply ok;
    ok.status = PromptReplyStatus::Ok;
    ok.primary = {'1', '2', '3', '4'};
    ok.secondary = {'5', '6', '7', '8'};
    auto parsed = parseMultiPromptReply(toCbor(ok).encode());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, PromptReplyStatus::Ok);
    // Distinct payloads: a primary/secondary swap cannot pass.
    EXPECT_EQ(parsed->primary, (std::vector<std::uint8_t>{'1', '2', '3', '4'}));
    EXPECT_EQ(parsed->secondary, (std::vector<std::uint8_t>{'5', '6', '7', '8'}));
}

TEST(PrompterProtocol, MultiReplyOkRequiresBothSecrets)
{
    // Ok with only one of the two secrets fails closed (MissingField); the
    // HoldScrub guard zeroes the decoded tree on these early exits.
    for (const auto* present : {"primary", "secondary"}) {
        CborValue::Map m;
        m.emplace("t", CborValue("Secrets"));
        m.emplace("status", CborValue("ok"));
        m.emplace(present, CborValue(CborValue::Bytes{'1'}));
        EXPECT_EQ(parseMultiPromptReply(CborValue(std::move(m)).encode()).error(), PrompterParseError::MissingField);
    }
}

TEST(PrompterProtocol, MultiReplyRejectsEitherOversizedSecretFailClosed)
{
    // Oversized primary.
    MultiPromptReply a;
    a.status = PromptReplyStatus::Ok;
    a.primary.assign(kMaxSecretBytes + 1, 0x41);
    a.secondary = {'1'};
    EXPECT_EQ(parseMultiPromptReply(toCbor(a).encode()).error(), PrompterParseError::SecretTooLarge);
    // Oversized secondary — the already-extracted primary copy is scrubbed on
    // this exit too (HoldScrub tree zeroing + explicit sibling-copy zeroing).
    MultiPromptReply b;
    b.status = PromptReplyStatus::Ok;
    b.primary = {'1'};
    b.secondary.assign(kMaxSecretBytes + 1, 0x42);
    EXPECT_EQ(parseMultiPromptReply(toCbor(b).encode()).error(), PrompterParseError::SecretTooLarge);
    // Both at the bound are accepted (a per-secret cap, not a combined one).
    MultiPromptReply atCap;
    atCap.status = PromptReplyStatus::Ok;
    atCap.primary.assign(kMaxSecretBytes, 0x41);
    atCap.secondary.assign(kMaxSecretBytes, 0x42);
    auto parsed = parseMultiPromptReply(toCbor(atCap).encode());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->primary.size(), kMaxSecretBytes);
    EXPECT_EQ(parsed->secondary.size(), kMaxSecretBytes);
}

TEST(PrompterProtocol, MultiReplyTreeScrubZeroesBothSecrets)
{
    // The exact tree shape toCbor(MultiPromptReply) builds is fully covered by
    // the recursive CborValue::scrub — the same mechanism the parse-failure
    // HoldScrub guard and the send path run.
    MultiPromptReply ok;
    ok.status = PromptReplyStatus::Ok;
    ok.primary = {'1', '2', '3', '4'};
    ok.secondary = {'5', '6', '7', '8'};
    CborValue msg = toCbor(ok);
    msg.scrub();
    for (const auto* key : {"primary", "secondary"}) {
        const auto* field = msg.find(key);
        ASSERT_NE(field, nullptr) << key;
        const auto* bytes = field->asBytes();
        ASSERT_NE(bytes, nullptr) << key;
        // Size preserved: scrub zeroes IN PLACE, it does not clear. A
        // hypothetical scrub-by-clear would pass the all_of below vacuously
        // (mirror of the send-path test's size guards).
        ASSERT_EQ(bytes->size(), 4u) << key;
        EXPECT_TRUE(std::all_of(bytes->begin(), bytes->end(), [](std::uint8_t b) { return b == 0; })) << key;
    }
}

TEST(PrompterProtocol, SendMultiReplyScrubsBothSecretsAfterDelivery)
{
    int sv[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    MultiPromptReply reply;
    reply.status = PromptReplyStatus::Ok;
    reply.primary = {'1', '2', '3', '4'};
    reply.secondary = {'5', '6', '7', '8'};
    sendPromptReplyScrubbed(sv[0], reply);

    // Sender-side copies are zeroed in place the moment the frame went out
    // (size preserved — the non-empty asserts keep the all_of non-vacuous).
    ASSERT_EQ(reply.primary.size(), 4u);
    ASSERT_EQ(reply.secondary.size(), 4u);
    EXPECT_TRUE(std::all_of(reply.primary.begin(), reply.primary.end(), [](std::uint8_t b) { return b == 0; }));
    EXPECT_TRUE(std::all_of(reply.secondary.begin(), reply.secondary.end(), [](std::uint8_t b) { return b == 0; }));

    // ...while the peer received both secrets intact and unswapped.
    auto frame = recvFrame(sv[1]);
    ASSERT_TRUE(frame.has_value());
    auto parsed = parseMultiPromptReply(frame->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, PromptReplyStatus::Ok);
    EXPECT_EQ(parsed->primary, (std::vector<std::uint8_t>{'1', '2', '3', '4'}));
    EXPECT_EQ(parsed->secondary, (std::vector<std::uint8_t>{'5', '6', '7', '8'}));

    ::close(sv[0]);
    ::close(sv[1]);
}

} // namespace
