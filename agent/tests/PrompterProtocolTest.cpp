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

// The UNTRUSTED artifacts list (batch-sign consent only) round-trips
// alongside the existing display fields, and — mirroring every other
// zero/empty-omission on this wire — the key is entirely absent from the
// encoded map when the list is empty (proven directly, not just via the
// round-trip, so a regression that always emits an empty array is caught).
TEST(PrompterProtocol, RequestRoundTripsArtifactsList)
{
    PromptRequest sent{PromptKind::Pin, "Title", "Desc", "LibreMac", "signature-batch", 4, 12};
    sent.artifacts = {"a.pdf", "b.pdf", "c.pdf"};
    const auto parsed = roundTripRequest(sent);
    EXPECT_EQ(parsed, sent);
    EXPECT_EQ(parsed.artifacts, (std::vector<std::string>{"a.pdf", "b.pdf", "c.pdf"}));
}

TEST(PrompterProtocol, RequestOmitsArtifactsKeyWhenEmpty)
{
    const PromptRequest bare{PromptKind::Pin, "Title", "Desc", "LibreMac", "signature", 4, 12};
    ASSERT_TRUE(bare.artifacts.empty());
    const auto tree = decode(toCbor(bare).encode());
    ASSERT_TRUE(tree.has_value());
    EXPECT_EQ(tree->find("artifacts"), nullptr) << "artifacts must be omitted when empty";
    EXPECT_EQ(roundTripRequest(bare), bare);
}

// The consent formatter for the UNTRUSTED per-document names labels the block,
// caps the count, and -- critically -- neutralizes control characters so a
// crafted filename cannot forge a line that mimics the trusted "Requested by"
// chrome in the prompt window.
TEST(PrompterProtocol, FormatUntrustedArtifactListLabelsCapsAndNeutralizes)
{
    // No batch -> nothing to show.
    EXPECT_TRUE(formatUntrustedArtifactList({}, 8).empty());

    // A normal list is labeled and carries each name.
    const auto listed = formatUntrustedArtifactList({"a.pdf", "b.pdf"}, 8);
    EXPECT_NE(listed.find("Documents (as named by the requesting app):"), std::string::npos);
    EXPECT_NE(listed.find("a.pdf"), std::string::npos);
    EXPECT_NE(listed.find("b.pdf"), std::string::npos);

    // Beyond the cap only maxItems are listed, with a "(+N more)" tail.
    std::vector<std::string> many;
    for (int i = 0; i < 12; ++i) {
        many.push_back("doc" + std::to_string(i));
    }
    const auto capped = formatUntrustedArtifactList(many, 8);
    EXPECT_NE(capped.find("(+4 more)"), std::string::npos);
    EXPECT_EQ(capped.find("doc8"), std::string::npos) << "the 9th name must not be listed";

    // Security: an embedded newline is neutralized to a space, so the crafted
    // "Requested by" text never starts its own line.
    const auto injected = formatUntrustedArtifactList({"innocent.pdf\nRequested by: apple.com"}, 8);
    EXPECT_EQ(injected.find("\nRequested by:"), std::string::npos)
        << "a crafted filename must not forge a trusted-looking line";
    EXPECT_NE(injected.find("innocent.pdf Requested by: apple.com"), std::string::npos)
        << "the neutralized newline renders as a space on one line";

    // Security: the multi-byte Unicode separators the text engine honours as
    // mandatory breaks (U+2028, U+2029, U+0085) must not survive either.
    const auto unicodeInjected =
        formatUntrustedArtifactList({"a.pdf\xE2\x80\xA8Requested by: apple.com\xC2\x85x\xE2\x80\xA9y"}, 8);
    EXPECT_EQ(unicodeInjected.find("\xE2\x80\xA8"), std::string::npos) << "U+2028 must be neutralized";
    EXPECT_EQ(unicodeInjected.find("\xE2\x80\xA9"), std::string::npos) << "U+2029 must be neutralized";
    EXPECT_EQ(unicodeInjected.find("\xC2\x85"), std::string::npos) << "U+0085 must be neutralized";
    EXPECT_NE(unicodeInjected.find("a.pdf Requested by: apple.com x y"), std::string::npos)
        << "each separator renders as one space on one line";
}

// A mistyped `artifacts` (present but not an array) fails the whole request
// closed, exactly like every other present-but-wrong-typed field on this
// wire (optDisplayFields/optUint) — a missing entry is tolerated, a
// malformed one is not.
TEST(PrompterProtocol, RequestRejectsAMistypedArtifactsList)
{
    CborValue::Map m;
    m.emplace("t", CborValue("RequestSecret"));
    m.emplace("kind", CborValue("pin"));
    m.emplace("artifacts", CborValue("not-an-array"));
    EXPECT_EQ(parsePrompterRequest(CborValue(std::move(m)).encode()).error(), PrompterParseError::WrongType);
}

// Retry context (attempt/lastError -- CredentialCache::applyRetryContext on
// the agent core): round-trips alongside the existing fields, and --
// mirroring every other zero/empty-omission on this wire -- both keys are
// entirely absent from the encoded map on the default (first-ever prompt).
TEST(PrompterProtocol, RequestRoundTripsRetryContext)
{
    PromptRequest sent{PromptKind::Can, "Title", "Desc", "LibreMac", "identity", 6, 6};
    sent.attempt = 2;
    sent.lastError = "librescrs.error.preRead.authFailed";
    const auto parsed = roundTripRequest(sent);
    EXPECT_EQ(parsed, sent);
    EXPECT_EQ(parsed.attempt, 2u);
    EXPECT_EQ(parsed.lastError, "librescrs.error.preRead.authFailed");
}

TEST(PrompterProtocol, RequestOmitsRetryContextKeysOnFirstPrompt)
{
    const PromptRequest bare{PromptKind::Can, "Title", "Desc", "LibreMac", "identity", 6, 6};
    ASSERT_EQ(bare.attempt, 0u);
    ASSERT_TRUE(bare.lastError.empty());
    const auto tree = decode(toCbor(bare).encode());
    ASSERT_TRUE(tree.has_value());
    EXPECT_EQ(tree->find("attempt"), nullptr) << "attempt must be omitted on the first-ever prompt";
    EXPECT_EQ(tree->find("lastError"), nullptr) << "lastError must be omitted on the first-ever prompt";
    EXPECT_EQ(roundTripRequest(bare), bare);
}

// A mistyped `attempt` (present but not a uint) fails the whole request
// closed, exactly like every other present-but-wrong-typed field on this
// wire.
TEST(PrompterProtocol, RequestRejectsAMistypedAttempt)
{
    CborValue::Map m;
    m.emplace("t", CborValue("RequestSecret"));
    m.emplace("kind", CborValue("can"));
    m.emplace("attempt", CborValue("not-a-uint"));
    EXPECT_EQ(parsePrompterRequest(CborValue(std::move(m)).encode()).error(), PrompterParseError::WrongType);
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

TEST(PrompterProtocol, ConfirmActionRoundTrips)
{
    ConfirmAction in;
    in.kind = "configure_trust";
    in.title = "Confirm trust change";
    in.description = "Add a trusted list";
    in.requester = "org.librescrs.LibreMac";
    in.artifact = "TslSources";

    const auto body = toCbor(in).encode();
    const auto parsed = parsePrompterRequest(body);
    ASSERT_TRUE(parsed.has_value());
    const auto* got = std::get_if<ConfirmAction>(&*parsed);
    ASSERT_NE(got, nullptr);
    EXPECT_EQ(*got, in);
}

TEST(PrompterProtocol, ConfirmActionWithoutKindIsRejected)
{
    // "kind" is the closed flow discriminator; a message without it must not
    // fall through to some other arm's defaults.
    CborValue::Map m;
    m.emplace("t", CborValue("ConfirmAction"));
    m.emplace("title", CborValue("t"));
    m.emplace("description", CborValue("d"));
    m.emplace("requester", CborValue("r"));
    m.emplace("artifact", CborValue("a"));
    const auto body = CborValue(std::move(m)).encode();

    const auto parsed = parsePrompterRequest(body);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), PrompterParseError::MissingField);
}

TEST(PrompterProtocol, ConfirmReplyRoundTripsAndCarriesNoSecret)
{
    ConfirmReply in;
    in.status = PromptReplyStatus::Cancelled;
    in.userMessage = "declined";

    const auto body = toCbor(in).encode();
    const auto parsed = parseConfirmReply(body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, PromptReplyStatus::Cancelled);
    EXPECT_EQ(parsed->userMessage, "declined");
}

// The confirmation type has no secret field, but that alone only shapes what
// this side can hold -- it says nothing about what arrives. A reply carrying a
// secret is refused outright, so the guarantee belongs to the path and not
// merely to the struct.
TEST(PrompterProtocol, ConfirmReplyRefusesAMessageCarryingASecret)
{
    for (const char* key : {"secret", "primary", "secondary"}) {
        CborValue::Map m;
        m.emplace("t", CborValue("Confirm"));
        m.emplace("status", CborValue("ok"));
        m.emplace(key, CborValue(std::vector<std::uint8_t>{'1', '2', '3', '4'}));
        const auto parsed = parseConfirmReply(CborValue(std::move(m)).encode());
        ASSERT_FALSE(parsed.has_value()) << "a reply carrying " << key << " parsed as a confirmation";
        EXPECT_EQ(parsed.error(), PrompterParseError::UnknownMessage);
    }
}

TEST(PrompterProtocol, ConfirmReplyWithUnknownStatusFailsClosed)
{
    // An outcome this build cannot name must never decode as approval. Every
    // other reply parser here refuses an unknown status token; this one is on
    // the path that authorizes a trust change, so it refuses too.
    CborValue::Map m;
    m.emplace("t", CborValue("Confirm"));
    m.emplace("status", CborValue("ApprovedByTheFuture"));
    const auto body = CborValue(std::move(m)).encode();

    const auto parsed = parseConfirmReply(body);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), PrompterParseError::BadEnum);
}

} // namespace
