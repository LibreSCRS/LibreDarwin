// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Every request round-trips through the typed model and the canonical CBOR wire
// (parseRequest(encode(toCbor(env))) == env). Reply/event builders produce the
// reconciled shapes. Malformed / unknown requests fail closed.
//
// This binary doubles as the cross-implementation fixture generator for the
// LibreMac Swift client's decode tests: run with `--dump-fixtures <dir>` to
// write the canonical FRAME BODY bytes (CBOR only, no 8-byte frame header) of
// one instance of every reply/event shape to `<dir>/<ShapeName>.cbor`, instead
// of running the gtest suite. See dumpFixtures() below.
#include <LibreSCRS/Darwin/backend/wire/Messages.h>

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string_view>

using namespace LibreSCRS::Darwin::wire;

using LibreSCRS::Agent::CredentialOpResult;
using LibreSCRS::Agent::CredentialOutcome;
using LibreSCRS::Agent::CredentialRecord;

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

// A credential record with EVERY optional present (exercises all 22 wire keys).
CredentialRecord makeFullCredentialRecord()
{
    CredentialRecord rec;
    rec.id = "sign:0x92";
    rec.label = "Signing PIN";
    rec.kind = "sign";
    rec.state = "operational";
    rec.retriesLeft = 3;
    rec.retriesMax = 3;
    rec.usesLeft = 5;
    rec.unblocksLeft = 10;
    rec.minLength = 4;
    rec.maxLength = 8;
    rec.canChange = true;
    rec.unblockable = true;
    rec.unblockStyle = "unblockAndChange";
    rec.activatable = true;
    rec.keyActivationPending = true;
    rec.keyActivatable = true;
    rec.recovery = "holderViaPuk";
    rec.probeSafe = true;
    rec.blockedGuidanceKey = "guidance.blocked.key";
    rec.blockedGuidanceFallback = "Blocked; contact issuer";
    rec.keyActivationGuidanceKey = "guidance.activate.key";
    rec.keyActivationGuidanceFallback = "Activate your signing key";
    return rec;
}

// A credential record with EVERY optional absent (only the 12 required keys).
CredentialRecord makeBareCredentialRecord()
{
    CredentialRecord rec;
    rec.id = "unknown:0x00";
    rec.label = "";
    rec.kind = "unknown";
    rec.state = "unknown";
    rec.unblockStyle = "unknown";
    rec.recovery = "unknown";
    // all optionals nullopt (default); all bools false (default)
    return rec;
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

TEST(MessagesRoundTrip, CredentialManagementRequestsRoundTrip)
{
    expectStable({30, ListCredentials{"reader/0:card/0"}});
    // ManagePin with activateKey ABSENT (verb "change").
    expectStable({31, ManagePin{"reader/0:card/0", "sign:0x92", "change", std::nullopt}});
    // ManagePin with activateKey PRESENT=true (verb "activate_pin").
    expectStable({32, ManagePin{"reader/0:card/0", "user:0x01", "activate_pin", std::optional<bool>{true}}});
    // ManagePin with activateKey PRESENT=false (round-trip keeps the explicit false).
    expectStable({33, ManagePin{"reader/0:card/0", "user:0x01", "unblock", std::optional<bool>{false}}});
    expectStable({34, ActivateSigningKey{"reader/0:card/0"}});
}

// Tolerant decode: an unknown EXTRA map key inside a known request is ignored
// (mirrors the wire-wide tolerant decode; the parsed body drops the extra key).
TEST(MessagesRoundTrip, IgnoresUnknownRequestMapKeys)
{
    CborValue::Map m;
    m.emplace("t", CborValue("ManagePin"));
    m.emplace("req", CborValue::uint(7));
    m.emplace("card", CborValue(std::string("reader/0:card/0")));
    m.emplace("pinId", CborValue(std::string("sign:0x92")));
    m.emplace("verb", CborValue(std::string("change")));
    m.emplace("futureField", CborValue(std::string("ignored"))); // unknown extra key
    const auto r = parseRequest(CborValue(std::move(m)).encode());
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->req, 7u);
    ASSERT_TRUE(std::holds_alternative<ManagePin>(r->body));
    EXPECT_EQ(std::get<ManagePin>(r->body), (ManagePin{"reader/0:card/0", "sign:0x92", "change", std::nullopt}));
}

// The two credential-management named errors carry their exact wire names.
TEST(MessagesRoundTrip, SyncErrorNamesForCredentialErrors)
{
    EXPECT_EQ(syncErrorName(SyncError::UnknownCredential), "UnknownCredential");
    EXPECT_EQ(syncErrorName(SyncError::InvalidRequest), "InvalidRequest");

    const auto reply = makeErrorReply(7, ErrInfo{SyncError::UnknownCredential, std::nullopt, std::nullopt});
    const auto* err = reply.find("err");
    ASSERT_NE(err, nullptr);
    ASSERT_NE(err->find("name"), nullptr);
    EXPECT_EQ(*err->find("name")->asText(), "UnknownCredential");
    EXPECT_EQ(err->find("code"), nullptr); // named error, never numeric
}

// An Ok listing result: two records, one with every optional present (22 keys)
// and one with every optional absent (only the 12 required keys). The agent only
// ENCODES results, so this inspects the built frame (no decode side).
TEST(MessagesRoundTrip, CredentialsResultOkListingEncodesEveryRecordKey)
{
    CredentialsResult listing;
    listing.result.outcome = CredentialOutcome::Ok;
    listing.result.blocked = false;
    listing.records = {makeFullCredentialRecord(), makeBareCredentialRecord()};

    const CborValue c = toCbor(OpResultReady{40, listing});
    EXPECT_EQ(*c.find("t")->asText(), "OpResultReady");
    const auto* result = c.find("result");
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(*result->find("kind")->asText(), "Credentials");

    // cred-result: outcome "ok", blocked written, optional numerics omitted.
    const auto* cr = result->find("result");
    ASSERT_NE(cr, nullptr);
    EXPECT_EQ(*cr->find("outcome")->asText(), "ok");
    ASSERT_NE(cr->find("blocked"), nullptr);
    EXPECT_EQ(cr->find("blocked")->asBool(), false);
    EXPECT_EQ(cr->find("retriesLeft"), nullptr);
    EXPECT_EQ(cr->find("pinActivated"), nullptr);
    EXPECT_EQ(cr->find("keyActivated"), nullptr);

    const auto* records = result->find("records");
    ASSERT_NE(records, nullptr);
    ASSERT_NE(records->asArray(), nullptr);
    ASSERT_EQ(records->asArray()->size(), 2u);

    // Record 0: all 22 keys present.
    const auto& full = (*records->asArray())[0];
    ASSERT_NE(full.asMap(), nullptr);
    EXPECT_EQ(full.asMap()->size(), 22u);
    EXPECT_EQ(*full.find("id")->asText(), "sign:0x92");
    EXPECT_EQ(*full.find("kind")->asText(), "sign");
    EXPECT_EQ(*full.find("state")->asText(), "operational");
    EXPECT_EQ(full.find("retriesLeft")->asUInt(), 3u);
    EXPECT_EQ(full.find("minLength")->asUInt(), 4u);
    EXPECT_EQ(full.find("maxLength")->asUInt(), 8u);
    EXPECT_EQ(full.find("canChange")->asBool(), true);
    EXPECT_EQ(full.find("probeSafe")->asBool(), true);
    EXPECT_EQ(*full.find("unblockStyle")->asText(), "unblockAndChange");
    EXPECT_EQ(*full.find("recovery")->asText(), "holderViaPuk");
    EXPECT_EQ(*full.find("blockedGuidanceKey")->asText(), "guidance.blocked.key");
    EXPECT_EQ(*full.find("keyActivationGuidanceFallback")->asText(), "Activate your signing key");

    // Record 1: only the 12 required keys; every optional omitted.
    const auto& bare = (*records->asArray())[1];
    ASSERT_NE(bare.asMap(), nullptr);
    EXPECT_EQ(bare.asMap()->size(), 12u);
    for (const char* omitted :
         {"retriesLeft", "retriesMax", "usesLeft", "unblocksLeft", "minLength", "maxLength", "blockedGuidanceKey",
          "blockedGuidanceFallback", "keyActivationGuidanceKey", "keyActivationGuidanceFallback"}) {
        EXPECT_EQ(bare.find(omitted), nullptr) << "expected optional key '" << omitted << "' to be omitted";
    }
    // Required keys present even when default-valued.
    EXPECT_EQ(*bare.find("kind")->asText(), "unknown");
    EXPECT_EQ(bare.find("canChange")->asBool(), false);
}

// A failed mutation: outcome invalidPin, retriesLeft=2, blocked=false, records=[].
TEST(MessagesRoundTrip, CredentialsResultFailedMutationEncoding)
{
    CredentialsResult failed;
    failed.result.outcome = CredentialOutcome::InvalidPin;
    failed.result.retriesLeft = 2;
    failed.result.blocked = false;

    const CborValue c = toCbor(OpResultReady{41, failed});
    const auto* result = c.find("result");
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(*result->find("kind")->asText(), "Credentials");
    const auto* cr = result->find("result");
    ASSERT_NE(cr, nullptr);
    EXPECT_EQ(*cr->find("outcome")->asText(), "invalidPin");
    EXPECT_EQ(cr->find("retriesLeft")->asUInt(), 2u);
    EXPECT_EQ(cr->find("blocked")->asBool(), false);
    // A mutation carries an always-present (empty) records array.
    const auto* records = result->find("records");
    ASSERT_NE(records, nullptr);
    ASSERT_NE(records->asArray(), nullptr);
    EXPECT_TRUE(records->asArray()->empty());
}

// Partial signing-key bring-up: keyActivationFailed with pinActivated=true,
// keyActivated=false (both booleans present because they are engaged).
TEST(MessagesRoundTrip, CredentialsResultKeyActivationFailedEncoding)
{
    CredentialsResult keyFail;
    keyFail.result.outcome = CredentialOutcome::KeyActivationFailed;
    keyFail.result.blocked = false;
    keyFail.result.pinActivated = true;
    keyFail.result.keyActivated = false;

    const CborValue c = toCbor(OpResultReady{42, keyFail});
    const auto* cr = c.find("result")->find("result");
    ASSERT_NE(cr, nullptr);
    EXPECT_EQ(*cr->find("outcome")->asText(), "keyActivationFailed");
    ASSERT_NE(cr->find("pinActivated"), nullptr);
    EXPECT_EQ(cr->find("pinActivated")->asBool(), true);
    ASSERT_NE(cr->find("keyActivated"), nullptr);
    EXPECT_EQ(cr->find("keyActivated")->asBool(), false);
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

// --- --dump-fixtures: cross-implementation fixture generator ----------------
// One representative instance of every reply/event shape, written as raw
// canonical CBOR frame bodies (no frame header) for the LibreMac Swift
// client's MessagesRoundTripTests to decode and typecheck against. Covers the
// op-path shapes (OpProgress/OpResultReady/OpFinished) the card-free smoke
// tests cannot reach.

CertInfo makeSampleCertInfo()
{
    CertInfo ci;
    ci.certId = "deadbeef";
    ci.signingCapable = true;
    ci.fields["Subject"]["CN"] = CertField{"cn.subject.key", "Common Name", "John Doe"};
    ci.keyUsageBits = 1;
    ci.ekus = {"clientAuth"};
    ci.chainSubjectCns = {"Root CA"};
    ci.trustStatus = 0;
    return ci;
}

void writeFixture(const std::filesystem::path& dir, std::string_view name, const CborValue& v)
{
    const auto bytes = v.encode();
    std::ofstream out(dir / (std::string(name) + ".cbor"), std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

int dumpFixtures(const std::filesystem::path& dir)
{
    std::filesystem::create_directories(dir);

    // ---- replies ----
    writeFixture(dir, "HelloAck", makeReply(1, HelloAck{"0.1.0", {"pki", "sign"}}));
    writeFixture(dir, "OpStarted", makeReply(2, OpStarted{42}));
    {
        StateReply state;
        state.readers.push_back(ReaderState{"r1", "Reader One", true, std::string("c1")});
        state.cards.push_back(CardState{"c1", "r1", 0x3, PreReadAuthMethod::PaceCan});
        writeFixture(dir, "State", makeReply(3, state));
    }
    {
        CertListReply certList;
        certList.certs.push_back(makeSampleCertInfo());
        writeFixture(dir, "CertList", makeReply(4, certList));
    }
    writeFixture(dir, "CertDer", makeReply(5, CertDerReply{{0xDE, 0xAD, 0xBE, 0xEF}}));
    {
        ConfigReply config;
        config.entries.emplace("DefaultLevel", CborValue(std::string("b-t")));
        writeFixture(dir, "Config", makeReply(6, config));
    }
    writeFixture(dir, "Ack", makeReply(7, AckReply{}));
    writeFixture(dir, "SignRecovery", makeSignRecoveryReply(8, SignResult{5, SignMeta{"pades", "b-lta", true, true}}));
    writeFixture(
        dir, "ErrCode",
        makeErrorReply(9, ErrInfo{ErrorCode::CardRemoved, std::string("cardRemoved"), std::string("Card removed")}));
    writeFixture(dir, "ErrName", makeErrorReply(10, ErrInfo{SyncError::UnknownCard, std::nullopt, std::nullopt}));
    writeFixture(dir, "ErrNameUnknownCredential",
                 makeErrorReply(11, ErrInfo{SyncError::UnknownCredential, std::nullopt, std::nullopt}));

    // ---- requests (client -> agent; the Swift client mirrors encode(req: 1)) ----
    writeFixture(dir, "ListCredentials", toCbor(RequestEnvelope{1, ListCredentials{"reader/0:card/0"}}));
    writeFixture(dir, "ManagePin",
                 toCbor(RequestEnvelope{1, ManagePin{"reader/0:card/0", "sign:0x92", "change", std::nullopt}}));
    writeFixture(dir, "ActivateSigningKey", toCbor(RequestEnvelope{1, ActivateSigningKey{"reader/0:card/0"}}));

    // ---- events ----
    writeFixture(dir, "ReaderAdded", toCbor(ReaderAdded{ReaderState{"r1", "Reader One", false, std::nullopt}}));
    writeFixture(dir, "ReaderRemoved", toCbor(ReaderRemoved{"r1"}));
    writeFixture(dir, "CardAdded", toCbor(CardAdded{CardState{"c1", "r1", 0x3, PreReadAuthMethod::PaceCan}}));
    writeFixture(dir, "CardRemoved", toCbor(CardRemoved{"c1"}));
    {
        std::map<std::string, CborValue> props;
        props.emplace("hasCard", CborValue(true));
        writeFixture(dir, "PropertyChanged", toCbor(PropertyChanged{"r1", "org.librescrs.Reader1", props}));
    }
    writeFixture(dir, "ConfigChanged", toCbor(ConfigChanged{"DefaultLevel"}));
    // Fractional progress: 0.5 lands as f16 on the wire via QCBOR preferred serialization.
    writeFixture(dir, "OpProgress", toCbor(OpProgress{9, OperationPhase::Signing, 0.5, std::nullopt, std::nullopt}));
    {
        IdentityResult idResult;
        idResult.fields["MRZ"]["Name"] = IdentityField{"name.key", "Name", "text", std::string("JOHN DOE")};
        writeFixture(dir, "OpResultReadyIdentity", toCbor(OpResultReady{20, idResult}));
    }
    {
        PhotoResult photoResult;
        photoResult.photos.push_back(PhotoItem{"MRZ:Photo", 0});
        writeFixture(dir, "OpResultReadyPhoto", toCbor(OpResultReady{21, photoResult}));
    }
    {
        CertListResult certListResult;
        certListResult.certs.push_back(makeSampleCertInfo());
        writeFixture(dir, "OpResultReadyCertificates", toCbor(OpResultReady{22, certListResult}));
    }
    // fd index (never inline bytes) for the signed artifact.
    writeFixture(dir, "OpResultReadySign",
                 toCbor(OpResultReady{23, SignResult{5, SignMeta{"pades", "b-lta", true, true}}}));
    {
        // Ok listing: one fully-populated record (exercises all 22 cred-record keys).
        CredentialsResult listing;
        listing.result.outcome = CredentialOutcome::Ok;
        listing.result.blocked = false;
        listing.records.push_back(makeFullCredentialRecord());
        writeFixture(dir, "OpResultReadyCredentialsList", toCbor(OpResultReady{25, listing}));
    }
    {
        // Failed mutation: invalidPin, retriesLeft=2, blocked=false, records=[].
        CredentialsResult failed;
        failed.result.outcome = CredentialOutcome::InvalidPin;
        failed.result.retriesLeft = 2;
        failed.result.blocked = false;
        writeFixture(dir, "OpResultReadyCredentialsFailed", toCbor(OpResultReady{26, failed}));
    }
    writeFixture(dir, "OpFinished",
                 toCbor(OpFinished{24, OperationStatus::Error, ErrorCode::CardRemoved, "op.failed", "Card removed"}));
    writeFixture(dir, "AgentQuiesced", toCbor(AgentQuiesced{QuiesceReason::ScreenLocked}));

    std::fprintf(stderr, "wrote fixtures to %s\n", dir.c_str());
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--dump-fixtures" && i + 1 < argc) {
            return dumpFixtures(std::filesystem::path(argv[i + 1]));
        }
    }
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
