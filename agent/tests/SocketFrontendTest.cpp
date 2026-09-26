// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SocketFrontend inbound dispatch over a real bound socket + a blocking client,
// against a real LibreAgent::Core wired to hermetic fakes (no PC/SC): each
// request routes to the right core call, replies carry the correct `req`, and
// the method-entry gates map to the right sync-error. The credentials suite
// additionally drives a real op end-to-end (detached LM session + fake
// prompter) through the REAL twin + SocketOperationChannel. The remaining
// card-op worker path + broker path are exercised by the PIN-guarded hardware
// gate, not here.
#include <LibreSCRS/Darwin/backend/SocketFrontend.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Agent/wire/Cbor.h>
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Agent/wire/Messages.h>

#include "SocketRig.h"         // Rig, errName, makeInputFile, the hermetic fakes
#include "CardRemovalCaches.h" // invalidateCardRemovalCaches (the production removal-invalidation code)
#include "FullScrubCaches.h"   // clearFullScrubCaches (the production fullScrub cache-clearing code)

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/OperationPhase.h> // OperationStatus
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/BatchSignFlow.h>     // isValidBatchDocumentCount, kMin/kMaxBatchDocuments
#include <LibreSCRS/Agent/operations/CardSessionHolder.h> // SessionFactory
#include <LibreSCRS/Agent/operations/OperationManager.h>  // setSessionFactoryForTest
#include <LibreSCRS/Agent/operations/LmSeams.h>           // LmCredentialDepositor
#include <LibreSCRS/Agent/operations/RateLimiter.h>       // kMaxPerWindow
#include <LibreSCRS/Agent/operations/Seams.h>             // NullCredentialDepositor
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialSnapshot
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>    // ErrorCode
#include <LibreSCRS/Plugin/CardPluginService.h>     // the registry a depositor is bound over
#include <LibreSCRS/SmartCard/CardSession.h>        // detail::makeDetachedCardSession (LIBRESCRS_INTERNAL_BUILD)
#include <LibreSCRS/Secure/String.h>                // the BlockingPrompter's dummy Ok secrets

#include <gtest/gtest.h>

#include <dispatch/dispatch.h>
#include <fstream>
#include <sstream>
#include <unistd.h>

#include <chrono>
#include <array>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

using namespace LibreSCRS::Darwin;
using namespace LibreSCRS::Darwin::TestSupport;
namespace Agent = ::LibreSCRS::Agent;

namespace {

// Multi-secret prompter double: the change modal reports Cancelled immediately
// (the user dismissed it), so the change flow resolves userCancelled without
// touching any seam or card.
struct CancellingPrompter final : Agent::Operations::PrompterClientBase
{
    Agent::PromptResult requestPin(const Agent::PromptOptions&) override
    {
        return {};
    }
    Agent::PromptResult requestCan(const Agent::PromptOptions&) override
    {
        return {};
    }
    Agent::PromptResult requestMrz(const Agent::PromptOptions&) override
    {
        return {};
    }
    Agent::PinChangePromptResult requestPinChange(const Agent::PromptOptions&) override
    {
        return Agent::PinChangePromptResult{Agent::PromptStatus::Cancelled, std::nullopt, std::nullopt, ""};
    }
};

// Blocks the change modal until cancel(promptId) — the op's prompter-cancel hook — fires,
// then reports Cancelled: the mid-prompt CancelOp shape. If the deadline lapses
// with no cancel, it reports Ok with dummy secrets instead — a bounded FAILURE
// path (the op proceeds and misses the userCancelled asserts), so only a real
// cancel(promptId) can produce the Cancelled outcome the test pins.
class BlockingPrompter final : public Agent::Operations::PrompterClientBase
{
public:
    Agent::PromptResult requestPin(const Agent::PromptOptions&) override
    {
        return {};
    }
    Agent::PromptResult requestCan(const Agent::PromptOptions&) override
    {
        return {};
    }
    Agent::PromptResult requestMrz(const Agent::PromptOptions&) override
    {
        return {};
    }
    Agent::PinChangePromptResult requestPinChange(const Agent::PromptOptions&) override
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_entered = true;
        m_cv.notify_all();
        if (!m_cv.wait_for(lock, std::chrono::seconds(5), [this] { return m_cancelled; })) {
            // Deadline hit with no cancel(promptId): report Ok with dummy secrets, NOT
            // Cancelled — a cancel that never reaches the prompter must fail
            // the userCancelled asserts, not impersonate a genuine cancel.
            return Agent::PinChangePromptResult{Agent::PromptStatus::Ok, LibreSCRS::Secure::String{"0000"},
                                                LibreSCRS::Secure::String{"123456"}, ""};
        }
        return Agent::PinChangePromptResult{Agent::PromptStatus::Cancelled, std::nullopt, std::nullopt, ""};
    }
    void cancel(const std::string&) noexcept override
    {
        const std::lock_guard<std::mutex> lock(m_mutex);
        m_cancelled = true;
        m_cv.notify_all();
    }
    // Block the TEST thread until the worker is inside the modal (so a CancelOp
    // sent afterwards is genuinely mid-prompt). False on timeout.
    [[nodiscard]] bool waitEntered()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_cv.wait_for(lock, std::chrono::seconds(5), [this] { return m_entered; });
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_entered{false};
    bool m_cancelled{false};
};

// Hermetic session seam: the reader worker opens a detached LM session (no
// PC/SC), so a credential op reaches its prompt gate on a test box.
Agent::Operations::SessionFactory detachedSessionFactory()
{
    return [](const std::string& reader)
               -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(reader);
    };
}

// @p count fresh CAdES-sniffing (0x30 leading byte) regular-file fds, named
// "doc<N>.pdf" — the Card1.SignBatch analog of makeInputFile above, mirroring
// LibreLinux's CardObjectOperationsTest.cpp makeDocuments() helper. Returns
// the BatchDocument entries (fdIndex == position in the returned fd vector)
// alongside the raw fds so a test can close them after the round trip.
std::pair<std::vector<Agent::Wire::BatchDocument>, std::vector<int>> makeBatchDocuments(std::size_t count)
{
    std::vector<Agent::Wire::BatchDocument> docs;
    std::vector<int> fds;
    docs.reserve(count);
    fds.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const int fd = makeInputFile(std::string_view{"\x30\x82\x01\x00", 4});
        docs.push_back(Agent::Wire::BatchDocument{"doc" + std::to_string(i) + ".pdf", static_cast<std::uint64_t>(i)});
        fds.push_back(fd);
    }
    return {std::move(docs), std::move(fds)};
}

constexpr std::uint32_t kIdentityCap = 1U << 1; // CardCapabilities::IdentityData
constexpr std::uint32_t kPkiCap = 1U << 0;      // CardCapabilities::PKI
constexpr std::uint32_t kPinMgmtCap = 1U << 3;  // CardCapabilities::PinManagement

// injectCard publishes the card as ObjectId(8); the per-card cache key is the
// stringified ObjectId (SocketTransport::publishCard mints routing.cardKey).
constexpr const char* kInjectedCardKey = "8";

// The FIRST client connection on a fresh transport carries this caller token
// (conn ids are minted sequentially from 1) — the key the authorizer + rate
// limiter see, mirroring the Linux e2e's use of the client's unique bus name.
constexpr const char* kFirstConnCaller = "conn:1";

// A single-record snapshot seeded under the injected card's key (bypasses the
// list flow, exactly like the Linux e2e seeding): a changeable UserPIN
// addressed by "user:0x01", so a change request resolves to a canChange record.
Agent::CredentialSnapshot makeSnapshot()
{
    Agent::CredentialRecord r;
    r.id = "user:0x01";
    r.label = "UserPIN";
    r.kind = "user";
    r.state = "operational";
    r.retriesLeft = 3;
    r.minLength = 4;
    r.maxLength = 8;
    r.canChange = true;
    Agent::CredentialSnapshot s;
    s.records.push_back(std::move(r));
    s.version = 1;
    return s;
}

TEST(SocketFrontend, HelloReturnsAck)
{
    Rig rig;
    const auto reply = rig.roundTrip(1, Agent::Wire::Hello{1, std::nullopt});
    ASSERT_NE(reply.find("t"), nullptr);
    EXPECT_EQ(*reply.find("t")->asText(), "Reply");
    ASSERT_NE(reply.find("agentVer"), nullptr);
    EXPECT_EQ(*reply.find("agentVer")->asText(), "0.1-test");
    ASSERT_NE(reply.find("req"), nullptr);
    EXPECT_EQ(reply.find("req")->asUInt().value_or(0), 1u);
}

TEST(SocketFrontend, GetStateReturnsSnapshot)
{
    Rig rig;
    const auto reply = rig.roundTrip(2, Agent::Wire::GetState{});
    ASSERT_NE(reply.find("readers"), nullptr);
    ASSERT_NE(reply.find("cards"), nullptr);
}

// Card-state's cardType/atr are optional (absent-until-known) keys, and
// SocketTransport::updateCardType pushes the post-read authoritative value
// through a PropertyChanged that the NEXT GetState snapshot also reflects
// (currentState() reads the SAME m_cards map updateCardType mutates).
TEST(SocketFrontend, CardStateCarriesAtrAndCardTypeAndUpdateCardTypeFlipsTheSnapshot)
{
    Rig rig;
    SocketTransport* trp = rig.transport.get();
    dispatch_sync(trp->loopQueue(), ^{
      Agent::ReaderState r;
      r.id = Agent::ObjectId(7);
      r.name = "Test Reader";
      r.hasCard = true;
      r.card = Agent::ObjectId(8);
      trp->publishReader(r);
      Agent::CardState c;
      c.id = Agent::ObjectId(8);
      c.reader = Agent::ObjectId(7);
      c.capabilities = 0;
      c.atrHex = "3B7F9600";
      // cardType left empty here on purpose: "empty until known" -- the
      // deferred single-candidate resolve is exercised by
      // CardOperationsIntegrationTest's D-Bus twin, not this low-level inject.
      trp->publishCard(c);
    });

    __block std::string handle;
    dispatch_sync(trp->loopQueue(), ^{
      for (const auto& cs : trp->currentState().cards) {
          handle = cs.handle;
      }
    });
    ASSERT_FALSE(handle.empty());

    {
        const auto reply = rig.roundTrip(1, Agent::Wire::GetState{});
        const auto* cards = reply.find("cards");
        ASSERT_NE(cards, nullptr);
        const auto* cardsArr = cards->asArray();
        ASSERT_NE(cardsArr, nullptr);
        ASSERT_EQ(cardsArr->size(), 1u);
        const auto& card0 = (*cardsArr)[0];
        ASSERT_NE(card0.find("atr"), nullptr);
        EXPECT_EQ(*card0.find("atr")->asText(), "3B7F9600");
        EXPECT_EQ(card0.find("cardType"), nullptr) << "cardType must be ABSENT (not an empty string) until known";
    }

    dispatch_sync(trp->loopQueue(), ^{
      trp->updateCardType(handle, "SRB-eID");
    });

    {
        const auto reply = rig.roundTrip(2, Agent::Wire::GetState{});
        const auto* cards = reply.find("cards");
        ASSERT_NE(cards, nullptr);
        const auto* cardsArr = cards->asArray();
        ASSERT_NE(cardsArr, nullptr);
        ASSERT_EQ(cardsArr->size(), 1u);
        const auto& card0 = (*cardsArr)[0];
        ASSERT_NE(card0.find("cardType"), nullptr);
        EXPECT_EQ(*card0.find("cardType")->asText(), "SRB-eID")
            << "updateCardType must be reflected in the very next GetState snapshot";
    }
}

TEST(SocketFrontend, ReadIdentityUnknownCardIsUnknownCard)
{
    Rig rig;
    const auto reply = rig.roundTrip(3, Agent::Wire::ReadIdentity{"obj/999"});
    EXPECT_EQ(errName(reply), "UnknownCard");
}

TEST(SocketFrontend, SignOnNonPkiCardIsUnsupported)
{
    Rig rig;
    const std::string card = rig.injectCard(kIdentityCap); // no PKI bit
    const auto reply = rig.roundTrip(
        4, Agent::Wire::Sign{card, "cert-id", 0,
                             Agent::Wire::SignOpts{.format = "pades", .level = "b-b", .packaging = "enveloped"}});
    EXPECT_EQ(errName(reply), "UnsupportedOnThisCard");
}

TEST(SocketFrontend, SignWithEmptyCertIsRejected)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const auto reply = rig.roundTrip(
        5, Agent::Wire::Sign{card, "", 0,
                             Agent::Wire::SignOpts{.format = "pades", .level = "b-b", .packaging = "enveloped"}});
    EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter");
}

// ---- tsaUrl / visualSignature method-entry validation ----------------

TEST(SocketFrontend, SignRejectsANonHttpsTsaUrl)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const int fd = makeInputFile("%PDF-1.7");
    ASSERT_GE(fd, 0);
    Agent::Wire::SignOpts opts{.format = "pades", .level = "b-t", .packaging = "enveloped"};
    opts.tsaUrl = std::string{"http://tsa.example.com"};
    const auto reply = rig.roundTrip(50, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
    ::close(fd);
    EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter");
}

TEST(SocketFrontend, SignRejectsTsaUrlPairedWithTheBaselineLevel)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const int fd = makeInputFile("%PDF-1.7");
    ASSERT_GE(fd, 0);
    Agent::Wire::SignOpts opts{.format = "pades", .level = "b-b", .packaging = "enveloped"};
    opts.tsaUrl = std::string{"https://tsa.example.com/ts"};
    const auto reply = rig.roundTrip(51, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
    ::close(fd);
    EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter");
}

TEST(SocketFrontend, SignAcceptsTsaUrlOverrideAtTheTimestampedLevel)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const int fd = makeInputFile("%PDF-1.7");
    ASSERT_GE(fd, 0);
    Agent::Wire::SignOpts opts{.format = "pades", .level = "b-t", .packaging = "enveloped"};
    opts.tsaUrl = std::string{"https://tsa.example.com/ts"};
    // The method-entry gate passes -- an Operation is minted (no "err" key).
    // SignParams.tsaUrl's exact threading into the LM signing request is
    // unit-tested card-free in LibreAgent's LmSigningRequestBuilderTest.cpp.
    const auto reply = rig.roundTrip(52, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
    ::close(fd);
    EXPECT_EQ(errName(reply), "");
}

TEST(SocketFrontend, SignAcceptsTheAgentDecidesSentinelForLevel)
{
    // The arm this pins is what every deferring client relies on. It exists
    // and has never been asserted: remove it and this is the only thing in
    // the stack that goes red. Acceptance only -- see the companion test
    // below for the half that proves the configured default was consulted.
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    for (const char* sentinel : {"auto", ""}) {
        const int fd = makeInputFile("%PDF-1.7");
        ASSERT_GE(fd, 0);
        const Agent::Wire::SignOpts opts{.format = "pades", .level = sentinel, .packaging = "enveloped"};
        const auto reply = rig.roundTrip(90, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
        ::close(fd);
        EXPECT_EQ(errName(reply), "") << "sentinel: " << sentinel;
    }
}

TEST(SocketFrontend, SignAcceptsATsaUrlAlongsideTheAgentDecidesSentinel)
{
    // The agent has NO configured TSA and defaults to b-b, but the request
    // supplies one. Without the fix the level resolves to b-b and the request
    // is then rejected for pairing a tsaUrl with the baseline -- a refusal the
    // client cannot predict, because it depends on the agent's configuration.
    // This proves acceptance only, against the precondition made explicit and
    // real below (a fresh Rig already defaults to b-b, so the SetConfig call
    // is a no-op restating that default -- checked here rather than assumed).
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const auto setConfigReply =
        rig.roundTrip(91, Agent::Wire::SetConfig{"DefaultLevel", Agent::Wire::CborValue(std::string{"b-b"})});
    ASSERT_NE(setConfigReply.find("ok"), nullptr);
    EXPECT_TRUE(setConfigReply.find("ok")->asBool().value_or(false));
    const int fd = makeInputFile("%PDF-1.7");
    ASSERT_GE(fd, 0);
    Agent::Wire::SignOpts opts{.format = "pades", .level = "auto", .packaging = "enveloped"};
    opts.tsaUrl = std::string{"https://tsa.example.com/ts"};
    const auto reply = rig.roundTrip(92, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
    ::close(fd);
    EXPECT_EQ(errName(reply), "");
}

TEST(SocketFrontend, SignSniffsTheFormatWhenTheCallerDefersIt)
{
    // A deferred format is sniffed from the document, not validated as a
    // format: a PDF resolves, and bytes no sniffer recognises are refused
    // with the same out-of-vocabulary error as any other unresolvable
    // signing parameter -- never "the document could not be read".
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    for (const char* sentinel : {"auto", ""}) {
        const int fd = makeInputFile("%PDF-1.7");
        ASSERT_GE(fd, 0);
        const Agent::Wire::SignOpts opts{.format = sentinel, .level = "b-b", .packaging = "enveloped"};
        const auto reply = rig.roundTrip(93, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
        ::close(fd);
        EXPECT_EQ(errName(reply), "") << "sentinel: " << sentinel;
    }
    for (const char* sentinel : {"auto", ""}) {
        const int fd = makeInputFile("zzzz");
        ASSERT_GE(fd, 0);
        const Agent::Wire::SignOpts opts{.format = sentinel, .level = "b-b", .packaging = "enveloped"};
        const auto reply = rig.roundTrip(94, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
        ::close(fd);
        EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter") << "sentinel: " << sentinel;
    }
}

TEST(SocketFrontend, SignTakesTheFormatsDefaultPackagingWhenTheCallerDefersIt)
{
    // A deferred packaging is not judged as a packaging mode -- the sentinel
    // is not a member of that closed vocabulary -- it takes the resolved
    // format's own default instead.
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    for (const char* sentinel : {"auto", ""}) {
        const int fd = makeInputFile("%PDF-1.7");
        ASSERT_GE(fd, 0);
        const Agent::Wire::SignOpts opts{.format = "pades", .level = "b-b", .packaging = sentinel};
        const auto reply = rig.roundTrip(95, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
        ::close(fd);
        EXPECT_EQ(errName(reply), "") << "sentinel: " << sentinel;
    }
}

TEST(SocketFrontend, SignRejectsVisualSignatureOnANonPadesFormat)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const int fd = makeInputFile("%PDF-1.7");
    ASSERT_GE(fd, 0);
    Agent::Wire::SignOpts opts{.format = "cades", .level = "b-b", .packaging = "detached"};
    opts.visualSignature = Agent::Wire::VisualSignatureOpts{0, 0.0, 0.0, 100.0, 50.0, "x"};
    const auto reply = rig.roundTrip(53, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
    ::close(fd);
    EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter");
}

TEST(SocketFrontend, SignAcceptsVisualSignatureOnPades)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const int fd = makeInputFile("%PDF-1.7");
    ASSERT_GE(fd, 0);
    Agent::Wire::SignOpts opts{.format = "pades", .level = "b-b", .packaging = "enveloped"};
    opts.visualSignature = Agent::Wire::VisualSignatureOpts{1, 10.5, 20.25, 150.0, 60.0, "Signed by {cn}"};
    // The method-entry gate passes -- an Operation is minted (no "err" key).
    // The exact field-for-field mapping into LM's VisualSignatureParams is
    // unit-tested card-free in LibreAgent's LmSigningRequestBuilderTest.cpp.
    const auto reply = rig.roundTrip(54, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
    ::close(fd);
    EXPECT_EQ(errName(reply), "");
}

// A finite-guard on all four of visualSignature's x/y/width/height: CBOR
// carries +-inf/NaN canonically, so a hostile/buggy caller can put one on
// this wire (identically to D-Bus's `d` type on LibreLinux). Without a
// std::isfinite gate at method entry (SignatureParams::isValidVisualGeometry,
// shared with LibreLinux's CardObject::Sign), such a value would sail past
// the plain positivity checks and reach LmSeams's
// `static_cast<int>(std::lround(...))` narrowing downstream — lround on a
// non-finite double is unspecified, and the subsequent int narrowing of an
// out-of-range double is undefined behaviour. These three vectors mirror
// LibreLinux's CardObjectOperationsTest twins exactly (+inf width, NaN x,
// -inf y). This repo compiles only under Apple (the CMakeLists.txt
// `if(NOT APPLE)` gate).
TEST(SocketFrontend, SignRejectsVisualSignatureWithNonFiniteWidth)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const int fd = makeInputFile("%PDF-1.7");
    ASSERT_GE(fd, 0);
    Agent::Wire::SignOpts opts{.format = "pades", .level = "b-b", .packaging = "enveloped"};
    opts.visualSignature =
        Agent::Wire::VisualSignatureOpts{0, 0.0, 0.0, std::numeric_limits<double>::infinity(), 50.0, "x"};
    const auto reply = rig.roundTrip(55, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
    ::close(fd);
    EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter");
}

TEST(SocketFrontend, SignRejectsVisualSignatureWithNaNX)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const int fd = makeInputFile("%PDF-1.7");
    ASSERT_GE(fd, 0);
    Agent::Wire::SignOpts opts{.format = "pades", .level = "b-b", .packaging = "enveloped"};
    opts.visualSignature =
        Agent::Wire::VisualSignatureOpts{0, std::numeric_limits<double>::quiet_NaN(), 0.0, 100.0, 50.0, "x"};
    const auto reply = rig.roundTrip(56, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
    ::close(fd);
    EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter");
}

TEST(SocketFrontend, SignRejectsVisualSignatureWithNegativeInfinityY)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const int fd = makeInputFile("%PDF-1.7");
    ASSERT_GE(fd, 0);
    Agent::Wire::SignOpts opts{.format = "pades", .level = "b-b", .packaging = "enveloped"};
    opts.visualSignature =
        Agent::Wire::VisualSignatureOpts{0, 0.0, -std::numeric_limits<double>::infinity(), 100.0, 50.0, "x"};
    const auto reply = rig.roundTrip(57, Agent::Wire::Sign{card, "cert-id", 0, opts}, std::array{fd});
    ::close(fd);
    EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter");
}

// ---- Card1.SignBatch method-entry resolution (entry-gate only — mirrors the
// Sign entry-gate tests above; none of these wait for the worker to complete,
// same convention) ----------------------------------------------------------

TEST(SocketFrontend, SignBatchOnNonPkiCardIsUnsupported)
{
    Rig rig;
    const std::string card = rig.injectCard(kIdentityCap); // no PKI bit
    auto [docs, fds] = makeBatchDocuments(1);
    const auto reply = rig.roundTrip(
        58,
        Agent::Wire::SignBatch{card, "cert-id", docs,
                               Agent::Wire::SignOpts{.format = "pades", .level = "b-b", .packaging = "enveloped"}},
        fds);
    EXPECT_EQ(errName(reply), "UnsupportedOnThisCard");
    for (const int fd : fds) {
        ::close(fd);
    }
}

TEST(SocketFrontend, SignBatchWithEmptyCertIsRejected)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    auto [docs, fds] = makeBatchDocuments(1);
    const auto reply = rig.roundTrip(
        59,
        Agent::Wire::SignBatch{card, "", docs,
                               Agent::Wire::SignOpts{.format = "pades", .level = "b-b", .packaging = "enveloped"}},
        fds);
    EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter");
    for (const int fd : fds) {
        ::close(fd);
    }
}

TEST(SocketFrontend, SignBatchRejectsZeroDocuments)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const auto reply = rig.roundTrip(
        60,
        Agent::Wire::SignBatch{
            card, "cert-id", {}, Agent::Wire::SignOpts{.format = "pades", .level = "b-b", .packaging = "enveloped"}});
    EXPECT_EQ(errName(reply), "InvalidRequest");
}

// Pins that handleSignBatch's method-entry gate calls the SAME shared
// predicate LibreAgent's BatchSignFlow uses (Operations::
// isValidBatchDocumentCount) — not a parallel, driftable copy of the 1-12
// range — mirroring LibreLinux's
// CardObjectOperations.SignBatchDocumentCountGateUsesTheSharedValidityPredicate.
TEST(SocketFrontend, SignBatchDocumentCountGateUsesTheSharedValidityPredicate)
{
    EXPECT_TRUE(Agent::Operations::isValidBatchDocumentCount(1));
    EXPECT_TRUE(Agent::Operations::isValidBatchDocumentCount(12));
    EXPECT_FALSE(Agent::Operations::isValidBatchDocumentCount(0));
    EXPECT_FALSE(Agent::Operations::isValidBatchDocumentCount(13));
}

TEST(SocketFrontend, SignBatchAcceptsOneDocumentAndMintsOp)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    auto [docs, fds] = makeBatchDocuments(1);
    const auto reply = rig.roundTrip(
        61,
        Agent::Wire::SignBatch{card, "cert-id", docs,
                               Agent::Wire::SignOpts{.format = "pades", .level = "b-b", .packaging = "enveloped"}},
        fds);
    EXPECT_EQ(errName(reply), "");
    ASSERT_NE(reply.find("op"), nullptr);
    for (const int fd : fds) {
        ::close(fd);
    }
}

// Exercises a genuine multi-document batch at exactly kMaxBatchDocuments
// (12): the entry gate does not special-case any value inside
// [1, kMaxBatchDocuments] — it is the ONE isValidBatchDocumentCount range
// check — so this, together with the 1-document and 0-document cases
// above/below, covers the gate's live dispatch path.
TEST(SocketFrontend, SignBatchAcceptsATwelveDocumentBatchAndMintsOp)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    auto [docs, fds] = makeBatchDocuments(Agent::Operations::kMaxBatchDocuments);
    const auto reply = rig.roundTrip(
        62,
        Agent::Wire::SignBatch{card, "cert-id", docs,
                               Agent::Wire::SignOpts{.format = "pades", .level = "b-b", .packaging = "enveloped"}},
        fds);
    EXPECT_EQ(errName(reply), "");
    ASSERT_NE(reply.find("op"), nullptr);
    for (const int fd : fds) {
        ::close(fd);
    }
}

TEST(SocketFrontend, SignBatchRejectsThirteenDocuments)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    auto [docs, fds] = makeBatchDocuments(Agent::Operations::kMaxBatchDocuments + 1);
    const auto reply = rig.roundTrip(
        63,
        Agent::Wire::SignBatch{card, "cert-id", docs,
                               Agent::Wire::SignOpts{.format = "pades", .level = "b-b", .packaging = "enveloped"}},
        fds);
    EXPECT_EQ(errName(reply), "InvalidRequest");
    for (const int fd : fds) {
        ::close(fd);
    }
}

// Proves SignBatch reuses the EXACT SAME options resolver Sign does (not a
// parallel, driftable copy): the identical non-https-tsaUrl rejection Sign
// already exercises above must fire here too.
TEST(SocketFrontend, SignBatchRejectsANonHttpsTsaUrlViaTheSharedOptionsResolver)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    auto [docs, fds] = makeBatchDocuments(2);
    Agent::Wire::SignOpts opts{.format = "pades", .level = "b-t", .packaging = "enveloped"};
    opts.tsaUrl = std::string{"http://tsa.example.com"};
    const auto reply = rig.roundTrip(64, Agent::Wire::SignBatch{card, "cert-id", docs, opts}, fds);
    EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter");
    for (const int fd : fds) {
        ::close(fd);
    }
}

// Entry gate (rate limit): a valid SignBatch request from an over-cap caller
// is RateLimited before any document is read — mirrors
// ManagePinOverCapCallerIsRateLimited's pre-exhaust pattern, applied to the
// Sign rate-limit action SignBatch shares with a single Sign.
TEST(SocketFrontend, SignBatchOverCapCallerIsRateLimited)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const Agent::CallerToken caller{kFirstConnCaller};
    for (std::size_t i = 0; i < Agent::Operations::RateLimiter::kMaxPerWindow; ++i) {
        ASSERT_TRUE(rig.core->rateLimiter().allow(caller));
    }
    auto [docs, fds] = makeBatchDocuments(1);
    const auto reply = rig.roundTrip(
        65,
        Agent::Wire::SignBatch{card, "cert-id", docs,
                               Agent::Wire::SignOpts{.format = "pades", .level = "b-b", .packaging = "enveloped"}},
        fds);
    EXPECT_EQ(errName(reply), "RateLimited");
    for (const int fd : fds) {
        ::close(fd);
    }
}

// Gate ORDER (rate limit BEFORE the document-count gate): an over-cap caller
// sending a ZERO-document batch — entry-invalid on its own — must still see
// RateLimited, not InvalidRequest, proving handleSignBatch checks the limiter
// before isValidBatchDocumentCount, mirroring LibreLinux's
// SignBatchRateLimitFiresBeforeTheDocumentCountGate.
TEST(SocketFrontend, SignBatchRateLimitFiresBeforeTheDocumentCountGate)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const Agent::CallerToken caller{kFirstConnCaller};
    for (std::size_t i = 0; i < Agent::Operations::RateLimiter::kMaxPerWindow; ++i) {
        ASSERT_TRUE(rig.core->rateLimiter().allow(caller));
    }
    const auto reply = rig.roundTrip(
        66,
        Agent::Wire::SignBatch{
            card, "cert-id", {}, Agent::Wire::SignOpts{.format = "pades", .level = "b-b", .packaging = "enveloped"}});
    EXPECT_EQ(errName(reply), "RateLimited");
}

TEST(SocketFrontend, SetReadOnlyConfigKeyIsRejected)
{
    Rig rig;
    const auto reply = rig.roundTrip(6, Agent::Wire::SetConfig{"LastTsaUrl", Agent::Wire::CborValue(std::string{"x"})});
    EXPECT_EQ(errName(reply), "ReadOnlyConfig");
}

TEST(SocketFrontend, SetUnknownConfigKeyIsRejected)
{
    Rig rig;
    const auto reply =
        rig.roundTrip(7, Agent::Wire::SetConfig{"Nonexistent", Agent::Wire::CborValue(std::string{"x"})});
    EXPECT_EQ(errName(reply), "UnknownConfigKey");
}

TEST(SocketFrontend, SetDefaultLevelSucceeds)
{
    Rig rig;
    const auto reply =
        rig.roundTrip(8, Agent::Wire::SetConfig{"DefaultLevel", Agent::Wire::CborValue(std::string{"b-t"})});
    ASSERT_NE(reply.find("ok"), nullptr);
    EXPECT_TRUE(reply.find("ok")->asBool().value_or(false));
}

// This case used to die with SIGBUS here, and the cause was not in this repo.
// CborValue's map alternative was a std::map named while CborValue was still an
// incomplete type, which left a relocated map addressing a freed buffer; the
// deep copy this reply performs was what walked it. Fixed in LibreAgent, where
// CborRelocationTest now states the property directly and a macOS ASan job
// checks it. Kept unskipped here because this is the shape that found it: a
// real config store, a real socket, and a reply built the way the agent builds
// it.
TEST(SocketFrontend, GetConfigReturnsEntries)
{
    Rig rig;
    const auto reply = rig.roundTrip(9, Agent::Wire::GetConfig{});
    const auto* entries = reply.find("entries");
    ASSERT_NE(entries, nullptr);
    ASSERT_NE(entries->asMap(), nullptr);
    EXPECT_NE(entries->find("DefaultLevel"), nullptr);
}

TEST(SocketFrontend, CancelReturnsAck)
{
    Rig rig;
    const auto reply = rig.roundTrip(10, Agent::Wire::CancelOp{999});
    ASSERT_NE(reply.find("ok"), nullptr);
    EXPECT_TRUE(reply.find("ok")->asBool().value_or(false));
}

// An unknown (or unowned, or grace-evicted) op yields the dedicated NoResult
// name, not KeyNotFound: handleGetSignResult replies uniformly so an enumerated
// op id cannot be used as a presence oracle (the IDOR guard). KeyNotFound was
// the pre-pinning borrow for this outcome.
TEST(SocketFrontend, GetSignResultUnknownOpIsNoResult)
{
    Rig rig;
    const auto reply = rig.roundTrip(11, Agent::Wire::GetSignResult{999});
    EXPECT_EQ(errName(reply), "NoResult");
}

// --- credentials (PIN/PUK management over the socket) -------------------------

TEST(SocketFrontend, HelloAdvertisesCredentialsFeature)
{
    Rig rig;
    const auto reply = rig.roundTrip(20, Agent::Wire::Hello{1, std::nullopt});
    const auto* features = reply.find("features");
    ASSERT_NE(features, nullptr);
    ASSERT_NE(features->asArray(), nullptr);
    bool found = false;
    for (const auto& f : *features->asArray()) {
        found = found || (f.asText() != nullptr && *f.asText() == "credentials");
    }
    EXPECT_TRUE(found) << "HelloAck.features must contain \"credentials\"";
}

// Entry gate 1 (capability): a ManagePin against a card without the
// PinManagement bit is refused at entry with no Operation minted.
TEST(SocketFrontend, ManagePinWithoutPinManagementCapIsUnsupported)
{
    Rig rig;
    const std::string card = rig.injectCard(kIdentityCap); // no PinManagement bit
    const auto reply = rig.roundTrip(21, Agent::Wire::ManagePin{card, "user:0x01", "change", std::nullopt});
    EXPECT_EQ(errName(reply), "UnsupportedOnThisCard");
}

// Entry gate 2 (validation), asserted in gate order on one request each:
// unknown verb -> InvalidRequest; the activateKey wire key on a verb that
// cannot carry it -> InvalidRequest (the macOS analog of Linux's undefined
// options key); a valid verb with no prior listing -> UnknownCredential.
TEST(SocketFrontend, ManagePinEntryValidationRejectsInOrder)
{
    Rig rig;
    const std::string card = rig.injectCard(kPinMgmtCap);

    const auto badVerb = rig.roundTrip(22, Agent::Wire::ManagePin{card, "user:0x01", "frobnicate", std::nullopt});
    EXPECT_EQ(errName(badVerb), "InvalidRequest");

    const auto badCombo = rig.roundTrip(23, Agent::Wire::ManagePin{card, "user:0x01", "change", true});
    EXPECT_EQ(errName(badCombo), "InvalidRequest");

    const auto noListing = rig.roundTrip(24, Agent::Wire::ManagePin{card, "user:0x01", "change", std::nullopt});
    EXPECT_EQ(errName(noListing), "UnknownCredential");
}

// Entry gate 3 (authorize): a valid request from a policy-denied caller is
// NotAuthorized — after validation, before any prompt or rate-limit spend.
TEST(SocketFrontend, ManagePinDeniedCallerIsNotAuthorized)
{
    DenyAllAuthorizer deny;
    Rig rig(&deny);
    const std::string card = rig.injectCard(kPinMgmtCap);
    rig.core->credentialSnapshotCache().put(kInjectedCardKey, makeSnapshot());
    const auto reply = rig.roundTrip(25, Agent::Wire::ManagePin{card, "user:0x01", "change", std::nullopt});
    EXPECT_EQ(errName(reply), "NotAuthorized");
}

// Entry gate 4 (rate limit): a valid, authorized request from an over-cap
// caller is RateLimited before any prompt.
TEST(SocketFrontend, ManagePinOverCapCallerIsRateLimited)
{
    Rig rig;
    const std::string card = rig.injectCard(kPinMgmtCap);
    rig.core->credentialSnapshotCache().put(kInjectedCardKey, makeSnapshot());
    // Pre-exhaust the shared limiter for the caller token the request will
    // carry (the Linux e2e does the same with the client's unique bus name).
    const Agent::CallerToken caller{kFirstConnCaller};
    for (std::size_t i = 0; i < Agent::Operations::RateLimiter::kMaxPerWindow; ++i) {
        ASSERT_TRUE(rig.core->rateLimiter().allow(caller));
    }
    const auto reply = rig.roundTrip(26, Agent::Wire::ManagePin{card, "user:0x01", "change", std::nullopt});
    EXPECT_EQ(errName(reply), "RateLimited");
}

// Gate ORDER (authorize BEFORE rate limit): a caller that is BOTH policy-denied
// AND over cap gets NotAuthorized — the policy verdict wins, and the limiter is
// never consulted for a request policy already refused.
TEST(SocketFrontend, ManagePinDeniedAndOverCapCallerIsNotAuthorized)
{
    DenyAllAuthorizer deny;
    Rig rig(&deny);
    const std::string card = rig.injectCard(kPinMgmtCap);
    rig.core->credentialSnapshotCache().put(kInjectedCardKey, makeSnapshot());
    const Agent::CallerToken caller{kFirstConnCaller};
    for (std::size_t i = 0; i < Agent::Operations::RateLimiter::kMaxPerWindow; ++i) {
        ASSERT_TRUE(rig.core->rateLimiter().allow(caller));
    }
    const auto reply = rig.roundTrip(32, Agent::Wire::ManagePin{card, "user:0x01", "change", std::nullopt});
    EXPECT_EQ(errName(reply), "NotAuthorized");
}

TEST(SocketFrontend, ListCredentialsWithoutPinManagementCapIsUnsupported)
{
    Rig rig;
    const std::string card = rig.injectCard(kIdentityCap); // no PinManagement bit
    const auto reply = rig.roundTrip(27, Agent::Wire::ListCredentials{card});
    EXPECT_EQ(errName(reply), "UnsupportedOnThisCard");
}

// ListCredentials is a read: it gates on the capability but is NOT rate-limited
// — an over-cap caller still gets an op.
TEST(SocketFrontend, ListCredentialsIsNotRateLimited)
{
    Rig rig;
    rig.core->operationManager().setSessionFactoryForTest(detachedSessionFactory());
    const std::string card = rig.injectCard(kPinMgmtCap);
    const Agent::CallerToken caller{kFirstConnCaller};
    for (std::size_t i = 0; i < Agent::Operations::RateLimiter::kMaxPerWindow; ++i) {
        ASSERT_TRUE(rig.core->rateLimiter().allow(caller));
    }
    Client client(rig.path);
    client.send(28, Agent::Wire::ListCredentials{card});
    const auto reply = client.waitFor("Reply");
    EXPECT_EQ(errName(reply), "");
    ASSERT_NE(reply.find("op"), nullptr) << "an over-cap caller must still get a listing op";
    // Drain to the op's terminal event so the rig tears down with an idle worker.
    static_cast<void>(client.waitFor("OpFinished"));
}

// ListCredentials gates on the capability ONLY: a policy-denied caller still
// gets a listing op — the credentials authorize gate applies to mutations, not
// to the list read.
TEST(SocketFrontend, ListCredentialsDeniedCallerStillGetsOp)
{
    DenyAllAuthorizer deny;
    Rig rig(&deny);
    rig.core->operationManager().setSessionFactoryForTest(detachedSessionFactory());
    const std::string card = rig.injectCard(kPinMgmtCap);
    Client client(rig.path);
    client.send(33, Agent::Wire::ListCredentials{card});
    const auto reply = client.waitFor("Reply");
    EXPECT_EQ(errName(reply), "");
    ASSERT_NE(reply.find("op"), nullptr) << "a policy-denied caller must still get a listing op";
    // Drain to the op's terminal event so the rig tears down with an idle worker.
    static_cast<void>(client.waitFor("OpFinished"));
}

// ActivateSigningKey duplicates the entry-gate code rather than sharing
// ManagePin's, so it needs its own pins. Gate 1 (capability): a card without
// the PinManagement bit is refused at entry with no Operation minted.
TEST(SocketFrontend, ActivateSigningKeyWithoutPinManagementCapIsUnsupported)
{
    Rig rig;
    const std::string card = rig.injectCard(kIdentityCap); // no PinManagement bit
    const auto reply = rig.roundTrip(34, Agent::Wire::ActivateSigningKey{card});
    EXPECT_EQ(errName(reply), "UnsupportedOnThisCard");
}

// Gate 2 (authorize): capability present but a policy-denied caller is
// NotAuthorized. Unlike ManagePin there is no validation gate in between —
// the addressed signing-key record is resolved inside the operation, not at
// entry — so no seeded snapshot is needed to reach the authorizer.
TEST(SocketFrontend, ActivateSigningKeyDeniedCallerIsNotAuthorized)
{
    DenyAllAuthorizer deny;
    Rig rig(&deny);
    const std::string card = rig.injectCard(kPinMgmtCap);
    const auto reply = rig.roundTrip(35, Agent::Wire::ActivateSigningKey{card});
    EXPECT_EQ(errName(reply), "NotAuthorized");
}

// A valid ManagePin after a listing mints an op, and the op's failed (cancelled)
// attempt rides the REAL twin + channel: OpResultReady(Credentials) with outcome
// userCancelled and empty records, then OpFinished(Cancelled, None).
TEST(SocketFrontend, ManagePinCancelledPromptEmitsCredentialsResultThenFinished)
{
    Rig rig(nullptr, std::make_shared<CancellingPrompter>());
    rig.core->operationManager().setSessionFactoryForTest(detachedSessionFactory());
    const std::string card = rig.injectCard(kPinMgmtCap);
    rig.core->credentialSnapshotCache().put(kInjectedCardKey, makeSnapshot());

    Client client(rig.path);
    client.send(29, Agent::Wire::ManagePin{card, "user:0x01", "change", std::nullopt});
    const auto reply = client.waitFor("Reply");
    EXPECT_EQ(errName(reply), "");
    ASSERT_NE(reply.find("op"), nullptr) << "a valid ManagePin must mint an op";

    const auto ready = client.waitFor("OpResultReady");
    const auto* result = ready.find("result");
    ASSERT_NE(result, nullptr);
    ASSERT_NE(result->find("kind"), nullptr);
    EXPECT_EQ(*result->find("kind")->asText(), "Credentials");
    const auto* credResult = result->find("result");
    ASSERT_NE(credResult, nullptr);
    ASSERT_NE(credResult->find("outcome"), nullptr);
    EXPECT_EQ(*credResult->find("outcome")->asText(), "userCancelled");
    const auto* records = result->find("records");
    ASSERT_NE(records, nullptr);
    ASSERT_NE(records->asArray(), nullptr);
    EXPECT_TRUE(records->asArray()->empty()) << "a mutation carries no record listing";

    const auto finished = client.waitFor("OpFinished");
    ASSERT_NE(finished.find("status"), nullptr);
    EXPECT_EQ(finished.find("status")->asUInt().value_or(99),
              static_cast<std::uint64_t>(Agent::Operations::OperationStatus::Cancelled));
    ASSERT_NE(finished.find("code"), nullptr);
    EXPECT_EQ(finished.find("code")->asUInt().value_or(99), static_cast<std::uint64_t>(Agent::ErrorCode::None));
}

// CancelOp on a credentials op mid-prompt: the owner-scoped silent-ack cancel
// path applies unchanged to the new op kinds — the op resolves userCancelled,
// then OpFinished(Cancelled, None).
TEST(SocketFrontend, CancelledMidPromptOpResolvesUserCancelledThenCancelledFinish)
{
    auto prompter = std::make_shared<BlockingPrompter>();
    Rig rig(nullptr, prompter);
    rig.core->operationManager().setSessionFactoryForTest(detachedSessionFactory());
    const std::string card = rig.injectCard(kPinMgmtCap);
    rig.core->credentialSnapshotCache().put(kInjectedCardKey, makeSnapshot());

    Client client(rig.path);
    client.send(30, Agent::Wire::ManagePin{card, "user:0x01", "change", std::nullopt});
    const auto reply = client.waitFor("Reply");
    EXPECT_EQ(errName(reply), "");
    const auto* op = reply.find("op");
    ASSERT_NE(op, nullptr);
    const std::uint64_t opId = op->asUInt().value_or(0);

    ASSERT_TRUE(prompter->waitEntered()) << "the change modal must be up before the cancel";

    client.send(31, Agent::Wire::CancelOp{opId});
    const auto ack = client.waitFor("Reply");
    ASSERT_NE(ack.find("ok"), nullptr);
    EXPECT_TRUE(ack.find("ok")->asBool().value_or(false)) << "CancelOp acks silently";

    const auto ready = client.waitFor("OpResultReady");
    const auto* result = ready.find("result");
    ASSERT_NE(result, nullptr);
    const auto* credResult = result->find("result");
    ASSERT_NE(credResult, nullptr);
    ASSERT_NE(credResult->find("outcome"), nullptr);
    EXPECT_EQ(*credResult->find("outcome")->asText(), "userCancelled");

    const auto finished = client.waitFor("OpFinished");
    ASSERT_NE(finished.find("status"), nullptr);
    EXPECT_EQ(finished.find("status")->asUInt().value_or(99),
              static_cast<std::uint64_t>(Agent::Operations::OperationStatus::Cancelled));
    ASSERT_NE(finished.find("code"), nullptr);
    EXPECT_EQ(finished.find("code")->asUInt().value_or(99), static_cast<std::uint64_t>(Agent::ErrorCode::None));
}

// Card removal must drop the per-card ListCredentials snapshot. Rather than
// hand-mirroring the invalidation set (which would pass even if the real hook
// forgot the snapshot), this drives invalidateCardRemovalCaches() — the SHARED
// helper the production main.cpp setOnKeyRemoved hook actually calls. A
// regression that drops the snapshot cache from that helper fails here AND in
// production together, so the hook's cache set is genuinely under test.
TEST(SocketFrontend, CardRemovalDropsSnapshot)
{
    Agent::CredentialCache credCache;
    Agent::CardReadCache readCache;
    Agent::CredentialSnapshotCache snapshotCache;
    const std::string cardKey = kInjectedCardKey;
    snapshotCache.put(cardKey, makeSnapshot());
    ASSERT_TRUE(snapshotCache.get(cardKey).has_value());

    // The exact production removal-invalidation code (not a re-implementation).
    Agent::invalidateCardRemovalCaches(credCache, readCache, snapshotCache, cardKey);

    EXPECT_FALSE(snapshotCache.get(cardKey).has_value()) << "card removal must drop the credential snapshot";
}

// main.cpp's fullScrub (sleep / fast-user-switch away) must also drop the
// per-card ListCredentials snapshots — the listing id namespace dies with the
// session. Rather than re-stating the scrub's cache statements (which would
// pass even if the real scrub forgot the snapshots), this drives
// clearFullScrubCaches() — the SHARED helper the production fullScrub lambda
// actually calls — so dropping the snapshot clear from the scrub fails here
// AND in production together. Both caches in the helper's set are seeded and
// asserted empty: the CAN/MRZ secret cache and the snapshot cache.
TEST(SocketFrontend, FullScrubDropsCredentialSnapshots)
{
    Agent::CredentialCache credCache;
    Agent::CredentialSnapshotCache snapshotCache;
    const std::string cardKey = kInjectedCardKey;
    credCache.putCan(cardKey, Agent::CredentialCache::Secret{"123456"});
    ASSERT_TRUE(credCache.hasCan(cardKey));
    snapshotCache.put(cardKey, makeSnapshot());
    ASSERT_TRUE(snapshotCache.get(cardKey).has_value());

    // The exact production scrub cache-clearing code (not a re-statement).
    Agent::clearFullScrubCaches(credCache, snapshotCache);

    EXPECT_FALSE(credCache.hasCan(cardKey)) << "fullScrub must drop the cached secrets";
    EXPECT_FALSE(snapshotCache.get(cardKey).has_value()) << "fullScrub must drop the credential snapshots";
}

// --- trust tier: a human confirms, or the value does not move ----------------
//
// The verdict is injected, so these prove the wiring and nothing about the
// dialog itself. What they do prove is the part that must hold whatever the
// human says: a refusal leaves the stored value exactly as it was.

Agent::Wire::CborValue cborArrayOfStrings(std::vector<std::string> items)
{
    std::vector<Agent::Wire::CborValue> out;
    out.reserve(items.size());
    for (auto& s : items) {
        out.emplace_back(std::move(s));
    }
    return Agent::Wire::CborValue(std::move(out));
}

TEST(SocketFrontend, DeclinedTrustConfirmationLeavesThePreviousValueInPlace)
{
    Rig rig;
    const auto before = rig.core->configStore().tsaUrls();
    rig.frontend->setConfirmProvider(
        [](const wire::ConfirmAction&) { return wire::ConfirmReply{wire::PromptReplyStatus::Cancelled, "declined"}; });

    const auto reply =
        rig.roundTrip(70, Agent::Wire::SetConfig{"TsaUrls", cborArrayOfStrings({"https://tsa.example/"})});

    EXPECT_EQ(errName(reply), "NotAuthorized");
    EXPECT_EQ(rig.core->configStore().tsaUrls(), before) << "a declined change must not move the value";
}

TEST(SocketFrontend, ApprovedTrustConfirmationAppliesTheWrite)
{
    Rig rig;
    rig.frontend->setConfirmProvider(
        [](const wire::ConfirmAction&) { return wire::ConfirmReply{wire::PromptReplyStatus::Ok, {}}; });

    const auto reply =
        rig.roundTrip(71, Agent::Wire::SetConfig{"TsaUrls", cborArrayOfStrings({"https://tsa.example/"})});

    ASSERT_NE(reply.find("ok"), nullptr);
    EXPECT_TRUE(reply.find("ok")->asBool().value_or(false));
    EXPECT_EQ(rig.core->configStore().tsaUrls(), (std::vector<std::string>{"https://tsa.example/"}));
}

// The confused-deputy guard: the human must be told what is being changed.
TEST(SocketFrontend, TheConfirmationNamesTheKeyItIsAbout)
{
    Rig rig;
    wire::ConfirmAction seen;
    rig.frontend->setConfirmProvider([&seen](const wire::ConfirmAction& a) {
        seen = a;
        return wire::ConfirmReply{wire::PromptReplyStatus::Cancelled, {}};
    });

    static_cast<void>(rig.roundTrip(72, Agent::Wire::SetConfig{"TslSources", cborArrayOfStrings({})}));

    EXPECT_EQ(seen.kind, "configure_trust");
    EXPECT_EQ(seen.artifact, "TslSources");
    EXPECT_FALSE(seen.description.empty()) << "a dialog that cannot say what it changes must not be shown";
    EXPECT_EQ(seen.descriptionKey, "prompter_trust_tsl")
        << "the sentence must be named, or only an English reader is being told what changes";
}

// The other named trust source. Two keys, not one: a single key covering both
// would merge "which timestamping authority" with "which trusted list" into one
// translatable sentence that can only be right about one of them -- and the two
// are indistinguishable to every other assertion here, because the kind, the
// artifact and the refusal are the same on both paths.
TEST(SocketFrontend, TheConfirmationForATimestampingAuthorityNamesItsOwnSentence)
{
    Rig rig;
    wire::ConfirmAction seen;
    rig.frontend->setConfirmProvider([&seen](const wire::ConfirmAction& a) {
        seen = a;
        return wire::ConfirmReply{wire::PromptReplyStatus::Cancelled, {}};
    });

    static_cast<void>(rig.roundTrip(73, Agent::Wire::SetConfig{"TsaUrls", cborArrayOfStrings({})}));

    EXPECT_EQ(seen.kind, "configure_trust");
    EXPECT_EQ(seen.artifact, "TsaUrls");
    EXPECT_EQ(seen.description, "Change the timestamping authorities this computer will use.");
    EXPECT_EQ(seen.descriptionKey, "prompter_trust_tsa");
}

// A trust key with no sentence written for it: CscaSources is gated exactly
// like the two above and has no wording of its own, so it must arrive carrying
// the generic sentence AND the generic key. An unnamed fallback is the one that
// would go untranslated without anything failing.
TEST(SocketFrontend, ATrustKeyWithNoSentenceOfItsOwnFallsBackToTheGenericOne)
{
    Rig rig;
    wire::ConfirmAction seen;
    rig.frontend->setConfirmProvider([&seen](const wire::ConfirmAction& a) {
        seen = a;
        return wire::ConfirmReply{wire::PromptReplyStatus::Cancelled, {}};
    });

    static_cast<void>(rig.roundTrip(74, Agent::Wire::SetConfig{"CscaSources", cborArrayOfStrings({})}));

    EXPECT_EQ(seen.kind, "configure_trust");
    EXPECT_EQ(seen.artifact, "CscaSources");
    EXPECT_EQ(seen.description, "Change a trust setting on this computer.");
    EXPECT_EQ(seen.descriptionKey, "prompter_trust_generic");
}

// An ordinary key must not acquire a prompt, or the latency of one.
TEST(SocketFrontend, OrdinaryConfigWritesNeverAskForConfirmation)
{
    Rig rig;
    std::atomic<bool> asked{false};
    rig.frontend->setConfirmProvider([&asked](const wire::ConfirmAction&) {
        asked = true;
        return wire::ConfirmReply{wire::PromptReplyStatus::Ok, {}};
    });

    const auto reply =
        rig.roundTrip(73, Agent::Wire::SetConfig{"DefaultReason", Agent::Wire::CborValue(std::string{"Approval"})});

    EXPECT_FALSE(asked.load());
    ASSERT_NE(reply.find("ok"), nullptr);
    EXPECT_TRUE(reply.find("ok")->asBool().value_or(false));
}

TEST(SocketFrontend, DeclinedTrustResetLeavesThePreviousValueInPlace)
{
    Rig rig;
    ASSERT_TRUE(rig.core->configStore().setTsaUrls({"https://tsa.example/"}).ok);
    rig.frontend->setConfirmProvider(
        [](const wire::ConfirmAction&) { return wire::ConfirmReply{wire::PromptReplyStatus::Cancelled, {}}; });

    const auto reply = rig.roundTrip(74, Agent::Wire::ResetConfig{"TsaUrls"});

    EXPECT_EQ(errName(reply), "NotAuthorized");
    EXPECT_EQ(rig.core->configStore().tsaUrls(), (std::vector<std::string>{"https://tsa.example/"}))
        << "a declined reset must not clear the value";
}

TEST(SocketFrontend, ApprovedTrustResetClearsTheValue)
{
    Rig rig;
    ASSERT_TRUE(rig.core->configStore().setTsaUrls({"https://tsa.example/"}).ok);
    rig.frontend->setConfirmProvider(
        [](const wire::ConfirmAction&) { return wire::ConfirmReply{wire::PromptReplyStatus::Ok, {}}; });

    const auto reply = rig.roundTrip(75, Agent::Wire::ResetConfig{"TsaUrls"});

    ASSERT_NE(reply.find("ok"), nullptr);
    EXPECT_TRUE(reply.find("ok")->asBool().value_or(false));
}

} // namespace

// --- country-signing config surface ------------------------------------------
//
// Three completeness gates over ConfigStore's key table, and the ordering
// invariant the import path owes.
//
// The gates ask the STORE which keys exist and how each may be changed, never a
// list of spellings kept here: a hand-written list is the same species of
// artefact as the surface it checks, so the two drift together and stay green.
// Both directions of the drift matter -- a key the store owns and this host
// never serves is a client that cannot read its own configuration, and a key
// this host would write that the store calls read-only is a policy hole -- so
// each direction gets its own assertion rather than one combined pass.

namespace {

using Agent::Config::ConfigStore;
using Agent::Config::Mutability;

// A value of the wrong SHAPE on purpose. The gates below assert which REFUSAL
// comes back, not that a write succeeds: a branch that exists answers
// "invalid value", and one that does not answers "unknown key". That
// distinction is the whole measurement, and it needs no valid value per key.
Agent::Wire::CborValue wrongShapeValue()
{
    return Agent::Wire::CborValue(std::uint64_t{0});
}

std::string joined(const std::vector<std::string>& keys)
{
    std::string out;
    for (const auto& k : keys) {
        out += (out.empty() ? "" : ", ") + k;
    }
    return out;
}

} // namespace

TEST(SocketFrontendConfigSurface, GetConfigServesEveryKeyTheStoreOwnsAndDoesNotHide)
{
    Rig rig;
    const auto reply = rig.roundTrip(1, Agent::Wire::GetConfig{});
    const auto* entries = reply.find("entries");
    ASSERT_NE(entries, nullptr) << "GetConfig reply carried no entries map";
    const auto* served = entries->asMap();
    ASSERT_NE(served, nullptr);

    // File-only keys MAY be served (three are today, read-only) but need not be:
    // publishing one is a free choice this gate does not make for the host. What
    // it does hold is that everything else arrives -- a key a client cannot read
    // is a client that cannot see its own configuration.
    std::vector<std::string> missing;
    for (const std::string& key : ConfigStore::keys()) {
        const auto how = ConfigStore::mutability(key);
        ASSERT_TRUE(how.has_value()) << key << " is owned by the store but classified by nothing";
        if (*how == Mutability::FileOnly) {
            continue;
        }
        if (served->find(key) == served->end()) {
            missing.push_back(key);
        }
    }
    EXPECT_TRUE(missing.empty()) << joined(missing)
                                 << " :: the store owns these keys and GetConfig does not serve them";
}

TEST(SocketFrontendConfigSurface, SetConfigAcceptsEveryKeyTheStoreCallsWritable)
{
    Rig rig;
    // Trust-tier writes go through a human confirmation before any branch runs.
    // Without a provider that answers, every one of them stops at NotAuthorized
    // and this gate measures the confirmation step instead of the surface it
    // was written for.
    rig.frontend->setConfirmProvider([](const auto&) {
        return LibreSCRS::Darwin::wire::ConfirmReply{LibreSCRS::Darwin::wire::PromptReplyStatus::Ok, ""};
    });
    std::uint64_t req = 1;
    std::vector<std::string> unknown;
    for (const std::string& key : ConfigStore::keys()) {
        const auto how = ConfigStore::mutability(key);
        ASSERT_TRUE(how.has_value()) << key;
        if (*how != Mutability::DbusMutable && *how != Mutability::DbusMutableTrust) {
            continue;
        }
        const auto reply = rig.roundTrip(req++, Agent::Wire::SetConfig{key, wrongShapeValue()});
        // "invalid value" means a branch took the key and disliked what came
        // with it. "unknown key" means no branch exists -- which is the failure
        // this gate is here to catch, and which today reads to a client as a
        // key the agent has never heard of even though the vocabulary lists it.
        // Positive, not "anything but unknown": a branch that exists takes the
        // key and rejects the shape. Accepting merely "not UnknownConfigKey"
        // was this gate's first form and it PASSED with the branch deleted,
        // because the trust tier answered NotAuthorized long before reaching
        // any branch -- the confirmation step is what a rig without a
        // confirming provider fails first. Measured, then fixed.
        if (errName(reply) != "InvalidConfigValue") {
            unknown.push_back(key + " -> " + errName(reply));
        }
    }
    EXPECT_TRUE(unknown.empty()) << joined(unknown)
                                 << " :: the store calls these keys writable and SetConfig has no branch for them";
}

TEST(SocketFrontendConfigSurface, SetConfigRefusesEveryKeyTheStoreCallsReadOnly)
{
    Rig rig;
    std::uint64_t req = 1;
    std::vector<std::string> accepted;
    for (const std::string& key : ConfigStore::keys()) {
        const auto how = ConfigStore::mutability(key);
        ASSERT_TRUE(how.has_value()) << key;
        if (*how != Mutability::ReadOnly && *how != Mutability::FileOnly) {
            continue;
        }
        const auto reply = rig.roundTrip(req++, Agent::Wire::SetConfig{key, wrongShapeValue()});
        if (errName(reply) != "ReadOnlyConfig") {
            accepted.push_back(key + " -> " + errName(reply));
        }
    }
    EXPECT_TRUE(accepted.empty()) << joined(accepted)
                                  << " :: these keys are not client-settable and the refusal did not say so";
}

// --- the ordering the import path owes ---------------------------------------
//
// THE ERROR NAME CANNOT TELL THESE APART. An implementation that reads the
// descriptor and authorizes afterwards answers NotAuthorized exactly like one
// that refuses first, so no assertion over the reply can separate them.
//
// What separates them is the descriptor itself. It arrives over SCM_RIGHTS,
// which duplicates the descriptor but NOT the open file description behind it:
// sender and receiver share one file offset. So a read on the agent's side
// moves OUR offset, and lseek(SEEK_CUR) here measures whether the agent touched
// what a refused caller handed over.
//
// The pair is deliberate. The refusal case alone would pass just as happily if
// the frontend never read the fd under any circumstance -- if the fd index were
// wrong, say, or the handler unreachable -- so the companion below proves the
// same measurement DOES move when the read is allowed to happen. Without it
// this is a test that cannot fail for the reason it was written.

TEST(SocketFrontend, RefusedImportNeverAdvancesTheDescriptorItWasHanded)
{
    DenyAllAuthorizer deny;
    Rig rig(&deny);

    const int fd = makeInputFile(std::string(8192, '\x30'));
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::lseek(fd, 0, SEEK_CUR), 0) << "the fixture must start at the beginning";

    const std::array<int, 1> fds{fd};
    const auto reply = rig.roundTrip(1, Agent::Wire::ImportCscaMasterList{0}, fds);
    EXPECT_EQ(errName(reply), "NotAuthorized");

    EXPECT_EQ(::lseek(fd, 0, SEEK_CUR), 0)
        << "the agent read the master list before deciding the caller was allowed to send one";
    ::close(fd);
}

TEST(SocketFrontend, AnAuthorizedImportDoesAdvanceTheDescriptor)
{
    Rig rig; // allow-all
    confirmEverything(rig);

    const int fd = makeInputFile(std::string(8192, '\x30'));
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::lseek(fd, 0, SEEK_CUR), 0);

    const std::array<int, 1> fds{fd};
    const auto reply = rig.roundTrip(1, Agent::Wire::ImportCscaMasterList{0}, fds);
    // Eight kilobytes of 0x30 is not a master list, and being refused as one is
    // the point: the bytes had to be READ to be judged.
    EXPECT_EQ(errName(reply), "InvalidRequest");

    EXPECT_GT(::lseek(fd, 0, SEEK_CUR), 0) << "nothing read the descriptor, so the refusal test above proves nothing";
    ::close(fd);
}

// --- what a collection leaves fillable ---------------------------------------
//
// One import takes in a COLLECTION of separately signed lists, while the
// remembered record and the property built from it speak a single-publisher
// vocabulary. Which fields that leaves unfillable is the decision under test.
//
// Measured against hand-built states rather than a signed multi-list file: the
// mapping is pure logic over a public type, and the only signed fixture that
// carries several publishers lives in the producer's test tree, which this repo
// does not link. Arguing this from the type and shipping it untested was the
// first draft, and it would have left the collection path — the one a person
// actually hits with the real directory export — measured nowhere.

namespace {

Agent::Trust::AcceptedSigner signer(std::uint8_t tag, bool established,
                                    std::optional<std::int64_t> signedAt = std::nullopt)
{
    Agent::Trust::AcceptedSigner s;
    s.fingerprint.fill(tag);
    s.identityEstablished = established;
    s.signedAt = signedAt;
    return s;
}

Agent::Trust::AnchorState stateWith(std::vector<Agent::Trust::AcceptedSigner> signers)
{
    Agent::Trust::AnchorState st;
    st.present = true;
    st.signers = std::move(signers);
    st.anchorCount = 903;
    st.issuerCount = 146;
    st.acceptedAt = 1'700'000'000;
    st.origin = "import";
    return st;
}

} // namespace

TEST(CscaRecordedState, OnePublisherFillsEverythingTheVocabularyCanSay)
{
    const auto out = LibreSCRS::Darwin::detail::recordedStateFor(stateWith({signer(0xAB, true, 1'690'000'000)}));
    EXPECT_FALSE(out.signer.empty()) << "one publisher is exactly what this vocabulary was written for";
    EXPECT_TRUE(out.signerPinned);
    ASSERT_TRUE(out.signedAt.has_value());
    EXPECT_EQ(*out.signedAt, 1'690'000'000);
    EXPECT_EQ(out.anchors, 903u);
    EXPECT_EQ(out.issuers, 146u);
}

TEST(CscaRecordedState, SeveralPublishersNameNoneOfThem)
{
    const auto out = LibreSCRS::Darwin::detail::recordedStateFor(
        stateWith({signer(0xAB, true, 1'690'000'000), signer(0xCD, true, 1'695'000'000)}));
    // The whole point: one fingerprint out of many, under a label a dialog
    // renders as "the publisher", is a concrete untruth. Absence is not.
    EXPECT_TRUE(out.signer.empty()) << "one publisher out of several was named as THE publisher";
    EXPECT_FALSE(out.signedAt.has_value()) << "one publisher's signing time was served as the collection's";
    EXPECT_EQ(out.anchors, 903u) << "the counts are the union and stay fillable";
}

TEST(CscaRecordedState, OneUnestablishedPublisherAmongManyClearsTheAggregate)
{
    const auto out = LibreSCRS::Darwin::detail::recordedStateFor(stateWith({signer(0xAB, true), signer(0xCD, false)}));
    // Deliberately the WEAKEST of its parts. One unestablished publisher is a
    // trust-on-first-import for that country's anchors, and a surface rendering
    // "authenticity verified" over the aggregate would overstate the
    // measurement for every other publisher too.
    EXPECT_FALSE(out.signerPinned) << "the aggregate claimed more than every part had";
}

TEST(CscaRecordedState, EveryPublisherEstablishedSetsTheAggregate)
{
    const auto out = LibreSCRS::Darwin::detail::recordedStateFor(stateWith({signer(0xAB, true), signer(0xCD, true)}));
    EXPECT_TRUE(out.signerPinned);
}

TEST(CscaRecordedState, NoPublisherAtAllIsNotPinned)
{
    // Guards the aggregate's own vacuous case: all_of over an empty range is
    // true, and a record claiming an established publisher it does not have
    // would be the strongest possible overstatement.
    const auto out = LibreSCRS::Darwin::detail::recordedStateFor(stateWith({}));
    EXPECT_FALSE(out.signerPinned);
    EXPECT_TRUE(out.signer.empty());
}

// --- a report the cache no longer bears out ----------------------------------
//
// The store remembers what an import accepted so a client that has just
// connected can be told what is installed without one. That record can outlive
// what it describes: anchors deleted from the cache directory, or a cache that
// no longer establishes the pinned publisher, leave a claim behind with nothing
// under it -- and a claim of "903 anchors" over an empty directory is worse on a
// trust surface than showing nothing at all.
//
// Reconciling is the library's judgement (WHAT is stale) and this host's timing
// (WHEN to ask). Asserted here rather than taken on the library's word, because
// this host owning the timing means this host can simply never ask -- which is
// exactly what it did before, with every library test still green.

TEST(CscaReconciliation, ConstructionDiscardsAReportTheCacheDoesNotBearOut)
{
    const auto shared = std::filesystem::temp_directory_path() /
                        ("ld-fe-recon-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()));

    // The second rig is built while the FIRST is still alive, deliberately: a
    // Rig deletes its state directory on the way out, so tearing the first one
    // down before building the second hands the second an empty directory and
    // the assertion below passes with the reconciliation removed. That is what
    // the first draft did, and perturbing the call away is what exposed it.
    Rig first(nullptr, nullptr, shared);
    Agent::Config::CscaAnchorState recorded;
    recorded.anchors = 903;
    recorded.issuers = 146;
    recorded.replayRefusalActive = true;
    recorded.signer = std::string(64, 'a');
    recorded.signerPinned = true;
    recorded.acceptedAt = 1'700'000'000;
    recorded.origin = "import";
    first.core->configStore().recordCscaAnchorState(recorded);
    ASSERT_TRUE(first.core->configStore().cscaAnchorState().has_value())
        << "the fixture must record something for the reconciliation to have anything to discard";

    // Nothing was ever imported, so the cache under this root holds no anchor
    // and establishes no signer: the record above is a claim with nothing
    // behind it, which is the state a wiped cache leaves.
    Rig second(nullptr, nullptr, shared);
    EXPECT_FALSE(second.core->configStore().cscaAnchorState().has_value())
        << "a report the cache does not bear out was served as current";
}

TEST(CscaReconciliation, ConstructionLeavesAStoreWithNothingRecordedAlone)
{
    // Guards the guard. If construction cleared the key unconditionally the
    // test above would pass for the wrong reason, and this one would too -- so
    // it asserts the OTHER half: a second rig over a directory whose report was
    // never written must find the store no worse off, and must not have written
    // a cleared key into a file that had none.
    const auto shared = std::filesystem::temp_directory_path() /
                        ("ld-fe-recon2-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()));
    Rig first(nullptr, nullptr, shared);
    ASSERT_FALSE(first.core->configStore().cscaAnchorState().has_value());

    Rig second(nullptr, nullptr, shared);
    EXPECT_FALSE(second.core->configStore().cscaAnchorState().has_value());

    std::ifstream in(shared / "config.json");
    std::stringstream buffer;
    buffer << in.rdbuf();
    EXPECT_EQ(buffer.str().find("CscaAnchorState"), std::string::npos)
        << "a key nothing had recorded was written out by reconciling";
}

// --- a way out of the pin ----------------------------------------------------
//
// The rotation rule refuses a list signed by a publisher the agent does not
// follow unless it chains to an anchor already held. Right, and it has a
// consequence nobody chose: import one country's list, then be offered the ICAO
// collection, and every list in it is refused. Without a way out the protection
// is also a trap, and the only cure is knowing about a cache directory and
// deleting it by hand -- outside the authorization covering every other change
// to this store, which is the point of putting it on the wire at all.

TEST(SocketFrontend, ForgetCscaAnchorsClearsTheRecordedReport)
{
    Rig rig;
    confirmEverything(rig);

    Agent::Config::CscaAnchorState recorded;
    recorded.anchors = 903;
    recorded.issuers = 146;
    recorded.replayRefusalActive = true;
    recorded.signer = std::string(64, 'a');
    recorded.signerPinned = true;
    recorded.acceptedAt = 1'700'000'000;
    recorded.origin = "import";
    rig.core->configStore().recordCscaAnchorState(recorded);
    ASSERT_TRUE(rig.core->configStore().cscaAnchorState().has_value());

    const auto reply = rig.roundTrip(1, Agent::Wire::ForgetCscaAnchors{});
    ASSERT_NE(reply.find("t"), nullptr);
    // Not the envelope tag: a refusal is tagged "Reply" as well, and a gate on
    // the tag passed for every answer the verb could give.
    EXPECT_EQ(errName(reply), "") << "forgetting was refused";

    EXPECT_FALSE(rig.core->configStore().cscaAnchorState().has_value())
        << "the report survived the verb whose whole purpose is to remove it";

    // Zero, and correct: the count comes from the CACHE's own record of what it
    // believed it held, and nothing was ever imported into this rig's cache.
    // Counting files instead would put a second, disagreeing answer next to the
    // one every other surface here gives.
    ASSERT_NE(reply.find("anchorsForgotten"), nullptr);
    EXPECT_EQ(reply.find("anchorsForgotten")->asUInt().value_or(999u), 0u);
}

TEST(SocketFrontend, ForgetCscaAnchorsHoldingNothingIsNotAFailure)
{
    Rig rig;
    confirmEverything(rig);

    // An installation with nothing imported must not be told the operation
    // failed: there is a difference between "could not remove" and "there was
    // nothing to remove", and only the first is a refusal.
    const auto reply = rig.roundTrip(1, Agent::Wire::ForgetCscaAnchors{});
    ASSERT_NE(reply.find("t"), nullptr);
    EXPECT_EQ(errName(reply), "") << "holding nothing was reported as a failure";
    ASSERT_NE(reply.find("hadPinnedSigner"), nullptr);
    EXPECT_FALSE(reply.find("hadPinnedSigner")->asBool().value_or(true));
}

// The sentence the person reads before the anchors go. Import and forget share
// a config key, so the key cannot say which of the two is being asked for -- and
// a forget carrying the import's sentence, or the generic one, refuses and
// clears exactly the same way.
TEST(SocketFrontend, TheConfirmationForForgettingNamesWhatWillBeRemoved)
{
    Rig rig;
    wire::ConfirmAction seen;
    rig.frontend->setConfirmProvider([&seen](const wire::ConfirmAction& a) {
        seen = a;
        return wire::ConfirmReply{wire::PromptReplyStatus::Cancelled, {}};
    });

    static_cast<void>(rig.roundTrip(1, Agent::Wire::ForgetCscaAnchors{}));

    EXPECT_EQ(seen.kind, "configure_trust");
    EXPECT_EQ(seen.artifact, "CscaAnchorState");
    EXPECT_EQ(seen.description, "Remove every country signing certificate this computer holds.");
    EXPECT_EQ(seen.descriptionKey, "prompter_trust_forget");
}

TEST(SocketFrontend, ARefusedCallerForgetsNothing)
{
    DenyAllAuthorizer deny;
    Rig rig(&deny);
    confirmEverything(rig);

    Agent::Config::CscaAnchorState recorded;
    recorded.anchors = 903;
    recorded.issuers = 146;
    recorded.origin = "import";
    rig.core->configStore().recordCscaAnchorState(recorded);

    const auto reply = rig.roundTrip(1, Agent::Wire::ForgetCscaAnchors{});
    EXPECT_EQ(errName(reply), "NotAuthorized");

    // The assertion that matters. A refusal that still destroyed the anchors
    // would answer exactly like one that did not, so the reply cannot tell
    // these apart and the store is the only place the difference shows.
    EXPECT_TRUE(rig.core->configStore().cscaAnchorState().has_value())
        << "a caller the policy refused still cleared the report";
}

// --- which depositor an identity read is handed ------------------------------
//
// The identity and photo flows hand a renegotiated passport MRZ to the
// candidate plugins through a CredentialDepositor, and only the plugin registry
// can resolve those targets. The shared core offers a no-op for a wiring site
// that has no registry; this host HAS one, and for two months handed the flows
// a no-op of its own regardless, so a CAN prompt renegotiated into an MRZ read
// deposited nothing and the re-run failed auth. Which seam this host binds is a
// decision, and it gets a test of its own: nothing here can drive a
// renegotiation without a passport in a reader.

TEST(SocketFrontend, BindsTheRegistryBackedDepositorWhenComposedWithARegistry)
{
    // An empty plugin directory: a registry that resolves nothing, but a
    // registry -- which is all the binding decision looks at.
    const auto dir = std::filesystem::temp_directory_path() /
                     ("ld-fe-plugins-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()));
    std::filesystem::create_directories(dir);
    auto plugins = std::make_shared<LibreSCRS::Plugin::CardPluginService>(dir);

    Rig rig(nullptr, nullptr, {}, plugins);
    EXPECT_NE(dynamic_cast<Agent::Operations::LmCredentialDepositor*>(&rig.frontend->credentialDepositor()), nullptr)
        << "a host composed with a plugin registry bound the no-op depositor";

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

TEST(SocketFrontend, FallsBackToTheNoOpDepositorWithoutARegistry)
{
    Rig rig; // no registry
    EXPECT_NE(dynamic_cast<Agent::Operations::NullCredentialDepositor*>(&rig.frontend->credentialDepositor()), nullptr)
        << "a host with no registry must hand the flows the shared no-op, not nothing";
}

namespace {

// The bench roster: the two OMNIKEY slots share a serial and differ only in
// the bracketed product string, which is what tells the contact slot from its
// contactless twin. A single-interface Gemalto is the control. Readers 1..3,
// cards 11..13, one card per reader.
struct BenchReader
{
    Agent::ObjectId reader;
    Agent::ObjectId card;
    const char* name;
};
const std::array<BenchReader, 3> kBench{{
    {Agent::ObjectId(1), Agent::ObjectId(11), "Gemalto PC Twin Reader (69988A87) 02 00"},
    {Agent::ObjectId(2), Agent::ObjectId(12),
     "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (IM0O2C00NF10456904) 01 00"},
    {Agent::ObjectId(3), Agent::ObjectId(13),
     "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (IM0O2C00NF10456904) 00 00"},
}};

// Export the bench through the PRODUCTION presence path: onReaderPublished ->
// onCardPublished -> deferred held-session resolve on the reader's worker ->
// applyCardResolution -> publishCard, with the detached session factory so no
// PC/SC daemon is needed. Cards go in the order PresenceModel emits an
// insertion: the card object, then the reader's HasCard/Card flip. The fake
// resolver knows no plugin, so each resolve exhausts its retries and publishes
// the card with no capabilities -- the export still happens, which is what the
// hold is keyed on. Returns once every card is exported (bounded); a fatal
// failure here aborts only this helper, so callers wrap it in
// ASSERT_NO_FATAL_FAILURE.
void exportBench(Rig& rig)
{
    rig.core->operationManager().setSessionFactoryForTest(detachedSessionFactory());
    for (const auto& b : kBench) {
        Agent::ReaderState r;
        r.id = b.reader;
        r.name = b.name;
        rig.frontend->onReaderPublished(r);
    }
    for (const auto& b : kBench) {
        Agent::CardState c;
        c.id = b.card;
        c.reader = b.reader;
        rig.frontend->onCardPublished(c);
        rig.frontend->onReaderPropertiesChanged(b.reader, Agent::PropertyDelta{.hasCard = true, .card = b.card});
    }
    SocketTransport* trp = rig.transport.get();
    const auto publishedCards = [trp] {
        __block std::size_t n = 0;
        dispatch_sync(trp->loopQueue(), ^{
          n = trp->currentState().cards.size();
        });
        return n;
    };
    const auto start = std::chrono::steady_clock::now();
    while (publishedCards() < kBench.size() && std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_EQ(publishedCards(), kBench.size()) << "every card was exported within 5 s";
}

} // namespace

// Export of a card on the CONTACT slot of a dual-interface unit asks the
// reader's worker for a bare power hold, so the same single-chip card's
// contactless twin stops flapping in and out of the CL slot; a card on the CL
// slot, or in a single-interface reader, never does. Read back through the
// operation manager's hold flag -- the thing the worker acts on -- not through
// a log line. All three workers exist after the export (each card resolved on
// its own), so a false here is the flag, not an absent worker.
TEST(SocketFrontend, ExportOfAContactSlotCardHoldsTheReaderAndOtherSlotsDoNot)
{
    Rig rig;
    ASSERT_NO_FATAL_FAILURE(exportBench(rig));

    auto& ops = rig.core->operationManager();
    EXPECT_TRUE(ops.isReaderHeldForTest(Agent::ObjectId(2))) << "the OMNIKEY contact slot is held on export";
    EXPECT_FALSE(ops.isReaderHeldForTest(Agent::ObjectId(3))) << "the OMNIKEY CL slot is never held";
    EXPECT_FALSE(ops.isReaderHeldForTest(Agent::ObjectId(1))) << "a single-interface reader is never held";
}

// The prompt gate stamps every dialog with the reader holding the card. The
// rig installs the resolver through the SAME helper main.cpp calls
// (installReaderIdentityResolver), so this drives the composed lookup -- core
// -> resolver -> transport roster -> core labelling -- rather than the seam in
// isolation. Before that helper existed, the daemon never set a resolver and
// every macOS prompt named no reader.
TEST(SocketFrontend, ThePromptGateNamesTheReaderHoldingTheCard)
{
    Rig rig;
    ASSERT_NO_FATAL_FAILURE(exportBench(rig));

    const auto& gate = rig.core->promptSerializer();
    const auto contact = gate.readerIdentityFor("12");
    EXPECT_EQ(contact.iface, Agent::ReaderInterface::Contact);
    EXPECT_EQ(contact.full, kBench[1].name);
    EXPECT_FALSE(contact.model.empty());
    EXPECT_EQ(gate.readerIdentityFor("13").iface, Agent::ReaderInterface::Contactless);
    const auto single = gate.readerIdentityFor("11");
    EXPECT_EQ(single.iface, Agent::ReaderInterface::Unknown);
    EXPECT_EQ(single.full, kBench[0].name);
    EXPECT_EQ(gate.readerIdentityFor("99"), Agent::ReaderIdentity{}) << "a card that is gone names no reader";
}

// Card removal clears the hold flag, so a later idle sweep cannot re-acquire a
// hold on an empty reader. Driven through releaseReaderOnCardRemoved() -- the
// SHARED helper main.cpp's card-removed hook calls -- so the release is under
// test rather than re-mirrored by hand: dropping it from the helper fails here
// AND in production together. The helper's release-then-invalidate ORDER is a
// documented convention, not an observable: the worker handles both flags in
// one pass and ends in releaseHold() either way, so no seam can tell the two
// orders apart.
TEST(SocketFrontend, CardRemovalReleasesTheHold)
{
    Rig rig;
    ASSERT_NO_FATAL_FAILURE(exportBench(rig));
    auto& ops = rig.core->operationManager();
    ASSERT_TRUE(ops.isReaderHeldForTest(Agent::ObjectId(2)));

    // The exact production removal code (not a re-implementation).
    Agent::releaseReaderOnCardRemoved(ops, Agent::ObjectId(2));

    EXPECT_FALSE(ops.isReaderHeldForTest(Agent::ObjectId(2))) << "the flag is the host's to clear on removal";
    EXPECT_FALSE(ops.isReaderHeldForTest(Agent::ObjectId(3))) << "an unrelated reader is untouched";
}

// A withdrawn READER takes its worker with it, as the Linux host's unexport
// does. Without that, the worker outlives the reader with its hold flag set,
// and its 45 s sweep keeps re-acquiring a hold BY READER NAME: a same-named
// unit plugged back in with a card in the contact slot is then held by an
// orphan no card-removed hook can reach (the hook targets the new reader id).
// Observed through the one seam that tells "worker gone" from "flag false":
// setReaderHold is a silent no-op without a worker, so a set that does not
// land proves the worker is gone. Reader 1's worker, never withdrawn, is the
// control that the probe itself works.
TEST(SocketFrontend, AWithdrawnReaderTakesItsWorkerAndItsHoldWithIt)
{
    Rig rig;
    ASSERT_NO_FATAL_FAILURE(exportBench(rig));
    auto& ops = rig.core->operationManager();
    ASSERT_TRUE(ops.isReaderHeldForTest(Agent::ObjectId(2)));

    // The order PresenceModel emits on unplug: the card, then the reader.
    rig.frontend->onWithdrawn(Agent::ObjectId(12));
    rig.frontend->onWithdrawn(Agent::ObjectId(2));
    dispatch_sync(rig.transport->loopQueue(), ^{
                  }); // both withdraws have run

    ops.setReaderHold(Agent::ObjectId(2), true);
    EXPECT_FALSE(ops.isReaderHeldForTest(Agent::ObjectId(2)))
        << "the flag landed: a worker survived the reader that owned it";

    ops.setReaderHold(Agent::ObjectId(1), true);
    EXPECT_TRUE(ops.isReaderHeldForTest(Agent::ObjectId(1))) << "control: a live reader's worker takes the flag";
    ops.setReaderHold(Agent::ObjectId(1), false);
}
