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
#include <LibreSCRS/Darwin/backend/wire/Cbor.h>
#include <LibreSCRS/Darwin/backend/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/Messages.h>

#include "CardRemovalCaches.h" // invalidateCardRemovalCaches (the production removal-invalidation code)
#include "FullScrubCaches.h"   // clearFullScrubCaches (the production fullScrub cache-clearing code)

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/OperationPhase.h> // OperationStatus
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h> // SessionFactory
#include <LibreSCRS/Agent/operations/OperationManager.h>  // setSessionFactoryForTest
#include <LibreSCRS/Agent/operations/RateLimiter.h>       // kMaxPerWindow
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialSnapshot
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>    // ErrorCode
#include <LibreSCRS/SmartCard/CardSession.h>        // detail::makeDetachedCardSession (LIBRESCRS_INTERNAL_BUILD)
#include <LibreSCRS/Secure/String.h>                // the BlockingPrompter's dummy Ok secrets

#include <gtest/gtest.h>

#include <dispatch/dispatch.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

using namespace LibreSCRS::Darwin;
namespace Agent = ::LibreSCRS::Agent;

namespace {

// Hermetic fakes: the resolver returns nothing (no plugin), the prompter is
// never reached on the tested paths, the seams resolve nothing.
struct FakeResolver final : Agent::CapabilityResolver
{};

struct NoPrompter final : Agent::Operations::PrompterClientBase
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
};

// Denies every action — the "site policy forbids it" arm of the credentials
// authorization gate.
struct DenyAllAuthorizer final : Agent::Authorizer
{
    [[nodiscard]] bool authorize(std::string_view /*actionId*/, const Agent::CallerToken& /*caller*/) override
    {
        return false;
    }
};

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

// Blocks the change modal until cancel() — the op's prompter-cancel hook — fires,
// then reports Cancelled: the mid-prompt CancelOp shape. If the deadline lapses
// with no cancel, it reports Ok with dummy secrets instead — a bounded FAILURE
// path (the op proceeds and misses the userCancelled asserts), so only a real
// cancel() can produce the Cancelled outcome the test pins.
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
            // Deadline hit with no cancel(): report Ok with dummy secrets, NOT
            // Cancelled — a cancel that never reaches the prompter must fail
            // the userCancelled asserts, not impersonate a genuine cancel.
            return Agent::PinChangePromptResult{Agent::PromptStatus::Ok, LibreSCRS::Secure::String{"0000"},
                                                LibreSCRS::Secure::String{"123456"}, ""};
        }
        return Agent::PinChangePromptResult{Agent::PromptStatus::Cancelled, std::nullopt, std::nullopt, ""};
    }
    void cancel() noexcept override
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

std::string uniqueSocketPath()
{
    return "/tmp/ld-fe-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()) + ".sock";
}

int connectClient(const std::string& path)
{
    const int c = ::socket(AF_UNIX, SOCK_STREAM, 0);
    EXPECT_GE(c, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    EXPECT_EQ(::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    return c;
}

// Full test rig: a bound transport + a real AgentCore + the frontend started.
struct Rig
{
    std::string path{uniqueSocketPath()};
    std::unique_ptr<SocketTransport> transport;
    FakeResolver resolver;
    Agent::AllowAllAuthorizer authz;
    std::shared_ptr<NoPrompter> prompter{std::make_shared<NoPrompter>()};
    std::filesystem::path tmp{std::filesystem::temp_directory_path() /
                              ("ld-fe-core-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()))};
    std::optional<Agent::AgentCore> core;
    std::optional<SocketFrontend> frontend;

    // Overrides let the credentials tests swap the policy gate (deny-all) or the
    // prompter (cancelling / blocking multi-secret fakes) while every other test
    // keeps the hermetic defaults.
    explicit Rig(Agent::Authorizer* authorizerOverride = nullptr,
                 std::shared_ptr<Agent::Operations::PrompterClientBase> prompterOverride = nullptr)
    {
        std::filesystem::create_directories(tmp);
        transport = std::move(*SocketTransport::create(path));
        core.emplace(
            resolver, *transport, authorizerOverride != nullptr ? *authorizerOverride : authz,
            prompterOverride != nullptr ? std::move(prompterOverride)
                                        : std::shared_ptr<Agent::Operations::PrompterClientBase>(prompter),
            tmp / "config.json", tmp / "cache",
            [](const std::string&) -> std::optional<Agent::ReaderCard> { return std::nullopt; },
            [](const std::string&) -> std::optional<Agent::ObjectId> { return std::nullopt; });
        frontend.emplace(*transport, *core, "0.1-test");
        frontend->start();
    }

    ~Rig()
    {
        // Drain the loop first so a worker-posted continuation that captures the
        // frontend (the op-owner prune sink) runs before the frontend dies —
        // the same quiesce-then-drain ordering main.cpp's teardown uses.
        dispatch_sync(transport->loopQueue(), ^{
                      });
        frontend.reset();
        core.reset();
        transport.reset();
        std::filesystem::remove(path);
        std::error_code ec;
        std::filesystem::remove_all(tmp, ec);
    }

    // Send a request envelope, block for its correlated reply, and return the
    // decoded reply map.
    wire::CborValue roundTrip(std::uint64_t req, wire::Request body)
    {
        const int client = connectClient(path);
        const auto bytes = wire::toCbor(wire::RequestEnvelope{req, std::move(body)}).encode();
        EXPECT_TRUE(wire::sendFrame(client, bytes).has_value());
        const auto frame = wire::recvFrame(client);
        EXPECT_TRUE(frame.has_value());
        const auto decoded = wire::decode(frame->body);
        EXPECT_TRUE(decoded.has_value());
        ::close(client);
        return decoded.value_or(wire::CborValue{});
    }

    // Inject a reader + card into the transport presence directly (bypassing the
    // deferred resolve), so a card-op gate can be exercised hermetically.
    std::string injectCard(std::uint32_t caps)
    {
        SocketTransport* trp = transport.get();
        dispatch_sync(transport->loopQueue(), ^{
          Agent::ReaderState r;
          r.id = Agent::ObjectId(7);
          r.name = "Test Reader";
          r.hasCard = true;
          r.card = Agent::ObjectId(8);
          trp->publishReader(r);
          Agent::CardState c;
          c.id = Agent::ObjectId(8);
          c.reader = Agent::ObjectId(7);
          c.capabilities = caps;
          trp->publishCard(c);
        });
        // The card wire handle is minted deterministically as obj/<n>; resolve it
        // from the snapshot rather than hard-coding.
        __block std::string handle;
        dispatch_sync(transport->loopQueue(), ^{
          for (const auto& cs : trp->currentState().cards) {
              handle = cs.handle;
          }
        });
        return handle;
    }
};

std::string errName(const wire::CborValue& reply)
{
    const auto* err = reply.find("err");
    if (err == nullptr) {
        return {};
    }
    const auto* name = err->find("name");
    return (name != nullptr && name->asText() != nullptr) ? *name->asText() : std::string{};
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

// A persistent client connection: sends requests and reads frames (replies AND
// unsolicited op events) on ONE socket, so op events arrive here and an
// owner-scoped CancelOp shares the caller token with the op it cancels.
struct Client
{
    int fd{-1};

    explicit Client(const std::string& path) : fd(connectClient(path)) {}
    ~Client()
    {
        if (fd >= 0) {
            ::close(fd);
        }
    }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    void send(std::uint64_t req, wire::Request body)
    {
        const auto bytes = wire::toCbor(wire::RequestEnvelope{req, std::move(body)}).encode();
        EXPECT_TRUE(wire::sendFrame(fd, bytes).has_value());
    }

    wire::CborValue recv()
    {
        const auto frame = wire::recvFrame(fd);
        EXPECT_TRUE(frame.has_value());
        if (!frame) {
            return {};
        }
        const auto decoded = wire::decode(frame->body);
        EXPECT_TRUE(decoded.has_value());
        return decoded.value_or(wire::CborValue{});
    }

    // Read frames until one tagged @p tag arrives (skipping OpProgress and any
    // other interleaved event), and return it. Bounded so a missing frame fails
    // the test instead of wedging it.
    wire::CborValue waitFor(std::string_view tag, int maxFrames = 32)
    {
        for (int i = 0; i < maxFrames; ++i) {
            auto msg = recv();
            const auto* t = msg.find("t");
            if (t != nullptr && t->asText() != nullptr && *t->asText() == tag) {
                return msg;
            }
        }
        ADD_FAILURE() << "no frame tagged " << tag << " within " << maxFrames << " frames";
        return {};
    }
};

TEST(SocketFrontend, HelloReturnsAck)
{
    Rig rig;
    const auto reply = rig.roundTrip(1, wire::Hello{1, std::nullopt});
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
    const auto reply = rig.roundTrip(2, wire::GetState{});
    ASSERT_NE(reply.find("readers"), nullptr);
    ASSERT_NE(reply.find("cards"), nullptr);
}

TEST(SocketFrontend, ReadIdentityUnknownCardIsUnknownCard)
{
    Rig rig;
    const auto reply = rig.roundTrip(3, wire::ReadIdentity{"obj/999"});
    EXPECT_EQ(errName(reply), "UnknownCard");
}

TEST(SocketFrontend, SignOnNonPkiCardIsUnsupported)
{
    Rig rig;
    const std::string card = rig.injectCard(kIdentityCap); // no PKI bit
    const auto reply = rig.roundTrip(4, wire::Sign{card, "cert-id", 0, wire::SignOpts{"pades", "b-b", "enveloped"}});
    EXPECT_EQ(errName(reply), "UnsupportedOnThisCard");
}

TEST(SocketFrontend, SignWithEmptyCertIsRejected)
{
    Rig rig;
    const std::string card = rig.injectCard(kPkiCap);
    const auto reply = rig.roundTrip(5, wire::Sign{card, "", 0, wire::SignOpts{"pades", "b-b", "enveloped"}});
    EXPECT_EQ(errName(reply), "UnsupportedSignatureParameter");
}

TEST(SocketFrontend, SetReadOnlyConfigKeyIsRejected)
{
    Rig rig;
    const auto reply = rig.roundTrip(6, wire::SetConfig{"LastTsaUrl", wire::CborValue(std::string{"x"})});
    EXPECT_EQ(errName(reply), "ReadOnlyConfig");
}

TEST(SocketFrontend, SetUnknownConfigKeyIsRejected)
{
    Rig rig;
    const auto reply = rig.roundTrip(7, wire::SetConfig{"Nonexistent", wire::CborValue(std::string{"x"})});
    EXPECT_EQ(errName(reply), "UnknownConfigKey");
}

TEST(SocketFrontend, SetDefaultLevelSucceeds)
{
    Rig rig;
    const auto reply = rig.roundTrip(8, wire::SetConfig{"DefaultLevel", wire::CborValue(std::string{"b-t"})});
    ASSERT_NE(reply.find("ok"), nullptr);
    EXPECT_TRUE(reply.find("ok")->asBool().value_or(false));
}

TEST(SocketFrontend, GetConfigReturnsEntries)
{
    Rig rig;
    const auto reply = rig.roundTrip(9, wire::GetConfig{});
    const auto* entries = reply.find("entries");
    ASSERT_NE(entries, nullptr);
    ASSERT_NE(entries->asMap(), nullptr);
    EXPECT_NE(entries->find("DefaultLevel"), nullptr);
}

TEST(SocketFrontend, CancelReturnsAck)
{
    Rig rig;
    const auto reply = rig.roundTrip(10, wire::CancelOp{999});
    ASSERT_NE(reply.find("ok"), nullptr);
    EXPECT_TRUE(reply.find("ok")->asBool().value_or(false));
}

TEST(SocketFrontend, GetSignResultUnknownOpIsKeyNotFound)
{
    Rig rig;
    const auto reply = rig.roundTrip(11, wire::GetSignResult{999});
    EXPECT_EQ(errName(reply), "KeyNotFound");
}

// --- credentials (PIN/PUK management over the socket) -------------------------

TEST(SocketFrontend, HelloAdvertisesCredentialsFeature)
{
    Rig rig;
    const auto reply = rig.roundTrip(20, wire::Hello{1, std::nullopt});
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
    const auto reply = rig.roundTrip(21, wire::ManagePin{card, "user:0x01", "change", std::nullopt});
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

    const auto badVerb = rig.roundTrip(22, wire::ManagePin{card, "user:0x01", "frobnicate", std::nullopt});
    EXPECT_EQ(errName(badVerb), "InvalidRequest");

    const auto badCombo = rig.roundTrip(23, wire::ManagePin{card, "user:0x01", "change", true});
    EXPECT_EQ(errName(badCombo), "InvalidRequest");

    const auto noListing = rig.roundTrip(24, wire::ManagePin{card, "user:0x01", "change", std::nullopt});
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
    const auto reply = rig.roundTrip(25, wire::ManagePin{card, "user:0x01", "change", std::nullopt});
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
    const auto reply = rig.roundTrip(26, wire::ManagePin{card, "user:0x01", "change", std::nullopt});
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
    const auto reply = rig.roundTrip(32, wire::ManagePin{card, "user:0x01", "change", std::nullopt});
    EXPECT_EQ(errName(reply), "NotAuthorized");
}

TEST(SocketFrontend, ListCredentialsWithoutPinManagementCapIsUnsupported)
{
    Rig rig;
    const std::string card = rig.injectCard(kIdentityCap); // no PinManagement bit
    const auto reply = rig.roundTrip(27, wire::ListCredentials{card});
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
    client.send(28, wire::ListCredentials{card});
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
    client.send(33, wire::ListCredentials{card});
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
    const auto reply = rig.roundTrip(34, wire::ActivateSigningKey{card});
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
    const auto reply = rig.roundTrip(35, wire::ActivateSigningKey{card});
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
    client.send(29, wire::ManagePin{card, "user:0x01", "change", std::nullopt});
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
    client.send(30, wire::ManagePin{card, "user:0x01", "change", std::nullopt});
    const auto reply = client.waitFor("Reply");
    EXPECT_EQ(errName(reply), "");
    const auto* op = reply.find("op");
    ASSERT_NE(op, nullptr);
    const std::uint64_t opId = op->asUInt().value_or(0);

    ASSERT_TRUE(prompter->waitEntered()) << "the change modal must be up before the cancel";

    client.send(31, wire::CancelOp{opId});
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

} // namespace
