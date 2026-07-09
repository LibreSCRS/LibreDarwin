// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SocketFrontend inbound dispatch over a real bound socket + a blocking client,
// against a real LibreAgent::Core wired to hermetic fakes (no PC/SC): each
// request routes to the right core call, replies carry the correct `req`, and
// the method-entry gates map to the right sync-error. The card-op worker path +
// broker path are exercised by the PIN-guarded hardware gate, not here.
#include <LibreSCRS/Darwin/backend/SocketFrontend.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Darwin/backend/wire/Cbor.h>
#include <LibreSCRS/Darwin/backend/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/Messages.h>

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>

#include <gtest/gtest.h>

#include <dispatch/dispatch.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <optional>
#include <string>

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

    Rig()
    {
        std::filesystem::create_directories(tmp);
        transport = std::move(*SocketTransport::create(path));
        core.emplace(
            resolver, *transport, authz, prompter, tmp / "config.json", tmp / "cache",
            [](const std::string&) -> std::optional<Agent::ReaderCard> { return std::nullopt; },
            [](const std::string&) -> std::optional<Agent::ObjectId> { return std::nullopt; });
        frontend.emplace(*transport, *core, "0.1-test");
        frontend->start();
    }

    ~Rig()
    {
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

} // namespace
