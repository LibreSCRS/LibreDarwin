// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

// The socket-host test rig: a bound SocketTransport, a real AgentCore wired to
// hermetic fakes (no PC/SC), and the SocketFrontend started over them -- plus
// the blocking client round-trip that drives one request through the whole
// stack and hands back the decoded reply.
//
// Shared between SocketFrontendTest (every verb's entry gates and the
// credentials ops) and CscaImportSocketTest (the anchor-import verb, which
// needs a signed master list and so links the agent's fixture archive). One
// rig, because a second copy would be a second place for the quiesce-then-drain
// teardown below to be got wrong -- and it was got wrong once already.
//
// Test-only: nothing here is installed or reachable from a production target.

#include <LibreSCRS/Darwin/backend/SocketFrontend.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Agent/wire/Cbor.h>
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Agent/wire/Messages.h>

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/presence/CapabilityResolver.h>

#include <gtest/gtest.h>

#include <dispatch/dispatch.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace LibreSCRS::Plugin {
class CardPluginService;
}

namespace LibreSCRS::Darwin::TestSupport {

namespace Agent = ::LibreSCRS::Agent;

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
    [[nodiscard]] Agent::AuthorizationOutcome authorize(std::string_view /*actionId*/,
                                                        const Agent::CallerToken& /*caller*/) override
    {
        return Agent::AuthorizationOutcome::Denied;
    }
};

inline std::string uniqueSocketPath()
{
    return "/tmp/ld-fe-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()) + ".sock";
}

inline int connectClient(const std::string& path)
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
    // tmpOverride lets a test build a SECOND rig over the FIRST one's state
    // directory -- the only way to observe what construction does to a report
    // that was already on disk, which is a restart in everything but name.
    // plugins is the card-plugin registry the frontend is composed with; the
    // default, none, is what every hermetic case wants.
    explicit Rig(Agent::Authorizer* authorizerOverride = nullptr,
                 std::shared_ptr<Agent::Operations::PrompterClientBase> prompterOverride = nullptr,
                 std::filesystem::path tmpOverride = {},
                 std::shared_ptr<LibreSCRS::Plugin::CardPluginService> plugins = nullptr)
    {
        if (!tmpOverride.empty()) {
            tmp = std::move(tmpOverride);
        }
        std::filesystem::create_directories(tmp);
        transport = std::move(*SocketTransport::create(path));
        core.emplace(
            resolver, *transport, authorizerOverride != nullptr ? *authorizerOverride : authz,
            prompterOverride != nullptr ? std::move(prompterOverride)
                                        : std::shared_ptr<Agent::Operations::PrompterClientBase>(prompter),
            tmp / "config.json", tmp / "cache",
            [](const std::string&) -> std::optional<Agent::ReaderCard> { return std::nullopt; },
            [](const std::string&) -> std::optional<Agent::ObjectId> { return std::nullopt; });
        frontend.emplace(*transport, *core, "0.1-test", std::move(plugins));
        frontend->start();
    }

    ~Rig()
    {
        // Quiesce the loop BEFORE draining and releasing the frontend: the
        // drop-flag makes every subsequently-run posted block — including a sign
        // worker's op-owner prune continuation that captures the frontend — a
        // no-op, so the drain then flushes only already-live work and the
        // frontend dies unreferenced. This is the quiesce-then-drain ordering
        // main.cpp and SignHwSmokeTest's teardown use; the bare drain alone raced
        // an in-flight worker's post, running it against a freed frontend
        // (use-after-free).
        //
        // Guarded on the transport, so a case that has already performed this
        // teardown BY HAND -- the one that has to answer a confirmation after
        // every piece is gone -- is destroyed without dereferencing the
        // transport it released. The resets below are already no-ops on an
        // empty optional / unique_ptr, and the two removals below still run, so
        // a hand-torn-down rig still cleans up after itself.
        if (transport != nullptr) {
            transport->quiesceLoop();
            dispatch_sync(transport->loopQueue(), ^{
                          });
        }
        frontend.reset();
        core.reset();
        transport.reset();
        std::filesystem::remove(path);
        std::error_code ec;
        std::filesystem::remove_all(tmp, ec);
    }

    // Send a request envelope, block for its correlated reply, and return the
    // decoded reply map. @p fds rides SCM_RIGHTS alongside the frame (empty
    // for every request that carries no descriptor; Sign, SignBatch and
    // ImportCscaMasterList address it by 0-based index) — sendFrame already
    // supports this (Framing.h), so no new wire mechanism is introduced here,
    // only a test-side parameter.
    Agent::Wire::CborValue roundTrip(std::uint64_t req, Agent::Wire::Request body, std::span<const int> fds = {})
    {
        const int client = connectClient(path);
        const auto bytes = Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{req, std::move(body)}).encode();
        EXPECT_TRUE(Agent::Wire::sendFrame(client, bytes, fds).has_value());
        const auto frame = Agent::Wire::recvFrame(client);
        EXPECT_TRUE(frame.has_value());
        const auto decoded = Agent::Wire::decode(frame->body);
        EXPECT_TRUE(decoded.has_value());
        ::close(client);
        return decoded.value_or(Agent::Wire::CborValue{});
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

inline std::string errName(const Agent::Wire::CborValue& reply)
{
    const auto* err = reply.find("err");
    if (err == nullptr) {
        return {};
    }
    const auto* name = err->find("name");
    return (name != nullptr && name->asText() != nullptr) ? *name->asText() : std::string{};
}

// A regular, seekable temp file holding @p bytes for an input descriptor — the
// socket frontend's readDocument only requires a regular file (rejecting
// pipes/sockets), so a plain unlinked temp file suffices; unlike
// SignHwSmokeTest.cpp's on-disk fixture this one never needs a name once
// opened. Portable (no memfd_create, which does not exist on Darwin).
inline int makeInputFile(std::string_view bytes)
{
    char path[] = "/tmp/ld-fe-sign-XXXXXX";
    const int fd = ::mkstemp(path);
    if (fd < 0) {
        return -1;
    }
    ::unlink(path);
    if (::write(fd, bytes.data(), bytes.size()) != static_cast<ssize_t>(bytes.size())) {
        ::close(fd);
        return -1;
    }
    ::lseek(fd, 0, SEEK_SET);
    return fd;
}

// Trust-tier calls stop at a human confirmation before any work runs. A rig
// without a provider answers NotAuthorized to all of them, which would make a
// case measure the confirmation step rather than the verb -- the exact
// shape that let a config-surface gate pass with its branch deleted.
inline void confirmEverything(Rig& rig)
{
    rig.frontend->setConfirmProvider([](const auto&) {
        return LibreSCRS::Darwin::wire::ConfirmReply{LibreSCRS::Darwin::wire::PromptReplyStatus::Ok, ""};
    });
}

// A persistent client connection: sends requests and reads frames (replies AND
// unsolicited op events) on ONE socket, so op events arrive here, an
// owner-scoped CancelOp shares the caller token with the op it cancels, and a
// rate-limit budget can be spent the way a real client spends it. @p fds on
// send rides SCM_RIGHTS exactly as in Rig::roundTrip.
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

    void send(std::uint64_t req, Agent::Wire::Request body, std::span<const int> fds = {})
    {
        const auto bytes = Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{req, std::move(body)}).encode();
        EXPECT_TRUE(Agent::Wire::sendFrame(fd, bytes, fds).has_value());
    }

    Agent::Wire::CborValue recv()
    {
        const auto frame = Agent::Wire::recvFrame(fd);
        EXPECT_TRUE(frame.has_value());
        if (!frame) {
            return {};
        }
        const auto decoded = Agent::Wire::decode(frame->body);
        EXPECT_TRUE(decoded.has_value());
        return decoded.value_or(Agent::Wire::CborValue{});
    }

    // Read frames until one tagged @p tag arrives (skipping OpProgress and any
    // other interleaved event), and return it. Bounded so a missing frame fails
    // the test instead of wedging it. An error reply is tagged "Reply" too --
    // the tag says which envelope arrived, errName() says whether it refused.
    Agent::Wire::CborValue waitFor(std::string_view tag, int maxFrames = 32)
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

} // namespace LibreSCRS::Darwin::TestSupport
