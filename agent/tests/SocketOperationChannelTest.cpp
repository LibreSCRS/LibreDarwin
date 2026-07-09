// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SocketOperationChannel over a real transport + client: OpProgress/OpFinished
// events and a Sign result whose artifact rides an SCM_RIGHTS fd (shm_open) the
// client reads back.
#include <LibreSCRS/Darwin/backend/SocketOperationChannel.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Darwin/backend/wire/Cbor.h>
#include <LibreSCRS/Darwin/backend/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/Messages.h>

#include <gtest/gtest.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

using namespace LibreSCRS::Darwin;
namespace Ops = ::LibreSCRS::Agent::Operations;

namespace {

std::string uniquePath()
{
    return "/tmp/ld-oc-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()) + ".sock";
}

int connectClient(const std::string& path)
{
    const int c = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    EXPECT_EQ(::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    return c;
}

// Establish a connection, return (transport, client fd, connId).
struct Wired
{
    std::unique_ptr<SocketTransport> tr;
    int client{-1};
    std::uint64_t connId{0};
    std::string path;
};

Wired wireUp()
{
    Wired w;
    w.path = uniquePath();
    w.tr = std::move(*SocketTransport::create(w.path));

    std::mutex m;
    std::condition_variable cv;
    std::atomic<std::uint64_t> id{0};
    w.tr->setRequestSink([&](SocketTransport::Inbound&& in) {
        id.store(in.connId);
        cv.notify_all();
    });
    w.client = connectClient(w.path);
    const auto hello = wire::toCbor(wire::RequestEnvelope{1, wire::Hello{1, std::nullopt}}).encode();
    EXPECT_TRUE(wire::sendFrame(w.client, hello).has_value());
    std::unique_lock<std::mutex> lk(m);
    cv.wait_for(lk, std::chrono::seconds(2), [&] { return id.load() != 0; });
    w.connId = id.load();
    return w;
}

wire::CborValue recvEvent(int client)
{
    auto frame = wire::recvFrame(client);
    EXPECT_TRUE(frame.has_value());
    auto decoded = wire::decode(frame->body);
    EXPECT_TRUE(decoded.has_value());
    return *decoded;
}

TEST(SocketOperationChannel, EmitsProgressAndFinished)
{
    Wired w = wireUp();
    ASSERT_NE(w.connId, 0u);
    auto state = std::make_shared<Ops::OperationState>();
    state->phase.store(static_cast<std::uint32_t>(Ops::OperationPhase::Signing));
    SocketOperationChannel channel(*w.tr, w.connId, 77, state);

    channel.emitPropertiesChanged();
    const auto progress = recvEvent(w.client);
    EXPECT_EQ(*progress.find("t")->asText(), "OpProgress");
    EXPECT_EQ(progress.find("op")->asUInt(), 77u);
    EXPECT_EQ(progress.find("phase")->asUInt(), static_cast<std::uint64_t>(Ops::OperationPhase::Signing));

    channel.emitFinished(Ops::OperationStatus::Ok, LibreSCRS::Agent::ErrorCode::None, "k", "f");
    const auto finished = recvEvent(w.client);
    EXPECT_EQ(*finished.find("t")->asText(), "OpFinished");
    EXPECT_EQ(finished.find("status")->asUInt(), static_cast<std::uint64_t>(Ops::OperationStatus::Ok));

    ::close(w.client);
    w.tr.reset();
    std::filesystem::remove(w.path);
}

TEST(SocketOperationChannel, SignResultRidesAnScmRightsFd)
{
    Wired w = wireUp();
    ASSERT_NE(w.connId, 0u);
    auto state = std::make_shared<Ops::OperationState>();
    SocketOperationChannel channel(*w.tr, w.connId, 9, state);

    Ops::SignedArtifact artifact;
    artifact.bytes = {'S', 'I', 'G', 'N', 'E', 'D'};
    artifact.meta = Ops::SignMeta{"pades", "b-lta", true, false};
    EXPECT_TRUE(channel.emitResult(Ops::ResultPayload{artifact}));

    auto frame = wire::recvFrame(w.client);
    ASSERT_TRUE(frame.has_value());
    ASSERT_EQ(frame->fds.size(), 1u); // one artifact fd
    const auto decoded = wire::decode(frame->body);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded->find("t")->asText(), "OpResultReady");
    const auto* res = decoded->find("result");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(*res->find("kind")->asText(), "Sign");
    EXPECT_EQ(res->find("artifact")->asUInt(), 0u); // fd-index 0

    // Read the artifact bytes back from the passed fd.
    const int fd = frame->fds[0].get();
    char buf[16] = {0};
    const ssize_t n = ::pread(fd, buf, sizeof(buf), 0);
    ASSERT_EQ(n, 6);
    EXPECT_EQ(std::string(buf, 6), "SIGNED");

    ::close(w.client);
    w.tr.reset();
    std::filesystem::remove(w.path);
}

} // namespace
