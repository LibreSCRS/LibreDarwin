// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SocketTransport end-to-end over a real bound socket + a blocking client:
// accept + peer identity, inbound request -> sink, publish -> broadcast event,
// post marshaling, and the client-disconnect fan-out (registration order). The
// transport's own serial dispatch queue is serviced by GCD (no run loop needed);
// loop-affine calls are marshaled with dispatch_sync.
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Darwin/backend/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/Messages.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

using namespace LibreSCRS::Darwin;

namespace {

namespace Agent = ::LibreSCRS::Agent;

std::string uniqueSocketPath()
{
    // Short path (well under sun_path 104) for the test socket.
    return "/tmp/ld-tt-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()) + ".sock";
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

// A synchronized latch for values produced on the loop thread.
template <class T>
struct Latch
{
    std::mutex m;
    std::condition_variable cv;
    std::vector<T> items;
    void push(T v)
    {
        std::lock_guard<std::mutex> lk(m);
        items.push_back(std::move(v));
        cv.notify_all();
    }
    bool waitFor(std::size_t n, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lk(m);
        return cv.wait_for(lk, timeout, [&] { return items.size() >= n; });
    }
};

TEST(SocketTransport, InboundRequestReachesSinkWithPeerToken)
{
    const std::string path = uniqueSocketPath();
    auto created = SocketTransport::create(path);
    ASSERT_TRUE(created.has_value()) << (created ? "" : created.error());
    auto tr = std::move(*created);

    Latch<std::pair<std::string, std::size_t>> sink; // (caller, request index)
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push({in.caller.str(), in.request.body.index()}); });

    const int client = connectClient(path);
    // Send a Hello request.
    const auto helloBytes = wire::toCbor(wire::RequestEnvelope{1, wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(wire::sendFrame(client, helloBytes).has_value());

    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2)));
    {
        std::lock_guard<std::mutex> lk(sink.m);
        EXPECT_EQ(sink.items[0].first.rfind("conn:", 0), 0u); // caller is "conn:<n>"
        EXPECT_EQ(sink.items[0].second, 0u);                  // Hello is variant index 0
    }

    ::close(client);
    tr.reset();
    std::filesystem::remove(path);
}

TEST(SocketTransport, PublishBroadcastsEventToClient)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });

    const int client = connectClient(path);
    const auto helloBytes = wire::toCbor(wire::RequestEnvelope{1, wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(wire::sendFrame(client, helloBytes).has_value());
    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2))); // connection is up

    // Publish a reader on the loop; the client should receive a ReaderAdded event.
    SocketTransport* trp = tr.get();
    dispatch_sync(tr->loopQueue(), ^{
      Agent::ReaderState r;
      r.id = Agent::ObjectId(7);
      r.name = "Test Reader";
      r.hasCard = false;
      trp->publishReader(r);
    });

    const auto frame = wire::recvFrame(client);
    ASSERT_TRUE(frame.has_value());
    const auto decoded = wire::decode(frame->body);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_NE(decoded->find("t"), nullptr);
    EXPECT_EQ(*decoded->find("t")->asText(), "ReaderAdded");
    const auto* reader = decoded->find("reader");
    ASSERT_NE(reader, nullptr);
    EXPECT_EQ(*reader->find("name")->asText(), "Test Reader");

    ::close(client);
    tr.reset();
    std::filesystem::remove(path);
}

TEST(SocketTransport, DisconnectFiresHandlersInRegistrationOrder)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });

    Latch<int> order;
    tr->onClientDisconnect([&](Agent::CallerToken) { order.push(1); });
    tr->onClientDisconnect([&](Agent::CallerToken) { order.push(2); });

    const int client = connectClient(path);
    const auto helloBytes = wire::toCbor(wire::RequestEnvelope{1, wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(wire::sendFrame(client, helloBytes).has_value());
    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2)));

    ::close(client); // triggers EOF -> closeConnection -> fan-out
    ASSERT_TRUE(order.waitFor(2, std::chrono::seconds(2)));
    {
        std::lock_guard<std::mutex> lk(order.m);
        ASSERT_EQ(order.items.size(), 2u);
        EXPECT_EQ(order.items[0], 1); // registration order
        EXPECT_EQ(order.items[1], 2);
    }

    tr.reset();
    std::filesystem::remove(path);
}

TEST(SocketTransport, ConnectionCapRefusesTheExcessConnection)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });

    // Fill the cap: 32 registered connections, paced by the per-client sink
    // ack (a burst of raw connects would overflow the listen(16) backlog and
    // fail at connect() before the cap is even exercised).
    std::vector<int> clients;
    const auto helloBytes = wire::toCbor(wire::RequestEnvelope{1, wire::Hello{1, std::nullopt}}).encode();
    for (std::size_t i = 0; i < 32; ++i) {
        const int c = connectClient(path);
        ASSERT_TRUE(wire::sendFrame(c, helloBytes).has_value());
        clients.push_back(c);
        ASSERT_TRUE(sink.waitFor(i + 1, std::chrono::seconds(5)));
    }

    // The 33rd connects at the kernel level (listen backlog) but the transport
    // refuses it at accept: the client observes EOF.
    const int excess = connectClient(path);
    timeval tv{5, 0};
    ::setsockopt(excess, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[8] = {0};
    EXPECT_EQ(::recv(excess, buf, sizeof(buf), 0), 0);

    ::close(excess);
    for (const int c : clients) {
        ::close(c);
    }
    tr.reset();
    std::filesystem::remove(path);
}

TEST(SocketTransport, WatchdogReapsOnlyThePartialFrameConnection)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));
    tr->setFirstFrameTimeoutForTest(std::chrono::milliseconds(50));

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });

    // A well-behaved client delivers its first frame inside the window.
    const int good = connectClient(path);
    const auto helloBytes = wire::toCbor(wire::RequestEnvelope{1, wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(wire::sendFrame(good, helloBytes).has_value());
    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2)));

    // A slow-loris client sends half a length prefix and stalls.
    const int slow = connectClient(path);
    const std::uint8_t partial[2] = {0x10, 0x00};
    ASSERT_EQ(::send(slow, partial, sizeof(partial), 0), 2);

    // EOF on the stalled connection IS the watchdog event (no sleeps).
    timeval tv{5, 0};
    ::setsockopt(slow, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[8] = {0};
    EXPECT_EQ(::recv(slow, buf, sizeof(buf), 0), 0);

    // The good connection outlived the same window (its timer was cancelled on
    // the first frame): it still receives broadcasts.
    SocketTransport* trp = tr.get();
    dispatch_sync(tr->loopQueue(), ^{
      Agent::ReaderState r;
      r.id = Agent::ObjectId(9);
      r.name = "Survivor";
      r.hasCard = false;
      trp->publishReader(r);
    });
    const auto frame = wire::recvFrame(good);
    ASSERT_TRUE(frame.has_value());
    const auto decoded = wire::decode(frame->body);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded->find("t")->asText(), "ReaderAdded");

    ::close(good);
    ::close(slow);
    tr.reset();
    std::filesystem::remove(path);
}

TEST(SocketTransport, PostRunsOnTheLoop)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));

    Latch<int> ran;
    tr->post([&] { ran.push(1); });
    EXPECT_TRUE(ran.waitFor(1, std::chrono::seconds(2)));

    tr.reset();
    std::filesystem::remove(path);
}

} // namespace
