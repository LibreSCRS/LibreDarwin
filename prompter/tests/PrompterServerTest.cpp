// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// PrompterServer over real socket connections with injected seams (no display,
// no real code signing): a cross-connection CancelCurrent lands while a
// provider call is blocked (the modal), stop() returns promptly with a modal
// pending, peer-auth fails closed, and a request round-trips its reply. Real
// sockets + latches, no sleeps. The AppKit window + real SecTask peer-auth are
// exercised manually / in the HW gate.
#include "PrompterServer.h"

#include <LibreSCRS/Darwin/backend/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

using namespace LibreSCRS::Darwin;

namespace {

std::string uniqueSocketPath()
{
    return "/tmp/ld-ps-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()) + ".sock";
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

// A counting latch (no sleeps anywhere).
struct Latch
{
    std::mutex m;
    std::condition_variable cv;
    int count{0};
    void signal()
    {
        {
            std::lock_guard<std::mutex> lk(m);
            ++count;
        }
        cv.notify_all();
    }
    bool wait(int n, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lk(m);
        return cv.wait_for(lk, timeout, [&] { return count >= n; });
    }
};

wire::PromptReply okReply(std::vector<std::uint8_t> secret)
{
    wire::PromptReply r;
    r.status = wire::PromptReplyStatus::Ok;
    r.secret = std::move(secret);
    return r;
}

const auto kPinRequestBytes = [] {
    return wire::toCbor(wire::PromptRequest{wire::PromptKind::Pin, {}, {}, {}, {}, 0, 0}).encode();
};

TEST(PrompterServer, AuthorizedRequestGetsProviderReply)
{
    const std::string path = uniqueSocketPath();
    PrompterServer server(
        path, [](const wire::PromptRequest&) { return okReply({'8', '8', '8', '8'}); }, // fake test value
        [] {}, [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    const int conn = connectClient(path);
    ASSERT_TRUE(wire::sendFrame(conn, kPinRequestBytes()).has_value());

    auto reply = wire::recvFrame(conn);
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parsePromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Ok);
    EXPECT_EQ(parsed->secret, (std::vector<std::uint8_t>{'8', '8', '8', '8'}));

    ::close(conn);
    server.stop();
    std::filesystem::remove(path);
}

TEST(PrompterServer, CancelOnASecondConnectionDismissesWhileModalIsUp)
{
    const std::string path = uniqueSocketPath();
    Latch providerEntered;
    Latch releaseProvider;
    Latch cancelSeen;
    PrompterServer server(
        path,
        [&](const wire::PromptRequest&) {
            providerEntered.signal();
            releaseProvider.wait(1, std::chrono::seconds(10)); // the "modal"
            return okReply({'4', '2'});
        },
        [&] { cancelSeen.signal(); }, [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    const int conn1 = connectClient(path);
    ASSERT_TRUE(wire::sendFrame(conn1, kPinRequestBytes()).has_value());
    ASSERT_TRUE(providerEntered.wait(1, std::chrono::seconds(2))); // the modal is up and blocked

    // The old accept-thread design could never read this frame while the
    // provider blocked; now it MUST fire with connection 1 still pending.
    const int conn2 = connectClient(path);
    ASSERT_TRUE(wire::sendFrame(conn2, wire::toCbor(wire::PromptCancel{}).encode()).has_value());
    ASSERT_TRUE(cancelSeen.wait(1, std::chrono::seconds(2)));

    releaseProvider.signal();
    auto reply = wire::recvFrame(conn1); // connection 1 still receives its reply
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parsePromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Ok);
    EXPECT_EQ(parsed->secret, (std::vector<std::uint8_t>{'4', '2'}));

    ::close(conn1);
    ::close(conn2);
    server.stop();
    std::filesystem::remove(path);
}

TEST(PrompterServer, StopReturnsPromptlyWithAModalPending)
{
    const std::string path = uniqueSocketPath();
    Latch providerEntered;
    Latch releaseProvider;
    PrompterServer server(
        path,
        [&](const wire::PromptRequest&) {
            providerEntered.signal();
            releaseProvider.wait(1, std::chrono::seconds(10));
            return okReply({'7'});
        },
        [] {}, [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    const int conn = connectClient(path);
    ASSERT_TRUE(wire::sendFrame(conn, kPinRequestBytes()).has_value());
    ASSERT_TRUE(providerEntered.wait(1, std::chrono::seconds(2)));

    // The old design joined a thread blocked in accept()/the provider: stop()
    // hung. Now it must return well under a second with the modal still up.
    const auto t0 = std::chrono::steady_clock::now();
    server.stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LT(elapsed, std::chrono::seconds(1));

    // The detached provider call still completes and delivers its reply over
    // the fd share it co-owns.
    releaseProvider.signal();
    auto reply = wire::recvFrame(conn);
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parsePromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Ok);

    ::close(conn);
    std::filesystem::remove(path);
}

TEST(PrompterServer, UnauthorizedPeerFailsClosedWithNoProviderCall)
{
    const std::string path = uniqueSocketPath();
    Latch providerCalled;
    PrompterServer server(
        path,
        [&](const wire::PromptRequest&) {
            providerCalled.signal();
            return okReply({'0'});
        },
        [] {}, [](const PeerCredentials&) { return false; }); // NOT the agent
    ASSERT_TRUE(server.start().has_value());

    // The rejection arrives at accept time, before any request is read.
    const int conn = connectClient(path);
    auto reply = wire::recvFrame(conn);
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parsePromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Unauthorized);

    // The server closed the connection: EOF, and the provider never ran.
    char buf[8] = {0};
    EXPECT_EQ(::recv(conn, buf, sizeof(buf), 0), 0);
    EXPECT_FALSE(providerCalled.wait(1, std::chrono::milliseconds(0)));

    ::close(conn);
    server.stop();
    std::filesystem::remove(path);
}

} // namespace
