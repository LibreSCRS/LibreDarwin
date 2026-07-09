// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// PrompterServer peer-auth + protocol dispatch, over a socketpair with injected
// seams (no display, no real code signing). The AppKit window + real SecTask
// peer-auth are exercised manually / in the HW gate.
#include "PrompterServer.h"

#include <LibreSCRS/Darwin/backend/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <string>

using namespace LibreSCRS::Darwin;

namespace {

struct Pair
{
    int fds[2]{-1, -1};
    Pair()
    {
        EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    }
    ~Pair()
    {
        if (fds[0] >= 0) {
            ::close(fds[0]);
        }
        if (fds[1] >= 0) {
            ::close(fds[1]);
        }
    }
};

wire::PromptReply ok(std::vector<std::uint8_t> secret)
{
    wire::PromptReply r;
    r.status = wire::PromptReplyStatus::Ok;
    r.secret = std::move(secret);
    return r;
}

TEST(PrompterServer, AuthorizedRequestGetsProviderReply)
{
    Pair p;
    // Client writes a RequestSecret (buffered).
    ASSERT_TRUE(wire::sendFrame(p.fds[1],
                                wire::toCbor(wire::PromptRequest{wire::PromptKind::Pin, {}, {}, {}, {}, 0, 0}).encode())
                    .has_value());

    bool providerCalled = false;
    PrompterServer server(
        "/tmp/ld-unused.sock",
        [&](const wire::PromptRequest&) {
            providerCalled = true;
            return ok({'8', '8', '8', '8'}); // fake test value
        },
        [] {}, [](const PeerCredentials&) { return true; });

    server.handleConnection(p.fds[0]);
    EXPECT_TRUE(providerCalled);

    auto reply = wire::recvFrame(p.fds[1]);
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parsePromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Ok);
    EXPECT_EQ(parsed->secret, (std::vector<std::uint8_t>{'8', '8', '8', '8'}));
}

TEST(PrompterServer, UnauthorizedPeerGetsUnauthorizedReplyAndNoProvider)
{
    Pair p;
    ASSERT_TRUE(wire::sendFrame(p.fds[1],
                                wire::toCbor(wire::PromptRequest{wire::PromptKind::Pin, {}, {}, {}, {}, 0, 0}).encode())
                    .has_value());

    bool providerCalled = false;
    PrompterServer server(
        "/tmp/ld-unused.sock",
        [&](const wire::PromptRequest&) {
            providerCalled = true;
            return ok({'0'});
        },
        [] {}, [](const PeerCredentials&) { return false; }); // NOT the agent

    server.handleConnection(p.fds[0]);
    EXPECT_FALSE(providerCalled);

    auto reply = wire::recvFrame(p.fds[1]);
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parsePromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Unauthorized);
}

TEST(PrompterServer, CancelCurrentInvokesHandlerWithNoReply)
{
    Pair p;
    ASSERT_TRUE(wire::sendFrame(p.fds[1], wire::toCbor(wire::PromptCancel{}).encode()).has_value());

    bool cancelled = false;
    bool providerCalled = false;
    PrompterServer server(
        "/tmp/ld-unused.sock",
        [&](const wire::PromptRequest&) {
            providerCalled = true;
            return ok({'0'});
        },
        [&] { cancelled = true; }, [](const PeerCredentials&) { return true; });

    server.handleConnection(p.fds[0]);
    EXPECT_TRUE(cancelled);
    EXPECT_FALSE(providerCalled);
}

} // namespace
