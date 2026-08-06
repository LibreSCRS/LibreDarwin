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

#include <LibreSCRS/Agent/wire/Framing.h>
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
namespace Agent = ::LibreSCRS::Agent;

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

wire::MultiPromptReply okMultiReply(std::vector<std::uint8_t> primary, std::vector<std::uint8_t> secondary)
{
    wire::MultiPromptReply r;
    r.status = wire::PromptReplyStatus::Ok;
    r.primary = std::move(primary);
    r.secondary = std::move(secondary);
    return r;
}

const auto kPinRequestBytes = [] {
    return wire::toCbor(wire::PromptRequest{wire::PromptKind::Pin, {}, {}, {}, {}, 0, 0}).encode();
};

// Distinct per-role bounds (4-8 current, 6-10 new) pin the primary*/new* field
// mapping through the codec and the dispatch.
const auto kChangeRequest = [] {
    return wire::RequestSecrets{
        "change_pin", "Change your PIN", "signature PIN", "LibreMac", "identity card", 4, 8, 6, 10};
};

// Providers for the paths a test must NOT route into: the variant dispatch has
// to keep the single-secret, change and cancel arms strictly apart.
PrompterServer::SecretProvider rejectSingleProvider()
{
    return [](const wire::PromptRequest&) {
        ADD_FAILURE() << "SecretProvider must not run for this test";
        return wire::PromptReply{};
    };
}

PrompterServer::MultiSecretProvider rejectMultiProvider()
{
    return [](const wire::RequestSecrets&) {
        ADD_FAILURE() << "MultiSecretProvider must not run for this test";
        return wire::MultiPromptReply{};
    };
}

PrompterServer::ConfirmProvider rejectConfirmProvider()
{
    return [](const wire::ConfirmAction&) {
        ADD_FAILURE() << "ConfirmProvider must not run for this test";
        return wire::ConfirmReply{};
    };
}

TEST(PrompterServer, AuthorizedRequestGetsProviderReply)
{
    const std::string path = uniqueSocketPath();
    PrompterServer server(
        path, [](const wire::PromptRequest&) { return okReply({'8', '8', '8', '8'}); }, // fake test value
        rejectMultiProvider(), [] {}, rejectConfirmProvider(), [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    const int conn = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn, kPinRequestBytes()).has_value());

    auto reply = Agent::Wire::recvFrame(conn);
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
        rejectMultiProvider(), [&] { cancelSeen.signal(); }, rejectConfirmProvider(),
        [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    const int conn1 = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn1, kPinRequestBytes()).has_value());
    ASSERT_TRUE(providerEntered.wait(1, std::chrono::seconds(2))); // the modal is up and blocked

    // The old accept-thread design could never read this frame while the
    // provider blocked; now it MUST fire with connection 1 still pending.
    const int conn2 = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn2, wire::toCbor(wire::PromptCancel{}).encode()).has_value());
    ASSERT_TRUE(cancelSeen.wait(1, std::chrono::seconds(2)));

    releaseProvider.signal();
    auto reply = Agent::Wire::recvFrame(conn1); // connection 1 still receives its reply
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
        rejectMultiProvider(), [] {}, rejectConfirmProvider(), [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    const int conn = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn, kPinRequestBytes()).has_value());
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
    auto reply = Agent::Wire::recvFrame(conn);
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
        rejectMultiProvider(), [] {}, rejectConfirmProvider(),
        [](const PeerCredentials&) { return false; }); // NOT the agent
    ASSERT_TRUE(server.start().has_value());

    // The rejection arrives at accept time, before any request is read.
    const int conn = connectClient(path);
    auto reply = Agent::Wire::recvFrame(conn);
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

TEST(PrompterServer, ChangeRequestRoutesToMultiProviderAndReplyRoundTrips)
{
    const std::string path = uniqueSocketPath();
    std::mutex seenMutex;
    wire::RequestSecrets seen;
    PrompterServer server(
        path, rejectSingleProvider(),
        [&](const wire::RequestSecrets& req) {
            {
                std::lock_guard<std::mutex> lk(seenMutex);
                seen = req;
            }
            return okMultiReply({'1', '2', '3', '4'}, {'5', '6', '7', '8'}); // fake test values
        },
        [] {}, rejectConfirmProvider(), [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    const int conn = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn, wire::toCbor(kChangeRequest()).encode()).has_value());

    // Fail-closed dispatch totality: before the visit restructure this frame
    // hit an unconditional std::get<PromptRequest> (bad_variant_access, dead
    // prompter). Receiving a served reply at all pins that EVERY variant
    // alternative is dispatched, not assumed.
    auto reply = Agent::Wire::recvFrame(conn);
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parseMultiPromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Ok);
    EXPECT_EQ(parsed->primary, (std::vector<std::uint8_t>{'1', '2', '3', '4'}));
    EXPECT_EQ(parsed->secondary, (std::vector<std::uint8_t>{'5', '6', '7', '8'}));
    {
        // Every request field (kind, chrome, per-role bounds) survived the
        // wire into the provider unchanged.
        std::lock_guard<std::mutex> lk(seenMutex);
        EXPECT_EQ(seen, kChangeRequest());
    }

    ::close(conn);
    server.stop();
    std::filesystem::remove(path);
}

TEST(PrompterServer, CancelOnASecondConnectionDismissesWhileChangeModalIsUp)
{
    const std::string path = uniqueSocketPath();
    Latch providerEntered;
    Latch releaseProvider;
    Latch cancelSeen;
    PrompterServer server(
        path, rejectSingleProvider(),
        [&](const wire::RequestSecrets&) {
            providerEntered.signal();
            releaseProvider.wait(1, std::chrono::seconds(10)); // the "change modal"
            return okMultiReply({'1'}, {'2'});
        },
        [&] { cancelSeen.signal(); }, rejectConfirmProvider(), [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    const int conn1 = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn1, wire::toCbor(kChangeRequest()).encode()).has_value());
    ASSERT_TRUE(providerEntered.wait(1, std::chrono::seconds(2))); // the change modal is up and blocked

    // The change arm must run on the worker exactly like the single-secret
    // arm: an inline (serial-queue) provider call could never read this frame
    // while the provider blocks.
    const int conn2 = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn2, wire::toCbor(wire::PromptCancel{}).encode()).has_value());
    ASSERT_TRUE(cancelSeen.wait(1, std::chrono::seconds(2)));

    releaseProvider.signal();
    auto reply = Agent::Wire::recvFrame(conn1); // connection 1 still receives its reply
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parseMultiPromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Ok);
    EXPECT_EQ(parsed->primary, (std::vector<std::uint8_t>{'1'}));
    EXPECT_EQ(parsed->secondary, (std::vector<std::uint8_t>{'2'}));

    ::close(conn1);
    ::close(conn2);
    server.stop();
    std::filesystem::remove(path);
}

TEST(PrompterServer, UnknownKindChangeRequestFailsClosedWithNoModal)
{
    // A RequestSecrets kind the window does not implement fails closed: an
    // Error reply, no secrets, and NOTHING modal-shaped runs. The production
    // gate lives in PromptWindow::showChangePrompt, BEFORE its dispatch to the
    // main queue (PrompterMain's multi provider is a bare pass-through into
    // it); AppKit cannot run in this display-free rig, so the provider here
    // replicates that gate's exact shape — Error-initialised reply, kind
    // check, early return — and the test pins the wire-visible contract.
    const std::string path = uniqueSocketPath();
    PrompterServer server(
        path, rejectSingleProvider(),
        [](const wire::RequestSecrets& req) {
            wire::MultiPromptReply reply; // status defaults to Error, like the window's pre-gate init
            if (req.kind != "change_pin") {
                reply.userMessage = "unsupported RequestSecrets kind";
                return reply;
            }
            // Past the gate = the modal would have run. Fail loudly AND
            // return secrets so the downstream assertions fail too.
            ADD_FAILURE() << "unknown kind must be rejected before any modal dispatch";
            return okMultiReply({'0'}, {'0'});
        },
        [] {}, rejectConfirmProvider(), [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    auto request = kChangeRequest();
    request.kind = "unexpected_kind"; // an open wire discriminator: it parses, the window rejects it
    const int conn = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn, wire::toCbor(request).encode()).has_value());

    // The rejection is still a well-formed reply on the change flow's parser.
    auto reply = Agent::Wire::recvFrame(conn);
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parseMultiPromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Error);
    EXPECT_TRUE(parsed->primary.empty());
    EXPECT_TRUE(parsed->secondary.empty());
    EXPECT_EQ(parsed->userMessage, "unsupported RequestSecrets kind");

    ::close(conn);
    server.stop();
    std::filesystem::remove(path);
}

// A kind this build does not implement is refused WITHOUT asking the human. A
// confirmation dialog that cannot describe what it is confirming teaches the
// user to approve anything, so the refusal happens before the prompt.
TEST(PrompterServer, UnknownConfirmKindIsRefusedWithoutAskingTheHuman)
{
    const std::string path = uniqueSocketPath();
    PrompterServer server(
        path, rejectSingleProvider(), rejectMultiProvider(), [] {}, rejectConfirmProvider(),
        [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    wire::ConfirmAction request;
    request.kind = "not_a_real_flow";
    request.title = "Confirm something";
    const int conn = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn, wire::toCbor(request).encode()).has_value());

    // Answered, not ignored: the caller must never be left waiting on a read.
    // rejectConfirmProvider() fails this test if the human was asked at all.
    auto reply = Agent::Wire::recvFrame(conn);
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parseConfirmReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Error);
    EXPECT_EQ(parsed->userMessage, "unsupported confirmation");

    ::close(conn);
    server.stop();
    std::filesystem::remove(path);
}

TEST(PrompterServer, ConfirmActionReachesTheProviderAndItsVerdictIsReturned)
{
    const std::string path = uniqueSocketPath();
    PrompterServer server(
        path, rejectSingleProvider(),
        [](const wire::RequestSecrets&) {
            ADD_FAILURE() << "a confirmation must never reach the secret providers";
            return wire::MultiPromptReply{};
        },
        [] {},
        [](const wire::ConfirmAction& req) {
            EXPECT_EQ(req.kind, "configure_trust");
            EXPECT_EQ(req.requester, "org.librescrs.LibreMac");
            EXPECT_EQ(req.artifact, "TslSources");
            return wire::ConfirmReply{wire::PromptReplyStatus::Cancelled, "declined"};
        },
        [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    wire::ConfirmAction request;
    request.kind = "configure_trust";
    request.title = "Confirm trust change";
    request.description = "Add a trusted list";
    request.requester = "org.librescrs.LibreMac";
    request.artifact = "TslSources";
    const int conn = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn, wire::toCbor(request).encode()).has_value());

    // A human who declines is not an error to be retried: the verdict travels
    // back exactly as given.
    auto reply = Agent::Wire::recvFrame(conn);
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parseConfirmReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Cancelled);
    EXPECT_EQ(parsed->userMessage, "declined");

    ::close(conn);
    server.stop();
    std::filesystem::remove(path);
}

TEST(PrompterServer, UnauthorizedPeerFailsClosedForChangeRequestsToo)
{
    const std::string path = uniqueSocketPath();
    Latch providerCalled;
    PrompterServer server(
        path,
        [&](const wire::PromptRequest&) {
            providerCalled.signal();
            return okReply({'0'});
        },
        [&](const wire::RequestSecrets&) {
            providerCalled.signal();
            return okMultiReply({'0'}, {'0'});
        },
        [] {}, rejectConfirmProvider(), [](const PeerCredentials&) { return false; }); // NOT the agent
    ASSERT_TRUE(server.start().has_value());

    const int conn = connectClient(path);
    // The rejection is queued at accept time and may close the server side
    // before this send lands: suppress SIGPIPE and treat the send as best-
    // effort — the point is that a change request on the wire changes nothing.
    int on = 1;
    ::setsockopt(conn, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
    (void)Agent::Wire::sendFrame(conn, wire::toCbor(kChangeRequest()).encode());

    auto reply = Agent::Wire::recvFrame(conn);
    ASSERT_TRUE(reply.has_value());
    // The change flow parses with the MULTI parser: the status-only rejection
    // map must be recognized as unauthorized there as well.
    auto parsed = wire::parseMultiPromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Unauthorized);

    // The server closed the connection: EOF, and neither provider ever ran.
    char buf[8] = {0};
    EXPECT_EQ(::recv(conn, buf, sizeof(buf), 0), 0);
    EXPECT_FALSE(providerCalled.wait(1, std::chrono::milliseconds(0)));

    ::close(conn);
    server.stop();
    std::filesystem::remove(path);
}

} // namespace
