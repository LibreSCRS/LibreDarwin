// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// PrompterServer over real socket connections with injected seams (no display,
// no real code signing): a cross-connection CancelCurrent lands while a
// provider call is blocked (the modal), stop() returns promptly with a modal
// pending, peer-auth fails closed, a request round-trips its reply, and a
// replaced socket path is bound again. Real sockets + latches; only the
// replaced-path test polls, since the guard is a timer. The AppKit window +
// real SecTask peer-auth are exercised manually / in the HW gate.
#include "PrompterServer.h"

#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <gtest/gtest.h>

#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <format>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
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
    // Bound every blocking recv on this socket -- a regression that leaves a
    // reply unsent must fail the read it blocks on with a message, not hang
    // the binary until ctest's own kill timeout. 20 s, not the file's usual
    // 10 s (releaseProvider.wait(1, seconds(10))): a fake provider that falls
    // back to answering after its OWN 10 s bound (see
    // ResetDismissesEveryLivePromptAndAnswersHowMany) must have room to
    // deliver that fallback reply before the client gives up on reading it,
    // or the two timers race and the failure lands on the wrong assertion.
    const timeval recvTimeout{.tv_sec = 20, .tv_usec = 0};
    ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &recvTimeout, sizeof(recvTimeout));
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
    return wire::toCbor(wire::PromptRequest{.kind = wire::PromptKind::Pin,
                                            .title = {},
                                            .description = {},
                                            .requester = {},
                                            .artifact = {},
                                            .minLength = 0,
                                            .maxLength = 0})
        .encode();
};

// Distinct per-role bounds (4-8 current, 6-10 new) pin the primary*/new* field
// mapping through the codec and the dispatch.
const auto kChangeRequest = [] {
    return wire::RequestSecrets{.kind = "change_pin",
                                .title = "Change your PIN",
                                .description = "signature PIN",
                                .requester = "LibreMac",
                                .artifact = "identity card",
                                .primaryMinLength = 4,
                                .primaryMaxLength = 8,
                                .newMinLength = 6,
                                .newMaxLength = 10};
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

PrompterServer::ResetHandler rejectResetHandler()
{
    return []() -> std::uint32_t {
        ADD_FAILURE() << "ResetHandler must not run for this test";
        return 0;
    };
}

TEST(PrompterServer, AuthorizedRequestGetsProviderReply)
{
    const std::string path = uniqueSocketPath();
    PrompterServer server(
        path, [](const wire::PromptRequest&) { return okReply({'8', '8', '8', '8'}); }, // fake test value
        rejectMultiProvider(), [](const std::string&) {}, rejectConfirmProvider(), rejectResetHandler(),
        [](const PeerCredentials&) { return true; });
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
        rejectMultiProvider(), [&](const std::string&) { cancelSeen.signal(); }, rejectConfirmProvider(),
        rejectResetHandler(), [](const PeerCredentials&) { return true; });
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
        rejectMultiProvider(), [](const std::string&) {}, rejectConfirmProvider(), rejectResetHandler(),
        [](const PeerCredentials&) { return true; });
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
        rejectMultiProvider(), [](const std::string&) {}, rejectConfirmProvider(), rejectResetHandler(),
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
        [](const std::string&) {}, rejectConfirmProvider(), rejectResetHandler(),
        [](const PeerCredentials&) { return true; });
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
        [&](const std::string&) { cancelSeen.signal(); }, rejectConfirmProvider(), rejectResetHandler(),
        [](const PeerCredentials&) { return true; });
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
        [](const std::string&) {}, rejectConfirmProvider(), rejectResetHandler(),
        [](const PeerCredentials&) { return true; });
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
        path, rejectSingleProvider(), rejectMultiProvider(), [](const std::string&) {}, rejectConfirmProvider(),
        rejectResetHandler(), [](const PeerCredentials&) { return true; });
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
        [](const std::string&) {},
        [](const wire::ConfirmAction& req) {
            EXPECT_EQ(req.kind, "configure_trust");
            EXPECT_EQ(req.requester, "org.librescrs.LibreMac");
            EXPECT_EQ(req.artifact, "TslSources");
            return wire::ConfirmReply{wire::PromptReplyStatus::Cancelled, "declined"};
        },
        rejectResetHandler(), [](const PeerCredentials&) { return true; });
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
        [](const std::string&) {}, rejectConfirmProvider(), rejectResetHandler(),
        [](const PeerCredentials&) { return false; }); // NOT the agent
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

// The dismissal must arrive with the id it addresses. A handler that receives
// nothing can only close whatever modal is up -- on a second reader, another
// card's window.
TEST(PrompterServer, CancelDeliversTheIdItAddresses)
{
    const std::string path = uniqueSocketPath();
    Latch cancelSeen;
    std::mutex receivedMutex;
    std::string received;
    PrompterServer server(
        path, rejectSingleProvider(), rejectMultiProvider(),
        [&](const std::string& id) {
            {
                const std::lock_guard<std::mutex> lk(receivedMutex);
                received = id;
            }
            cancelSeen.signal();
        },
        rejectConfirmProvider(), rejectResetHandler(), [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    wire::PromptCancel cancelMsg;
    cancelMsg.promptId = "n9:2";
    const int conn = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn, wire::toCbor(cancelMsg).encode()).has_value());
    ASSERT_TRUE(cancelSeen.wait(1, std::chrono::seconds(2)));
    {
        const std::lock_guard<std::mutex> lk(receivedMutex);
        EXPECT_EQ(received, "n9:2");
    }

    ::close(conn);
    server.stop();
    std::filesystem::remove(path);
}

// The Reset verb is answered, never merely absorbed: a caller that sends it
// waits for ResetDone, and silence would hang it. Two prompts stand at once,
// via fake providers standing in for two real windows -- Reset must reach
// BOTH (each answers Cancelled, exactly what a dismissed panel delivers to
// its blocked caller) and the reply must carry the true count, not a
// placeholder: a Reset that answered 0 with two windows still standing would
// be indistinguishable from a Reset that did nothing at all.
TEST(PrompterServer, ResetDismissesEveryLivePromptAndAnswersHowMany)
{
    const std::string path = uniqueSocketPath();
    Latch providersEntered; // wait(2, ...): BOTH modals up before Reset fires
    std::mutex releaseMutex;
    std::condition_variable releaseCv;
    bool released = false;
    auto twoLiveModals = [&](const wire::PromptRequest&) {
        providersEntered.signal();
        std::unique_lock<std::mutex> lk(releaseMutex);
        // Bounded like every other blocking wait in this file
        // (releaseProvider.wait(1, seconds(10))): a regression that never
        // calls the reset handler must fail THIS assertion with a message
        // after 10 s, not hang the binary forever. Either way -- released by
        // Reset or timed out -- the lambda still answers Cancelled below, so
        // a timeout here does not itself strand the connection.
        EXPECT_TRUE(releaseCv.wait_for(lk, std::chrono::seconds(10), [&] { return released; }))
            << "the reset handler never released this modal";
        return wire::PromptReply{.status = wire::PromptReplyStatus::Cancelled};
    };
    PrompterServer server(
        path, twoLiveModals, rejectMultiProvider(),
        [](const std::string&) { ADD_FAILURE() << "Reset must not route into the addressed-cancel arm"; },
        rejectConfirmProvider(),
        [&]() -> std::uint32_t {
            // Stands in for PromptWindow::dismissAll(): releases both blocked
            // callers (each then answers Cancelled on its own connection, like
            // a real dismissed panel) and reports how many it closed. The
            // count is a value distinct from the number of live prompts (2)
            // on purpose: a hardcoded pass-through matching that number would
            // let a recount bug (or a literal `return 2;` with no sweep at
            // all) go unnoticed.
            {
                const std::lock_guard<std::mutex> lk(releaseMutex);
                released = true;
            }
            releaseCv.notify_all();
            return 7;
        },
        [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    const int conn1 = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn1, kPinRequestBytes()).has_value());
    const int conn2 = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn2, kPinRequestBytes()).has_value());
    ASSERT_TRUE(providersEntered.wait(2, std::chrono::seconds(2))); // both modals up and blocked

    const int resetConn = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(resetConn, wire::toCbor(wire::PromptReset{}).encode()).has_value());

    // Both blocked requests are released by Reset and answer Cancelled.
    auto reply1 = Agent::Wire::recvFrame(conn1);
    ASSERT_TRUE(reply1.has_value());
    auto parsed1 = wire::parsePromptReply(reply1->body);
    ASSERT_TRUE(parsed1.has_value());
    EXPECT_EQ(parsed1->status, wire::PromptReplyStatus::Cancelled);

    auto reply2 = Agent::Wire::recvFrame(conn2);
    ASSERT_TRUE(reply2.has_value());
    auto parsed2 = wire::parsePromptReply(reply2->body);
    ASSERT_TRUE(parsed2.has_value());
    EXPECT_EQ(parsed2->status, wire::PromptReplyStatus::Cancelled);

    // The Reset caller's own reply carries the true count and the protocol
    // version. The raw frame is inspected before it is parsed: the agent
    // reads the helper's protocol off the reply itself, so the key has to be
    // ON the wire, not merely reconstructed by a parser that knows its own
    // version.
    auto resetReply = Agent::Wire::recvFrame(resetConn);
    ASSERT_TRUE(resetReply.has_value());
    const auto tree = Agent::Wire::decode(resetReply->body);
    ASSERT_TRUE(tree.has_value());
    ASSERT_NE(tree->find("t"), nullptr);
    ASSERT_NE(tree->find("t")->asText(), nullptr);
    EXPECT_EQ(*tree->find("t")->asText(), "ResetDone");
    ASSERT_NE(tree->find("v"), nullptr);
    EXPECT_EQ(tree->find("v")->asUInt().value_or(0), wire::kPrompterProtocolVersion);
    auto parsedReset = wire::parseResetDone(resetReply->body);
    ASSERT_TRUE(parsedReset.has_value());
    EXPECT_EQ(parsedReset->closed, 7u); // the fake handler's distinctive count, not the live-prompt count (2)

    ::close(conn1);
    ::close(conn2);
    ::close(resetConn);
    server.stop();
    std::filesystem::remove(path);
}

// A request one version ahead of what this build speaks cannot even have its
// message tag read: parsePrompterRequest checks "v" before it looks at "t",
// on purpose, so a message this build cannot fully read is never half-
// honoured. The server therefore cannot know which provider the message
// would have routed to -- it is answered Error rather than left to hang the
// caller, and every provider here is the rejecting kind, so any dispatch at
// all fails the test.
TEST(PrompterServer, ARequestOneVersionAheadIsRefusedWithoutAProviderCall)
{
    const std::string path = uniqueSocketPath();
    PrompterServer server(
        path, rejectSingleProvider(), rejectMultiProvider(),
        [](const std::string&) { ADD_FAILURE() << "an unsupported-version request must not reach the cancel arm"; },
        rejectConfirmProvider(), rejectResetHandler(), [](const PeerCredentials&) { return true; });
    ASSERT_TRUE(server.start().has_value());

    // A well-formed RequestSecret, but hand-built (not through wire::toCbor,
    // which always stamps the server's OWN version) so "v" can be set past
    // what this build speaks.
    Agent::Wire::CborValue::Map raw;
    raw.emplace("t", Agent::Wire::CborValue("RequestSecret"));
    raw.emplace("v", Agent::Wire::CborValue::uint(wire::kPrompterProtocolVersion + 1));
    raw.emplace("kind", Agent::Wire::CborValue("pin"));
    const auto rawBytes = Agent::Wire::CborValue(std::move(raw)).encode();

    const int conn = connectClient(path);
    ASSERT_TRUE(Agent::Wire::sendFrame(conn, rawBytes).has_value());

    auto reply = Agent::Wire::recvFrame(conn);
    ASSERT_TRUE(reply.has_value());
    auto parsed = wire::parsePromptReply(reply->body);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->status, wire::PromptReplyStatus::Error);
    EXPECT_FALSE(parsed->userMessage.empty());

    ::close(conn);
    server.stop();
    std::filesystem::remove(path);
}

// Under $TMPDIR (short enough for the 104-byte sun_path limit) -- never the
// App-Group container a live prompter may be serving.
std::string tmpSocketPath(const char* tag)
{
    return (std::filesystem::temp_directory_path() /
            std::format("ld-{}-{}-{}.sock", tag, ::getpid(), std::rand() % 100000))
        .string();
}

// What an attacker does: unlink whatever the path names and bind a listener
// of its own there. A guard tick can land between the unlink and the bind and
// re-bind first (EADDRINUSE / EEXIST); an attacker tries again, and so does this.
// `attempts` counts the unlinks: each one is a replacement the server may see.
int bindImpostor(const std::string& path, int* attempts = nullptr)
{
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    for (int attempt = 0; attempt < 100; ++attempt) {
        ::unlink(path.c_str());
        if (attempts != nullptr) {
            ++*attempts;
        }
        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        EXPECT_GE(fd, 0);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            EXPECT_EQ(::listen(fd, 4), 0);
            return fd;
        }
        const int err = errno;
        ::close(fd);
        if (err != EADDRINUSE && err != EEXIST) {
            ADD_FAILURE() << "bind(" << path << "): " << std::strerror(err);
            return -1;
        }
    }
    ADD_FAILURE() << "bind(" << path << "): the path never came free";
    return -1;
}

// The path names the new inode from bind() on, but connect() is refused until
// the server's listen() a moment later; retry through that window only.
int connectOnceListening(const std::string& path, std::chrono::milliseconds bound)
{
    const auto deadline = std::chrono::steady_clock::now() + bound;
    for (;;) {
        const int c = ::socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
        if (::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            const timeval recvTimeout{.tv_sec = 20, .tv_usec = 0};
            ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &recvTimeout, sizeof(recvTimeout));
            return c;
        }
        const int err = errno;
        ::close(c);
        if (err != ECONNREFUSED || std::chrono::steady_clock::now() >= deadline) {
            ADD_FAILURE() << "connect(" << path << "): " << std::strerror(err);
            return -1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

bool waitUntil(const std::function<bool()>& pred, std::chrono::milliseconds bound)
{
    const auto deadline = std::chrono::steady_clock::now() + bound;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

// A same-uid process unlinks prompter.sock and binds its own listener there.
// The prompter must notice and bind again, so the agent's next Reset reaches
// the PROMPTER (its handler's distinctive count comes back), not the impostor
// -- twice, to show the guard keeps watching after it re-bound.
TEST(PrompterServer, RebindsWhenTheSocketPathIsReplaced)
{
    const std::string path = tmpSocketPath("prb");
    std::mutex warnMutex;
    std::vector<std::string> warnings;
    PrompterServer server(
        path, rejectSingleProvider(), rejectMultiProvider(), [](const std::string&) {}, rejectConfirmProvider(),
        []() -> std::uint32_t { return 7; }, [](const PeerCredentials&) { return true; });
    server.setWarn([&](const std::string& line) {
        std::lock_guard<std::mutex> lk(warnMutex);
        warnings.push_back(line);
    });
    server.setPathGuardIntervalForTest(std::chrono::milliseconds(20));
    ASSERT_TRUE(server.start().has_value());

    int replacements = 0;
    for (int round = 1; round <= 2; ++round) {
        const int impostor = bindImpostor(path, &replacements);
        const auto impostorId = SocketPathIdentity::of(path);
        ASSERT_TRUE(impostorId.has_value());

        ASSERT_TRUE(waitUntil(
            [&] {
                // ONE lstat: two would race the server's own unlink-then-bind.
                const auto now = SocketPathIdentity::of(path);
                return now && (now->dev != impostorId->dev || now->ino != impostorId->ino);
            },
            std::chrono::seconds(5)))
            << "round " << round << ": the prompter never bound the replaced path again";

        const int conn = connectOnceListening(path, std::chrono::seconds(2));
        ASSERT_GE(conn, 0);
        ASSERT_TRUE(Agent::Wire::sendFrame(conn, wire::toCbor(wire::PromptReset{}).encode()).has_value());
        auto reply = Agent::Wire::recvFrame(conn);
        ASSERT_TRUE(reply.has_value()) << "round " << round << ": no reply on the path";
        auto parsed = wire::parseResetDone(reply->body);
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(parsed->closed, 7u);
        pollfd p{.fd = impostor, .events = POLLIN, .revents = 0};
        EXPECT_EQ(::poll(&p, 1, 0), 0) << "round " << round << ": the impostor got the client";
        ::close(conn);
        ::close(impostor);
    }

    // One line per replacement: at least one per round, never more than the
    // impostor's unlinks, and none at all over further ticks on a steady path.
    const auto replacedLines = [&] {
        std::lock_guard<std::mutex> lk(warnMutex);
        return std::ranges::count(warnings, std::string("socket path was replaced; re-binding"));
    };
    const auto settled = replacedLines();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(replacedLines(), settled) << "a steady path was reported as replaced";
    EXPECT_GE(settled, 2);
    EXPECT_LE(settled, replacements);
    server.stop();
    std::filesystem::remove(path);
}

} // namespace
