// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// MacPrompterClient against a fake prompter server on a real bound socket. The
// secret is a fake test value (never a real card PIN); it round-trips into a
// cleansing Secure::String.
#include <LibreSCRS/Darwin/backend/MacPrompterClient.h>
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <LibreSCRS/Secure/String.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <variant>
#include <vector>

using namespace LibreSCRS::Darwin;
namespace Agent = ::LibreSCRS::Agent;

namespace {

std::string uniquePath()
{
    return "/tmp/ld-pp-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()) + ".sock";
}

// A fake prompter: binds `path`, accepts connections, and replies to each
// request with a fixed reply. Stops on destruction.
class FakePrompter
{
public:
    FakePrompter(std::string path, wire::PromptReply reply) : m_path(std::move(path)), m_reply(std::move(reply))
    {
        m_listen = ::socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, m_path.c_str(), sizeof(addr.sun_path) - 1);
        ::unlink(m_path.c_str());
        EXPECT_EQ(::bind(m_listen, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        EXPECT_EQ(::listen(m_listen, 4), 0);
        m_thread = std::thread([this] { serve(); });
    }
    ~FakePrompter()
    {
        m_stop = true;
        ::shutdown(m_listen, SHUT_RDWR);
        ::close(m_listen);
        if (m_thread.joinable()) {
            m_thread.join();
        }
        std::filesystem::remove(m_path);
    }

private:
    void serve()
    {
        while (!m_stop) {
            const int c = ::accept(m_listen, nullptr, nullptr);
            if (c < 0) {
                break;
            }
            auto req = Agent::Wire::recvFrame(c);
            if (req.has_value()) {
                static_cast<void>(Agent::Wire::sendFrame(c, wire::toCbor(m_reply).encode()));
            }
            ::close(c);
        }
    }
    std::string m_path;
    wire::PromptReply m_reply;
    int m_listen{-1};
    std::atomic<bool> m_stop{false};
    std::thread m_thread;
};

// A fake change-PIN prompter: binds `path`, captures the RequestSecrets it
// parsed off the wire, and answers through the PRODUCTION multi-secret send
// path (sendPromptReplyScrubbed) — or with fixed raw bytes for malformed-reply
// tests. It RETAINS the reply struct it sent so tests can assert the send path
// left no plaintext in its observable buffers. Stops on destruction.
class FakeChangePrompter
{
public:
    FakeChangePrompter(std::string path, wire::MultiPromptReply reply)
        : m_path(std::move(path)), m_reply(std::move(reply))
    {
        start();
    }
    FakeChangePrompter(std::string path, std::vector<std::uint8_t> rawReplyBody)
        : m_path(std::move(path)), m_rawReplyBody(std::move(rawReplyBody))
    {
        start();
    }
    ~FakeChangePrompter()
    {
        m_stop = true;
        ::shutdown(m_listen, SHUT_RDWR);
        ::close(m_listen);
        if (m_thread.joinable()) {
            m_thread.join();
        }
        std::filesystem::remove(m_path);
    }

    // Blocks until one request has been fully served (request parsed, reply
    // sent AND scrubbed). The client's recvFrame can complete before the
    // fake's post-send scrub runs, so accessors are only race-free after this.
    // Bounded: a client regression that never connects (or never sends) must
    // fail the test, not hang it — generous deadline, same cv+mutex discipline.
    void waitUntilServed()
    {
        std::unique_lock lock(m_mutex);
        if (!m_servedCv.wait_for(lock, std::chrono::seconds(30), [this] { return m_served; })) {
            FAIL() << "FakeChangePrompter: no request served within 30s";
        }
    }
    [[nodiscard]] const std::optional<wire::RequestSecrets>& capturedRequest() const
    {
        return m_request;
    }
    [[nodiscard]] const wire::MultiPromptReply& retainedReply() const
    {
        return m_reply;
    }

private:
    void start()
    {
        m_listen = ::socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, m_path.c_str(), sizeof(addr.sun_path) - 1);
        ::unlink(m_path.c_str());
        EXPECT_EQ(::bind(m_listen, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        EXPECT_EQ(::listen(m_listen, 4), 0);
        m_thread = std::thread([this] { serve(); });
    }
    void serve()
    {
        while (!m_stop) {
            const int c = ::accept(m_listen, nullptr, nullptr);
            if (c < 0) {
                break;
            }
            auto req = Agent::Wire::recvFrame(c);
            if (req.has_value()) {
                std::lock_guard lock(m_mutex);
                auto parsed = wire::parsePrompterRequest(req->body);
                if (parsed.has_value()) {
                    if (auto* rs = std::get_if<wire::RequestSecrets>(&*parsed)) {
                        m_request = std::move(*rs);
                    }
                }
                if (m_rawReplyBody.has_value()) {
                    static_cast<void>(Agent::Wire::sendFrame(c, *m_rawReplyBody));
                } else {
                    // Production send path: zeroes the wire copies AND
                    // m_reply's secret vectors — retained for assertion.
                    wire::sendPromptReplyScrubbed(c, m_reply);
                }
                m_served = true;
                m_servedCv.notify_all();
            }
            ::close(c);
        }
    }
    std::string m_path;
    wire::MultiPromptReply m_reply;
    std::optional<std::vector<std::uint8_t>> m_rawReplyBody;
    std::optional<wire::RequestSecrets> m_request;
    std::mutex m_mutex;
    std::condition_variable m_servedCv;
    bool m_served{false};
    int m_listen{-1};
    std::atomic<bool> m_stop{false};
    std::thread m_thread;
};

TEST(MacPrompterClient, OkReplyScrubsSecretIntoSecureString)
{
    const std::string path = uniquePath();
    wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Ok;
    reply.secret = {'1', '3', '5', '7'}; // fake test value, not a card PIN
    FakePrompter server(path, reply);

    MacPrompterClient client(path);
    const auto r = client.requestPin(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Ok);
    ASSERT_TRUE(r.secret.has_value());
    EXPECT_EQ(r.secret->view(), "1357");
}

TEST(MacPrompterClient, CancelledReplyMapsToCancelled)
{
    const std::string path = uniquePath();
    wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Cancelled;
    FakePrompter server(path, reply);

    MacPrompterClient client(path);
    const auto r = client.requestCan(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Cancelled);
    EXPECT_FALSE(r.secret.has_value());
}

TEST(MacPrompterClient, UnauthorizedReplyMapsToError)
{
    const std::string path = uniquePath();
    wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Unauthorized;
    FakePrompter server(path, reply);

    MacPrompterClient client(path);
    const auto r = client.requestPin(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Error);
}

TEST(MacPrompterClient, MissingPrompterFailsWithError)
{
    MacPrompterClient client("/tmp/ld-nonexistent-" + std::to_string(std::rand()) + ".sock");
    const auto r = client.requestPin(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Error);
}

TEST(MacPrompterClient, ChangeOkReplyDeliversBothSecretsAndDuplicatesBounds)
{
    const std::string path = uniquePath();
    wire::MultiPromptReply reply;
    reply.status = wire::PromptReplyStatus::Ok;
    reply.primary = {'1', '3', '5', '7'}; // fake test values, not card PINs
    reply.secondary = {'2', '4', '6', '8'};
    FakeChangePrompter server(path, reply);

    Agent::PromptOptions options;
    options.title = "Change PIN";
    options.description = "Enter the current and the new PIN";
    options.requester = "example.client";
    options.artifact = "eID card";
    options.minLength = 4;
    options.maxLength = 8;

    MacPrompterClient client(path);
    const auto r = client.requestPinChange(options);
    EXPECT_EQ(r.status, Agent::PromptStatus::Ok);
    ASSERT_TRUE(r.current.has_value());
    ASSERT_TRUE(r.newPin.has_value());
    EXPECT_EQ(r.current->view(), "1357");
    EXPECT_EQ(r.newPin->view(), "2468");
    EXPECT_TRUE(r.userMessage.empty());

    server.waitUntilServed();
    const auto& req = server.capturedRequest();
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(req->kind, "change_pin");
    EXPECT_EQ(req->title, "Change PIN");
    EXPECT_EQ(req->description, "Enter the current and the new PIN");
    EXPECT_EQ(req->requester, "example.client");
    EXPECT_EQ(req->artifact, "eID card");
    // The seam carries ONE (min, max) bounds pair; it maps onto BOTH per-role
    // wire bounds — the same policy governs the current and the new PIN
    // (Linux prompter-client parity).
    EXPECT_EQ(req->primaryMinLength, 4u);
    EXPECT_EQ(req->primaryMaxLength, 8u);
    EXPECT_EQ(req->newMinLength, 4u);
    EXPECT_EQ(req->newMaxLength, 8u);
}

TEST(MacPrompterClient, ChangeOkReplyLeavesNoPlaintextInFakeBuffers)
{
    // The client contract: secrets come back ONLY as cleansing Secure::Strings.
    static_assert(
        std::is_same_v<decltype(Agent::PinChangePromptResult::current), std::optional<LibreSCRS::Secure::String>>);
    static_assert(
        std::is_same_v<decltype(Agent::PinChangePromptResult::newPin), std::optional<LibreSCRS::Secure::String>>);

    const std::string path = uniquePath();
    wire::MultiPromptReply reply;
    reply.status = wire::PromptReplyStatus::Ok;
    reply.primary = {'1', '3', '5', '7'}; // fake test values, not card PINs
    reply.secondary = {'2', '4', '6', '8'};
    FakeChangePrompter server(path, reply);

    MacPrompterClient client(path);
    const auto r = client.requestPinChange(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Ok);

    // The fake replied through the production multi-secret send path and
    // retained the struct it sent: after the round trip both secret buffers it
    // can still observe must be scrubbed (sizes retained, contents zeroed).
    server.waitUntilServed();
    const auto& sent = server.retainedReply();
    ASSERT_EQ(sent.primary.size(), 4u);
    ASSERT_EQ(sent.secondary.size(), 4u);
    EXPECT_TRUE(std::ranges::all_of(sent.primary, [](std::uint8_t b) { return b == 0; }));
    EXPECT_TRUE(std::ranges::all_of(sent.secondary, [](std::uint8_t b) { return b == 0; }));
}

TEST(MacPrompterClient, ChangeCancelledReplyMapsToCancelledWithoutSecrets)
{
    const std::string path = uniquePath();
    wire::MultiPromptReply reply;
    reply.status = wire::PromptReplyStatus::Cancelled;
    FakeChangePrompter server(path, reply);

    MacPrompterClient client(path);
    const auto r = client.requestPinChange(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Cancelled);
    EXPECT_FALSE(r.current.has_value());
    EXPECT_FALSE(r.newPin.has_value());
}

TEST(MacPrompterClient, ChangeErrorReplyCarriesUserMessage)
{
    const std::string path = uniquePath();
    wire::MultiPromptReply reply;
    reply.status = wire::PromptReplyStatus::Error;
    reply.userMessage = "change failed";
    FakeChangePrompter server(path, reply);

    MacPrompterClient client(path);
    const auto r = client.requestPinChange(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Error);
    EXPECT_EQ(r.userMessage, "change failed");
    EXPECT_FALSE(r.current.has_value());
    EXPECT_FALSE(r.newPin.has_value());
}

TEST(MacPrompterClient, ChangeMalformedReplyFailsClosed)
{
    const std::string path = uniquePath();
    // Not decodable CBOR: bare "break" stop codes.
    FakeChangePrompter server(path, std::vector<std::uint8_t>{0xFF, 0xFF, 0xFF});

    MacPrompterClient client(path);
    const auto r = client.requestPinChange(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Error);
    EXPECT_FALSE(r.current.has_value());
    EXPECT_FALSE(r.newPin.has_value());
    EXPECT_FALSE(r.userMessage.empty()); // client-supplied diagnostic
}

TEST(MacPrompterClient, ChangeOversizeSecretFailsClosed)
{
    const std::string path = uniquePath();
    wire::MultiPromptReply reply;
    reply.status = wire::PromptReplyStatus::Ok;
    reply.primary.assign(wire::kMaxSecretBytes + 1, std::uint8_t{'9'});
    reply.secondary = {'2', '4', '6', '8'};
    FakeChangePrompter server(path, reply);

    MacPrompterClient client(path);
    const auto r = client.requestPinChange(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Error);
    EXPECT_FALSE(r.current.has_value());
    EXPECT_FALSE(r.newPin.has_value());
}

TEST(MacPrompterClient, ChangeMissingPrompterFailsWithError)
{
    MacPrompterClient client("/tmp/ld-nonexistent-" + std::to_string(std::rand()) + ".sock");
    const auto r = client.requestPinChange(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Error);
    EXPECT_FALSE(r.current.has_value());
    EXPECT_FALSE(r.newPin.has_value());
}

} // namespace
