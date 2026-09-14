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

// The fake prompters below are served by this unsigned test binary itself, so
// the client's default code-signing verification of the serving peer would
// (correctly) reject them: inject a permissive verifier everywhere except the
// tests that pin the rejection path.
MacPrompterClient::PeerVerifier trustAnyPeerForTest()
{
    return [](int) { return true; };
}

// A reply that announces NO protocol: the map is assembled through the real
// CBOR types with the "v" key simply left out, then handed to the production
// encoder. That is what a helper predating the key puts on the wire, and
// toCbor() cannot produce it — it stamps the version onto every reply it
// builds. Hand-written bytes would prove only that this file can spell CBOR.
std::vector<std::uint8_t> secretReplyWithoutAVersion(const std::vector<std::uint8_t>& secret)
{
    wire::CborValue::Map m;
    m.emplace("t", wire::CborValue("Secret"));
    m.emplace("status", wire::CborValue("ok"));
    m.emplace("secret", wire::CborValue(secret));
    return wire::CborValue(std::move(m)).encode();
}

std::vector<std::uint8_t> secretsReplyWithoutAVersion(const std::vector<std::uint8_t>& primary,
                                                      const std::vector<std::uint8_t>& secondary)
{
    wire::CborValue::Map m;
    m.emplace("t", wire::CborValue("Secrets"));
    m.emplace("status", wire::CborValue("ok"));
    m.emplace("primary", wire::CborValue(primary));
    m.emplace("secondary", wire::CborValue(secondary));
    return wire::CborValue(std::move(m)).encode();
}

std::vector<std::uint8_t> confirmReplyWithoutAVersion()
{
    wire::CborValue::Map m;
    m.emplace("t", wire::CborValue("Confirm"));
    m.emplace("status", wire::CborValue("ok"));
    return wire::CborValue(std::move(m)).encode();
}

// Does @p haystack carry @p needle anywhere inside it? The bodies above are
// CBOR, so the secret sits at an offset these tests have no business computing.
bool carries(const std::vector<std::uint8_t>& haystack, const std::vector<std::uint8_t>& needle)
{
    return std::ranges::search(haystack, needle).begin() != haystack.end();
}

// A fake prompter: binds `path`, accepts connections, and replies to each
// request with a fixed reply. Also captures the LAST PromptRequest it parsed
// off the wire (mirrors FakeChangePrompter's capture below) so a test can
// assert what MacPrompterClient actually sent, not just what came back.
// Stops on destruction.
class FakePrompter
{
public:
    FakePrompter(std::string path, wire::PromptReply reply) : m_path(std::move(path)), m_reply(std::move(reply))
    {
        start();
    }
    // Fixed raw bytes instead of an encoded struct — the only way to put a
    // reply on the wire that toCbor cannot build, namely one announcing no
    // protocol at all (toCbor stamps the version onto every reply it makes).
    // Mirrors FakeChangePrompter's raw-body constructor below.
    FakePrompter(std::string path, std::vector<std::uint8_t> rawReplyBody)
        : m_path(std::move(path)), m_rawReplyBody(std::move(rawReplyBody))
    {
        start();
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

    // Blocks until one request has been captured (bounded, same discipline as
    // FakeChangePrompter::waitUntilServed).
    void waitUntilServed()
    {
        std::unique_lock lock(m_mutex);
        if (!m_servedCv.wait_for(lock, std::chrono::seconds(30), [this] { return m_served; })) {
            FAIL() << "FakePrompter: no request served within 30s";
        }
    }
    [[nodiscard]] const std::optional<wire::PromptRequest>& capturedRequest() const
    {
        return m_request;
    }
    // Exactly the bytes the fake put on the wire, as it built them. Nothing on
    // the client side can reach into this buffer, so a test can assert that a
    // refused reply really did carry the secret it was refused over.
    [[nodiscard]] const std::optional<std::vector<std::uint8_t>>& sentRawBody() const
    {
        return m_rawReplyBody;
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
                {
                    std::lock_guard lock(m_mutex);
                    auto parsed = wire::parsePrompterRequest(req->body);
                    if (parsed.has_value()) {
                        if (auto* pr = std::get_if<wire::PromptRequest>(&*parsed)) {
                            m_request = std::move(*pr);
                        }
                    }
                }
                if (m_rawReplyBody.has_value()) {
                    static_cast<void>(Agent::Wire::sendFrame(c, *m_rawReplyBody));
                } else {
                    static_cast<void>(Agent::Wire::sendFrame(c, wire::toCbor(m_reply).encode()));
                }
                {
                    std::lock_guard lock(m_mutex);
                    m_served = true;
                }
                m_servedCv.notify_all();
            }
            ::close(c);
        }
    }
    std::string m_path;
    wire::PromptReply m_reply;
    std::optional<std::vector<std::uint8_t>> m_rawReplyBody;
    std::optional<wire::PromptRequest> m_request;
    std::mutex m_mutex;
    std::condition_variable m_servedCv;
    bool m_served{false};
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
    // The raw-reply counterpart of retainedReply(), for the same purpose: what
    // the fake put on the wire, untouched by anything the client did with it.
    [[nodiscard]] const std::optional<std::vector<std::uint8_t>>& sentRawBody() const
    {
        return m_rawReplyBody;
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

    MacPrompterClient client(path, trustAnyPeerForTest());
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

    MacPrompterClient client(path, trustAnyPeerForTest());
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

    MacPrompterClient client(path, trustAnyPeerForTest());
    const auto r = client.requestPin(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Error);
}

TEST(MacPrompterClient, MissingPrompterFailsWithError)
{
    MacPrompterClient client("/tmp/ld-nonexistent-" + std::to_string(std::rand()) + ".sock");
    const auto r = client.requestPin(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Error);
}

// The batch-sign consent hop: PromptOptions::artifacts (the UNTRUSTED
// per-document display-name list BatchSignFlow populates) and the TRUSTED
// "signature-batch" artifact token both cross into the wire PromptRequest
// unchanged — proving the daemon-side plumbing this task adds, mirroring
// LibreLinux's PrompterClient.cpp forwarding the same option onto its own
// wire. The rendering side (PromptWindow) is untouched here.
TEST(MacPrompterClient, RequestPinForwardsArtifactsAndTheBatchTokenToTheWireRequest)
{
    const std::string path = uniquePath();
    wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Cancelled; // no secret needed for this assertion
    FakePrompter server(path, reply);

    Agent::PromptOptions options;
    options.requester = "example.client";
    options.artifact = "signature-batch";
    options.artifacts = {"a.pdf", "b.pdf", "c.pdf"};

    MacPrompterClient client(path, trustAnyPeerForTest());
    static_cast<void>(client.requestPin(options));

    server.waitUntilServed();
    const auto& req = server.capturedRequest();
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(req->requester, "example.client");
    EXPECT_EQ(req->artifact, "signature-batch");
    EXPECT_EQ(req->artifacts, (std::vector<std::string>{"a.pdf", "b.pdf", "c.pdf"}));
}

// A non-batch prompt (the common case) must NOT grow an artifacts list out
// of nowhere — proving the empty-by-default posture, not just the populated
// case above.
TEST(MacPrompterClient, RequestPinLeavesArtifactsEmptyForANonBatchPrompt)
{
    const std::string path = uniquePath();
    wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Cancelled;
    FakePrompter server(path, reply);

    Agent::PromptOptions options;
    options.artifact = "signature";

    MacPrompterClient client(path, trustAnyPeerForTest());
    static_cast<void>(client.requestPin(options));

    server.waitUntilServed();
    const auto& req = server.capturedRequest();
    ASSERT_TRUE(req.has_value());
    EXPECT_TRUE(req->artifacts.empty());
}

// Retry context (CredentialCache::applyRetryContext on the agent core):
// PromptOptions::attempt/lastError cross into the wire PromptRequest
// unchanged, mirroring LibreLinux's PrompterClient.cpp forwarding the same
// options onto its own wire. The rendering side (PromptWindow) is untouched
// here.
TEST(MacPrompterClient, RequestCanForwardsRetryContextToTheWireRequest)
{
    const std::string path = uniquePath();
    wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Cancelled; // no secret needed for this assertion
    FakePrompter server(path, reply);

    Agent::PromptOptions options;
    options.attempt = 2;
    options.lastError = "librescrs.error.preRead.authFailed";

    MacPrompterClient client(path, trustAnyPeerForTest());
    static_cast<void>(client.requestCan(options));

    server.waitUntilServed();
    const auto& req = server.capturedRequest();
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(req->attempt, 2u);
    EXPECT_EQ(req->lastError, "librescrs.error.preRead.authFailed");
}

// The first-ever prompt for a card (the common case): PromptOptions defaults
// (attempt == 0, lastError empty) must not grow retry context out of
// nowhere.
TEST(MacPrompterClient, RequestCanLeavesRetryContextAbsentForAFirstPrompt)
{
    const std::string path = uniquePath();
    wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Cancelled;
    FakePrompter server(path, reply);

    MacPrompterClient client(path, trustAnyPeerForTest());
    static_cast<void>(client.requestCan(Agent::PromptOptions{}));

    server.waitUntilServed();
    const auto& req = server.capturedRequest();
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(req->attempt, 0u);
    EXPECT_TRUE(req->lastError.empty());
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

    MacPrompterClient client(path, trustAnyPeerForTest());
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

    MacPrompterClient client(path, trustAnyPeerForTest());
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

    MacPrompterClient client(path, trustAnyPeerForTest());
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

    MacPrompterClient client(path, trustAnyPeerForTest());
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

    MacPrompterClient client(path, trustAnyPeerForTest());
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

    MacPrompterClient client(path, trustAnyPeerForTest());
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

// A fake confirmation prompter: binds `path`, captures the ConfirmAction it
// parsed off the wire, and answers through the production send path.
class FakeConfirmPrompter
{
public:
    FakeConfirmPrompter(std::string path, wire::ConfirmReply reply) : m_path(std::move(path)), m_reply(reply)
    {
        start();
    }
    // Raw bytes, for the same reason as FakePrompter's: a confirmation that
    // announces no protocol is one toCbor will not build.
    FakeConfirmPrompter(std::string path, std::vector<std::uint8_t> rawReplyBody)
        : m_path(std::move(path)), m_rawReplyBody(std::move(rawReplyBody))
    {
        start();
    }
    ~FakeConfirmPrompter()
    {
        m_stop = true;
        ::shutdown(m_listen, SHUT_RDWR);
        ::close(m_listen);
        if (m_thread.joinable()) {
            m_thread.join();
        }
        std::filesystem::remove(m_path);
    }
    [[nodiscard]] const std::optional<wire::ConfirmAction>& capturedAction() const
    {
        return m_action;
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
                auto parsed = wire::parsePrompterRequest(req->body);
                if (parsed.has_value()) {
                    if (auto* ca = std::get_if<wire::ConfirmAction>(&*parsed)) {
                        m_action = *ca;
                    }
                }
                if (m_rawReplyBody.has_value()) {
                    static_cast<void>(Agent::Wire::sendFrame(c, *m_rawReplyBody));
                } else {
                    wire::sendConfirmReply(c, m_reply);
                }
            }
            ::close(c);
        }
    }
    std::string m_path;
    wire::ConfirmReply m_reply;
    std::optional<std::vector<std::uint8_t>> m_rawReplyBody;
    std::optional<wire::ConfirmAction> m_action;
    int m_listen{-1};
    std::atomic<bool> m_stop{false};
    std::thread m_thread;
};

TEST(MacPrompterClient, ConfirmationCrossesTheWireAndTheVerdictComesBack)
{
    const std::string path = uniquePath();
    FakeConfirmPrompter server(path, wire::ConfirmReply{wire::PromptReplyStatus::Ok, "approved"});

    wire::ConfirmAction action;
    action.kind = "configure_trust";
    action.title = "Confirm trust change";
    action.description = "Add a trusted list";
    action.requester = "org.librescrs.LibreMac";
    action.artifact = "TslSources";

    MacPrompterClient client(path);
    const auto reply = client.requestConfirmation(action);

    EXPECT_EQ(reply.status, wire::PromptReplyStatus::Ok);
    EXPECT_EQ(reply.userMessage, "approved");
    ASSERT_TRUE(server.capturedAction().has_value());
    EXPECT_EQ(*server.capturedAction(), action) << "the prompter must be asked about exactly this change";
}

TEST(MacPrompterClient, DeclinedConfirmationComesBackAsCancelled)
{
    const std::string path = uniquePath();
    FakeConfirmPrompter server(path, wire::ConfirmReply{wire::PromptReplyStatus::Cancelled, "declined"});

    wire::ConfirmAction action;
    action.kind = "configure_trust";
    MacPrompterClient client(path);

    const auto reply = client.requestConfirmation(action);

    EXPECT_EQ(reply.status, wire::PromptReplyStatus::Cancelled);
}

// The whole point of the gate: no prompter means nobody was asked, and nobody
// asked can never read as somebody who agreed.
TEST(MacPrompterClient, MissingPrompterRefusesTheConfirmation)
{
    MacPrompterClient client("/tmp/ld-nonexistent-" + std::to_string(std::rand()) + ".sock");

    const auto reply = client.requestConfirmation(wire::ConfirmAction{"configure_trust", {}, {}, {}, {}});

    EXPECT_EQ(reply.status, wire::PromptReplyStatus::Error);
    EXPECT_NE(reply.status, wire::PromptReplyStatus::Ok);
}

// A serving peer that fails verification gets NOTHING: no request bytes cross
// the socket and its reply is never consumed — a same-uid process re-binding
// prompter.sock must not be able to feed the agent a "PIN" the card would
// burn a retry counter on.
TEST(MacPrompterClient, RejectedServingPeerGetsNoRequestAndItsReplyIsNeverConsumed)
{
    const std::string path = uniquePath();
    wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Ok;
    reply.secret = {'6', '6', '6', '6'}; // an injected wrong PIN, if it ever got through
    FakePrompter server(path, reply);

    MacPrompterClient client(path, [](int) { return false; }); // verification fails
    const auto r = client.requestPin(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Error);
    EXPECT_EQ(r.userMessage, "prompter peer verification failed");
    EXPECT_FALSE(r.secret.has_value());
    // The client bailed before sending: the fake can never have parsed a request.
    EXPECT_FALSE(server.capturedRequest().has_value());
}

// The change path takes the identical pre-send gate.
TEST(MacPrompterClient, RejectedServingPeerFailsTheChangeRequestClosed)
{
    const std::string path = uniquePath();
    wire::MultiPromptReply reply;
    reply.status = wire::PromptReplyStatus::Ok;
    reply.primary = {'6', '6', '6', '6'};
    reply.secondary = {'7', '7', '7', '7'};
    FakeChangePrompter server(path, reply);

    MacPrompterClient client(path, [](int) { return false; }); // verification fails
    const auto r = client.requestPinChange(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Error);
    EXPECT_EQ(r.userMessage, "prompter peer verification failed");
    EXPECT_FALSE(r.current.has_value());
    EXPECT_FALSE(r.newPin.has_value());
    EXPECT_FALSE(server.capturedRequest().has_value());
}

// A fake prompter for the Reset verb alone: counts the PromptReset messages it
// parsed off the wire and answers through the production ResetDone send path.
// A DISENGAGED reply makes it silent — it reads the Reset, answers nothing and
// HOLDS the connection open until destruction. Closing it would be an answer of
// its own (the client's read would end at once), and a wedged helper is exactly
// the case the bounded wait exists for.
class FakeResetPrompter
{
public:
    // Answer with the FRAME HEADER of a real ResetDone and then nothing. The
    // header promises a body that never arrives, so the peer's read of the
    // WHOLE frame is left hanging -- the half of the budget that the poll
    // cannot bound, and the only shape that reaches the receive timeout.
    struct HeaderThenStall
    {};

    FakeResetPrompter(std::string path, std::optional<wire::ResetDone> reply) : m_path(std::move(path)), m_reply(reply)
    {
        m_listen = ::socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, m_path.c_str(), sizeof(addr.sun_path) - 1);
        ::unlink(m_path.c_str());
        EXPECT_EQ(::bind(m_listen, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
        EXPECT_EQ(::listen(m_listen, 4), 0);
        listenOn();
    }
    FakeResetPrompter(std::string path, HeaderThenStall) : m_path(std::move(path)), m_truncate(true)
    {
        listenOn();
    }
    ~FakeResetPrompter()
    {
        m_stop = true;
        ::shutdown(m_listen, SHUT_RDWR);
        ::close(m_listen);
        if (m_thread.joinable()) {
            m_thread.join();
        }
        for (const int held : m_held) {
            ::close(held);
        }
        std::filesystem::remove(m_path);
    }

    // Bounded like every other fake here: a client that never connects must
    // fail the test, not hang it.
    void waitUntilServed()
    {
        std::unique_lock lock(m_mutex);
        if (!m_servedCv.wait_for(lock, std::chrono::seconds(30), [this] { return m_served; })) {
            FAIL() << "FakeResetPrompter: no Reset served within 30s";
        }
    }
    [[nodiscard]] unsigned resetCount() const
    {
        const std::lock_guard lock(m_mutex);
        return m_resets;
    }

private:
    void listenOn()
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
                {
                    const std::lock_guard lock(m_mutex);
                    auto parsed = wire::parsePrompterRequest(req->body);
                    if (parsed.has_value() && std::holds_alternative<wire::PromptReset>(*parsed)) {
                        ++m_resets;
                    }
                    m_served = true;
                }
                m_servedCv.notify_all();
                if (m_truncate) {
                    // The header of a REAL frame, built by the production
                    // encoder, and not one byte of the body it promises.
                    const auto whole = Agent::Wire::encodeFrame(wire::toCbor(wire::ResetDone{.closed = 1}).encode());
                    static_cast<void>(::send(c, whole.data(), Agent::Wire::kFrameHeaderBytes, 0));
                    m_held.push_back(c);
                    continue;
                }
                if (!m_reply.has_value()) {
                    m_held.push_back(c);
                    continue;
                }
                wire::sendResetDone(c, *m_reply);
            }
            ::close(c);
        }
    }
    std::string m_path;
    std::optional<wire::ResetDone> m_reply;
    bool m_truncate{false};
    mutable std::mutex m_mutex;
    std::condition_variable m_servedCv;
    bool m_served{false};
    unsigned m_resets{0};
    std::vector<int> m_held;
    int m_listen{-1};
    std::atomic<bool> m_stop{false};
    std::thread m_thread;
};

// The core stops its own watchdog once a prompt is up, on the understanding
// that the window carries a visible deadline. Both budgets therefore have to
// reach the prompter: what the holder gets for the requested form, and what
// the alternative form is worth if they switch to it in-dialog.
TEST(MacPrompterClient, RequestPinForwardsBothDeadlinesToTheWireRequest)
{
    const std::string path = uniquePath();
    wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Cancelled; // no secret needed for this assertion
    FakePrompter server(path, reply);

    Agent::PromptOptions options;
    options.deadlineMs = 90000;
    options.altDeadlineMs = 30000;

    MacPrompterClient client(path, trustAnyPeerForTest());
    static_cast<void>(client.requestPin(options));

    server.waitUntilServed();
    const auto& req = server.capturedRequest();
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(req->deadlineMs, 90000u);
    EXPECT_EQ(req->altDeadlineMs, 30000u);
}

// What the clock took is not what the person did. Folding the two together is
// how a holder gets told they cancelled an entry they were still making.
TEST(MacPrompterClient, TimeoutReplyMapsToTimeout)
{
    const std::string path = uniquePath();
    wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Timeout;
    FakePrompter server(path, reply);

    MacPrompterClient client(path, trustAnyPeerForTest());
    const auto r = client.requestCan(Agent::PromptOptions{});
    EXPECT_EQ(r.status, Agent::PromptStatus::Timeout);
    EXPECT_NE(r.status, Agent::PromptStatus::Cancelled);
    EXPECT_FALSE(r.secret.has_value());
}

// The helper outlives the agent that installed it, so a reply that names no
// protocol comes from a prompter that never saw the deadline — it showed a
// window with no visible clock while the core stopped watching. Nothing such a
// helper collected is taken, and the refusal happens before the secret in the
// reply can become a result.
TEST(MacPrompterClient, AReplyWithoutAVersionMapsToHelperTooOldBeforeAnySecretIsRead)
{
    const std::string path = uniquePath();
    const std::vector<std::uint8_t> secret{'1', '3', '5', '7'}; // fake test value, not a card PIN
    const auto body = secretReplyWithoutAVersion(secret);
    FakePrompter server(path, body);

    MacPrompterClient client(path, trustAnyPeerForTest());
    const auto r = client.requestPin(Agent::PromptOptions{});

    EXPECT_EQ(r.status, Agent::PromptStatus::HelperTooOld);
    EXPECT_NE(r.status, Agent::PromptStatus::Ok);
    EXPECT_FALSE(r.secret.has_value()) << "no secret from a helper this build cannot place";

    // And the refusal is not vacuous: the reply really did carry a secret.
    // carries() is the load-bearing half — the equality below compares two
    // test-side copies, which nothing the client does could have changed, and
    // stands only as a guard on the builder itself.
    server.waitUntilServed();
    ASSERT_TRUE(server.sentRawBody().has_value());
    EXPECT_EQ(*server.sentRawBody(), body);
    EXPECT_TRUE(carries(*server.sentRawBody(), secret));
}

// The change path takes the identical refusal, over BOTH secrets.
TEST(MacPrompterClient, AChangeReplyWithoutAVersionMapsToHelperTooOldBeforeAnySecretIsRead)
{
    const std::string path = uniquePath();
    const std::vector<std::uint8_t> current{'1', '3', '5', '7'}; // fake test values, not card PINs
    const std::vector<std::uint8_t> replacement{'2', '4', '6', '8'};
    const auto body = secretsReplyWithoutAVersion(current, replacement);
    FakeChangePrompter server(path, body);

    MacPrompterClient client(path, trustAnyPeerForTest());
    const auto r = client.requestPinChange(Agent::PromptOptions{});

    EXPECT_EQ(r.status, Agent::PromptStatus::HelperTooOld);
    EXPECT_FALSE(r.current.has_value());
    EXPECT_FALSE(r.newPin.has_value());

    // carries() is the load-bearing half here too, for the same reason.
    server.waitUntilServed();
    ASSERT_TRUE(server.sentRawBody().has_value());
    EXPECT_EQ(*server.sentRawBody(), body);
    EXPECT_TRUE(carries(*server.sentRawBody(), current));
    EXPECT_TRUE(carries(*server.sentRawBody(), replacement));
}

// A confirmation is an approval, and an approval from a helper that never said
// what it speaks is one this agent cannot place. The confirmation path has no
// secret to withhold, so it expresses the refusal the only way it can: a
// non-Ok verdict, which leaves the stored value exactly where it was.
TEST(MacPrompterClient, AConfirmationFromAHelperWithoutAVersionIsRefused)
{
    const std::string path = uniquePath();
    FakeConfirmPrompter server(path, confirmReplyWithoutAVersion());

    // A permissive verifier, like every other test here, and the EXACT text the
    // version guard refuses with. Every refusal on this path is an Error with
    // some message, so asserting only the status would keep passing if the
    // refusal ever came from somewhere else -- peer verification, say, were it
    // added to this path -- and the version guard would lose its only coverage
    // without anything going red.
    MacPrompterClient client(path, trustAnyPeerForTest());
    const auto reply = client.requestConfirmation(wire::ConfirmAction{"configure_trust", {}, {}, {}, {}});

    EXPECT_NE(reply.status, wire::PromptReplyStatus::Ok);
    EXPECT_EQ(reply.status, wire::PromptReplyStatus::Error);
    EXPECT_EQ(reply.userMessage, "prompter too old to confirm");
}

// The half of the budget the poll cannot bound. A helper that gets its first
// byte out and then stalls mid-frame leaves recvFrame reading a whole frame
// that never completes, so the receive timeout is the only thing that ends the
// wait -- and it must still be a timeout when the poll consumed nearly all of
// the allowance, because a remainder that rounds to nothing is spelled {0, 0},
// which on this platform is SO_RCVTIMEO's default: no timeout at all.
TEST(MacPrompterClient, ResetGivesUpOnAPrompterThatStallsMidFrame)
{
    const std::string path = uniquePath();
    FakeResetPrompter server(path, FakeResetPrompter::HeaderThenStall{});

    MacPrompterClient client(path, trustAnyPeerForTest());
    const auto begun = std::chrono::steady_clock::now();
    client.reset();
    const auto elapsed = std::chrono::steady_clock::now() - begun;

    EXPECT_LT(elapsed, std::chrono::seconds(1)) << "a half-sent frame must not hold the agent's start-up";
    server.waitUntilServed();
    EXPECT_EQ(server.resetCount(), 1u);
}

// Reset is how a fresh agent clears windows a previous one left standing —
// windows it cannot address by id, because it never minted them. It runs
// before anything is served, so all three shapes of prompter have to leave the
// agent able to start.
TEST(MacPrompterClient, ResetWaitsForResetDoneAndSurvivesAMissingPrompter)
{
    // (a) A live prompter is asked exactly once, and the call returns on the
    // answer it gives.
    {
        const std::string path = uniquePath();
        FakeResetPrompter server(path, wire::ResetDone{.closed = 1});

        MacPrompterClient client(path, trustAnyPeerForTest());
        static_assert(noexcept(client.reset()), "nothing may throw out of the agent's start-up reset");
        client.reset();

        server.waitUntilServed();
        EXPECT_EQ(server.resetCount(), 1u);
    }

    // (b) No prompter at all — the ordinary case on a machine whose helper has
    // never been launched. Nothing is standing because nobody raised anything,
    // and the agent starts.
    {
        MacPrompterClient client("/tmp/ld-nonexistent-" + std::to_string(std::rand()) + ".sock");
        const auto begun = std::chrono::steady_clock::now();
        client.reset();
        EXPECT_LT(std::chrono::steady_clock::now() - begun, std::chrono::seconds(1));
    }

    // (c) A prompter that takes the Reset and answers nothing, holding the
    // connection open. The wait is bounded, so a wedged helper delays the
    // agent's start instead of preventing it.
    {
        const std::string path = uniquePath();
        FakeResetPrompter server(path, std::nullopt);

        MacPrompterClient client(path, trustAnyPeerForTest());
        const auto begun = std::chrono::steady_clock::now();
        client.reset();
        EXPECT_LT(std::chrono::steady_clock::now() - begun, std::chrono::seconds(2));

        server.waitUntilServed();
        EXPECT_EQ(server.resetCount(), 1u);
    }
}

} // namespace
