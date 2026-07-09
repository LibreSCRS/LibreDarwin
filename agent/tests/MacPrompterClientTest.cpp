// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// MacPrompterClient against a fake prompter server on a real bound socket. The
// secret is a fake test value (never a real card PIN); it round-trips into a
// cleansing Secure::String.
#include <LibreSCRS/Darwin/backend/MacPrompterClient.h>
#include <LibreSCRS/Darwin/backend/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>

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
            auto req = wire::recvFrame(c);
            if (req.has_value()) {
                static_cast<void>(wire::sendFrame(c, wire::toCbor(m_reply).encode()));
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

} // namespace
