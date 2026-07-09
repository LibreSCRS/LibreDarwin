// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Prompter socket server. Peer-authenticates the agent (fail-closed
// "unauthorized"), then serves one RequestSecret / CancelCurrent per connection.
#include "PrompterServer.h"

#include <LibreSCRS/Darwin/backend/wire/Framing.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <format>
#include <utility>
#include <variant>

namespace LibreSCRS::Darwin {
namespace {

wire::PromptReply unauthorizedReply()
{
    wire::PromptReply r;
    r.status = wire::PromptReplyStatus::Unauthorized;
    r.userMessage = "caller is not the agent";
    return r;
}

} // namespace

PrompterServer::PrompterServer(std::string socketPath, SecretProvider provider, CancelHandler cancel,
                               PeerAuthorized peerAuth)
    : m_socketPath(std::move(socketPath)), m_provider(std::move(provider)), m_cancel(std::move(cancel)),
      m_peerAuth(std::move(peerAuth))
{}

PrompterServer::~PrompterServer()
{
    stop();
}

std::expected<void, std::string> PrompterServer::start()
{
    if (m_socketPath.size() >= sizeof(sockaddr_un{}.sun_path)) {
        return std::unexpected(std::format("prompter socket path exceeds sun_path limit"));
    }
    ::unlink(m_socketPath.c_str());
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return std::unexpected(std::format("socket(): {}", std::strerror(errno)));
    }
    m_listen = wire::UniqueFd(fd);
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, m_socketPath.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        return std::unexpected(std::format("bind(): {}", std::strerror(errno)));
    }
    ::chmod(m_socketPath.c_str(), 0600);
    if (::listen(fd, 8) != 0) {
        return std::unexpected(std::format("listen(): {}", std::strerror(errno)));
    }
    m_thread = std::thread([this] { acceptLoop(); });
    return {};
}

void PrompterServer::stop() noexcept
{
    if (m_stop.exchange(true)) {
        return;
    }
    if (m_listen) {
        ::shutdown(m_listen.get(), SHUT_RDWR);
    }
    if (m_thread.joinable()) {
        m_thread.join();
    }
    if (!m_socketPath.empty()) {
        ::unlink(m_socketPath.c_str());
    }
}

void PrompterServer::acceptLoop()
{
    while (!m_stop.load()) {
        const int c = ::accept(m_listen.get(), nullptr, nullptr);
        if (c < 0) {
            if (errno == EINTR) {
                continue;
            }
            break; // listen socket shut down
        }
        wire::UniqueFd conn(c);
        handleConnection(c);
    }
}

void PrompterServer::handleConnection(int connFd)
{
    // Peer-auth: only the agent may drive the prompter (Prompter1 "unauthorized").
    const auto creds = capturePeerCredentials(connFd);
    if (!creds || !m_peerAuth(*creds)) {
        static_cast<void>(wire::sendFrame(connFd, wire::toCbor(unauthorizedReply()).encode()));
        return;
    }

    auto frame = wire::recvFrame(connFd);
    if (!frame.has_value()) {
        return;
    }
    auto parsed = wire::parsePrompterRequest(frame->body);
    if (!parsed.has_value()) {
        return; // malformed; drop
    }

    if (std::holds_alternative<wire::PromptCancel>(*parsed)) {
        m_cancel(); // dismiss the active modal; CancelCurrent has no reply
        return;
    }
    const auto& req = std::get<wire::PromptRequest>(*parsed);
    const wire::PromptReply reply = m_provider(req);
    static_cast<void>(wire::sendFrame(connFd, wire::toCbor(reply).encode()));
}

} // namespace LibreSCRS::Darwin
