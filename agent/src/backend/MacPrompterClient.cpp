// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Agent-side prompter client: blocking CBOR request/reply over the private 0600
// prompter.sock, scrubbing the returned secret straight into a Secure::String
// and zeroing the transfer buffer. The secret never transits a client.
#include <LibreSCRS/Darwin/backend/MacPrompterClient.h>

#include <LibreSCRS/Darwin/backend/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/UniqueFd.h>

#include <LibreSCRS/Secure/String.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <string_view>
#include <utility>

namespace LibreSCRS::Darwin {
namespace {

wire::UniqueFd connectPrompter(const std::string& path)
{
    if (path.size() >= sizeof(sockaddr_un{}.sun_path)) {
        return {};
    }
    const int c = ::socket(AF_UNIX, SOCK_STREAM, 0); // blocking (prompter contract)
    if (c < 0) {
        return {};
    }
    wire::UniqueFd fd(c);
    ::fcntl(c, F_SETFD, FD_CLOEXEC);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        return {};
    }
    return fd;
}

wire::PromptRequest buildRequest(wire::PromptKind kind, const Agent::PromptOptions& o)
{
    wire::PromptRequest r;
    r.kind = kind;
    r.title = o.title;
    r.description = o.description;
    r.requester = o.requester;
    r.artifact = o.artifact;
    r.minLength = o.minLength;
    r.maxLength = o.maxLength;
    return r;
}

Agent::PromptResult errorResult(std::string message)
{
    Agent::PromptResult r;
    r.status = Agent::PromptStatus::Error;
    r.userMessage = std::move(message);
    return r;
}

} // namespace

MacPrompterClient::MacPrompterClient(std::string prompterSocketPath) : m_socketPath(std::move(prompterSocketPath)) {}

MacPrompterClient::~MacPrompterClient() = default;

Agent::PromptResult MacPrompterClient::request(wire::PromptKind kind, const Agent::PromptOptions& options)
{
    wire::UniqueFd fd = connectPrompter(m_socketPath);
    if (!fd) {
        return errorResult("prompter unavailable");
    }

    const auto body = wire::toCbor(buildRequest(kind, options)).encode();
    if (!wire::sendFrame(fd.get(), body).has_value()) {
        return errorResult("prompter send failed");
    }
    auto frame = wire::recvFrame(fd.get());
    if (!frame.has_value()) {
        return errorResult("prompter recv failed");
    }
    auto reply = wire::parsePromptReply(frame->body);
    if (!reply.has_value()) {
        return errorResult("prompter reply malformed");
    }

    Agent::PromptResult result;
    switch (reply->status) {
    case wire::PromptReplyStatus::Ok: {
        result.status = Agent::PromptStatus::Ok;
        // Scrub the inline secret into a cleansing Secure::String, then zero the
        // transfer buffer so no plaintext lingers in the CBOR frame.
        result.secret = LibreSCRS::Secure::String(
            std::string_view(reinterpret_cast<const char*>(reply->secret.data()), reply->secret.size()));
        std::fill(reply->secret.begin(), reply->secret.end(), std::uint8_t{0});
        break;
    }
    case wire::PromptReplyStatus::Cancelled:
        result.status = Agent::PromptStatus::Cancelled;
        break;
    case wire::PromptReplyStatus::Unauthorized:
        // We ARE the agent; unauthorized means the prompter rejected our peer
        // creds — a misconfiguration. Treat as an error (fail closed).
        result.status = Agent::PromptStatus::Error;
        result.userMessage = "prompter rejected the agent (unauthorized)";
        break;
    case wire::PromptReplyStatus::Error:
        result.status = Agent::PromptStatus::Error;
        break;
    }
    if (!reply->userMessage.empty() && result.userMessage.empty()) {
        result.userMessage = reply->userMessage;
    }
    return result;
}

Agent::PromptResult MacPrompterClient::requestPin(const Agent::PromptOptions& options)
{
    return request(wire::PromptKind::Pin, options);
}

Agent::PromptResult MacPrompterClient::requestCan(const Agent::PromptOptions& options)
{
    return request(wire::PromptKind::Can, options);
}

Agent::PromptResult MacPrompterClient::requestMrz(const Agent::PromptOptions& options)
{
    return request(wire::PromptKind::Mrz, options);
}

void MacPrompterClient::cancel() noexcept
{
    // Best-effort cross-connection dismiss of whatever modal is up.
    wire::UniqueFd fd = connectPrompter(m_socketPath);
    if (!fd) {
        return;
    }
    const auto body = wire::toCbor(wire::PromptCancel{}).encode();
    static_cast<void>(wire::sendFrame(fd.get(), body));
}

} // namespace LibreSCRS::Darwin
