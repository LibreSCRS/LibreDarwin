// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Agent-side prompter client: blocking CBOR request/reply over the private 0600
// prompter.sock, scrubbing the returned secret straight into a Secure::String
// and zeroing the transfer buffer. The secret never transits a client.
#include <LibreSCRS/Darwin/backend/MacPrompterClient.h>

#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h>

#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <LibreSCRS/Secure/String.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <optional>
#include <cstring>
#include <string_view>
#include <utility>

namespace LibreSCRS::Darwin {
namespace {

Agent::Wire::UniqueFd connectPrompter(const std::string& path)
{
    if (path.size() >= sizeof(sockaddr_un{}.sun_path)) {
        return {};
    }
    const int c = ::socket(AF_UNIX, SOCK_STREAM, 0); // blocking (prompter contract)
    if (c < 0) {
        return {};
    }
    Agent::Wire::UniqueFd fd(c);
    ::fcntl(c, F_SETFD, FD_CLOEXEC);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        return {};
    }
    return fd;
}

// How long the start-up reset waits for the prompter's answer. Short on
// purpose: nothing this agent offers is served until it elapses, and the only
// thing the answer adds is the COUNT -- which separates "nothing was standing"
// from "the helper ignored the verb". Worth a short wait, not a long one.
constexpr int kResetReplyBudgetMs = 500;

// The floor under the receive timeout below. SO_RCVTIMEO of {0, 0} is not
// "expire at once" on this platform -- it is the DEFAULT, which is no timeout
// at all -- so a remainder small enough to round away must still be asked for
// as a real interval, or the bound silently becomes its opposite.
constexpr std::int64_t kMinReceiveBudgetUs = 1000;

// Wait until @p fd has something to read, but not past @p deadline. poll's own
// timeout restarts from the top on every EINTR, so the deadline is kept here
// rather than handed to poll once and hoped for. Returns what is LEFT of the
// budget when the first byte lands, so the caller's own wait for the rest of
// the frame comes out of the same allowance -- two waits of the full budget
// would be twice the delay this bound exists to cap. That remainder can be
// zero or negative (the poll may return in the deadline's last fraction, or
// just past it); expressing it in MICROSECONDS keeps a sub-millisecond one
// from rounding to nothing, and the caller clamps what is left.
std::optional<std::chrono::microseconds> waitReadable(int fd, std::chrono::steady_clock::time_point deadline)
{
    for (;;) {
        const auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left <= std::chrono::milliseconds::zero()) {
            return std::nullopt;
        }
        pollfd waited{.fd = fd, .events = POLLIN, .revents = 0};
        const int ready = ::poll(&waited, 1, static_cast<int>(left.count()));
        if (ready > 0) {
            return std::chrono::duration_cast<std::chrono::microseconds>(deadline - std::chrono::steady_clock::now());
        }
        if (ready == 0 || errno != EINTR) {
            return std::nullopt;
        }
    }
}

// The reader's interface qualifier as its wire token. EXHAUSTIVE switch with
// no `default:`: an enumerator appended upstream must be a -Wswitch diagnostic
// here, not a silent fall to "unknown" that would make a dual-interface
// reader's two slots indistinguishable again. Same helper, same reason, as the
// Linux host's readerInterfaceToken().
const char* readerInterfaceToken(Agent::ReaderInterface iface)
{
    switch (iface) {
    case Agent::ReaderInterface::Contact:
        return wire::kReaderInterfaceContact;
    case Agent::ReaderInterface::Contactless:
        return wire::kReaderInterfaceContactless;
    case Agent::ReaderInterface::Unknown:
        return wire::kReaderInterfaceUnknown;
    }
    return wire::kReaderInterfaceUnknown;
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
    // UNTRUSTED per-document display names of a Card1.SignBatch consent
    // (BatchSignFlow's own PromptOptions::artifacts); empty for every prompt
    // that is not a batch sign. Mirrors LibreLinux's PrompterClient.cpp
    // marshaling the same option onto its own wire.
    r.artifacts = o.artifacts;
    // Retry context (CredentialCache::applyRetryContext): both stay at their
    // default (0 / empty) on the first-ever prompt for a card, so both are
    // omitted from the wire then — same convention as every other field here.
    r.attempt = o.attempt;
    r.lastError = o.lastError;
    // The agent's address for this prompt: the prompter records it and matches
    // a later dismissal against it.
    r.promptId = o.promptId;
    // The entry budgets. The core stops its own watchdog once a prompt is up,
    // on the understanding that the window carries a visible deadline -- so a
    // window shown without one is a window nothing is counting. Both travel:
    // what the requested form is worth, and what the alternative form is worth
    // if the holder switches to it in-dialog. 0 is spelled as absence further
    // down the wire and must never read as an instant expiry.
    r.deadlineMs = o.deadlineMs;
    r.altDeadlineMs = o.altDeadlineMs;
    // The reader that raised this prompt (stamped on every PromptOptions by the
    // core's stampPrompt). The seam carries it as ONE fact and the wire as three
    // flat keys, so the flattening happens here -- exactly where the Linux host
    // does it. An unresolved model/full name and an undetermined interface are
    // spelled as absence further down the wire, so a dialog names its reader or
    // says nothing, never the wrong one.
    r.readerModel = o.reader.model;
    r.readerInterface = readerInterfaceToken(o.reader.iface);
    r.readerFull = o.reader.full;
    return r;
}

// Options dictionary parity with the Linux change_pin path: the display
// chrome maps exactly as the single-secret request; the wire exposes PER-ROLE
// length bounds (primary* for the current-PIN field, new* for the new +
// confirm fields) while the seam carries ONE (min, max) pair — so the pair
// maps onto BOTH roles: the same policy applies to the current and the new
// PIN.
wire::RequestSecrets buildChangeRequest(const Agent::PromptOptions& o)
{
    wire::RequestSecrets r;
    r.kind = "change_pin";
    // Interim carry until the prompter wire gains card/pin label fields: the
    // shared change flow sends title="" with the context in cardLabel/pinLabel,
    // which this wire does not transport — surface the PIN label as the title
    // so the modal keeps identifying what is being changed.
    r.title = (o.title.empty() && !o.pinLabel.empty()) ? o.pinLabel : o.title;
    r.description = o.description;
    r.requester = o.requester;
    r.artifact = o.artifact;
    r.primaryMinLength = o.minLength;
    r.primaryMaxLength = o.maxLength;
    r.newMinLength = o.minLength;
    r.newMaxLength = o.maxLength;
    r.promptId = o.promptId;
    return r;
}

Agent::PromptResult errorResult(std::string message)
{
    Agent::PromptResult r;
    r.status = Agent::PromptStatus::Error;
    r.userMessage = std::move(message);
    return r;
}

Agent::PinChangePromptResult changeErrorResult(std::string message)
{
    Agent::PinChangePromptResult r;
    r.status = Agent::PromptStatus::Error;
    r.userMessage = std::move(message);
    return r;
}

} // namespace

MacPrompterClient::MacPrompterClient(std::string prompterSocketPath, PeerVerifier peerVerifier)
    : m_socketPath(std::move(prompterSocketPath)), m_peerVerifier(std::move(peerVerifier))
{
    if (!m_peerVerifier) {
        // Default: the serving peer must BE the prompter — signing id bound to
        // our Team ID via the App-Group entitlement (mirror of the prompter's
        // accept-time check on the agent).
        m_peerVerifier = [](int connectedFd) {
            return verifyConnectedPeer(connectedFd, ExpectedPeerIdentity{.signingId = std::string(kPrompterSigningId),
                                                                         .appGroup = std::string(kAppGroup)});
        };
    }
}

MacPrompterClient::~MacPrompterClient() = default;

wire::ConfirmReply MacPrompterClient::requestConfirmation(const wire::ConfirmAction& action)
{
    // Same connect/send/receive shape as request(), with no scrubbing anywhere:
    // nothing on this path carries a secret, and the reply type cannot.
    // Every failure is a refusal — an unreachable prompter must never read as
    // an approval nobody gave.
    const auto refuse = [](std::string why) {
        return wire::ConfirmReply{wire::PromptReplyStatus::Error, std::move(why)};
    };

    Agent::Wire::UniqueFd fd = connectPrompter(m_socketPath);
    if (!fd) {
        return refuse("prompter unavailable");
    }
    const auto body = wire::toCbor(action).encode();
    if (!Agent::Wire::sendFrame(fd.get(), body).has_value()) {
        return refuse("prompter send failed");
    }
    auto frame = Agent::Wire::recvFrame(fd.get());
    if (!frame.has_value()) {
        return refuse("prompter recv failed");
    }
    auto reply = wire::parseConfirmReply(frame->body);
    if (!reply.has_value()) {
        return refuse("prompter reply malformed");
    }
    // Same refusal as the two secret paths below, for the same reason: a reply
    // that does not say which protocol it speaks, or says an older one, comes
    // from a helper left behind by a previous install. An approval is the one
    // thing that must never be accepted from a peer this agent cannot place --
    // and the only refusal this path can express is a non-Ok verdict, which is
    // exactly what leaves the stored value where it was.
    if (!reply->protocolVersion || *reply->protocolVersion < wire::kPrompterProtocolVersion) {
        return refuse("prompter too old to confirm");
    }
    return std::move(*reply);
}

Agent::PromptResult MacPrompterClient::request(wire::PromptKind kind, const Agent::PromptOptions& options)
{
    Agent::Wire::UniqueFd fd = connectPrompter(m_socketPath);
    if (!fd) {
        return errorResult("prompter unavailable");
    }
    // Verify the SERVING peer before anything crosses the socket: a re-bound
    // prompter.sock must get no request and have no reply consumed.
    if (!m_peerVerifier(fd.get())) {
        return errorResult("prompter peer verification failed");
    }

    const auto body = wire::toCbor(buildRequest(kind, options)).encode();
    if (!Agent::Wire::sendFrame(fd.get(), body).has_value()) {
        return errorResult("prompter send failed");
    }
    auto frame = Agent::Wire::recvFrame(fd.get());
    if (!frame.has_value()) {
        return errorResult("prompter recv failed");
    }
    auto reply = wire::parsePromptReply(frame->body);
    // The raw frame body carries the secret inline for Ok replies; zero it the
    // moment it is parsed, whatever the outcome (parsePromptReply scrubbed its
    // own decoded intermediates, and decode() zeroed the canonical re-encode).
    Agent::Wire::secureZero(frame->body);
    if (!reply.has_value()) {
        return errorResult("prompter reply malformed");
    }

    Agent::PromptResult result;
    // The helper can outlive the agent that installed it. A reply that does
    // not say which protocol it speaks, or says an older one, comes from a
    // prompter that never saw the deadline, so nothing it entered is taken --
    // the same refusal the Linux host makes when it probes its helper.
    if (!reply->protocolVersion || *reply->protocolVersion < wire::kPrompterProtocolVersion) {
        result.status = Agent::PromptStatus::HelperTooOld;
        std::fill(reply->secret.begin(), reply->secret.end(), std::uint8_t{0});
        return result;
    }
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
    case wire::PromptReplyStatus::Timeout:
        // The window's own clock; never folded into Cancelled, which is the
        // person's act.
        result.status = Agent::PromptStatus::Timeout;
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

Agent::PinChangePromptResult MacPrompterClient::requestPinChange(const Agent::PromptOptions& options)
{
    Agent::Wire::UniqueFd fd = connectPrompter(m_socketPath);
    if (!fd) {
        return changeErrorResult("prompter unavailable");
    }
    // Same serving-peer verification as the single-secret path.
    if (!m_peerVerifier(fd.get())) {
        return changeErrorResult("prompter peer verification failed");
    }

    const auto body = wire::toCbor(buildChangeRequest(options)).encode();
    if (!Agent::Wire::sendFrame(fd.get(), body).has_value()) {
        return changeErrorResult("prompter send failed");
    }
    auto frame = Agent::Wire::recvFrame(fd.get());
    if (!frame.has_value()) {
        return changeErrorResult("prompter recv failed");
    }
    auto reply = wire::parseMultiPromptReply(frame->body);
    // The raw frame body carries BOTH secrets inline for Ok replies; zero it
    // the moment it is parsed, whatever the outcome (parseMultiPromptReply
    // scrubbed its own decoded intermediates, and decode() zeroed the
    // canonical re-encode).
    Agent::Wire::secureZero(frame->body);
    if (!reply.has_value()) {
        return changeErrorResult("prompter reply malformed");
    }

    Agent::PinChangePromptResult result;
    // The identical refusal, over BOTH secrets: a helper that never saw the
    // deadline never showed one, whichever modal it raised.
    if (!reply->protocolVersion || *reply->protocolVersion < wire::kPrompterProtocolVersion) {
        result.status = Agent::PromptStatus::HelperTooOld;
        std::fill(reply->primary.begin(), reply->primary.end(), std::uint8_t{0});
        std::fill(reply->secondary.begin(), reply->secondary.end(), std::uint8_t{0});
        return result;
    }
    switch (reply->status) {
    case wire::PromptReplyStatus::Ok: {
        result.status = Agent::PromptStatus::Ok;
        // Scrub each inline secret into a cleansing Secure::String, then zero
        // its transfer buffer so no plaintext lingers in the CBOR frame.
        result.current = LibreSCRS::Secure::String(
            std::string_view(reinterpret_cast<const char*>(reply->primary.data()), reply->primary.size()));
        std::fill(reply->primary.begin(), reply->primary.end(), std::uint8_t{0});
        result.newPin = LibreSCRS::Secure::String(
            std::string_view(reinterpret_cast<const char*>(reply->secondary.data()), reply->secondary.size()));
        std::fill(reply->secondary.begin(), reply->secondary.end(), std::uint8_t{0});
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
    case wire::PromptReplyStatus::Timeout:
        // The window's own clock; never folded into Cancelled, which is the
        // person's act.
        result.status = Agent::PromptStatus::Timeout;
        break;
    }
    if (!reply->userMessage.empty() && result.userMessage.empty()) {
        result.userMessage = reply->userMessage;
    }
    return result;
}

void MacPrompterClient::cancel(const std::string& promptId) noexcept
{
    // Best-effort cross-connection dismiss of the window this id names.
    // Verified like the request paths for uniformity (a rejected peer simply
    // gets no frame at all).
    Agent::Wire::UniqueFd fd = connectPrompter(m_socketPath);
    if (!fd || !m_peerVerifier(fd.get())) {
        return;
    }
    wire::PromptCancel cancelMsg;
    cancelMsg.promptId = promptId;
    const auto body = wire::toCbor(cancelMsg).encode();
    static_cast<void>(Agent::Wire::sendFrame(fd.get(), body));
}

void MacPrompterClient::reset() noexcept
{
    // One handler around the whole body: the log facade formats a line and
    // hands it to an injected std::function sink, so it can throw where a bare
    // write could not -- and a throw out of a noexcept function is the process.
    try {
        Agent::Wire::UniqueFd fd = connectPrompter(m_socketPath);
        if (!fd) {
            // The ordinary case on a machine whose prompter has never been
            // launched: nothing is standing, because nobody raised anything.
            // Said at the lowest level all the same -- a start-up that skips a
            // step silently reads the same as one that never had the step.
            Agent::log::info("prompter not running at start-up; nothing to reset");
            return;
        }
        // Verified like every other path here: a process that unlinked and
        // re-bound prompter.sock gets no frame from us.
        if (!m_peerVerifier(fd.get())) {
            Agent::log::warn("prompter reset skipped: the serving peer failed verification");
            return;
        }
        if (!Agent::Wire::sendFrame(fd.get(), wire::toCbor(wire::PromptReset{}).encode()).has_value()) {
            Agent::log::warn("prompter reset could not be sent");
            return;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kResetReplyBudgetMs);
        const auto left = waitReadable(fd.get(), deadline);
        if (!left) {
            Agent::log::warn("prompter did not answer the reset within the start-up budget");
            return;
        }
        // poll only says a byte arrived; recvFrame reads a WHOLE frame and
        // would sit on a peer that sent a partial one. The receive timeout is
        // what bounds that second wait -- out of what REMAINS of the same
        // budget, because a helper that dribbles half a frame is as wedged as
        // one that sends nothing, and must cost the start-up no more.
        //
        // Clamped to a floor, and never asked for as zero: a first byte landing
        // in the last fraction of the budget leaves a remainder that rounds
        // away (and a poll returning just past the deadline leaves a negative
        // one, which setsockopt refuses outright) -- and either way the socket
        // would keep SO_RCVTIMEO's default of no timeout, turning the bound
        // this comment promises into the unbounded read it exists to prevent.
        const timeval receiveBudget{
            .tv_sec = 0,
            .tv_usec = static_cast<suseconds_t>(std::max<std::int64_t>(left->count(), kMinReceiveBudgetUs))};
        if (::setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &receiveBudget, sizeof(receiveBudget)) != 0) {
            // With no bound in place there is nothing to stop the read below
            // sitting on a half-sent frame, so it is not attempted at all.
            Agent::log::warn("prompter reset: the reply wait could not be bounded, so it was not taken");
            return;
        }
        auto frame = Agent::Wire::recvFrame(fd.get());
        if (!frame.has_value()) {
            Agent::log::warn("prompter gave no readable answer to the reset");
            return;
        }
        const auto done = wire::parseResetDone(frame->body);
        if (!done.has_value()) {
            Agent::log::warn("prompter answered the reset with a message this build cannot read");
            return;
        }
        Agent::log::infof("prompter reset: {} window(s) closed", done->closed);
    } catch (...) {
        // Nothing on this path is worth the agent's life, and after a throw out
        // of the log facade there is nothing left to say it with either.
    }
}

} // namespace LibreSCRS::Darwin
