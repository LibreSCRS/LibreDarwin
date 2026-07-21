// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The macOS inbound dispatcher. Runs entirely on the transport loop thread for
// the request path (the sink fires there); presence entry points marshal to the
// loop. Mirrors LibreLinux's Card1/Manager1/Config1/Pkcs11_1 semantics against
// the neutral LibreAgent::Core.
#include <LibreSCRS/Darwin/backend/SocketFrontend.h>

#include <LibreSCRS/Darwin/backend/SocketOperationChannel.h>
#include <LibreSCRS/Darwin/backend/wire/AnonFd.h>

#include "operations/ActivateSigningKeyOperation.h"
#include "operations/GetPhotoOperation.h"
#include "operations/ListCredentialsOperation.h"
#include "operations/ManagePinOperation.h"
#include "operations/ReadCertificatesOperation.h"
#include "operations/ReadIdentityOperation.h"
#include "operations/SignOperation.h"

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include <LibreSCRS/Agent/Reply.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PinChangeFlow.h> // PinManageRequest, validatePinManageRequest
#include <LibreSCRS/Agent/operations/SignatureParams.h>
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/util/CallerLabel.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialSnapshot, EntryError

#include <LibreSCRS/Plugin/PluginTypes.h> // CardCapabilities

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <variant>
#include <vector>

namespace LibreSCRS::Darwin {
namespace {

namespace A = LibreSCRS::Agent;
namespace Ops = LibreSCRS::Agent::Operations;
namespace sp = LibreSCRS::Agent::Operations::SignatureParams;

constexpr std::uint32_t kIdentityCapBit = static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData);
constexpr std::uint32_t kPkiCapBit = static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PKI);
constexpr std::uint32_t kPinManagementCapBit =
    static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PinManagement);

constexpr const char* kArtifactIdentity = "identity";
constexpr const char* kArtifactPhoto = "photo";
constexpr const char* kArtifactCertificates = "certificates";
constexpr const char* kArtifactCredentials = "credentials";

// The credentials verb that may carry the activateKey wire key (the wire's
// closed cred-verb vocabulary; validatePinManageRequest owns the full check).
constexpr const char* kVerbActivatePin = "activate_pin";

constexpr std::size_t kMaxInputBytes = 256ull * 1024 * 1024;
constexpr std::chrono::milliseconds kResolveRetryDelay{50};

enum class ReadStatus { Ok, TooLarge, Error, NotRegular };
struct ReadDoc
{
    ReadStatus status{ReadStatus::Error};
    std::vector<std::uint8_t> bytes;
};

// Read the whole document off @p fd, capping at @p cap. The fd MUST be a regular
// file / anonymous file: a pipe/socket/char fd would let a client stall the
// blocking read on the loop thread (whole-agent DoS), so non-regular fds are
// rejected up front via fstat. (Mirror of LibreLinux CardObject::readDocument.)
ReadDoc readDocument(int fd, std::size_t cap)
{
    if (fd < 0) {
        return {ReadStatus::Error, {}};
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        return {ReadStatus::Error, {}};
    }
    if (!S_ISREG(st.st_mode)) {
        return {ReadStatus::NotRegular, {}};
    }
    std::vector<std::uint8_t> out;
    std::array<std::uint8_t, 64 * 1024> buf{};
    for (;;) {
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return {ReadStatus::Error, {}};
        }
        if (n == 0) {
            return {ReadStatus::Ok, std::move(out)};
        }
        if (out.size() + static_cast<std::size_t>(n) > cap) {
            return {ReadStatus::TooLarge, {}};
        }
        out.insert(out.end(), buf.data(), buf.data() + static_cast<std::size_t>(n));
    }
}

// Pkcs11Broker::CryptoOutcome -> wire sync error. CardError/Cancelled fail
// closed to CommunicationError (no dedicated cancelled sync error).
wire::SyncError mapCryptoOutcome(A::Pkcs11Broker::CryptoOutcome oc) noexcept
{
    using CO = A::Pkcs11Broker::CryptoOutcome;
    switch (oc) {
    case CO::KeyNotFound:
        return wire::SyncError::KeyNotFound;
    case CO::AuthFailed:
        return wire::SyncError::AuthFailed;
    case CO::NotSupported:
        return wire::SyncError::NotSupported;
    case CO::UnknownCard:
        return wire::SyncError::UnknownCard;
    case CO::UserNotLoggedIn:
        return wire::SyncError::UserNotLoggedIn;
    case CO::RateLimited:
        return wire::SyncError::RateLimited;
    case CO::Ok:
    case CO::Cancelled:
    case CO::CardError:
        break;
    }
    return wire::SyncError::CommunicationError;
}

wire::SyncError mapLoginOutcome(A::Pkcs11Broker::LoginOutcome oc) noexcept
{
    using LO = A::Pkcs11Broker::LoginOutcome;
    switch (oc) {
    case LO::NotAuthorizedByCard:
        return wire::SyncError::AuthFailed;
    case LO::UnknownCard:
        return wire::SyncError::UnknownCard;
    case LO::NotAuthorized:
        return wire::SyncError::NotAuthorized;
    case LO::Ok:
    case LO::Cancelled:
    case LO::CardError:
        break;
    }
    return wire::SyncError::CommunicationError;
}

// Map a validatePinManageRequest EntryError onto its typed wire error. UnknownVerb
// / UnknownOption / InvalidCombination are the client's fault (InvalidRequest);
// UnknownCredential (bad or unlisted pinId, incl. the never-listed case) is its own
// name so a client can distinguish "re-list and retry" from "fix your request".
// (Mirror of LibreLinux CardObject's throwEntryError.)
wire::SyncError mapEntryError(A::EntryError err) noexcept
{
    switch (err) {
    case A::EntryError::UnknownCredential:
        return wire::SyncError::UnknownCredential;
    case A::EntryError::UnknownVerb:
    case A::EntryError::UnknownOption:
    case A::EntryError::InvalidCombination:
    case A::EntryError::AmbiguousCredential: // non-unique label: the seam must never guess
        break;
    }
    return wire::SyncError::InvalidRequest;
}

// Extract a std::string from a CBOR text value; nullopt on a type mismatch.
std::optional<std::string> asString(const wire::CborValue& v)
{
    if (const auto* s = v.asText()) {
        return *s;
    }
    return std::nullopt;
}

// Marshal a reply/error onto the loop via the TRANSPORT ONLY (never the
// frontend). A broker Reply continuation fires from a worker thread — or from the
// Reply's fail-closed destructor when the op is torn down at shutdown — which may
// be after the frontend is freed; capturing only the long-lived transport pointer
// (taken on the loop at reply construction, while the frontend is alive) keeps
// that path lifetime-safe without relying on the loop-quiesce drop.
void postReply(SocketTransport* tr, std::uint64_t connId, wire::CborValue message)
{
    tr->post([tr, connId, message] { tr->sendTo(connId, message); });
}
void postErr(SocketTransport* tr, std::uint64_t connId, std::uint64_t req, wire::SyncError code)
{
    postReply(tr, connId, wire::makeErrorReply(req, wire::ErrInfo{code, std::nullopt, std::nullopt}));
}

} // namespace

SocketFrontend::SocketFrontend(SocketTransport& transport, A::AgentCore& core, std::string version)
    : m_transport(transport), m_core(core), m_version(std::move(version))
{}

void SocketFrontend::start()
{
    m_transport.setRequestSink([this](SocketTransport::Inbound&& in) { dispatch(std::move(in)); });
}

std::string SocketFrontend::requesterLabel(const A::CallerToken& caller) const
{
    if (const auto creds = m_transport.credentialsFor(caller)) {
        return A::sanitizeLabel(creds->label());
    }
    return {};
}

void SocketFrontend::sendReplyOnLoop(std::uint64_t connId, wire::CborValue message)
{
    m_transport.sendTo(connId, message);
}

void SocketFrontend::replyError(std::uint64_t connId, std::uint64_t req, wire::SyncError code)
{
    sendReplyOnLoop(connId, wire::makeErrorReply(req, wire::ErrInfo{code, std::nullopt, std::nullopt}));
}

void SocketFrontend::dispatch(SocketTransport::Inbound&& in)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const A::CallerToken caller = in.caller;
    auto& body = in.request.body;

    if (const auto* m = std::get_if<wire::Hello>(&body)) {
        handleHello(connId, req, *m);
    } else if (std::get_if<wire::GetState>(&body)) {
        handleGetState(connId, req);
    } else if (const auto* m = std::get_if<wire::ReadIdentity>(&body)) {
        handleReadIdentity(in, *m);
    } else if (const auto* m = std::get_if<wire::GetPhoto>(&body)) {
        handleGetPhoto(in, *m);
    } else if (const auto* m = std::get_if<wire::ReadCertificates>(&body)) {
        handleReadCertificates(in, *m);
    } else if (const auto* m = std::get_if<wire::Sign>(&body)) {
        handleSign(in, *m);
    } else if (const auto* m = std::get_if<wire::ListCredentials>(&body)) {
        handleListCredentials(in, *m);
    } else if (const auto* m = std::get_if<wire::ManagePin>(&body)) {
        handleManagePin(in, *m);
    } else if (const auto* m = std::get_if<wire::ActivateSigningKey>(&body)) {
        handleActivateSigningKey(in, *m);
    } else if (const auto* m = std::get_if<wire::GetCertDer>(&body)) {
        handleCertDer(connId, req, *m, caller);
    } else if (std::get_if<wire::GetConfig>(&body)) {
        handleGetConfig(connId, req);
    } else if (const auto* m = std::get_if<wire::SetConfig>(&body)) {
        handleSetConfig(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<wire::ResetConfig>(&body)) {
        handleResetConfig(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<wire::CancelOp>(&body)) {
        handleCancel(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<wire::GetSignResult>(&body)) {
        handleGetSignResult(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<wire::PkLogin>(&body)) {
        handlePkLogin(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<wire::PkLogout>(&body)) {
        handlePkLogout(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<wire::PkPublicKey>(&body)) {
        handlePkPublicKey(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<wire::PkSignRaw>(&body)) {
        handlePkSignRaw(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<wire::PkDecrypt>(&body)) {
        handlePkDecrypt(connId, req, *m, caller);
    }
}

void SocketFrontend::handleHello(std::uint64_t connId, std::uint64_t req, const wire::Hello& /*msg*/)
{
    wire::HelloAck ack;
    ack.agentVer = m_version;
    ack.features = {"identity", "certificates", "photo", "sign", "pkcs11", "config", "credentials"};
    sendReplyOnLoop(connId, wire::makeReply(req, ack));
}

void SocketFrontend::handleGetState(std::uint64_t connId, std::uint64_t req)
{
    sendReplyOnLoop(connId, wire::makeReply(req, m_transport.currentState()));
}

// --- card operations ---------------------------------------------------------

void SocketFrontend::handleReadIdentity(SocketTransport::Inbound& in, const wire::ReadIdentity& msg)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kIdentityCapBit) == 0) {
        replyError(connId, req, wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    const std::string requester = requesterLabel(in.caller);
    const std::string cardKey = routing->cardKey;
    const std::string readerName = routing->readerName;
    const A::ObjectId readerId = routing->readerId;
    auto& core = m_core;

    try {
        const auto id = core.operationManager().publish(
            readerId, readerName, in.caller,
            [this, connId, &core, cardKey, readerName,
             requester](Ops::CardSessionHolder* holder, A::OperationId opId) -> std::unique_ptr<Ops::OperationBase> {
                auto reader = std::make_shared<Ops::LmCardReader>();
                auto state = std::make_shared<Ops::OperationState>();
                auto channel = std::make_unique<SocketOperationChannel>(m_transport, connId, opId.value(), state,
                                                                        SocketOperationChannel::SignArtifactSink{},
                                                                        makeOpFinishedSink());
                Ops::ReadIdentityOperation::Deps deps{
                    .holder = holder,
                    .reader = *reader,
                    .prompter = *core.sharedCryptoContext()->prompter,
                    .serializer = *core.sharedCryptoContext()->serializer,
                    .credentials = core.credentialCache(),
                    .readCache = core.cardReadCache(),
                    .cardKey = cardKey,
                    .readerName = readerName,
                    .requester = requester,
                    .artifact = kArtifactIdentity,
                };
                auto op = std::make_unique<Ops::ReadIdentityOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(reader);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = in.caller;
        sendReplyOnLoop(connId, wire::makeReply(req, wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleGetPhoto(SocketTransport::Inbound& in, const wire::GetPhoto& msg)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kIdentityCapBit) == 0) {
        replyError(connId, req, wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    const std::string requester = requesterLabel(in.caller);
    const std::string cardKey = routing->cardKey;
    const std::string readerName = routing->readerName;
    const A::ObjectId readerId = routing->readerId;
    auto& core = m_core;

    try {
        const auto id = core.operationManager().publish(
            readerId, readerName, in.caller,
            [this, connId, &core, cardKey, readerName,
             requester](Ops::CardSessionHolder* holder, A::OperationId opId) -> std::unique_ptr<Ops::OperationBase> {
                auto reader = std::make_shared<Ops::LmCardReader>();
                auto state = std::make_shared<Ops::OperationState>();
                auto channel = std::make_unique<SocketOperationChannel>(m_transport, connId, opId.value(), state,
                                                                        SocketOperationChannel::SignArtifactSink{},
                                                                        makeOpFinishedSink());
                Ops::GetPhotoOperation::Deps deps{
                    .holder = holder,
                    .reader = *reader,
                    .prompter = *core.sharedCryptoContext()->prompter,
                    .serializer = *core.sharedCryptoContext()->serializer,
                    .credentials = core.credentialCache(),
                    .readCache = core.cardReadCache(),
                    .cardKey = cardKey,
                    .readerName = readerName,
                    .requester = requester,
                    .artifact = kArtifactPhoto,
                };
                auto op = std::make_unique<Ops::GetPhotoOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(reader);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = in.caller;
        sendReplyOnLoop(connId, wire::makeReply(req, wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleReadCertificates(SocketTransport::Inbound& in, const wire::ReadCertificates& msg)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPkiCapBit) == 0) {
        replyError(connId, req, wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    const std::string requester = requesterLabel(in.caller);
    const std::string cardKey = routing->cardKey;
    const std::string readerName = routing->readerName;
    const A::ObjectId readerId = routing->readerId;
    auto& core = m_core;

    try {
        const auto id = core.operationManager().publish(
            readerId, readerName, in.caller,
            [this, connId, &core, cardKey, readerName,
             requester](Ops::CardSessionHolder* holder, A::OperationId opId) -> std::unique_ptr<Ops::OperationBase> {
                auto certReader = std::make_shared<Ops::LmCertificateReader>();
                auto state = std::make_shared<Ops::OperationState>();
                auto channel = std::make_unique<SocketOperationChannel>(m_transport, connId, opId.value(), state,
                                                                        SocketOperationChannel::SignArtifactSink{},
                                                                        makeOpFinishedSink());
                Ops::ReadCertificatesOperation::Deps deps{
                    .holder = holder,
                    .certReader = *certReader,
                    .prompter = *core.sharedCryptoContext()->prompter,
                    .serializer = *core.sharedCryptoContext()->serializer,
                    .credentials = core.credentialCache(),
                    .readCache = core.cardReadCache(),
                    .cardKey = cardKey,
                    .readerName = readerName,
                    .requester = requester,
                    .artifact = kArtifactCertificates,
                };
                auto op = std::make_unique<Ops::ReadCertificatesOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(certReader);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = in.caller;
        sendReplyOnLoop(connId, wire::makeReply(req, wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleSign(SocketTransport::Inbound& in, const wire::Sign& msg)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPkiCapBit) == 0) {
        replyError(connId, req, wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    if (msg.cert.empty()) {
        replyError(connId, req, wire::SyncError::UnsupportedSignatureParameter);
        return;
    }

    // Authorize the CLIENT then apply the sign-flood rate-limit BEFORE ingesting
    // the document (a rejected caller never makes the agent read up to 256 MiB).
    if (!m_core.authorizer().authorize(A::kActionSign, in.caller)) {
        replyError(connId, req, wire::SyncError::NotAuthorized);
        return;
    }
    if (!m_core.rateLimiter().allow(in.caller)) {
        replyError(connId, req, wire::SyncError::RateLimited);
        return;
    }

    // The input document rides SCM_RIGHTS as fd-index msg.inFd into in.fds.
    if (msg.inFd >= in.fds.size()) {
        replyError(connId, req, wire::SyncError::UnsupportedSignatureParameter);
        return;
    }
    auto doc = readDocument(in.fds[msg.inFd].get(), kMaxInputBytes);
    if (doc.status == ReadStatus::NotRegular) {
        replyError(connId, req, wire::SyncError::UnsupportedSignatureParameter);
        return;
    }
    if (doc.status == ReadStatus::TooLarge) {
        replyError(connId, req, wire::SyncError::InputTooLarge);
        return;
    }
    if (doc.status == ReadStatus::Error) {
        replyError(connId, req, wire::SyncError::CommunicationError); // internal read failure
        return;
    }
    if (doc.bytes.empty()) {
        replyError(connId, req, wire::SyncError::UnsupportedSignatureParameter); // empty document
        return;
    }

    // Resolve format (sniff on auto), level (TSA-derived default), packaging to
    // concrete vocabulary; out-of-vocabulary is a method-entry rejection.
    std::string format = msg.opts.format;
    if (format == "auto" || format.empty()) {
        const auto sniffed = sp::sniffFormat(doc.bytes);
        if (!sniffed) {
            replyError(connId, req, wire::SyncError::UnsupportedSignatureParameter);
            return;
        }
        format = *sniffed;
    }
    if (!sp::isKnownFormat(format)) {
        replyError(connId, req, wire::SyncError::UnsupportedSignatureParameter);
        return;
    }
    std::optional<std::string> requestedLevel;
    if (!msg.opts.level.empty() && msg.opts.level != "auto") {
        requestedLevel = msg.opts.level;
    }
    std::string level = sp::resolveSignLevel(requestedLevel, m_core.configStore().defaultLevel(),
                                             !m_core.configStore().tsaUrls().empty());
    if (!sp::isKnownLevel(level) || !sp::isImplementedSignLevel(level)) {
        replyError(connId, req, wire::SyncError::UnsupportedSignatureParameter);
        return;
    }
    std::string packaging = msg.opts.packaging;
    if (packaging == "auto" || packaging.empty()) {
        packaging = sp::defaultPackagingFor(format);
    }
    if (!sp::isKnownPackaging(packaging)) {
        replyError(connId, req, wire::SyncError::UnsupportedSignatureParameter);
        return;
    }

    const std::string requester = requesterLabel(in.caller);
    Ops::SignParams params{
        .certId = msg.cert,
        .inputDocument = std::move(doc.bytes),
        .format = std::move(format),
        .level = std::move(level),
        .packaging = std::move(packaging),
        .allowExpired = msg.opts.allowExpired.value_or(false),
        .displayName = A::sanitizeLabel(msg.opts.displayName.value_or(std::string{})),
        .reason = msg.opts.reason.value_or(m_core.configStore().defaultReason()),
        .location = msg.opts.location.value_or(m_core.configStore().defaultLocation()),
    };

    const std::string cardKey = routing->cardKey;
    const std::string readerName = routing->readerName;
    const A::ObjectId readerId = routing->readerId;
    const A::CallerToken owner = in.caller;
    auto* tr = &m_transport;
    auto& core = m_core;

    try {
        const auto id = core.operationManager().publish(
            readerId, readerName, in.caller,
            [this, tr, connId, owner, &core, cardKey, readerName, requester, params = std::move(params)](
                Ops::CardSessionHolder* holder, A::OperationId opId) mutable -> std::unique_ptr<Ops::OperationBase> {
                auto signer = std::make_shared<Ops::LmSigner>(core.signingEngineProvider());
                auto state = std::make_shared<Ops::OperationState>();
                // The sign sink fires on the WORKER thread: touch only the
                // long-lived transport there, and marshal the frontend-state store
                // (m_signResults) onto the loop where the loop-quiesce drop guards
                // it against a post-teardown frontend.
                auto channel = std::make_unique<SocketOperationChannel>(
                    m_transport, connId, opId.value(), state,
                    [this, tr, owner](std::uint64_t sid, const Ops::SignedArtifact& artifact) {
                        tr->post([this, sid, owner, artifact] { stashSignArtifact(sid, owner, artifact); });
                    },
                    makeOpFinishedSink());
                Ops::SignOperation::Deps deps{
                    .holder = holder,
                    .signer = *signer,
                    .prompter = *core.sharedCryptoContext()->prompter,
                    .serializer = *core.sharedCryptoContext()->serializer,
                    .credentials = core.credentialCache(),
                    .cardKey = cardKey,
                    .readerName = readerName,
                    .requester = requester,
                    .params = std::move(params),
                };
                auto op = std::make_unique<Ops::SignOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(signer);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = owner;
        sendReplyOnLoop(connId, wire::makeReply(req, wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, wire::SyncError::RateLimited);
    }
}

// --- credentials (PIN/PUK management) ----------------------------------------

void SocketFrontend::handleListCredentials(SocketTransport::Inbound& in, const wire::ListCredentials& msg)
{
    // A read of the card's PIN credentials. Gates on PinManagement (no listing is
    // meaningful without it) but is NOT rate-limited — no card-state mutation.
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPinManagementCapBit) == 0) {
        replyError(connId, req, wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    const std::string requester = requesterLabel(in.caller);
    const std::string cardKey = routing->cardKey;
    const std::string readerName = routing->readerName;
    const A::ObjectId readerId = routing->readerId;
    auto& core = m_core;

    try {
        const auto id = core.operationManager().publish(
            readerId, readerName, in.caller,
            [this, connId, &core, cardKey, readerName,
             requester](Ops::CardSessionHolder* holder, A::OperationId opId) -> std::unique_ptr<Ops::OperationBase> {
                auto credentials = std::make_shared<Ops::LmCredentialManager>();
                auto state = std::make_shared<Ops::OperationState>();
                auto channel = std::make_unique<SocketOperationChannel>(m_transport, connId, opId.value(), state,
                                                                        SocketOperationChannel::SignArtifactSink{},
                                                                        makeOpFinishedSink());
                Ops::ListCredentialsOperation::Deps deps{
                    .holder = holder,
                    .credentials = *credentials,
                    .prompter = *core.sharedCryptoContext()->prompter,
                    .serializer = *core.sharedCryptoContext()->serializer,
                    .credCache = core.credentialCache(),
                    .snapshotCache = core.credentialSnapshotCache(),
                    .cardKey = cardKey,
                    .readerName = readerName,
                    .requester = requester,
                    .artifact = kArtifactCredentials,
                };
                auto op = std::make_unique<Ops::ListCredentialsOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(credentials);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = in.caller;
        sendReplyOnLoop(connId, wire::makeReply(req, wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleManagePin(SocketTransport::Inbound& in, const wire::ManagePin& msg)
{
    // Entry gating: capability -> authorize -> rate-limit -> validation, all
    // BEFORE any Operation (and thus any prompt) exists — the same matrix and
    // order as LibreLinux's Credentials1.ManagePin.
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPinManagementCapBit) == 0) {
        replyError(connId, req, wire::SyncError::UnsupportedOnThisCard);
        return;
    }

    // Authorize + rate-limit (BEFORE any prompt), same posture + ordering as Sign.
    if (!m_core.authorizer().authorize(A::kActionCredentialsManage, in.caller)) {
        replyError(connId, req, wire::SyncError::NotAuthorized);
        return;
    }
    if (!m_core.rateLimiter().allow(in.caller)) {
        replyError(connId, req, wire::SyncError::RateLimited);
        return;
    }

    // The CDDL admits no open options container, so Linux's undefined-options-key
    // entry rejection has one macOS analog: the activateKey wire key present on a
    // verb that cannot carry it. Checked BEFORE the optional is flattened into
    // the request (the flatten would erase a stray `activateKey: false`).
    if (msg.activateKey.has_value() && msg.verb != kVerbActivatePin) {
        replyError(connId, req, wire::SyncError::InvalidRequest);
        return;
    }

    Ops::PinManageRequest request{
        .cardKey = routing->cardKey,
        .pinId = msg.pinId,
        .verb = msg.verb,
        .activateKey = msg.activateKey.value_or(false),
    };
    // Resolve the addressed record against the LATEST listing captured at entry. A
    // client that never listed (no snapshot) or names an unknown id is rejected here
    // rather than triggering an implicit list — an implicit list could prompt for
    // the CAN inside a call the user never framed as a read.
    std::optional<A::CredentialSnapshot> snapshot = m_core.credentialSnapshotCache().get(routing->cardKey);
    if (const auto valid = Ops::validatePinManageRequest(request, snapshot ? &*snapshot : nullptr); !valid) {
        replyError(connId, req, mapEntryError(valid.error()));
        return;
    }

    const std::string requester = requesterLabel(in.caller);
    const std::string cardKey = routing->cardKey;
    const std::string readerName = routing->readerName;
    const A::ObjectId readerId = routing->readerId;
    auto& core = m_core;

    try {
        const auto id = core.operationManager().publish(
            readerId, readerName, in.caller,
            [this, connId, &core, cardKey, readerName, requester, request = std::move(request),
             snapshot = std::move(*snapshot)](Ops::CardSessionHolder* holder,
                                              A::OperationId opId) mutable -> std::unique_ptr<Ops::OperationBase> {
                auto credentials = std::make_shared<Ops::LmCredentialManager>();
                auto state = std::make_shared<Ops::OperationState>();
                auto channel = std::make_unique<SocketOperationChannel>(m_transport, connId, opId.value(), state,
                                                                        SocketOperationChannel::SignArtifactSink{},
                                                                        makeOpFinishedSink());
                Ops::ManagePinOperation::Deps deps{
                    .holder = holder,
                    .credentials = *credentials,
                    .prompter = *core.sharedCryptoContext()->prompter,
                    .serializer = *core.sharedCryptoContext()->serializer,
                    .credCache = core.credentialCache(),
                    .snapshotCache = core.credentialSnapshotCache(),
                    .readCache = core.cardReadCache(),
                    .cardKey = cardKey,
                    .readerName = readerName,
                    .requester = requester,
                    .artifact = kArtifactCredentials,
                    .request = std::move(request),
                    .snapshot = std::move(snapshot),
                };
                auto op = std::make_unique<Ops::ManagePinOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(credentials);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = in.caller;
        sendReplyOnLoop(connId, wire::makeReply(req, wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleActivateSigningKey(SocketTransport::Inbound& in, const wire::ActivateSigningKey& msg)
{
    // Authorize + rate-limit (BEFORE any prompt). No client-supplied arguments to
    // validate — the addressed signing-key record is resolved inside the operation
    // from the latest listing (a card that exposes none answers unsupported).
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPinManagementCapBit) == 0) {
        replyError(connId, req, wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    if (!m_core.authorizer().authorize(A::kActionCredentialsManage, in.caller)) {
        replyError(connId, req, wire::SyncError::NotAuthorized);
        return;
    }
    if (!m_core.rateLimiter().allow(in.caller)) {
        replyError(connId, req, wire::SyncError::RateLimited);
        return;
    }

    const std::string requester = requesterLabel(in.caller);
    const std::string cardKey = routing->cardKey;
    const std::string readerName = routing->readerName;
    const A::ObjectId readerId = routing->readerId;
    auto& core = m_core;

    try {
        const auto id = core.operationManager().publish(
            readerId, readerName, in.caller,
            [this, connId, &core, cardKey, readerName,
             requester](Ops::CardSessionHolder* holder, A::OperationId opId) -> std::unique_ptr<Ops::OperationBase> {
                auto credentials = std::make_shared<Ops::LmCredentialManager>();
                auto state = std::make_shared<Ops::OperationState>();
                auto channel = std::make_unique<SocketOperationChannel>(m_transport, connId, opId.value(), state,
                                                                        SocketOperationChannel::SignArtifactSink{},
                                                                        makeOpFinishedSink());
                Ops::ActivateSigningKeyOperation::Deps deps{
                    .holder = holder,
                    .credentials = *credentials,
                    .prompter = *core.sharedCryptoContext()->prompter,
                    .serializer = *core.sharedCryptoContext()->serializer,
                    .credCache = core.credentialCache(),
                    .snapshotCache = core.credentialSnapshotCache(),
                    .readCache = core.cardReadCache(),
                    .cardKey = cardKey,
                    .readerName = readerName,
                    .requester = requester,
                    .artifact = kArtifactCredentials,
                };
                auto op =
                    std::make_unique<Ops::ActivateSigningKeyOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(credentials);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = in.caller;
        sendReplyOnLoop(connId, wire::makeReply(req, wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleCancel(std::uint64_t connId, std::uint64_t req, const wire::CancelOp& msg,
                                  const A::CallerToken& caller)
{
    // Owner-scope the cancel: op ids are small + enumerable, so an unscoped cancel
    // lets any client abort another client's in-flight op. Silently ack unknown /
    // not-owned ops (no oracle) — the op simply isn't cancelled.
    const auto it = m_opOwners.find(msg.op);
    if (it != m_opOwners.end() && it->second == caller) {
        m_core.operationManager().cancel(A::OperationId{msg.op});
    }
    sendReplyOnLoop(connId, wire::makeReply(req, wire::AckReply{}));
}

void SocketFrontend::stashSignArtifact(std::uint64_t opId, const A::CallerToken& owner,
                                       const Ops::SignedArtifact& artifact)
{
    // Runs on the loop (the sign sink already marshaled here). Store owner-scoped
    // and schedule a grace-window eviction so the store cannot grow unbounded.
    m_signResults[opId] = SignRecord{artifact, owner};
    m_transport.postAfter(std::chrono::duration_cast<std::chrono::microseconds>(kSignResultGrace),
                          [this, opId] { evictSignResult(opId); });
}

void SocketFrontend::evictSignResult(std::uint64_t opId)
{
    m_signResults.erase(opId);
}

std::function<void(std::uint64_t)> SocketFrontend::makeOpFinishedSink()
{
    // Fires on the worker at emitFinished; touch only the long-lived transport
    // there and marshal the m_opOwners prune onto the loop (drop-guarded so a
    // post-teardown fire is dropped, not run against a freed frontend).
    auto* tr = &m_transport;
    return [tr, this](std::uint64_t oid) { tr->post([this, oid] { m_opOwners.erase(oid); }); };
}

void SocketFrontend::handleGetSignResult(std::uint64_t connId, std::uint64_t req, const wire::GetSignResult& msg,
                                         const A::CallerToken& caller)
{
    const auto it = m_signResults.find(msg.op);
    // Owner-scope (IDOR guard): the signed document is the client's own output;
    // op ids are enumerable, so a requester that did not initiate the op must get
    // the same KeyNotFound as a truly-absent op (no disclosure, no oracle).
    if (it == m_signResults.end() || !(it->second.owner == caller)) {
        replyError(connId, req, wire::SyncError::KeyNotFound);
        return;
    }
    auto fd = wire::anonFdFromBytes(it->second.artifact.bytes);
    if (!fd) {
        replyError(connId, req, wire::SyncError::CommunicationError);
        return;
    }
    wire::SignResult result;
    result.artifact = 0; // fd-index into the reply's SCM_RIGHTS vector
    result.meta = wire::SignMeta{it->second.artifact.meta.format, it->second.artifact.meta.level,
                                 it->second.artifact.meta.tsaUsed, it->second.artifact.meta.chainComplete};
    std::vector<wire::UniqueFd> fds;
    fds.push_back(std::move(*fd));
    m_transport.sendTo(connId, wire::makeSignRecoveryReply(req, result), std::move(fds));
}

// --- config ------------------------------------------------------------------

void SocketFrontend::handleGetConfig(std::uint64_t connId, std::uint64_t req)
{
    auto& cfg = m_core.configStore();
    wire::ConfigReply reply;
    reply.entries.emplace("DefaultLevel", wire::CborValue(cfg.defaultLevel()));
    {
        wire::CborValue::Array urls;
        for (auto& u : cfg.tsaUrls()) {
            urls.emplace_back(u);
        }
        reply.entries.emplace("TsaUrls", wire::CborValue(std::move(urls)));
    }
    reply.entries.emplace("LastTsaUrl", wire::CborValue(cfg.lastTsaUrl()));
    {
        wire::CborValue::Array sources;
        for (const auto& s : cfg.tslSources()) {
            wire::CborValue::Map m;
            m.emplace("url", wire::CborValue(s.url));
            m.emplace("isLotl", wire::CborValue(s.isLotl));
            m.emplace("eager", wire::CborValue(s.eager));
            sources.emplace_back(std::move(m));
        }
        reply.entries.emplace("TslSources", wire::CborValue(std::move(sources)));
    }
    reply.entries.emplace("TslCacheDir", wire::CborValue(cfg.tslCacheDir()));
    reply.entries.emplace("AiaCacheDir", wire::CborValue(cfg.aiaCacheDir()));
    reply.entries.emplace("DefaultReason", wire::CborValue(cfg.defaultReason()));
    reply.entries.emplace("DefaultLocation", wire::CborValue(cfg.defaultLocation()));
    reply.entries.emplace("PluginDir", wire::CborValue(cfg.pluginDir()));
    sendReplyOnLoop(connId, wire::makeReply(req, reply));
}

void SocketFrontend::handleSetConfig(std::uint64_t connId, std::uint64_t req, const wire::SetConfig& msg,
                                     const A::CallerToken& caller)
{
    const auto mut = A::Config::ConfigStore::mutability(msg.key);
    if (!mut) {
        replyError(connId, req, wire::SyncError::UnknownConfigKey);
        return;
    }
    if (*mut == A::Config::Mutability::FileOnly || *mut == A::Config::Mutability::ReadOnly) {
        replyError(connId, req, wire::SyncError::ReadOnlyConfig);
        return;
    }
    const char* action =
        (*mut == A::Config::Mutability::DbusMutableTrust) ? A::kActionConfigureTrust : A::kActionConfigure;
    if (!m_core.authorizer().authorize(action, caller)) {
        replyError(connId, req, wire::SyncError::NotAuthorized);
        return;
    }

    auto& cfg = m_core.configStore();
    A::Config::ConfigStore::SetResult r{false, {}, {}};
    if (msg.key == "DefaultLevel") {
        auto v = asString(msg.value);
        if (!v) {
            replyError(connId, req, wire::SyncError::InvalidConfigValue);
            return;
        }
        r = cfg.setDefaultLevel(*v);
    } else if (msg.key == "DefaultReason") {
        auto v = asString(msg.value);
        if (!v) {
            replyError(connId, req, wire::SyncError::InvalidConfigValue);
            return;
        }
        r = cfg.setDefaultReason(*v);
    } else if (msg.key == "DefaultLocation") {
        auto v = asString(msg.value);
        if (!v) {
            replyError(connId, req, wire::SyncError::InvalidConfigValue);
            return;
        }
        r = cfg.setDefaultLocation(*v);
    } else if (msg.key == "TsaUrls") {
        const auto* arr = msg.value.asArray();
        if (!arr) {
            replyError(connId, req, wire::SyncError::InvalidConfigValue);
            return;
        }
        std::vector<std::string> urls;
        for (const auto& e : *arr) {
            auto s = asString(e);
            if (!s) {
                replyError(connId, req, wire::SyncError::InvalidConfigValue);
                return;
            }
            urls.push_back(std::move(*s));
        }
        r = cfg.setTsaUrls(std::move(urls));
    } else if (msg.key == "TslSources") {
        const auto* arr = msg.value.asArray();
        if (!arr) {
            replyError(connId, req, wire::SyncError::InvalidConfigValue);
            return;
        }
        std::vector<A::Config::TslSource> sources;
        for (const auto& e : *arr) {
            const auto* m = e.asMap();
            if (!m) {
                replyError(connId, req, wire::SyncError::InvalidConfigValue);
                return;
            }
            A::Config::TslSource src;
            const auto* url = e.find("url");
            const auto* isLotl = e.find("isLotl");
            const auto* eager = e.find("eager");
            if (url == nullptr || !url->asText()) {
                replyError(connId, req, wire::SyncError::InvalidConfigValue);
                return;
            }
            src.url = *url->asText();
            src.isLotl = isLotl != nullptr && isLotl->asBool().value_or(false);
            src.eager = eager != nullptr && eager->asBool().value_or(false);
            sources.push_back(std::move(src));
        }
        r = cfg.setTslSources(std::move(sources));
    } else {
        replyError(connId, req, wire::SyncError::UnknownConfigKey);
        return;
    }

    if (!r.ok) {
        replyError(connId, req, wire::SyncError::InvalidConfigValue);
        return;
    }
    sendReplyOnLoop(connId, wire::makeReply(req, wire::AckReply{}));
}

void SocketFrontend::handleResetConfig(std::uint64_t connId, std::uint64_t req, const wire::ResetConfig& msg,
                                       const A::CallerToken& caller)
{
    const auto mut = A::Config::ConfigStore::mutability(msg.key);
    if (!mut) {
        replyError(connId, req, wire::SyncError::UnknownConfigKey);
        return;
    }
    if (*mut == A::Config::Mutability::FileOnly || *mut == A::Config::Mutability::ReadOnly) {
        replyError(connId, req, wire::SyncError::ReadOnlyConfig);
        return;
    }
    const char* action =
        (*mut == A::Config::Mutability::DbusMutableTrust) ? A::kActionConfigureTrust : A::kActionConfigure;
    if (!m_core.authorizer().authorize(action, caller)) {
        replyError(connId, req, wire::SyncError::NotAuthorized);
        return;
    }
    const auto r = m_core.configStore().resetKey(msg.key, /*fromDbus=*/true);
    if (!r.ok) {
        replyError(connId, req, wire::SyncError::InvalidConfigValue);
        return;
    }
    sendReplyOnLoop(connId, wire::makeReply(req, wire::AckReply{}));
}

// --- pkcs11 / cert-der (async broker handoff) --------------------------------

void SocketFrontend::handleCertDer(std::uint64_t connId, std::uint64_t req, const wire::GetCertDer& msg,
                                   const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& der) {
            postReply(tr, connId, wire::makeReply(req, wire::CertDerReply{der}));
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, mapCryptoOutcome(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    m_core.pkcs11().certDer(msg.reader, msg.cert, c, reply);
}

void SocketFrontend::handlePkPublicKey(std::uint64_t connId, std::uint64_t req, const wire::PkPublicKey& msg,
                                       const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& n, const std::vector<std::uint8_t>& e) {
            wire::PublicKeyReply pk = wire::RsaPublicKey{n, e};
            postReply(tr, connId, wire::makeReply(req, pk));
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, mapCryptoOutcome(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    m_core.pkcs11().publicKey(msg.reader, msg.cert, c, reply);
}

void SocketFrontend::handlePkLogin(std::uint64_t connId, std::uint64_t req, const wire::PkLogin& msg,
                                   const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::LoginOutcome, std::uint32_t> reply{
        [tr, connId, req](std::uint32_t /*flags*/) { postReply(tr, connId, wire::makeReply(req, wire::AckReply{})); },
        [tr, connId, req](A::Pkcs11Broker::LoginOutcome oc) { postErr(tr, connId, req, mapLoginOutcome(oc)); },
        A::Pkcs11Broker::LoginOutcome::CardError};
    m_core.pkcs11().login(msg.reader, c, reply);
}

void SocketFrontend::handlePkLogout(std::uint64_t connId, std::uint64_t req, const wire::PkLogout& msg,
                                    const A::CallerToken& caller)
{
    m_core.pkcs11().logout(msg.reader, A::Pkcs11Broker::Caller{caller, requesterLabel(caller)});
    sendReplyOnLoop(connId, wire::makeReply(req, wire::AckReply{}));
}

void SocketFrontend::handlePkSignRaw(std::uint64_t connId, std::uint64_t req, const wire::PkSignRaw& msg,
                                     const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& sig) {
            postReply(tr, connId, wire::makeReply(req, wire::RawSignatureReply{sig}));
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, mapCryptoOutcome(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    m_core.pkcs11().signRaw(msg.reader, msg.cert, A::Mechanism::RsaPkcs1Sign, A::MechParamsEmpty{}, msg.data, c, reply);
}

void SocketFrontend::handlePkDecrypt(std::uint64_t connId, std::uint64_t req, const wire::PkDecrypt& msg,
                                     const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& plain) {
            postReply(tr, connId, wire::makeReply(req, wire::RawSignatureReply{plain}));
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, mapCryptoOutcome(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    m_core.pkcs11().decrypt(msg.reader, msg.cert, A::Mechanism::RsaPkcs1Decrypt, A::MechParamsEmpty{}, msg.data, c,
                            reply);
}

// --- presence (deferred capability resolve) ----------------------------------

void SocketFrontend::onReaderPublished(const A::ReaderState& reader)
{
    m_transport.post([this, reader] {
        m_readerNames[reader.id.value()] = reader.name;
        m_transport.publishReader(reader);
    });
}

void SocketFrontend::onCardPublished(const A::CardState& card)
{
    m_transport.post([this, card] { scheduleCardResolve(card); });
}

void SocketFrontend::onWithdrawn(A::ObjectId object)
{
    m_transport.post([this, object] {
        m_pendingCards.erase(object.value());
        m_readerNames.erase(object.value());
        m_transport.withdraw(object);
    });
}

void SocketFrontend::onReaderPropertiesChanged(A::ObjectId reader, const A::PropertyDelta& delta)
{
    m_transport.post([this, reader, delta] { m_transport.updateProperties(reader, delta); });
}

void SocketFrontend::scheduleCardResolve(const A::CardState& card)
{
    // Loop thread. Record the pending card and enqueue the held-session resolve
    // on the reader's worker; the worker computes the capability union + pre-read
    // auth on the OPEN session and marshals the result back to applyCardResolution.
    auto& pending = m_pendingCards[card.id.value()];
    pending.card = card;

    std::string readerName;
    if (const auto it = m_readerNames.find(card.reader.value()); it != m_readerNames.end()) {
        readerName = it->second;
    }

    // The worker hop runs on the reader WORKER thread and may block in
    // fullResolution() well past shutdown; it must touch ONLY the long-lived
    // transport (never `this`->m_transport). The applyCardResolution continuation
    // captures `this` for the frontend state but is dropped by the loop-quiesce if
    // the frontend is already gone (mirrors AgentFrontend::makeCardResolver).
    auto* tr = &m_transport;
    const bool queued = m_core.operationManager().enqueueOnReaderWorker(
        card.reader, readerName, [this, tr, card](Ops::CardSessionHolder& holder) {
            const auto resolution = holder.fullResolution();
            tr->post([this, card, caps = resolution.capabilities, preAuth = resolution.preReadAuth] {
                applyCardResolution(card, caps, preAuth);
            });
        });
    if (!queued) {
        // Backpressure: retry on the loop after a short delay (the card stays
        // pending, so a withdraw meanwhile drops it).
        m_transport.postAfter(std::chrono::duration_cast<std::chrono::microseconds>(kResolveRetryDelay), [this, card] {
            if (m_pendingCards.contains(card.id.value())) {
                scheduleCardResolve(card);
            }
        });
    }
}

void SocketFrontend::applyCardResolution(A::CardState card, std::uint32_t caps, wire::PreReadAuthMethod preAuth)
{
    const auto it = m_pendingCards.find(card.id.value());
    if (it == m_pendingCards.end()) {
        return; // withdrawn while resolving
    }
    if (caps == 0 && it->second.attempts < kMaxResolveAttempts) {
        ++it->second.attempts;
        m_transport.postAfter(std::chrono::duration_cast<std::chrono::microseconds>(kResolveRetryDelay), [this, card] {
            if (m_pendingCards.contains(card.id.value())) {
                scheduleCardResolve(card);
            }
        });
        return;
    }
    m_pendingCards.erase(it);
    A::CardState refined{card.id, card.reader, caps, preAuth};
    m_transport.publishCard(refined);
}

// --- config-changed / lease --------------------------------------------------

void SocketFrontend::emitConfigChanged(const std::string& key)
{
    m_transport.post([this, key] { m_transport.broadcastConfigChanged(key); });
}

void SocketFrontend::onCardRemovedForLease(A::ObjectId cardKey)
{
    // Mirror of AgentFrontend::onCardRemovedForLease: invalidate any PKCS#11 lease
    // bound to the removed card so a later SignRaw/Decrypt on a stale handle fails
    // closed. Wired in main.cpp alongside the credential/read-cache scrub.
    m_transport.post([this, cardKey] { m_core.pkcs11().onCardRemoved(cardKey); });
}

void SocketFrontend::onClientDisconnected(const A::CallerToken& caller)
{
    // Evict the disconnecting client's op ownership + Sign recovery artifacts so
    // the stores cannot grow for the process lifetime and a reused caller token
    // cannot inherit a prior client's signed documents. Loop-affine.
    m_transport.post([this, caller] {
        std::erase_if(m_opOwners, [&caller](const auto& kv) { return kv.second == caller; });
        std::erase_if(m_signResults, [&caller](const auto& kv) { return kv.second.owner == caller; });
    });
}

} // namespace LibreSCRS::Darwin
