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
#include "operations/ReadTokenInfoOperation.h"
#include "operations/ReadIdentityOperation.h"
#include "operations/SignOperation.h"
#include "operations/SignBatchOperation.h"

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/CryptoWorkerContext.h>
#include <LibreSCRS/Agent/FeatureTokens.h>
#include <LibreSCRS/Agent/Reply.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/operations/BatchSignFlow.h> // isValidBatchDocumentCount, kMin/kMaxBatchDocuments, BatchDocumentInput
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/LmSeams.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PinChangeFlow.h> // PinManageRequest, validatePinManageRequest
#include <LibreSCRS/Agent/operations/SignatureParams.h>
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/util/CallerLabel.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h> // CredentialSnapshot, EntryError
#include <LibreSCRS/Agent/wire/Framing.h>           // kMaxFrameFds (socket per-frame fd budget)

#include <LibreSCRS/Plugin/CardPlugin.h>  // CardPlugin::pluginId() (the single-candidate cardType)
#include <LibreSCRS/Plugin/PluginTypes.h> // CardCapabilities

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <expected>
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

// The socket frame fd budget must cover a maximum-size SignBatch: the request
// leg carries one SCM_RIGHTS fd per document (and the result leg one artifact fd
// per row). kMaxFrameFds is sized to the D-Bus per-message fd budget so this
// holds; assert it rather than truncate a batch at send time.
static_assert(Ops::kMaxBatchDocuments <= A::Wire::kMaxFrameFds,
              "socket frame fd budget must cover a maximum SignBatch");

constexpr std::uint32_t kIdentityCapBit = static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::IdentityData);
constexpr std::uint32_t kPkiCapBit = static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PKI);
constexpr std::uint32_t kPinManagementCapBit =
    static_cast<std::uint32_t>(LibreSCRS::Plugin::CardCapabilities::PinManagement);

constexpr const char* kArtifactIdentity = "identity";
constexpr const char* kArtifactPhoto = "photo";
constexpr const char* kArtifactCertificates = "certificates";
constexpr const char* kArtifactTokenInfo = "token";
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
A::Wire::SyncError mapCryptoOutcome(A::Pkcs11Broker::CryptoOutcome oc) noexcept
{
    using CO = A::Pkcs11Broker::CryptoOutcome;
    switch (oc) {
    case CO::KeyNotFound:
        return A::Wire::SyncError::KeyNotFound;
    case CO::AuthFailed:
        return A::Wire::SyncError::AuthFailed;
    case CO::NotSupported:
        return A::Wire::SyncError::NotSupported;
    case CO::UnknownCard:
        return A::Wire::SyncError::UnknownCard;
    case CO::UserNotLoggedIn:
        return A::Wire::SyncError::UserNotLoggedIn;
    case CO::RateLimited:
        return A::Wire::SyncError::RateLimited;
    case CO::Ok:
    case CO::Cancelled:
    case CO::CardError:
        break;
    }
    return A::Wire::SyncError::CommunicationError;
}

A::Wire::SyncError mapLoginOutcome(A::Pkcs11Broker::LoginOutcome oc) noexcept
{
    using LO = A::Pkcs11Broker::LoginOutcome;
    switch (oc) {
    case LO::NotAuthorizedByCard:
        return A::Wire::SyncError::AuthFailed;
    case LO::UnknownCard:
        return A::Wire::SyncError::UnknownCard;
    case LO::NotAuthorized:
        return A::Wire::SyncError::NotAuthorized;
    case LO::Ok:
    case LO::Cancelled:
    case LO::CardError:
        break;
    }
    return A::Wire::SyncError::CommunicationError;
}

// Map a validatePinManageRequest EntryError onto its typed wire error. UnknownVerb
// / UnknownOption / InvalidCombination are the client's fault (InvalidRequest);
// UnknownCredential (bad or unlisted pinId, incl. the never-listed case) is its own
// name so a client can distinguish "re-list and retry" from "fix your request".
// (Mirror of LibreLinux CardObject's throwEntryError.)
A::Wire::SyncError mapEntryError(A::EntryError err) noexcept
{
    switch (err) {
    case A::EntryError::UnknownCredential:
        return A::Wire::SyncError::UnknownCredential;
    case A::EntryError::UnknownVerb:
    case A::EntryError::UnknownOption:
    case A::EntryError::InvalidCombination:
    case A::EntryError::AmbiguousCredential: // non-unique label: the seam must never guess
        break;
    }
    return A::Wire::SyncError::InvalidRequest;
}

// Extract a std::string from a CBOR text value; nullopt on a type mismatch.
std::optional<std::string> asString(const A::Wire::CborValue& v)
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
void postReply(SocketTransport* tr, std::uint64_t connId, A::Wire::CborValue message)
{
    tr->post([tr, connId, message] { tr->sendTo(connId, message); });
}
void postErr(SocketTransport* tr, std::uint64_t connId, std::uint64_t req, A::Wire::SyncError code)
{
    postReply(tr, connId, A::Wire::makeErrorReply(req, A::Wire::ErrInfo{code, std::nullopt, std::nullopt}));
}

// The sign-opts vocabulary resolved to concrete values, shared by Sign and
// SignBatch so the two entry points can never drift on validation (mirror of
// LibreLinux CardObject.cpp's own resolveSignOptions extraction).
struct ResolvedSignOptions
{
    std::string format;
    std::string level;
    std::string packaging;
    bool allowExpired{false};
    std::string reason;
    std::string location;
    std::optional<std::string> tsaUrl;
    std::optional<Ops::VisualParams> visual;
};

// Resolve format (sniff on auto), level (TSA-derived default), packaging to
// concrete vocabulary, and validate allowExpired/tsaUrl/visualSignature —
// out-of-vocabulary is a method-entry rejection, never reaches an Operation.
// `sniffSource` is the bytes format=auto sniffs off: Sign's own single
// document; SignBatch shares this ONE resolution across the whole batch,
// sniffing off the FIRST document only (its own displayName/reason/location
// defaults still come from `opts` — only the sniff source differs from a
// single Sign's).
std::expected<ResolvedSignOptions, A::Wire::SyncError> resolveSignOptions(const A::Wire::SignOpts& opts,
                                                                          const std::vector<std::uint8_t>& sniffSource,
                                                                          const A::Config::ConfigStore& config)
{
    std::string format = opts.format;
    if (format == "auto" || format.empty()) {
        const auto sniffed = sp::sniffFormat(sniffSource);
        if (!sniffed) {
            return std::unexpected(A::Wire::SyncError::UnsupportedSignatureParameter);
        }
        format = *sniffed;
    }
    if (!sp::isKnownFormat(format)) {
        return std::unexpected(A::Wire::SyncError::UnsupportedSignatureParameter);
    }
    std::optional<std::string> requestedLevel;
    if (!opts.level.empty() && opts.level != "auto") {
        requestedLevel = opts.level;
    }
    std::string level = sp::resolveSignLevel(requestedLevel, config.defaultLevel(), !config.tsaUrls().empty());
    if (!sp::isKnownLevel(level) || !sp::isImplementedSignLevel(level)) {
        return std::unexpected(A::Wire::SyncError::UnsupportedSignatureParameter);
    }
    std::string packaging = opts.packaging;
    if (packaging == "auto" || packaging.empty()) {
        packaging = sp::defaultPackagingFor(format);
    }
    if (!sp::isKnownPackaging(packaging)) {
        return std::unexpected(A::Wire::SyncError::UnsupportedSignatureParameter);
    }

    // tsaUrl overrides the configured TSA for THIS sign only — https +
    // non-empty host, and meaningful only for the timestamped/long-term
    // family (paired with level "b-b" it is a method-entry rejection, the
    // same stricter-but-documented posture LibreLinux's CardObject::Sign
    // takes). The CBOR codec already guarantees opts.tsaUrl is a well-formed
    // tstr when present (Messages.cpp's parseSignOpts) — only the semantic
    // https+host+level check happens here.
    if (opts.tsaUrl) {
        if (!sp::isValidTsaUrl(*opts.tsaUrl)) {
            return std::unexpected(A::Wire::SyncError::UnsupportedSignatureParameter);
        }
        if (level == "b-b") {
            return std::unexpected(A::Wire::SyncError::UnsupportedSignatureParameter);
        }
    }

    // visualSignature attaches a PAdES visible-signature appearance; the
    // codec already guarantees all six nested fields are present and typed
    // when opts.visualSignature itself is present (Messages.cpp's
    // parseVisualSignatureOpts) — only the format + geometry checks happen
    // here.
    std::optional<Ops::VisualParams> visual;
    if (opts.visualSignature) {
        const auto& v = *opts.visualSignature;
        if (format != "pades" ||
            !sp::isValidVisualGeometry(static_cast<std::int64_t>(v.page), v.x, v.y, v.width, v.height)) {
            return std::unexpected(A::Wire::SyncError::UnsupportedSignatureParameter);
        }
        visual = Ops::VisualParams{
            .page = static_cast<int>(v.page),
            .x = static_cast<float>(v.x),
            .y = static_cast<float>(v.y),
            .width = static_cast<float>(v.width),
            .height = static_cast<float>(v.height),
            .text = v.text,
        };
    }

    return ResolvedSignOptions{
        .format = std::move(format),
        .level = std::move(level),
        .packaging = std::move(packaging),
        .allowExpired = opts.allowExpired.value_or(false),
        .reason = opts.reason.value_or(config.defaultReason()),
        .location = opts.location.value_or(config.defaultLocation()),
        .tsaUrl = opts.tsaUrl,
        .visual = std::move(visual),
    };
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

void SocketFrontend::sendReplyOnLoop(std::uint64_t connId, A::Wire::CborValue message)
{
    m_transport.sendTo(connId, message);
}

void SocketFrontend::replyError(std::uint64_t connId, std::uint64_t req, A::Wire::SyncError code)
{
    sendReplyOnLoop(connId, A::Wire::makeErrorReply(req, A::Wire::ErrInfo{code, std::nullopt, std::nullopt}));
}

void SocketFrontend::dispatch(SocketTransport::Inbound&& in)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const A::CallerToken caller = in.caller;
    auto& body = in.request.body;

    if (const auto* m = std::get_if<A::Wire::Hello>(&body)) {
        handleHello(connId, req, *m);
    } else if (std::get_if<A::Wire::GetState>(&body)) {
        handleGetState(connId, req);
    } else if (const auto* m = std::get_if<A::Wire::ReadIdentity>(&body)) {
        handleReadIdentity(in, *m);
    } else if (const auto* m = std::get_if<A::Wire::GetPhoto>(&body)) {
        handleGetPhoto(in, *m);
    } else if (const auto* m = std::get_if<A::Wire::ReadCertificates>(&body)) {
        handleReadCertificates(in, *m);
    } else if (const auto* m = std::get_if<A::Wire::ReadTokenInfo>(&body)) {
        handleReadTokenInfo(in, *m);
    } else if (const auto* m = std::get_if<A::Wire::Sign>(&body)) {
        handleSign(in, *m);
    } else if (const auto* m = std::get_if<A::Wire::SignBatch>(&body)) {
        handleSignBatch(in, *m);
    } else if (const auto* m = std::get_if<A::Wire::ListCredentials>(&body)) {
        handleListCredentials(in, *m);
    } else if (const auto* m = std::get_if<A::Wire::ManagePin>(&body)) {
        handleManagePin(in, *m);
    } else if (const auto* m = std::get_if<A::Wire::ActivateSigningKey>(&body)) {
        handleActivateSigningKey(in, *m);
    } else if (const auto* m = std::get_if<A::Wire::GetCertDer>(&body)) {
        handleCertDer(connId, req, *m, caller);
    } else if (std::get_if<A::Wire::GetConfig>(&body)) {
        handleGetConfig(connId, req);
    } else if (const auto* m = std::get_if<A::Wire::SetConfig>(&body)) {
        handleSetConfig(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::ResetConfig>(&body)) {
        handleResetConfig(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::CancelOp>(&body)) {
        handleCancel(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::GetSignResult>(&body)) {
        handleGetSignResult(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::PkLogin>(&body)) {
        handlePkLogin(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::PkLogout>(&body)) {
        handlePkLogout(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::PkPublicKey>(&body)) {
        handlePkPublicKey(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::PkSignRaw>(&body)) {
        handlePkSignRaw(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::PkDecrypt>(&body)) {
        handlePkDecrypt(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::LayoutVisual>(&body)) {
        handleLayoutVisual(connId, req, *m);
    } else if (std::get_if<A::Wire::GetAppearanceFont>(&body)) {
        handleGetAppearanceFont(connId, req);
    }
}

void SocketFrontend::handleHello(std::uint64_t connId, std::uint64_t req, const A::Wire::Hello& /*msg*/)
{
    A::Wire::HelloAck ack;
    ack.agentVer = m_version;
    // Served verbatim from the single source of truth in LibreAgent core
    // (LibreSCRS::Agent::kAgentFeatures, FeatureTokens.h) — never a local
    // literal, so this daemon and the D-Bus backend's Manager1.Features can
    // never drift on which feature tokens are actually live.
    ack.features.assign(A::kAgentFeatures.begin(), A::kAgentFeatures.end());
    sendReplyOnLoop(connId, A::Wire::makeReply(req, ack));
}

void SocketFrontend::handleGetState(std::uint64_t connId, std::uint64_t req)
{
    sendReplyOnLoop(connId, A::Wire::makeReply(req, m_transport.currentState()));
}

// --- Card-independent visual-signature layout preview --------------------

void SocketFrontend::handleLayoutVisual(std::uint64_t connId, std::uint64_t req, const A::Wire::LayoutVisual& msg)
{
    // Method-entry rejection for a non-finite or non-positive box — the SAME
    // gate Sign's visualSignature option runs (handleSign below), before
    // narrowing to LM's integer Rect (SignatureParams::isValidLayoutRect's
    // own comment documents the UB this avoids).
    if (!sp::isValidLayoutRect(msg.x, msg.y, msg.width, msg.height)) {
        replyError(connId, req, A::Wire::SyncError::InvalidRequest);
        return;
    }
    const Ops::VisualLayoutResult result =
        Ops::layoutVisualSignature(msg.text, Ops::LayoutBox{msg.x, msg.y, msg.width, msg.height});
    A::Wire::LayoutReply reply;
    reply.fontSize = result.fontSize;
    reply.lineHeight = result.lineHeight;
    reply.lines = result.lines;
    reply.clipped = result.clipped;
    sendReplyOnLoop(connId, A::Wire::makeReply(req, reply));
}

void SocketFrontend::handleGetAppearanceFont(std::uint64_t connId, std::uint64_t req)
{
    const std::vector<std::uint8_t> bytes = Ops::appearanceFontBytes();
    auto fd = wire::anonFdFromBytes(bytes);
    if (!fd) {
        replyError(connId, req, A::Wire::SyncError::CommunicationError);
        return;
    }
    A::Wire::AppearanceFontReply reply;
    reply.fd = 0; // fd-index into this reply's SCM_RIGHTS vector
    std::vector<A::Wire::UniqueFd> fds;
    fds.push_back(std::move(*fd));
    m_transport.sendTo(connId, A::Wire::makeReply(req, reply), std::move(fds));
}

// --- card operations ---------------------------------------------------------

void SocketFrontend::handleReadIdentity(SocketTransport::Inbound& in, const A::Wire::ReadIdentity& msg)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, A::Wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kIdentityCapBit) == 0) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    const std::string requester = requesterLabel(in.caller);
    const std::string cardKey = routing->cardKey;
    const std::string readerName = routing->readerName;
    const A::ObjectId readerId = routing->readerId;
    auto& core = m_core;
    // Value-captured (never `this`): safe to invoke from the worker thread at
    // any later time, mirroring scheduleCardResolve's worker->loop marshal.
    auto* tr = &m_transport;
    const std::string cardHandle = msg.card;

    try {
        const auto id = core.operationManager().publish(
            readerId, readerName, in.caller,
            [this, connId, &core, cardKey, readerName, requester, tr,
             cardHandle](Ops::CardSessionHolder* holder, A::OperationId opId) -> std::unique_ptr<Ops::OperationBase> {
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
                    .onCardType =
                        [tr, cardHandle](const std::string& cardType) {
                            tr->post([tr, cardHandle, cardType] { tr->updateCardType(cardHandle, cardType); });
                        },
                };
                auto op = std::make_unique<Ops::ReadIdentityOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(reader);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = in.caller;
        sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleGetPhoto(SocketTransport::Inbound& in, const A::Wire::GetPhoto& msg)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, A::Wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kIdentityCapBit) == 0) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    const std::string requester = requesterLabel(in.caller);
    const std::string cardKey = routing->cardKey;
    const std::string readerName = routing->readerName;
    const A::ObjectId readerId = routing->readerId;
    auto& core = m_core;
    // Value-captured (never `this`): safe to invoke from the worker thread at
    // any later time, mirroring scheduleCardResolve's worker->loop marshal.
    auto* tr = &m_transport;
    const std::string cardHandle = msg.card;

    try {
        const auto id = core.operationManager().publish(
            readerId, readerName, in.caller,
            [this, connId, &core, cardKey, readerName, requester, tr,
             cardHandle](Ops::CardSessionHolder* holder, A::OperationId opId) -> std::unique_ptr<Ops::OperationBase> {
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
                    .onCardType =
                        [tr, cardHandle](const std::string& cardType) {
                            tr->post([tr, cardHandle, cardType] { tr->updateCardType(cardHandle, cardType); });
                        },
                };
                auto op = std::make_unique<Ops::GetPhotoOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(reader);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = in.caller;
        sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleReadCertificates(SocketTransport::Inbound& in, const A::Wire::ReadCertificates& msg)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, A::Wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPkiCapBit) == 0) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedOnThisCard);
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
                // Reuses core.signingEngineProvider()'s already-built
                // TrustStoreService (see SigningEngineProvider::trustSnapshot())
                // -- no separate trust store, no new LM API, mirroring the
                // Sign path's own core.signingEngineProvider() reuse below.
                auto trustVerifier = std::make_shared<Ops::LmTrustVerifier>(core.signingEngineProvider());
                auto state = std::make_shared<Ops::OperationState>();
                auto channel = std::make_unique<SocketOperationChannel>(m_transport, connId, opId.value(), state,
                                                                        SocketOperationChannel::SignArtifactSink{},
                                                                        makeOpFinishedSink());
                Ops::ReadCertificatesOperation::Deps deps{
                    .holder = holder,
                    .certReader = *certReader,
                    .trustVerifier = *trustVerifier,
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
                op->keepAlive(trustVerifier);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = in.caller;
        sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleReadTokenInfo(SocketTransport::Inbound& in, const A::Wire::ReadTokenInfo& msg)
{
    // Token info is PKI-adjacent (pkcs15), so it shares ReadCertificates'
    // gate bit. Result rides the SAME Identity1-shaped op-result-ready arm
    // ReadIdentity uses (a single "token" group) -- no new result shape.
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, A::Wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPkiCapBit) == 0) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedOnThisCard);
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
                Ops::ReadTokenInfoOperation::Deps deps{
                    .holder = holder,
                    .reader = *reader,
                    .prompter = *core.sharedCryptoContext()->prompter,
                    .serializer = *core.sharedCryptoContext()->serializer,
                    .credentials = core.credentialCache(),
                    .cardKey = cardKey,
                    .readerName = readerName,
                    .requester = requester,
                    .artifact = kArtifactTokenInfo,
                };
                auto op = std::make_unique<Ops::ReadTokenInfoOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(reader);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = in.caller;
        sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleSign(SocketTransport::Inbound& in, const A::Wire::Sign& msg)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, A::Wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPkiCapBit) == 0) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    if (msg.cert.empty()) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedSignatureParameter);
        return;
    }

    // Authorize the CLIENT then apply the sign-flood rate-limit BEFORE ingesting
    // the document (a rejected caller never makes the agent read up to 256 MiB).
    if (!m_core.authorizer().authorize(A::kActionSign, in.caller)) {
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    }
    if (!m_core.rateLimiter().allow(in.caller)) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
        return;
    }

    // The input document rides SCM_RIGHTS as fd-index msg.inFd into in.fds.
    if (msg.inFd >= in.fds.size()) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedSignatureParameter);
        return;
    }
    auto doc = readDocument(in.fds[msg.inFd].get(), kMaxInputBytes);
    if (doc.status == ReadStatus::NotRegular) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedSignatureParameter);
        return;
    }
    if (doc.status == ReadStatus::TooLarge) {
        replyError(connId, req, A::Wire::SyncError::InputTooLarge);
        return;
    }
    if (doc.status == ReadStatus::Error) {
        replyError(connId, req, A::Wire::SyncError::CommunicationError); // internal read failure
        return;
    }
    if (doc.bytes.empty()) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedSignatureParameter); // empty document
        return;
    }

    // Resolve format (sniff on auto), level, packaging, allowExpired, reason,
    // location, tsaUrl and visualSignature to concrete/validated values —
    // out-of-vocabulary is a method-entry rejection. Shared verbatim with
    // handleSignBatch below via resolveSignOptions() so the two entries can
    // never drift.
    auto resolved = resolveSignOptions(msg.opts, doc.bytes, m_core.configStore());
    if (!resolved) {
        replyError(connId, req, resolved.error());
        return;
    }

    const std::string requester = requesterLabel(in.caller);
    Ops::SignParams params{
        .certId = msg.cert,
        .inputDocument = std::move(doc.bytes),
        .format = std::move(resolved->format),
        .level = std::move(resolved->level),
        .packaging = std::move(resolved->packaging),
        .allowExpired = resolved->allowExpired,
        .displayName = A::sanitizeLabel(msg.opts.displayName.value_or(std::string{})),
        .reason = std::move(resolved->reason),
        .location = std::move(resolved->location),
        .tsaUrl = resolved->tsaUrl.value_or(std::string{}),
        .visual = std::move(resolved->visual),
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
        sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleSignBatch(SocketTransport::Inbound& in, const A::Wire::SignBatch& msg)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, A::Wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPkiCapBit) == 0) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    if (msg.cert.empty()) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedSignatureParameter);
        return;
    }

    // Authorize the CLIENT then apply the SAME sign-flood rate-limit as a
    // single Sign, keyed on the caller — BEFORE the document-count gate and
    // before reading any document, mirroring Sign's own ordering exactly.
    // MANDATORY invariant: this ONE allow() call is the ONLY rate-limiter
    // charge for the whole dispatch — the batch loops over `msg.docs` entirely
    // below and inside BatchSignFlow, never re-entering this method or
    // charging again, so one SignBatch call (of any size 1-kMaxBatchDocuments)
    // always costs exactly one charge, the same one-call-one-charge
    // discipline handleSign's own dispatch already relies on.
    if (!m_core.authorizer().authorize(A::kActionSign, in.caller)) {
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    }
    if (!m_core.rateLimiter().allow(in.caller)) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
        return;
    }

    if (!Ops::isValidBatchDocumentCount(msg.docs.size())) {
        replyError(connId, req, A::Wire::SyncError::InvalidRequest);
        return;
    }

    // Read every document off its own fd-index, in request order — the SAME
    // 256 MiB cap + regular-file-only + non-empty rule Sign's own
    // readDocument enforces for its single document, applied per document
    // here. A single bad document rejects the WHOLE call (no Operation
    // minted): method entry has no per-row partial semantics, only the flow
    // does (auth/crypto failures).
    std::vector<Ops::BatchDocumentInput> inputs;
    inputs.reserve(msg.docs.size());
    for (const auto& entry : msg.docs) {
        if (entry.fdIndex >= in.fds.size()) {
            replyError(connId, req, A::Wire::SyncError::UnsupportedSignatureParameter);
            return;
        }
        auto doc = readDocument(in.fds[entry.fdIndex].get(), kMaxInputBytes);
        if (doc.status == ReadStatus::NotRegular) {
            replyError(connId, req, A::Wire::SyncError::UnsupportedSignatureParameter);
            return;
        }
        if (doc.status == ReadStatus::TooLarge) {
            replyError(connId, req, A::Wire::SyncError::InputTooLarge);
            return;
        }
        if (doc.status == ReadStatus::Error) {
            replyError(connId, req, A::Wire::SyncError::CommunicationError); // internal read failure
            return;
        }
        if (doc.bytes.empty()) {
            replyError(connId, req, A::Wire::SyncError::UnsupportedSignatureParameter); // empty document
            return;
        }
        inputs.push_back(Ops::BatchDocumentInput{
            .displayName = A::sanitizeLabel(entry.name),
            .bytes = std::move(doc.bytes),
        });
    }

    // Options: IDENTICAL vocabulary to Sign's own, resolved via the SAME
    // shared helper. format=auto sniffs off the FIRST document only — the
    // whole batch shares one resolved format/level/packaging, not a
    // per-document resolution.
    auto resolved = resolveSignOptions(msg.opts, inputs.front().bytes, m_core.configStore());
    if (!resolved) {
        replyError(connId, req, resolved.error());
        return;
    }

    const std::string requester = requesterLabel(in.caller);
    Ops::SignParams params{
        .certId = msg.cert,
        // Ignored by BatchSignFlow — each entry in `inputs` above supplies
        // its own bytes/name — left explicitly default.
        .inputDocument = {},
        .format = std::move(resolved->format),
        .level = std::move(resolved->level),
        .packaging = std::move(resolved->packaging),
        .allowExpired = resolved->allowExpired,
        .displayName = {},
        .reason = std::move(resolved->reason),
        .location = std::move(resolved->location),
        .tsaUrl = resolved->tsaUrl.value_or(std::string{}),
        .visual = std::move(resolved->visual),
    };

    const std::string cardKey = routing->cardKey;
    const std::string readerName = routing->readerName;
    const A::ObjectId readerId = routing->readerId;
    const A::CallerToken owner = in.caller;
    auto& core = m_core;

    try {
        const auto id = core.operationManager().publish(
            readerId, readerName, in.caller,
            [this, connId, owner, &core, cardKey, readerName, requester, params = std::move(params),
             documents = std::move(inputs)](Ops::CardSessionHolder* holder,
                                            A::OperationId opId) mutable -> std::unique_ptr<Ops::OperationBase> {
                auto signer = std::make_shared<Ops::LmSigner>(core.signingEngineProvider());
                auto state = std::make_shared<Ops::OperationState>();
                // No SignArtifactSink: unlike a single Sign, SignBatch has no
                // GetSignResult-style pull recovery on this wire (the CDDL
                // pins recovery Sign-only), so nothing needs stashing.
                auto channel = std::make_unique<SocketOperationChannel>(m_transport, connId, opId.value(), state,
                                                                        SocketOperationChannel::SignArtifactSink{},
                                                                        makeOpFinishedSink());
                Ops::SignBatchOperation::Deps deps{
                    .holder = holder,
                    .signer = *signer,
                    .prompter = *core.sharedCryptoContext()->prompter,
                    .serializer = *core.sharedCryptoContext()->serializer,
                    .credentials = core.credentialCache(),
                    .cardKey = cardKey,
                    .readerName = readerName,
                    .requester = requester,
                    .params = std::move(params),
                    .documents = std::move(documents),
                };
                auto op = std::make_unique<Ops::SignBatchOperation>(std::move(channel), std::move(deps), state);
                op->keepAlive(core.sharedCryptoContext());
                op->keepAlive(signer);
                op->bindShutdownToken(core.shutdownToken());
                return op;
            });
        m_opOwners[id.value()] = owner;
        sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
    }
}

// --- credentials (PIN/PUK management) ----------------------------------------

void SocketFrontend::handleListCredentials(SocketTransport::Inbound& in, const A::Wire::ListCredentials& msg)
{
    // A read of the card's PIN credentials. Gates on PinManagement (no listing is
    // meaningful without it) but is NOT rate-limited — no card-state mutation.
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, A::Wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPinManagementCapBit) == 0) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedOnThisCard);
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
        sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleManagePin(SocketTransport::Inbound& in, const A::Wire::ManagePin& msg)
{
    // Entry gating: capability -> authorize -> rate-limit -> validation, all
    // BEFORE any Operation (and thus any prompt) exists — the same matrix and
    // order as LibreLinux's Credentials1.ManagePin.
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, A::Wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPinManagementCapBit) == 0) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedOnThisCard);
        return;
    }

    // Authorize + rate-limit (BEFORE any prompt), same posture + ordering as Sign.
    if (!m_core.authorizer().authorize(A::kActionCredentialsManage, in.caller)) {
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    }
    if (!m_core.rateLimiter().allow(in.caller)) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
        return;
    }

    // The CDDL admits no open options container, so Linux's undefined-options-key
    // entry rejection has one macOS analog: the activateKey wire key present on a
    // verb that cannot carry it. Checked BEFORE the optional is flattened into
    // the request (the flatten would erase a stray `activateKey: false`).
    if (msg.activateKey.has_value() && msg.verb != kVerbActivatePin) {
        replyError(connId, req, A::Wire::SyncError::InvalidRequest);
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
        sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleActivateSigningKey(SocketTransport::Inbound& in, const A::Wire::ActivateSigningKey& msg)
{
    // Authorize + rate-limit (BEFORE any prompt). No client-supplied arguments to
    // validate — the addressed signing-key record is resolved inside the operation
    // from the latest listing (a card that exposes none answers unsupported).
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;
    const auto routing = m_transport.cardRouting(msg.card);
    if (!routing) {
        replyError(connId, req, A::Wire::SyncError::UnknownCard);
        return;
    }
    if ((routing->caps & kPinManagementCapBit) == 0) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedOnThisCard);
        return;
    }
    if (!m_core.authorizer().authorize(A::kActionCredentialsManage, in.caller)) {
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    }
    if (!m_core.rateLimiter().allow(in.caller)) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
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
        sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::OpStarted{id.value()}));
    } catch (const Ops::QueueFull&) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
    }
}

void SocketFrontend::handleCancel(std::uint64_t connId, std::uint64_t req, const A::Wire::CancelOp& msg,
                                  const A::CallerToken& caller)
{
    // Owner-scope the cancel: op ids are small + enumerable, so an unscoped cancel
    // lets any client abort another client's in-flight op. Silently ack unknown /
    // not-owned ops (no oracle) — the op simply isn't cancelled.
    const auto it = m_opOwners.find(msg.op);
    if (it != m_opOwners.end() && it->second == caller) {
        m_core.operationManager().cancel(A::OperationId{msg.op});
    }
    sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::AckReply{}));
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

void SocketFrontend::handleGetSignResult(std::uint64_t connId, std::uint64_t req, const A::Wire::GetSignResult& msg,
                                         const A::CallerToken& caller)
{
    const auto it = m_signResults.find(msg.op);
    // Owner-scope (IDOR guard): the signed document is the client's own output;
    // op ids are enumerable, so a requester that did not initiate the op must
    // get the SAME reply as a truly-absent op (no disclosure, no oracle) --
    // this branch also covers a genuinely-absent op, an op that was never a
    // Sign, and the caller's OWN op once the grace window evicted it, none of
    // which are distinguishable here from the IDOR case (the record is simply
    // gone by then). NoResult is the dedicated wire name for all of these
    // "nothing to give you" outcomes; it used to borrow KeyNotFound (a name
    // that has nothing to do with a missing sign result) before that name was
    // pinned.
    if (it == m_signResults.end() || !(it->second.owner == caller)) {
        replyError(connId, req, A::Wire::SyncError::NoResult);
        return;
    }
    auto fd = wire::anonFdFromBytes(it->second.artifact.bytes);
    if (!fd) {
        replyError(connId, req, A::Wire::SyncError::CommunicationError);
        return;
    }
    A::Wire::SignResult result;
    result.artifact = 0; // fd-index into the reply's SCM_RIGHTS vector
    result.meta = A::Wire::SignMeta{it->second.artifact.meta.format, it->second.artifact.meta.level,
                                    it->second.artifact.meta.tsaUsed, it->second.artifact.meta.chainComplete};
    std::vector<A::Wire::UniqueFd> fds;
    fds.push_back(std::move(*fd));
    m_transport.sendTo(connId, A::Wire::makeSignRecoveryReply(req, result), std::move(fds));
}

// --- config ------------------------------------------------------------------

void SocketFrontend::handleGetConfig(std::uint64_t connId, std::uint64_t req)
{
    auto& cfg = m_core.configStore();
    A::Wire::ConfigReply reply;
    reply.entries.emplace("DefaultLevel", A::Wire::CborValue(cfg.defaultLevel()));
    {
        A::Wire::CborValue::Array urls;
        for (auto& u : cfg.tsaUrls()) {
            urls.emplace_back(u);
        }
        reply.entries.emplace("TsaUrls", A::Wire::CborValue(std::move(urls)));
    }
    reply.entries.emplace("LastTsaUrl", A::Wire::CborValue(cfg.lastTsaUrl()));
    {
        A::Wire::CborValue::Array sources;
        for (const auto& s : cfg.tslSources()) {
            A::Wire::CborValue::Map m;
            m.emplace("url", A::Wire::CborValue(s.url));
            m.emplace("isLotl", A::Wire::CborValue(s.isLotl));
            m.emplace("eager", A::Wire::CborValue(s.eager));
            sources.emplace_back(std::move(m));
        }
        reply.entries.emplace("TslSources", A::Wire::CborValue(std::move(sources)));
    }
    reply.entries.emplace("TslCacheDir", A::Wire::CborValue(cfg.tslCacheDir()));
    reply.entries.emplace("AiaCacheDir", A::Wire::CborValue(cfg.aiaCacheDir()));
    reply.entries.emplace("DefaultReason", A::Wire::CborValue(cfg.defaultReason()));
    reply.entries.emplace("DefaultLocation", A::Wire::CborValue(cfg.defaultLocation()));
    reply.entries.emplace("PluginDir", A::Wire::CborValue(cfg.pluginDir()));
    sendReplyOnLoop(connId, A::Wire::makeReply(req, reply));
}

void SocketFrontend::handleSetConfig(std::uint64_t connId, std::uint64_t req, const A::Wire::SetConfig& msg,
                                     const A::CallerToken& caller)
{
    const auto mut = A::Config::ConfigStore::mutability(msg.key);
    if (!mut) {
        replyError(connId, req, A::Wire::SyncError::UnknownConfigKey);
        return;
    }
    if (*mut == A::Config::Mutability::FileOnly || *mut == A::Config::Mutability::ReadOnly) {
        replyError(connId, req, A::Wire::SyncError::ReadOnlyConfig);
        return;
    }
    const char* action =
        (*mut == A::Config::Mutability::DbusMutableTrust) ? A::kActionConfigureTrust : A::kActionConfigure;
    if (!m_core.authorizer().authorize(action, caller)) {
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    }

    auto& cfg = m_core.configStore();
    A::Config::ConfigStore::SetResult r{false, {}, {}};
    if (msg.key == "DefaultLevel") {
        auto v = asString(msg.value);
        if (!v) {
            replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
            return;
        }
        r = cfg.setDefaultLevel(*v);
    } else if (msg.key == "DefaultReason") {
        auto v = asString(msg.value);
        if (!v) {
            replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
            return;
        }
        r = cfg.setDefaultReason(*v);
    } else if (msg.key == "DefaultLocation") {
        auto v = asString(msg.value);
        if (!v) {
            replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
            return;
        }
        r = cfg.setDefaultLocation(*v);
    } else if (msg.key == "TsaUrls") {
        const auto* arr = msg.value.asArray();
        if (!arr) {
            replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
            return;
        }
        std::vector<std::string> urls;
        for (const auto& e : *arr) {
            auto s = asString(e);
            if (!s) {
                replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
                return;
            }
            urls.push_back(std::move(*s));
        }
        r = cfg.setTsaUrls(std::move(urls));
    } else if (msg.key == "TslSources") {
        const auto* arr = msg.value.asArray();
        if (!arr) {
            replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
            return;
        }
        std::vector<A::Config::TslSource> sources;
        for (const auto& e : *arr) {
            const auto* m = e.asMap();
            if (!m) {
                replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
                return;
            }
            A::Config::TslSource src;
            const auto* url = e.find("url");
            const auto* isLotl = e.find("isLotl");
            const auto* eager = e.find("eager");
            if (url == nullptr || !url->asText()) {
                replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
                return;
            }
            src.url = *url->asText();
            src.isLotl = isLotl != nullptr && isLotl->asBool().value_or(false);
            src.eager = eager != nullptr && eager->asBool().value_or(false);
            sources.push_back(std::move(src));
        }
        r = cfg.setTslSources(std::move(sources));
    } else {
        replyError(connId, req, A::Wire::SyncError::UnknownConfigKey);
        return;
    }

    if (!r.ok) {
        replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
        return;
    }
    sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::AckReply{}));
}

void SocketFrontend::handleResetConfig(std::uint64_t connId, std::uint64_t req, const A::Wire::ResetConfig& msg,
                                       const A::CallerToken& caller)
{
    const auto mut = A::Config::ConfigStore::mutability(msg.key);
    if (!mut) {
        replyError(connId, req, A::Wire::SyncError::UnknownConfigKey);
        return;
    }
    if (*mut == A::Config::Mutability::FileOnly || *mut == A::Config::Mutability::ReadOnly) {
        replyError(connId, req, A::Wire::SyncError::ReadOnlyConfig);
        return;
    }
    const char* action =
        (*mut == A::Config::Mutability::DbusMutableTrust) ? A::kActionConfigureTrust : A::kActionConfigure;
    if (!m_core.authorizer().authorize(action, caller)) {
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    }
    const auto r = m_core.configStore().resetKey(msg.key, /*fromDbus=*/true);
    if (!r.ok) {
        replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
        return;
    }
    sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::AckReply{}));
}

// --- pkcs11 / cert-der (async broker handoff) --------------------------------

void SocketFrontend::handleCertDer(std::uint64_t connId, std::uint64_t req, const A::Wire::GetCertDer& msg,
                                   const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& der) {
            postReply(tr, connId, A::Wire::makeReply(req, A::Wire::CertDerReply{der}));
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, mapCryptoOutcome(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    m_core.pkcs11().certDer(msg.reader, msg.cert, c, reply);
}

void SocketFrontend::handlePkPublicKey(std::uint64_t connId, std::uint64_t req, const A::Wire::PkPublicKey& msg,
                                       const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& n, const std::vector<std::uint8_t>& e) {
            A::Wire::PublicKeyReply pk = A::Wire::RsaPublicKey{n, e};
            postReply(tr, connId, A::Wire::makeReply(req, pk));
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, mapCryptoOutcome(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    m_core.pkcs11().publicKey(msg.reader, msg.cert, c, reply);
}

void SocketFrontend::handlePkLogin(std::uint64_t connId, std::uint64_t req, const A::Wire::PkLogin& msg,
                                   const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::LoginOutcome, std::uint32_t> reply{
        [tr, connId, req](std::uint32_t /*flags*/) {
            postReply(tr, connId, A::Wire::makeReply(req, A::Wire::AckReply{}));
        },
        [tr, connId, req](A::Pkcs11Broker::LoginOutcome oc) { postErr(tr, connId, req, mapLoginOutcome(oc)); },
        A::Pkcs11Broker::LoginOutcome::CardError};
    m_core.pkcs11().login(msg.reader, c, reply);
}

void SocketFrontend::handlePkLogout(std::uint64_t connId, std::uint64_t req, const A::Wire::PkLogout& msg,
                                    const A::CallerToken& caller)
{
    m_core.pkcs11().logout(msg.reader, A::Pkcs11Broker::Caller{caller, requesterLabel(caller)});
    sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::AckReply{}));
}

void SocketFrontend::handlePkSignRaw(std::uint64_t connId, std::uint64_t req, const A::Wire::PkSignRaw& msg,
                                     const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& sig) {
            postReply(tr, connId, A::Wire::makeReply(req, A::Wire::RawSignatureReply{sig}));
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, mapCryptoOutcome(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    m_core.pkcs11().signRaw(msg.reader, msg.cert, A::Mechanism::RsaPkcs1Sign, A::MechParamsEmpty{}, msg.data, c, reply);
}

void SocketFrontend::handlePkDecrypt(std::uint64_t connId, std::uint64_t req, const A::Wire::PkDecrypt& msg,
                                     const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& plain) {
            postReply(tr, connId, A::Wire::makeReply(req, A::Wire::RawSignatureReply{plain}));
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
            // Card1.CardType (single-candidate case): the SAME held-session
            // candidate list caps/preAuth were just resolved from. Ambiguous
            // (more than one match) or empty (no match) both mean "not yet
            // known" -- stays empty; a real read resolves it authoritatively
            // via the property-update path (SocketTransport::updateCardType).
            std::string cardType;
            if (resolution.candidates.size() == 1 && resolution.candidates.front()) {
                cardType = resolution.candidates.front()->pluginId();
            }
            tr->post([this, card, caps = resolution.capabilities, preAuth = resolution.preReadAuth, cardType] {
                applyCardResolution(card, caps, preAuth, cardType);
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

void SocketFrontend::applyCardResolution(A::CardState card, std::uint32_t caps,
                                         LibreSCRS::Auth::PreReadAuthMethod preAuth, const std::string& cardType)
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
    // card.atrHex carries through unchanged from PresenceModel's insertion --
    // known synchronously, well before this held-session resolve.
    A::CardState refined{card.id, card.reader, caps, preAuth, cardType, card.atrHex};
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
