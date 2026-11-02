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

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/FeatureTokens.h>
#include <LibreSCRS/Agent/Reply.h>
#include <LibreSCRS/Agent/SecureZero.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Logging.h>

#include <algorithm>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/trust/CscaAnchorImport.h>
#include <LibreSCRS/Agent/crypto/Mechanism.h>
#include <LibreSCRS/Agent/operations/BatchSignFlow.h> // isValidBatchDocumentCount, kMin/kMaxBatchDocuments, BatchDocumentInput
#include <LibreSCRS/Agent/operations/LmSeams.h> // layoutVisualSignature, appearanceFontBytes
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <LibreSCRS/Agent/operations/PinChangeFlow.h> // PinManageRequest, validatePinManageRequest
#include <LibreSCRS/Agent/operations/SignatureParams.h>
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/util/CallerLabel.h>
#include <LibreSCRS/Agent/value/CredentialRecord.h>      // CredentialSnapshot, EntryError
#include <LibreSCRS/Agent/value/SyncErrorTaxonomy.h>     // toSyncError: the one table both hosts send
#include <LibreSCRS/Agent/wire/BoundedFdRead.h>          // readBoundedRegularFd, kMaxInputBytes
#include <LibreSCRS/Agent/wire/Framing.h>                // kMaxFrameFds (socket per-frame fd budget)
#include <LibreSCRS/Agent/wire/darwin/PeerCodeSigning.h> // the requester's signing identifier

#include <LibreSCRS/Plugin/PluginTypes.h> // CardCapabilities

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace LibreSCRS::Darwin {
namespace {

namespace A = LibreSCRS::Agent;
namespace log = LibreSCRS::log;
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

// The credentials verb that may carry the activateKey wire key (the wire's
// closed cred-verb vocabulary; validatePinManageRequest owns the full check).
constexpr const char* kVerbActivatePin = "activate_pin";

// The stored anchor record as the wire's reply type. One conversion for the
// import's reply and for GetConfig's CscaAnchorState entry, so LibreAgent's one
// encoder decides both: the field names, and which fields an absent value
// leaves out.
A::Wire::CscaAnchorStateReply toAnchorStateReply(const A::Config::CscaAnchorState& recorded)
{
    A::Wire::CscaAnchorStateReply reply;
    reply.anchors = recorded.anchors;
    reply.issuers = recorded.issuers;
    reply.replayRefusalActive = recorded.replayRefusalActive;
    // Absent when the import took in several publishers: there is then no
    // publisher to name, and an empty string would read as one whose
    // fingerprint happens to be blank.
    reply.signer = recorded.signer.empty() ? std::nullopt : std::optional<std::string>{recorded.signer};
    reply.signerPinned = recorded.signerPinned;
    reply.acceptedAt = recorded.acceptedAt;
    reply.signedAt = recorded.signedAt;
    reply.origin = recorded.origin;
    return reply;
}

// GetConfig's CscaAnchorState entry: the state as a value in a map, encoded by
// the same LibreAgent encoder the import's reply is built from, so the two
// cannot name or omit a field differently. Absent until an import has been
// accepted, and absent is not zero: a zeroed report and an accepted list that
// vouched for nothing mean opposite things. An empty map is this wire's
// "nothing installed".
A::Wire::CborValue anchorStateEntry(const std::optional<A::Config::CscaAnchorState>& held)
{
    return held ? A::Wire::encodeCscaAnchorState(toAnchorStateReply(*held))
                : A::Wire::CborValue(A::Wire::CborValue::Map{});
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

// A reply that carries a secret (decrypted plaintext, a derived secret). post()
// copies its closure more than once on the way to the loop, so the closure
// holds only a shared Secure::Buffer, which cleanses itself whether the
// closure runs or not. The wire message exists only while it is sent; it and
// the reply struct it was built from are wiped on every way out, a throwing
// build or send included.
template <typename SecretReply>
void postSecretReply(SocketTransport* tr, std::uint64_t connId, std::uint64_t req,
                     const std::vector<std::uint8_t>& secret, std::vector<std::uint8_t> SecretReply::* field)
{
    auto held = std::make_shared<const Secure::Buffer>(std::span<const std::uint8_t>{secret});
    tr->post([tr, connId, req, held, field] {
        SecretReply out;
        const A::SecureZeroOnExit wipeField(out.*field);
        out.*field = std::vector<std::uint8_t>(held->data(), held->data() + held->size());
        auto message = A::Wire::makeReply(req, out);
        try {
            tr->sendTo(connId, message);
        } catch (...) {
            message.scrub();
            throw;
        }
        message.scrub();
    });
}

// The one shape of a bare sync-error reply: the code and nothing else. Every
// path that answers with only a code builds it here.
A::Wire::CborValue syncErrorReply(std::uint64_t req, A::Wire::SyncError code)
{
    return A::Wire::makeErrorReply(req, A::Wire::ErrInfo{code, std::nullopt, std::nullopt});
}

void postErr(SocketTransport* tr, std::uint64_t connId, std::uint64_t req, A::Wire::SyncError code)
{
    postReply(tr, connId, syncErrorReply(req, code));
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
    std::string format;
    if (const auto requestedFormat = sp::requestedFormatFrom(opts.format)) {
        format = *requestedFormat;
    } else {
        const auto sniffed = sp::sniffFormat(sniffSource);
        if (!sniffed) {
            return std::unexpected(A::Wire::SyncError::UnsupportedSignatureParameter);
        }
        format = *sniffed;
    }
    if (!sp::isKnownFormat(format)) {
        return std::unexpected(A::Wire::SyncError::UnsupportedSignatureParameter);
    }
    const std::optional<std::string> requestedLevel = sp::requestedLevelFrom(opts.level);
    // A per-request tsaUrl counts: supplying a timestamp authority expresses
    // intent to timestamp, so a DEFAULTED baseline lifts to b-t instead of
    // resolving to b-b and then being rejected for carrying a tsaUrl at all.
    // An EXPLICIT b-b paired with a tsaUrl is still a rejection --
    // resolveSignLevel returns a requested level unchanged, so the existing
    // SignRejectsTsaUrlPairedWithTheBaselineLevel case is unaffected.
    const bool hasTsa = !config.tsaUrls().empty() || opts.tsaUrl.has_value();
    std::string level = sp::resolveSignLevel(requestedLevel, config.defaultLevel(), hasTsa);
    if (!sp::isKnownLevel(level) || !sp::isImplementedSignLevel(level)) {
        return std::unexpected(A::Wire::SyncError::UnsupportedSignatureParameter);
    }
    const std::string packaging = sp::requestedPackagingFrom(opts.packaging).value_or(sp::defaultPackagingFor(format));
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

SocketFrontend::SocketFrontend(SocketTransport& transport, A::AgentCore& core, std::string version,
                               std::shared_ptr<LibreSCRS::Plugin::CardPluginService> plugins)
    : m_transport(transport), m_core(core), m_version(std::move(version)), m_plugins(std::move(plugins)),
      // The deposit seam is the one read-path seam that needs the registry: a
      // renegotiated read hands the chosen passport MRZ to the candidate
      // plugins, and only the registry holds mutable handles to them. Bound
      // once, here, for every operation the launcher builds.
      m_launcher(core, Ops::OperationSeams::production(core, m_plugins.get())),
      m_resolution(detail::kResolveRetryBudget, detail::isRefusedSession)
{
    // Reconcile before this object can answer anything. The store has just been
    // loaded from its file and the loop is entered after construction, so no
    // client can have read the stale report and none can read it afterwards.
    //
    // It belongs to the object that SERVES the report rather than to the
    // composition root: not serving a claim known to be unbacked is this
    // object's own obligation. The library owns WHAT is stale -- anchors gone
    // from the cache, or a pinned signer the cache no longer establishes -- and
    // the host owns WHEN to ask. Same split, and the same placement, as the bus
    // host's.
    //
    // Without it this host served a remembered "903 anchors" over a directory
    // someone had emptied, and nothing anywhere would have said otherwise.
    A::Trust::discardStaleAnchorReport(m_core.configStore());
    m_confirmQueue = dispatch_queue_create("rs.librescrs.agent.confirm", DISPATCH_QUEUE_CONCURRENT);
    // Refuse by default. Nothing here knows how to ask a human until main.cpp
    // injects the prompter client, and a build that forgot to inject one must
    // refuse trust changes rather than wave them through.
    m_confirm = [](const wire::ConfirmAction&) {
        return wire::ConfirmReply{wire::PromptReplyStatus::Error, "no confirmation mechanism"};
    };
}

SocketFrontend::~SocketFrontend()
{
    // Mark the guard dead, and do NOT wait: a confirmation the person has not
    // answered yet would hold this destructor for as long as they leave the
    // dialog standing. The block wakes into a guard that says the frontend is
    // gone and drops the answer on the floor.
    {
        const std::lock_guard lock(m_confirmGuard->mutex);
        m_confirmGuard->alive = false;
    }
    if (m_confirmQueue != nullptr) {
        dispatch_release(m_confirmQueue);
        m_confirmQueue = nullptr;
    }
}

void SocketFrontend::setConfirmProvider(ConfirmFn fn)
{
    m_confirm = std::move(fn);
}

void SocketFrontend::start()
{
    m_transport.setRequestSink([this](SocketTransport::Inbound&& in) { dispatch(std::move(in)); });
}

std::string SocketFrontend::requesterLabel(const A::CallerToken& caller) const
{
    const auto creds = m_transport.credentialsFor(caller);
    if (!creds) {
        return {};
    }
    // No team: only the identifier is wanted here, not a verdict on who signed
    // it. The process label stays in the log, on the connect line.
    const auto signing = A::Wire::Darwin::resolvePeerCodeSigning(*creds, std::nullopt);
    return detail::requesterLabelFor(signing.signingId, creds->label());
}

void SocketFrontend::sendReplyOnLoop(std::uint64_t connId, A::Wire::CborValue message)
{
    m_transport.sendTo(connId, message);
}

void SocketFrontend::replyError(std::uint64_t connId, std::uint64_t req, A::Wire::SyncError code)
{
    sendReplyOnLoop(connId, syncErrorReply(req, code));
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
    } else if (const auto* m = std::get_if<A::Wire::PkLoginState>(&body)) {
        handlePkLoginState(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::PkPublicKey>(&body)) {
        handlePkPublicKey(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::PkSignRaw>(&body)) {
        handlePkSignRaw(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::PkDecrypt>(&body)) {
        handlePkDecrypt(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::PkDerive>(&body)) {
        handlePkDerive(connId, req, *m, caller);
    } else if (const auto* m = std::get_if<A::Wire::LayoutVisual>(&body)) {
        handleLayoutVisual(connId, req, *m);
    } else if (std::get_if<A::Wire::GetAppearanceFont>(&body)) {
        handleGetAppearanceFont(connId, req);
    } else if (const auto* m = std::get_if<A::Wire::ImportCscaMasterList>(&body)) {
        handleImportCscaMasterList(in, *m);
    } else if (std::get_if<A::Wire::ForgetCscaAnchors>(&body)) {
        handleForgetCscaAnchors(connId, req, caller);
    } else {
        // A request family this chain does not name used to fall out of here
        // with no reply and no log: the client waited out its timeout and
        // nothing recorded that the agent had been asked. Silence is the worst
        // of the three possible answers -- worse than refusing, because it
        // leaves no trace to find.
        //
        // The static_assert is the other half. The handlers take four different
        // shapes -- (connId, req, msg), (connId, req), (in, msg) and
        // (connId, req, msg, caller) -- so a std::visit here would mean
        // reshaping every call site, which is a larger change than the silence
        // is worth today. Instead, adding an alternative to Wire::Request breaks
        // THIS line, which forces a person to look at this chain rather than
        // let the new message class disappear into the else.
        static_assert(std::variant_size_v<A::Wire::Request> == 28,
                      "Wire::Request grew or shrank: give the new alternative a branch above "
                      "(or confirm the floor is right for it) and update this count");
        log::warnf("socket: unhandled request family on conn {} req {}", connId, req);
        replyError(connId, req, A::Wire::SyncError::InvalidRequest);
    }
}

void SocketFrontend::handleHello(std::uint64_t connId, std::uint64_t req, const A::Wire::Hello& msg)
{
    // A client of another wire version would otherwise meet a decode failure
    // somewhere in the middle of an operation; it is told here, once, and the
    // connection ends there. Left open, it could go on sending requests and
    // receiving presence events in a protocol it has just been told it does
    // not speak.
    if (msg.proto != A::Wire::kProtocolVersion) {
        m_transport.sendThenClose(connId, syncErrorReply(req, A::Wire::SyncError::UnsupportedProtocol));
        return;
    }
    m_transport.setWantsPresenceEvents(connId, msg.wantsEvents);
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
//
// Each handler checks what only this host can check -- the card handle, the
// capability bit, authorization, its own argument decoding -- and hands the
// rest to the shared launcher, which assembles and queues the operation the
// same way for every host.

Ops::OperationTarget SocketFrontend::operationTarget(const SocketTransport::CardRouting& routing,
                                                     const A::CallerToken& caller) const
{
    return Ops::OperationTarget{
        .card =
            A::ReaderCard{.readerId = routing.readerId, .readerName = routing.readerName, .cardKey = routing.cardKey},
        .caller = caller,
        .requester = requesterLabel(caller),
    };
}

Ops::OperationLauncher::ChannelFactory
SocketFrontend::channelFor(std::uint64_t connId, SocketOperationChannel::SignArtifactSink onSignArtifact)
{
    // Called by the launcher on this (loop) thread, once, for an accepted
    // launch; the channel it builds lives with the operation on the worker.
    return [this, connId, onSignArtifact = std::move(onSignArtifact)](
               A::OperationId id, const std::shared_ptr<Ops::OperationState>& state) {
        return std::make_unique<SocketOperationChannel>(m_transport, connId, id.value(), state, onSignArtifact,
                                                        makeOpFinishedSink());
    };
}

void SocketFrontend::replyLaunched(std::uint64_t connId, std::uint64_t req, const A::CallerToken& caller,
                                   const Ops::OperationLauncher::Launched& launched)
{
    if (!launched) {
        replyError(connId, req, launched.error());
        return;
    }
    m_opOwners[launched->value()] = caller;
    sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::OpStarted{launched->value()}));
}

Ops::OperationLauncher::CardTypeSink SocketFrontend::cardTypeSink(const std::string& cardHandle)
{
    // Fires on the worker: capture the long-lived transport, never `this`, and
    // let the loop publish the type the read resolved.
    auto* tr = &m_transport;
    return [tr, cardHandle](const std::string& cardType) {
        tr->post([tr, cardHandle, cardType] { tr->updateCardType(cardHandle, cardType); });
    };
}

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
    replyLaunched(connId, req, in.caller,
                  m_launcher.launch(operationTarget(*routing, in.caller), channelFor(connId),
                                    Ops::OperationLauncher::ReadIdentity{.onCardType = cardTypeSink(msg.card)}));
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
    replyLaunched(connId, req, in.caller,
                  m_launcher.launch(operationTarget(*routing, in.caller), channelFor(connId),
                                    Ops::OperationLauncher::GetPhoto{.onCardType = cardTypeSink(msg.card)}));
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
    replyLaunched(connId, req, in.caller,
                  m_launcher.launch(operationTarget(*routing, in.caller), channelFor(connId),
                                    Ops::OperationLauncher::ReadCertificates{}));
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
    replyLaunched(connId, req, in.caller,
                  m_launcher.launch(operationTarget(*routing, in.caller), channelFor(connId),
                                    Ops::OperationLauncher::ReadTokenInfo{}));
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
    switch (m_core.authorizer().authorize(A::kActionSign, in.caller)) {
    case A::AuthorizationOutcome::Granted:
        break;
    case A::AuthorizationOutcome::Denied:
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    case A::AuthorizationOutcome::Undecided:
        // Nothing was decided and nothing was changed -- see the LibreLinux
        // ManagerObject/CardObject switches this mirrors.
        replyError(connId, req, A::Wire::SyncError::CommunicationError);
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
    auto doc = A::Wire::readBoundedRegularFd(in.fds[msg.inFd].get(), A::Wire::kMaxInputBytes);
    if (doc.status == A::Wire::ReadStatus::NotRegular) {
        replyError(connId, req, A::Wire::SyncError::UnsupportedSignatureParameter);
        return;
    }
    if (doc.status == A::Wire::ReadStatus::TooLarge) {
        replyError(connId, req, A::Wire::SyncError::InputTooLarge);
        return;
    }
    if (doc.status == A::Wire::ReadStatus::Error) {
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

    // The sign sink fires on the WORKER thread: touch only the long-lived
    // transport there, and marshal the frontend-state store (m_signResults)
    // onto the loop where the loop-quiesce drop guards it against a
    // post-teardown frontend.
    auto* tr = &m_transport;
    const A::CallerToken owner = in.caller;
    auto stash = [this, tr, owner](std::uint64_t sid, const Ops::SignedArtifact& artifact) {
        tr->post([this, sid, owner, artifact] { stashSignArtifact(sid, owner, artifact); });
    };
    replyLaunched(connId, req, owner,
                  m_launcher.launch(operationTarget(*routing, owner), channelFor(connId, std::move(stash)),
                                    Ops::OperationLauncher::Sign{.params = std::move(params)}));
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
    switch (m_core.authorizer().authorize(A::kActionSign, in.caller)) {
    case A::AuthorizationOutcome::Granted:
        break;
    case A::AuthorizationOutcome::Denied:
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    case A::AuthorizationOutcome::Undecided:
        // Nothing was decided and nothing was changed -- see the LibreLinux
        // ManagerObject/CardObject switches this mirrors.
        replyError(connId, req, A::Wire::SyncError::CommunicationError);
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
    // 256 MiB cap + regular-file-only + non-empty rule Sign enforces for
    // its single document (readBoundedRegularFd), applied per document
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
        auto doc = A::Wire::readBoundedRegularFd(in.fds[entry.fdIndex].get(), A::Wire::kMaxInputBytes);
        if (doc.status == A::Wire::ReadStatus::NotRegular) {
            replyError(connId, req, A::Wire::SyncError::UnsupportedSignatureParameter);
            return;
        }
        if (doc.status == A::Wire::ReadStatus::TooLarge) {
            replyError(connId, req, A::Wire::SyncError::InputTooLarge);
            return;
        }
        if (doc.status == A::Wire::ReadStatus::Error) {
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

    // No sign sink: unlike a single Sign, SignBatch has no GetSignResult-style
    // pull recovery on this wire (the CDDL pins recovery Sign-only), so
    // nothing needs stashing.
    replyLaunched(connId, req, in.caller,
                  m_launcher.launch(
                      operationTarget(*routing, in.caller), channelFor(connId),
                      Ops::OperationLauncher::SignBatch{.params = std::move(params), .documents = std::move(inputs)}));
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
    replyLaunched(connId, req, in.caller,
                  m_launcher.launch(operationTarget(*routing, in.caller), channelFor(connId),
                                    Ops::OperationLauncher::ListCredentials{}));
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
    switch (m_core.authorizer().authorize(A::kActionCredentialsManage, in.caller)) {
    case A::AuthorizationOutcome::Granted:
        break;
    case A::AuthorizationOutcome::Denied:
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    case A::AuthorizationOutcome::Undecided:
        // Nothing was decided and nothing was changed -- see the LibreLinux
        // ManagerObject/CardObject switches this mirrors.
        replyError(connId, req, A::Wire::SyncError::CommunicationError);
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
        replyError(connId, req, A::toSyncError(valid.error()));
        return;
    }

    replyLaunched(connId, req, in.caller,
                  m_launcher.launch(operationTarget(*routing, in.caller), channelFor(connId),
                                    Ops::OperationLauncher::ManagePin{.request = std::move(request),
                                                                      .snapshot = std::move(*snapshot)}));
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
    switch (m_core.authorizer().authorize(A::kActionCredentialsManage, in.caller)) {
    case A::AuthorizationOutcome::Granted:
        break;
    case A::AuthorizationOutcome::Denied:
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    case A::AuthorizationOutcome::Undecided:
        // Nothing was decided and nothing was changed -- see the LibreLinux
        // ManagerObject/CardObject switches this mirrors.
        replyError(connId, req, A::Wire::SyncError::CommunicationError);
        return;
    }
    if (!m_core.rateLimiter().allow(in.caller)) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
        return;
    }

    replyLaunched(connId, req, in.caller,
                  m_launcher.launch(operationTarget(*routing, in.caller), channelFor(connId),
                                    Ops::OperationLauncher::ActivateSigningKey{}));
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
    {
        A::Wire::CborValue::Array sources;
        for (const auto& s : cfg.cscaSources()) {
            A::Wire::CborValue::Map m;
            m.emplace("uri", A::Wire::CborValue(s.uri));
            m.emplace("eager", A::Wire::CborValue(s.eager));
            sources.emplace_back(std::move(m));
        }
        reply.entries.emplace("CscaSources", A::Wire::CborValue(std::move(sources)));
    }
    reply.entries.emplace("CscaAnchorState", anchorStateEntry(cfg.cscaAnchorState()));
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
    switch (m_core.authorizer().authorize(action, caller)) {
    case A::AuthorizationOutcome::Granted:
        break;
    case A::AuthorizationOutcome::Denied:
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    case A::AuthorizationOutcome::Undecided:
        // Nothing was decided and nothing was changed -- see the LibreLinux
        // ManagerObject/CardObject switches this mirrors.
        replyError(connId, req, A::Wire::SyncError::CommunicationError);
        return;
    }

    if (*mut == A::Config::Mutability::DbusMutableTrust) {
        // Each one raises a dialog, so the same budget as every other verb
        // that asks a person something.
        if (!m_core.rateLimiter().allow(caller)) {
            replyError(connId, req, A::Wire::SyncError::RateLimited);
            return;
        }
        confirmThenApply(connId, req, msg.key, caller, TrustChange::SetValue,
                         [this, connId, req, msg] { applyConfigWrite(connId, req, msg); });
        return;
    }
    applyConfigWrite(connId, req, msg);
}

void SocketFrontend::applyConfigWrite(std::uint64_t connId, std::uint64_t req, const A::Wire::SetConfig& msg)
{
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
    } else if (msg.key == "CscaSources") {
        const auto* arr = msg.value.asArray();
        if (!arr) {
            replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
            return;
        }
        std::vector<A::Config::CscaSource> sources;
        for (const auto& e : *arr) {
            // Two members, not three: a country-signing source has no LOTL
            // equivalent, so mirroring TslSource's shape here would invent a
            // field with nothing to put in it.
            if (e.asMap() == nullptr) {
                replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
                return;
            }
            A::Config::CscaSource src;
            const auto* uri = e.find("uri");
            const auto* eager = e.find("eager");
            if (uri == nullptr || !uri->asText()) {
                replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
                return;
            }
            src.uri = *uri->asText();
            src.eager = eager != nullptr && eager->asBool().value_or(false);
            sources.push_back(std::move(src));
        }
        r = cfg.setCscaSources(std::move(sources));
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

namespace {

// The refusal the core reports, in this wire's vocabulary. Replayed is the one
// name a person can act on directly ("you already have this list"), so it stays
// separate; the rest share the invalid-argument bucket because a malformed
// file, a bad signature and a wrong publisher are all "this file will not do"
// to the caller, and the agent's log carries which one it was.
A::Wire::SyncError syncErrorFor(A::Trust::ImportRefusal reason) noexcept
{
    switch (reason) {
    case A::Trust::ImportRefusal::Replayed:
        return A::Wire::SyncError::MasterListReplayed;
    case A::Trust::ImportRefusal::CacheNotWritable:
        return A::Wire::SyncError::CommunicationError;
    case A::Trust::ImportRefusal::NotAMasterList:
    case A::Trust::ImportRefusal::Empty:
    case A::Trust::ImportRefusal::Malformed:
    case A::Trust::ImportRefusal::BadSignature:
    case A::Trust::ImportRefusal::SignerChanged:
        break;
    }
    return A::Wire::SyncError::InvalidRequest;
}

} // namespace

namespace detail {

bool isRefusedSession(const LibreSCRS::SmartCard::OpenError& failure) noexcept
{
    return failure.kind == LibreSCRS::SmartCard::OpenError::Kind::SessionRefused;
}

std::string requesterLabelFor(const std::optional<std::string>& signingId, std::string fallback)
{
    if (!signingId || signingId->empty()) {
        return A::sanitizeLabel(std::move(fallback));
    }
    return A::sanitizeLabel(*signingId);
}

A::Config::CscaAnchorState recordedStateFor(const A::Trust::AnchorState& imported)
{
    // One import can now take in a COLLECTION of separately signed lists, so
    // the single-publisher vocabulary this record and the wire reply speak
    // cannot always be filled. Two fields are left ABSENT rather than picked:
    // handing one fingerprint out of twenty-eight to a surface whose label
    // reads "the publisher" is a concrete untruth, and on a trust surface a
    // wrong answer and no answer are not failures of the same size. Absence is
    // a shape this reply has always had -- a list with no signing time has
    // omitted signedAt since the first version -- so a client written before
    // collections reads it correctly without knowing they exist.
    const A::Trust::AcceptedSigner* only = imported.signers.size() == 1 ? &imported.signers.front() : nullptr;

    A::Config::CscaAnchorState out;
    out.anchors = imported.anchorCount;
    out.issuers = imported.issuerCount;
    out.replayRefusalActive = imported.replayRefusalActive();
    out.signer = only != nullptr ? A::Trust::toHex(only->fingerprint) : std::string{};
    // Asked of the state rather than recomputed here. The aggregate is a
    // property of what was accepted, and it has one owner now: both hosts had
    // written the same fold independently, and both had to remember on their
    // own that all_of over an empty range is true -- which would report a state
    // with NO publisher as fully established, the strongest possible
    // overstatement on a trust surface.
    out.signerPinned = imported.everyPublisherEstablished();
    out.acceptedAt = imported.acceptedAt;
    out.signedAt = only != nullptr ? only->signedAt : std::nullopt;
    out.origin = imported.origin;
    return out;
}

} // namespace detail

void SocketFrontend::handleImportCscaMasterList(SocketTransport::Inbound& in, const A::Wire::ImportCscaMasterList& msg)
{
    const std::uint64_t connId = in.connId;
    const std::uint64_t req = in.request.req;

    // ORDER IS THE CONTRACT, and it is not observable from the error name: an
    // implementation that reads first and authorizes after answers NotAuthorized
    // just the same. What separates them is the descriptor. It arrives sharing
    // an open file description with the sender, so a read here MOVES THE
    // SENDER'S OFFSET -- which is how a test can tell whether a refused caller
    // was turned away before or after the agent touched what they handed over.
    //
    // Authorize the client. Then rate-limit, then the person, and only then
    // read. The trust-tier action is shared with CscaSources: an import is a
    // larger trust change than naming a source, not a smaller one.
    switch (m_core.authorizer().authorize(A::kActionConfigureTrust, in.caller)) {
    case A::AuthorizationOutcome::Granted:
        break;
    case A::AuthorizationOutcome::Denied:
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    case A::AuthorizationOutcome::Undecided:
        // Nothing was decided and nothing was changed -- see the LibreLinux
        // ManagerObject/CardObject switches this mirrors.
        replyError(connId, req, A::Wire::SyncError::CommunicationError);
        return;
    }
    if (!m_core.rateLimiter().allow(in.caller)) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
        return;
    }

    if (msg.list >= in.fds.size()) {
        replyError(connId, req, A::Wire::SyncError::InvalidRequest);
        return;
    }
    // Then a person, before a byte is read -- the same place the Linux host
    // puts its consent (polkit runs inside authorize(), ahead of the read).
    // The request's descriptor vector dies with this dispatch and the person
    // answers later, so the descriptor moves into the detour and comes back
    // with the answer. Nothing below runs unless they said yes.
    auto held = std::make_shared<A::Wire::UniqueFd>(std::move(in.fds[msg.list]));
    confirmThenApply(connId, req, "CscaAnchorState", in.caller, TrustChange::ImportAnchors, [this, connId, req, held] {
        // A PLAIN descriptor, deliberately: a master list is public data, and the
        // sealed anonymous file this agent uses elsewhere is its vocabulary for
        // secrets.
        auto input = A::Wire::readBoundedRegularFd(held->get(), A::Trust::kMaxMasterListBytes);
        if (input.status == A::Wire::ReadStatus::NotRegular) {
            replyError(connId, req, A::Wire::SyncError::InvalidRequest);
            return;
        }
        if (input.status == A::Wire::ReadStatus::TooLarge) {
            replyError(connId, req, A::Wire::SyncError::InputTooLarge);
            return;
        }
        if (input.status == A::Wire::ReadStatus::Error) {
            replyError(connId, req, A::Wire::SyncError::CommunicationError);
            return;
        }

        auto& cfg = m_core.configStore();
        A::Trust::AnchorCache cache(cfg.cscaCacheDir());
        const auto now =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        auto imported = A::Trust::importMasterList(input.bytes, cache, now);
        if (!imported) {
            replyError(connId, req, syncErrorFor(imported.error().reason));
            return;
        }

        // Says what was DONE, never that anything was proved: on a first import no
        // publisher is established, and a surface rendering "authenticity verified"
        // over that claims more than the agent measured. The publisher COUNT is
        // logged rather than served, because the remembered record has no member
        // that carries it: a key present in the import reply and gone from the
        // property a moment later would be worse than silence.
        log::infof("country signing anchors imported: anchors={} issuers={} publishers={} established={}",
                   imported->anchorCount, imported->issuerCount, imported->signers.size(),
                   std::ranges::count_if(imported->signers,
                                         [](const A::Trust::AcceptedSigner& s) { return s.identityEstablished; }));

        // The reply tells THIS client what it installed; the record is what tells
        // the next client to connect, which has no reply to read. The store
        // persists it and notifies observers itself.
        const A::Config::CscaAnchorState recorded = detail::recordedStateFor(*imported);
        cfg.recordCscaAnchorState(recorded);

        sendReplyOnLoop(connId, A::Wire::makeReply(req, toAnchorStateReply(recorded)));
    });
}

void SocketFrontend::handleForgetCscaAnchors(std::uint64_t connId, std::uint64_t req, const A::CallerToken& caller)
{
    // The trust tier, shared with the import and with CscaSources: undoing a
    // trust decision is the same size of decision as making one, and a person
    // who may not add anchors may not silently drop them either.
    switch (m_core.authorizer().authorize(A::kActionConfigureTrust, caller)) {
    case A::AuthorizationOutcome::Granted:
        break;
    case A::AuthorizationOutcome::Denied:
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    case A::AuthorizationOutcome::Undecided:
        // Nothing was decided and nothing was changed -- see the LibreLinux
        // ManagerObject/CardObject switches this mirrors.
        replyError(connId, req, A::Wire::SyncError::CommunicationError);
        return;
    }
    if (!m_core.rateLimiter().allow(caller)) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
        return;
    }
    // Human confirmation, same as a trust-tier config write. This one destroys
    // rather than replaces, and there is nothing to read it back from
    // afterwards, so the reply below is the only account of what went.
    confirmThenApply(connId, req, "CscaAnchorState", caller, TrustChange::ForgetAnchors, [this, connId, req] {
        auto& cfg = m_core.configStore();
        const auto forgotten = A::Trust::forgetCscaAnchors(cfg);
        if (!forgotten) {
            // Nothing was changed, the report included -- which is why this is
            // not reported as a partial success. Holding nothing would have
            // answered a zeroed report, so an empty answer here really does
            // mean the anchors could not be removed.
            replyError(connId, req, A::Wire::SyncError::CommunicationError);
            return;
        }
        log::infof("country signing anchors forgotten: anchors={} hadPinnedSigner={}", forgotten->anchors,
                   forgotten->hadPinnedSigner);
        A::Wire::ForgetCscaAnchorsReply reply;
        reply.anchorsForgotten = forgotten->anchors;
        reply.hadPinnedSigner = forgotten->hadPinnedSigner;
        sendReplyOnLoop(connId, A::Wire::makeReply(req, reply));
    });
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
    switch (m_core.authorizer().authorize(action, caller)) {
    case A::AuthorizationOutcome::Granted:
        break;
    case A::AuthorizationOutcome::Denied:
        replyError(connId, req, A::Wire::SyncError::NotAuthorized);
        return;
    case A::AuthorizationOutcome::Undecided:
        // Nothing was decided and nothing was changed -- see the LibreLinux
        // ManagerObject/CardObject switches this mirrors.
        replyError(connId, req, A::Wire::SyncError::CommunicationError);
        return;
    }
    if (*mut == A::Config::Mutability::DbusMutableTrust) {
        if (!m_core.rateLimiter().allow(caller)) {
            replyError(connId, req, A::Wire::SyncError::RateLimited);
            return;
        }
        confirmThenApply(connId, req, msg.key, caller, TrustChange::Reset,
                         [this, connId, req, msg] { applyConfigReset(connId, req, msg); });
        return;
    }
    applyConfigReset(connId, req, msg);
}

void SocketFrontend::applyConfigReset(std::uint64_t connId, std::uint64_t req, const A::Wire::ResetConfig& msg)
{
    const auto r = m_core.configStore().resetKey(msg.key, /*fromDbus=*/true);
    if (!r.ok) {
        replyError(connId, req, A::Wire::SyncError::InvalidConfigValue);
        return;
    }
    sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::AckReply{}));
}

// Three phases, and the middle one is the reason this exists. The gate check
// above ran on the loop queue, which serves every connection's reads and the
// accept source. The human takes as long as they take, and the dialog has no
// timeout, so asking there would freeze every other client for the duration.
// The verdict comes back to the loop before anything touches the store or the
// connection registry: sendTo walks m_connections with no lock and is
// loop-thread-only, so replying from the worker would be a data race.
void SocketFrontend::confirmThenApply(std::uint64_t connId, std::uint64_t req, const std::string& key,
                                      const A::CallerToken& caller, TrustChange what, std::function<void()> apply)
{
    if (!m_confirmsInFlight.insert(caller).second) {
        replyError(connId, req, A::Wire::SyncError::RateLimited);
        return;
    }
    wire::ConfirmAction ask;
    ask.kind = "configure_trust";
    ask.title = "Confirm trust change";
    const TrustChangeCopy copy = describeTrustChange(key, what);
    ask.description = std::string(copy.text);
    ask.descriptionKey = std::string(copy.key);
    // The CLAIMED caller identity. The public SecTask path cannot verify it,
    // so nothing here may word it as verified -- the human is deciding, and a
    // name presented as proven would be doing the deciding for them.
    ask.requester = requesterLabel(caller);
    ask.artifact = key;

    auto* transport = &m_transport;
    const ConfirmFn confirm = m_confirm;
    // The guard, not the frontend, is what survives this call: the block below
    // holds the person's attention for as long as they want it, and both the
    // frontend and the transport it captures by raw pointer may be released
    // meanwhile.
    //
    // The lock is held ACROSS transport->post, and that is what makes a
    // FRONTEND-liveness guard safe to gate a TRANSPORT dereference with:
    // ~SocketFrontend blocks on this same mutex, so either the guard is already
    // dead and nothing is posted, or the wrapper block is enqueued on the
    // serial loop queue before the destructor can proceed. Both hosts destroy
    // the frontend BEFORE the transport, so that enqueue precedes
    // ~SocketTransport's own dispatch_sync and the block runs before the queue
    // is released. Narrowing the lock to the check alone, or reordering a host
    // to drop the transport first, reopens the crash this guards against.
    const auto guard = m_confirmGuard;
    // A copy: a block captures a C++ reference as a reference, and `caller`
    // does not outlive this call.
    const A::CallerToken waiting = caller;
    dispatch_async(m_confirmQueue, ^{
      const wire::ConfirmReply verdict = confirm(ask);
      const std::lock_guard lock(guard->mutex);
      if (!guard->alive) {
          // A literal, not a formatted line, and swallowed: the facade formats
          // and calls a std::function sink, so it can throw, and a throw out of
          // a dispatch block terminates the process on the teardown path.
          try {
              log::warn("trust confirmation answered after the frontend was gone; discarded");
          } catch (...) {
              // Nothing left to say it with.
          }
          return;
      }
      transport->post([this, guard, connId, req, waiting, verdict, apply] {
          const std::lock_guard continuationLock(guard->mutex);
          if (!guard->alive) {
              // The same fact reached the other way round: the answer was in
              // time when the worker marshalled it here and is not any more.
              // The suffix is what separates the two, because no teardown can
              // close this window by waiting -- it opens after the last moment
              // a host could wait for. Swallowed for the same reason as above.
              try {
                  log::warn("trust confirmation answered after the frontend was gone; discarded on the loop");
              } catch (...) {
                  // Nothing left to say it with.
              }
              return;
          }
          m_confirmsInFlight.erase(waiting);
          if (verdict.status != wire::PromptReplyStatus::Ok) {
              // Anything that is not an explicit approval leaves the stored
              // value exactly where it was.
              replyError(connId, req, A::Wire::SyncError::NotAuthorized);
              return;
          }
          apply();
      });
    });
}

// The key and the English travel together, and the English is unchanged: a
// prompter that resolves the key shows the holder's language, one that cannot
// shows exactly what it showed before there were keys. The two trust-source
// sentences keep two keys -- one key covering both would merge "which
// timestamping authority" with "which trusted list" into a single translatable
// sentence that can only be right about one of them.
SocketFrontend::TrustChangeCopy SocketFrontend::describeTrustChange(const std::string& key, TrustChange what)
{
    switch (what) {
    case TrustChange::ImportAnchors:
        return {.key = "prompter_trust_import",
                .text = "Install the country signing certificates from the offered file, replacing the ones this "
                        "computer checks passports against."};
    case TrustChange::ForgetAnchors:
        return {.key = "prompter_trust_forget",
                .text = "Remove every country signing certificate this computer holds."};
    case TrustChange::SetValue:
    case TrustChange::Reset:
        break;
    }
    if (key == "TsaUrls") {
        return {.key = "prompter_trust_tsa", .text = "Change the timestamping authorities this computer will use."};
    }
    if (key == "TslSources") {
        return {.key = "prompter_trust_tsl",
                .text = "Change the trusted lists this computer accepts signatures against."};
    }
    return {.key = "prompter_trust_generic", .text = "Change a trust setting on this computer."};
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
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, A::toSyncError(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    m_core.pkcs11().certDer(msg.reader, msg.cert, c, reply);
}

void SocketFrontend::handlePkPublicKey(std::uint64_t connId, std::uint64_t req, const A::Wire::PkPublicKey& msg,
                                       const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, A::Pkcs11Broker::PublicKey> reply{
        [tr, connId, req](const A::Pkcs11Broker::PublicKey& key) {
            const A::Wire::PublicKeyReply pk = std::visit(
                [](const auto& k) -> A::Wire::PublicKeyReply {
                    using K = std::decay_t<decltype(k)>;
                    if constexpr (std::is_same_v<K, A::Operations::RsaPublicKey>) {
                        return A::Wire::RsaPublicKey{k.modulus, k.exponent};
                    } else {
                        return A::Wire::EcPublicKey{k.crv, k.x, k.y};
                    }
                },
                key);
            postReply(tr, connId, A::Wire::makeReply(req, pk));
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, A::toSyncError(oc)); },
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
        [tr, connId, req](A::Pkcs11Broker::LoginOutcome oc) { postErr(tr, connId, req, A::toSyncError(oc)); },
        A::Pkcs11Broker::LoginOutcome::CardError};
    m_core.pkcs11().login(msg.reader, c, reply);
}

void SocketFrontend::handlePkLogout(std::uint64_t connId, std::uint64_t req, const A::Wire::PkLogout& msg,
                                    const A::CallerToken& caller)
{
    m_core.pkcs11().logout(msg.reader, A::Pkcs11Broker::Caller{caller, requesterLabel(caller)});
    sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::AckReply{}));
}

void SocketFrontend::handlePkLoginState(std::uint64_t connId, std::uint64_t req, const A::Wire::PkLoginState& msg,
                                        const A::CallerToken& caller)
{
    // Lease bookkeeping only, like Logout: no card, no prompt.
    const bool active =
        m_core.pkcs11().loginActive(msg.reader, A::Pkcs11Broker::Caller{caller, requesterLabel(caller)});
    sendReplyOnLoop(connId, A::Wire::makeReply(req, A::Wire::LoginStateReply{active}));
}

void SocketFrontend::handlePkSignRaw(std::uint64_t connId, std::uint64_t req, const A::Wire::PkSignRaw& msg,
                                     const A::CallerToken& caller)
{
    // The mechanism the caller named, exactly: an unknown token is refused
    // here, before any card is touched; a known one runs as itself.
    const auto mechanism = A::signMechanismFromToken(msg.mech);
    if (!mechanism) {
        replyError(connId, req, A::Wire::SyncError::InvalidRequest);
        return;
    }
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& sig) {
            postReply(tr, connId, A::Wire::makeReply(req, A::Wire::RawSignatureReply{sig}));
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, A::toSyncError(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    m_core.pkcs11().signRaw(msg.reader, msg.cert, *mechanism, A::MechParamsEmpty{}, msg.data, c, reply);
}

void SocketFrontend::handlePkDecrypt(std::uint64_t connId, std::uint64_t req, const A::Wire::PkDecrypt& msg,
                                     const A::CallerToken& caller)
{
    // The mechanism the caller named, exactly: an unknown token is refused
    // here, before any card is touched; a known one runs as itself.
    const auto mechanism = A::decryptMechanismFromToken(msg.mech);
    if (!mechanism) {
        replyError(connId, req, A::Wire::SyncError::InvalidRequest);
        return;
    }
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& plain) {
            postSecretReply(tr, connId, req, plain, &A::Wire::RawSignatureReply::sig);
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, A::toSyncError(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    m_core.pkcs11().decrypt(msg.reader, msg.cert, *mechanism, A::MechParamsEmpty{}, msg.data, c, reply);
}

void SocketFrontend::handlePkDerive(std::uint64_t connId, std::uint64_t req, const A::Wire::PkDerive& msg,
                                    const A::CallerToken& caller)
{
    auto* tr = &m_transport;
    A::Pkcs11Broker::Caller c{caller, requesterLabel(caller)};
    A::Reply<A::Pkcs11Broker::CryptoOutcome, std::vector<std::uint8_t>> reply{
        [tr, connId, req](const std::vector<std::uint8_t>& z) {
            postSecretReply(tr, connId, req, z, &A::Wire::DerivedSecretReply::z);
        },
        [tr, connId, req](A::Pkcs11Broker::CryptoOutcome oc) { postErr(tr, connId, req, A::toSyncError(oc)); },
        A::Pkcs11Broker::CryptoOutcome::CardError};
    // ECDH with CKD_NULL and no shared data: the raw secret, the only
    // derivation this surface runs.
    m_core.pkcs11().derive(msg.reader, msg.cert,
                           A::MechParamsEcdh{.peerPublicPoint = msg.data, .kdf = A::kEcdhKdfNull, .sharedData = {}}, c,
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
        // A withdrawn READER takes its worker with it, as AgentFrontend's
        // unexport does: queued ops finish CardRemoved, the thread stops (or
        // is detached if wedged in a card call), and its power-hold flag dies
        // with it. The cost on this loop is bounded, not zero: at most the
        // 250 ms grace when an op is in flight, or one PC/SC disconnect on
        // the gone reader when the worker is in its invalidate branch, and
        // never a wait on a wedged op. Left alive, the
        // orphan's idle sweep would keep re-acquiring a hold BY READER NAME,
        // so a same-named unit plugged back in would be held by a worker no
        // card-removed hook can reach. The next insert lazily spins a fresh
        // worker. Only readers live in m_readerNames, so the erase count is
        // the reader/card distinction.
        if (m_readerNames.erase(object.value()) > 0) {
            m_core.operationManager().removeReader(object);
        }
        m_transport.withdraw(object);
    });
}

void SocketFrontend::onReaderPropertiesChanged(A::ObjectId reader, const A::PropertyDelta& delta)
{
    m_transport.post([this, reader, delta] { m_transport.updateProperties(reader, delta); });
}

void SocketFrontend::onReaderRelabelled(const A::ReaderState& reader)
{
    m_transport.post([this, reader] { m_transport.relabelReader(reader); });
}

void SocketFrontend::scheduleCardResolve(const A::CardState& card)
{
    // Loop thread. Record the pending card and queue the insertion probe on the
    // reader's worker, which opens the card and marshals what it learned back
    // to applyCardResolution.
    auto& pending = m_pendingCards[card.id.value()];
    pending.card = card;

    std::string readerName;
    if (const auto it = m_readerNames.find(card.reader.value()); it != m_readerNames.end()) {
        readerName = it->second;
    }

    // The probe's continuation runs on the reader WORKER thread and may run
    // well past shutdown; it must touch ONLY the long-lived transport (never
    // `this`->m_transport). The applyCardResolution continuation captures `this`
    // for the frontend state but is dropped by the loop-quiesce if the frontend
    // is already gone.
    auto* tr = &m_transport;
    const bool queued = A::CardResolutionPolicy::probeOnWorker(
        m_core.operationManager(), card.reader, readerName, [this, tr, card](A::CardProbe probe) {
            tr->post([this, card, probe = std::move(probe)] { applyCardResolution(card, probe); });
        });
    if (!queued) {
        // Backpressure: ask again on the loop after a short delay (the card
        // stays pending, so a withdraw meanwhile drops it).
        m_transport.postAfter(std::chrono::duration_cast<std::chrono::microseconds>(m_resolution.budget().firstDelay),
                              [this, card] {
                                  if (m_pendingCards.contains(card.id.value())) {
                                      scheduleCardResolve(card);
                                  }
                              });
    }
}

void SocketFrontend::applyCardResolution(const A::CardState& card, const A::CardProbe& probe)
{
    const auto it = m_pendingCards.find(card.id.value());
    if (it == m_pendingCards.end()) {
        return; // withdrawn while resolving
    }
    // Only a session refused while someone else holds the card is asked about
    // again (detail::isRefusedSession), with waits that together outlast the
    // other prober's hold: under CryptoTokenKit a session is exclusive, and a
    // card the system is probing at insertion may be refused rather than waited
    // for. Every other outcome is the answer, including a card no plugin serves.
    if (const auto delay = m_resolution.retryAfter(probe, it->second.attempts)) {
        m_transport.postAfter(std::chrono::duration_cast<std::chrono::microseconds>(*delay), [this, card] {
            if (m_pendingCards.contains(card.id.value())) {
                scheduleCardResolve(card);
            }
        });
        return;
    }
    m_pendingCards.erase(it);
    // card.atrHex carries through unchanged from PresenceModel's insertion --
    // known synchronously, well before this probe.
    A::CardState refined{card.id, card.reader, probe.capabilities, probe.preReadAuth, probe.cardType, card.atrHex};
    m_transport.publishCard(refined);

    // Power hold: the policy's rule, classified from the transport's presence
    // roster, the same lookup the prompt dialog uses. Released by main.cpp's
    // card-removed hook.
    //
    // On macOS today this never fires. The classification reads the interface
    // from pcsc-lite's reader-name tail (" (serial) <ifd> <slot>"), and the
    // CryptoTokenKit slot names this host sees carry no such tail, so every
    // reader classifies as Unknown and no card is held. A dual-interface unit's
    // contactless twin therefore still flaps here; the branch is kept so a
    // classification that works on these names turns it on unchanged.
    if (A::CardResolutionPolicy::holdsReader(probe, m_transport.presenceRoster(), std::to_string(card.id.value()))) {
        m_core.operationManager().setReaderHold(card.reader, true);
        std::string readerName;
        if (const auto rn = m_readerNames.find(card.reader.value()); rn != m_readerNames.end()) {
            readerName = rn->second;
        }
        log::infof("reader {}: holding the contact interface to quiet its contactless twin", readerName);
    }
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
        m_confirmsInFlight.erase(caller);
    });
}

} // namespace LibreSCRS::Darwin
