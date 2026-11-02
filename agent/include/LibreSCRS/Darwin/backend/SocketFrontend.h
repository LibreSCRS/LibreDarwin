// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/SocketOperationChannel.h> // SignArtifactSink
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h> // ConfirmAction / ConfirmReply
#include <LibreSCRS/Agent/wire/Messages.h>
#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h> // Operations::SignedArtifact
#include <LibreSCRS/Agent/config/ConfigStore.h>       // Config::CscaAnchorState (detail::recordedStateFor)
#include <LibreSCRS/Agent/operations/OperationLauncher.h>
#include <LibreSCRS/Agent/presence/CardResolutionPolicy.h>
#include <LibreSCRS/Agent/trust/CscaAnchorImport.h> // Trust::AnchorState (detail::recordedStateFor)
#include <LibreSCRS/SmartCard/CardSession.h>        // OpenError (detail::isRefusedSession)

#include <cstdint>
#include <chrono>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace LibreSCRS::Agent {
class AgentCore;
} // namespace LibreSCRS::Agent

namespace LibreSCRS::Plugin {
class CardPluginService;
}

namespace LibreSCRS::Darwin {

// The inbound dispatch glue — the macOS twin of LibreLinux's AgentFrontend +
// Card1/Manager1/Config1/Pkcs11_1 objects, collapsed into one loop-thread
// dispatcher (there are no persistent per-card wire objects on macOS; the
// transport's presence snapshot replaces them). Registered as the transport's
// request sink; every request is dispatched ON THE LOOP THREAD to the neutral
// LibreAgent::Core:
//   - ReadIdentity/GetPhoto/ReadCertificates/ReadTokenInfo/Sign/SignBatch ->
//     the shared OperationLauncher over a SocketOperationChannel, reply
//     OpStarted (or the launcher's refusal);
//   - ListCredentials/ManagePin/ActivateSigningKey -> the same launch path
//     behind the PinManagement capability + the credentials entry gates
//     (validate -> authorize -> rate-limit; the read is capability-gated only);
//   - GetCertDer / Pkcs11.{PublicKey,Login,Logout,SignRaw,Decrypt} -> Pkcs11Broker
//     (async server-handoff; reply on completion; all reader-addressed);
//   - GetState -> transport snapshot; Cancel -> OperationManager::cancel;
//     GetSignResult -> the grace-window Sign recovery store;
//   - Get/Set/ResetConfig -> ConfigStore with the mutability + Authorizer gate
//     replicated here (the core ConfigStore does NOT self-gate).
//
// It ALSO owns the presence materialization: the core ObjectRegistry observers
// (wired in main.cpp) call onReaderPublished/onCardPublished/onWithdrawn/
// onReaderPropertiesChanged. Cards go through a deferred held-session capability
// resolve (the per-reader worker hop, same pattern as AgentFrontend::
// scheduleCardResolve) before publishCard, because the core publishes ATR-only
// caps + preReadAuth=None (a live session is needed for AID-only cards + the
// pre-read auth method).
class SocketFrontend
{
public:
    // @p plugins is the card-plugin registry, when this host has one. The
    // identity and photo flows hand a renegotiated passport MRZ to the candidate
    // plugins through a CredentialDepositor, and only the registry can resolve
    // those targets: with a registry the launcher's operations get the LM-backed
    // depositor, without one (a test rig) the shared core's no-op, so a
    // renegotiated read deposits nothing and fails auth truthfully -- the Linux
    // host's rule, applied here.
    SocketFrontend(SocketTransport& transport, Agent::AgentCore& core, std::string version,
                   std::shared_ptr<LibreSCRS::Plugin::CardPluginService> plugins = nullptr);
    ~SocketFrontend();

    SocketFrontend(const SocketFrontend&) = delete;
    SocketFrontend& operator=(const SocketFrontend&) = delete;

    // The launcher every card operation goes through, so a test can see what
    // an operation is handed (the depositor; see the constructor).
    [[nodiscard]] const Agent::Operations::OperationLauncher& operationLauncher() const noexcept
    {
        return m_launcher;
    }

    // Register with the transport as the inbound-request sink. Call once at
    // startup (after the transport is created, before the loop starts serving).
    void start();

    // Presence entry points, wired to the core ObjectRegistry observers in
    // main.cpp. Safe to call from the monitor thread — each marshals to the loop.
    void onReaderPublished(const Agent::ReaderState& reader);
    void onCardPublished(const Agent::CardState& card);
    void onWithdrawn(Agent::ObjectId object);
    void onReaderPropertiesChanged(Agent::ObjectId reader, const Agent::PropertyDelta& delta);
    void onReaderRelabelled(const Agent::ReaderState& reader);

    // ConfigStore::setOnChanged -> Config1.Changed event. Loop-safe.
    void emitConfigChanged(const std::string& key);

    // CardKeyTracker::onKeyRemoved -> broker lease revoke (paired with the cache
    // scrub in main.cpp). The cardKey is the per-insertion card ObjectId.
    void onCardRemovedForLease(Agent::ObjectId cardKey);

    // A client dropped off the socket: evict its owned op/sign-recovery state so
    // the recovery store cannot grow for the process lifetime and a reused caller
    // token cannot inherit a prior client's artifacts, and its place among the
    // connections waiting on a trust confirmation. Wired as a third
    // onClientDisconnect handler in main.cpp.
    void onClientDisconnected(const Agent::CallerToken& caller);

    // How many connections have a trust confirmation waiting. Loop-thread only.
    [[nodiscard]] std::size_t confirmsInFlightForTest() const noexcept
    {
        return m_confirmsInFlight.size();
    }

    // Ask the human to confirm a trust-tier change. Blocks for as long as the
    // person takes, so it is called on a worker queue and NEVER on the loop.
    using ConfirmFn = std::function<wire::ConfirmReply(const wire::ConfirmAction&)>;
    // Injected at the composition root with the real prompter, and by tests
    // with a fixed verdict. Call before serving requests. Left unset, trust
    // writes are refused rather than allowed.
    void setConfirmProvider(ConfirmFn fn);

private:
    // The request sink (loop thread).
    void dispatch(SocketTransport::Inbound&& in);

    // Per-request handlers (loop thread). Each replies via transport.sendTo.
    void handleHello(std::uint64_t connId, std::uint64_t req, const Agent::Wire::Hello& msg);
    void handleGetState(std::uint64_t connId, std::uint64_t req);
    // Card-independent, synchronous visible-signature layout preview —
    // no card, no Operation object (unlike every OTHER request above). Both
    // reply directly off Operations::layoutVisualSignature/
    // appearanceFontBytes (LmSeams.h), the SAME production entry point the
    // D-Bus daemon's Manager1 calls through.
    void handleLayoutVisual(std::uint64_t connId, std::uint64_t req, const Agent::Wire::LayoutVisual& msg);
    void handleGetAppearanceFont(std::uint64_t connId, std::uint64_t req);

    // Takes the whole Inbound, not (connId, req, msg): the list rides
    // SCM_RIGHTS in `in.fds` and the caller identity in `in.caller`, and both
    // are needed before a single byte is read.
    void handleImportCscaMasterList(SocketTransport::Inbound& in, const Agent::Wire::ImportCscaMasterList& msg);

    // No message members and none possible: forgetting is all-or-nothing,
    // because the rotation rule is applied against the whole anchor set.
    void handleForgetCscaAnchors(std::uint64_t connId, std::uint64_t req, const Agent::CallerToken& caller);
    void handleReadIdentity(SocketTransport::Inbound& in, const Agent::Wire::ReadIdentity& msg);
    void handleGetPhoto(SocketTransport::Inbound& in, const Agent::Wire::GetPhoto& msg);
    void handleReadCertificates(SocketTransport::Inbound& in, const Agent::Wire::ReadCertificates& msg);
    // Lightweight token-info read. Result rides the SAME Identity1-shaped
    // op-result-ready arm as ReadIdentity — no new result shape. Gates on
    // PKI (token info is PKI-adjacent, the same bit ReadCertificates uses).
    void handleReadTokenInfo(SocketTransport::Inbound& in, const Agent::Wire::ReadTokenInfo& msg);
    void handleSign(SocketTransport::Inbound& in, const Agent::Wire::Sign& msg);
    // N documents signed under ONE consent + credential prompt (see
    // Agent::Operations::BatchSignFlow). Entry gates mirror Sign's own
    // ordering exactly (capability -> cert -> authorize -> rate-limit, ONE
    // charge for the whole dispatch) plus the shared document-count gate;
    // options are resolved through the SAME resolveSignOptions helper Sign
    // uses, sniffing format off the FIRST document only. No GetSignResult-style
    // pull recovery exists for this kind (the CDDL pins recovery Sign-only).
    void handleSignBatch(SocketTransport::Inbound& in, const Agent::Wire::SignBatch& msg);
    void handleListCredentials(SocketTransport::Inbound& in, const Agent::Wire::ListCredentials& msg);
    void handleManagePin(SocketTransport::Inbound& in, const Agent::Wire::ManagePin& msg);
    void handleActivateSigningKey(SocketTransport::Inbound& in, const Agent::Wire::ActivateSigningKey& msg);
    void handleCancel(std::uint64_t connId, std::uint64_t req, const Agent::Wire::CancelOp& msg,
                      const Agent::CallerToken& caller);
    void handleGetSignResult(std::uint64_t connId, std::uint64_t req, const Agent::Wire::GetSignResult& msg,
                             const Agent::CallerToken& caller);
    void handleGetConfig(std::uint64_t connId, std::uint64_t req);
    void handleSetConfig(std::uint64_t connId, std::uint64_t req, const Agent::Wire::SetConfig& msg,
                         const Agent::CallerToken& caller);
    void handleResetConfig(std::uint64_t connId, std::uint64_t req, const Agent::Wire::ResetConfig& msg,
                           const Agent::CallerToken& caller);
    void handleCertDer(std::uint64_t connId, std::uint64_t req, const Agent::Wire::GetCertDer& msg,
                       const Agent::CallerToken& caller);
    void handlePkLogin(std::uint64_t connId, std::uint64_t req, const Agent::Wire::PkLogin& msg,
                       const Agent::CallerToken& caller);
    void handlePkLogout(std::uint64_t connId, std::uint64_t req, const Agent::Wire::PkLogout& msg,
                        const Agent::CallerToken& caller);
    void handlePkLoginState(std::uint64_t connId, std::uint64_t req, const Agent::Wire::PkLoginState& msg,
                            const Agent::CallerToken& caller);
    void handlePkPublicKey(std::uint64_t connId, std::uint64_t req, const Agent::Wire::PkPublicKey& msg,
                           const Agent::CallerToken& caller);
    void handlePkSignRaw(std::uint64_t connId, std::uint64_t req, const Agent::Wire::PkSignRaw& msg,
                         const Agent::CallerToken& caller);
    void handlePkDecrypt(std::uint64_t connId, std::uint64_t req, const Agent::Wire::PkDecrypt& msg,
                         const Agent::CallerToken& caller);
    void handlePkDerive(std::uint64_t connId, std::uint64_t req, const Agent::Wire::PkDerive& msg,
                        const Agent::CallerToken& caller);

    // Reply helpers.
    void replyError(std::uint64_t connId, std::uint64_t req, Agent::Wire::SyncError code);
    void sendReplyOnLoop(std::uint64_t connId, Agent::Wire::CborValue message);

    // The shared shape of every card operation's entry: where it runs and who
    // asked, its result channel over this connection (with the Sign recovery
    // sink when there is one), the identity reads' card-type sink, and the
    // reply -- OpStarted with the new id, or the launcher's refusal.
    [[nodiscard]] Agent::Operations::OperationTarget operationTarget(const SocketTransport::CardRouting& routing,
                                                                     const Agent::CallerToken& caller) const;
    [[nodiscard]] Agent::Operations::OperationLauncher::ChannelFactory
    channelFor(std::uint64_t connId, SocketOperationChannel::SignArtifactSink onSignArtifact = {});
    [[nodiscard]] Agent::Operations::OperationLauncher::CardTypeSink cardTypeSink(const std::string& cardHandle);
    void replyLaunched(std::uint64_t connId, std::uint64_t req, const Agent::CallerToken& caller,
                       const Agent::Operations::OperationLauncher::Launched& launched);

    // Best-effort human label for the requesting client (consent-prompt chrome):
    // detail::requesterLabelFor over the connection's peer.
    [[nodiscard]] std::string requesterLabel(const Agent::CallerToken& caller) const;

    // Presence: the deferred insertion probe on the reader's worker (loop thread).
    void scheduleCardResolve(const Agent::CardState& card);
    // Loop side of the probe: ask again after the wait m_resolution names, or
    // publish the card with what @p probe learned and take the reader's power
    // hold when the policy says so. The probe carries the core's OWN
    // vocabulary, not the wire mirror; SocketTransport::publishCard converts.
    void applyCardResolution(const Agent::CardState& card, const Agent::CardProbe& probe);

    // A Sign artifact stashed for the grace-window GetSignResult recovery.
    void stashSignArtifact(std::uint64_t opId, const Agent::CallerToken& owner,
                           const Agent::Operations::SignedArtifact& artifact);
    // Evict a stale recovery entry after its grace window (bounds the store).
    void evictSignResult(std::uint64_t opId);
    // Worker-safe prune-on-completion sink for m_opOwners (captures the long-lived
    // transport for the worker-side post; the erase continuation is drop-guarded).
    [[nodiscard]] std::function<void(std::uint64_t)> makeOpFinishedSink();

    SocketTransport& m_transport;
    Agent::AgentCore& m_core;
    std::string m_version;
    // The plugin registry this host was composed with (nullptr in a rig with no
    // plugins), and the launcher whose seams are bound over it -- see the
    // constructor. Declared in this order: the launcher's seams borrow the
    // registry.
    std::shared_ptr<LibreSCRS::Plugin::CardPluginService> m_plugins;
    Agent::Operations::OperationLauncher m_launcher;

    // reader ObjectId -> human reader name, for the card-resolve worker hop.
    std::map<std::uint64_t, std::string> m_readerNames;

    // The insertion-probe rule, with this host's budget and predicate
    // (detail::kResolveRetryBudget, detail::isRefusedSession).
    const Agent::CardResolutionPolicy m_resolution;
    // Cards awaiting their insertion probe, keyed by card ObjectId value.
    struct PendingCard
    {
        Agent::CardState card;
        Agent::ResolveAttempts attempts;
    };
    std::map<std::uint64_t, PendingCard> m_pendingCards;
    // Grace window after which an unclaimed Sign recovery entry is evicted. The
    // recovery path only covers a client that raced the inline OpResultReady fd, so
    // a short window suffices; keeping it short bounds the in-memory retention of
    // full signed documents (also evicted on client disconnect).
    static constexpr std::chrono::seconds kSignResultGrace{60};

    // Owner (requesting caller) of each in-flight op, for the Cancel/GetSignResult
    // owner-scope check. Populated at publish; pruned on op completion (the channel
    // OnFinished sink) and on client disconnect, so it does not grow unbounded.
    std::map<std::uint64_t, Agent::CallerToken> m_opOwners;

    // Sign recovery store: op id -> {artifact bytes + meta, owning caller}, kept
    // for the client's grace-window GetSignResult after the OpResultReady fd may
    // have been missed. Owner-scoped (an IDOR otherwise: op ids are enumerable) and
    // grace/disconnect-evicted (unbounded otherwise).
    struct SignRecord
    {
        Agent::Operations::SignedArtifact artifact;
        Agent::CallerToken owner;
    };
    std::map<std::uint64_t, SignRecord> m_signResults;

    // The human confirmation for trust-tier writes, and the queue it blocks on.
    // Concurrent, mirroring the prompter server's own worker: the loop queue
    // serves every connection's reads and must never wait on a person.
    ConfirmFn m_confirm;
    dispatch_queue_t m_confirmQueue{nullptr};

    // The block that waits for the person outlives whatever asked it: the
    // person answers in their own time and the frontend may be gone by then.
    // The guard is what the block and the continuation consult before touching
    // the frontend or its transport; the destructor marks it dead and does not
    // wait.
    struct ConfirmGuard
    {
        std::mutex mutex;
        bool alive{true};
    };
    std::shared_ptr<ConfirmGuard> m_confirmGuard{std::make_shared<ConfirmGuard>()};

    // Connections with a trust confirmation waiting for a person. One each:
    // every confirmation holds a worker here and in the prompter until it is
    // answered, and a dialog per request is how a flood turns into a click
    // that makes it stop. Keyed by the connection's caller token, so the entry
    // leaves with the connection as well as with the answer. Loop-thread only.
    std::set<Agent::CallerToken> m_confirmsInFlight;

    // What a trust-tier verb is about to do, for the sentence the person reads.
    // The config key alone cannot say it: import and forget share a key.
    enum class TrustChange { SetValue, Reset, ImportAnchors, ForgetAnchors };

    // The trust-tier detour: ask on a worker, come back to the loop, then run
    // `apply`. All four trust-tier verbs share it so none can drift out of the
    // gate.
    void confirmThenApply(std::uint64_t connId, std::uint64_t req, const std::string& key,
                          const Agent::CallerToken& caller, TrustChange what, std::function<void()> apply);
    // The sentence the person reads, and the catalogue id that names it. Two
    // fields rather than one, because the agent owns no catalogue: it writes
    // the English it always wrote and hands the prompter the name to look up
    // instead, so a prompter that cannot resolve the name still shows the
    // sentence rather than nothing.
    struct TrustChangeCopy
    {
        std::string_view key;
        std::string_view text;
    };
    static TrustChangeCopy describeTrustChange(const std::string& key, TrustChange what);
    // The per-key write cascades, shared by the immediate and the confirmed
    // path so both run identical code.
    void applyConfigWrite(std::uint64_t connId, std::uint64_t req, const Agent::Wire::SetConfig& msg);
    void applyConfigReset(std::uint64_t connId, std::uint64_t req, const Agent::Wire::ResetConfig& msg);
};

namespace detail {

/// The remembered record for what an import accepted.
///
/// Free and declared, rather than folded into the import handler where it began,
/// because it is the whole of a decision that cannot be reached from outside: an
/// import takes in a COLLECTION of separately signed lists, while this record and
/// the property built from it speak a single-publisher vocabulary. Which fields
/// that leaves unfillable is pure logic over a public type, so it can be measured
/// directly — the alternative was a signed multi-list fixture, which lives in the
/// producer's test tree and would have left this untested on this side.
///
/// Two fields are ABSENT rather than picked when several publishers were
/// accepted, and `signerPinned` is the aggregate: true only when every publisher
/// was established.
[[nodiscard]] Agent::Config::CscaAnchorState recordedStateFor(const Agent::Trust::AnchorState& imported);

/// What the consent dialogs name as the requester: the signing identifier the
/// peer's own signature claims (claimed, never verified -- the same standing as
/// the program name the Linux host shows), and nothing else. The agent has no
/// catalogue, so any word around it -- the token extension's, which acts for
/// the Keychain -- is the prompter's to add. @p fallback (the process label)
/// when the peer carries no identifier. Always sanitised to one inert line.
[[nodiscard]] std::string requesterLabelFor(const std::optional<std::string>& signingId, std::string fallback);

/// How long a card whose insertion probe was refused a session is asked about
/// again: waits doubling from 50 ms up to 1 s, until together they reach 10 s,
/// the time the middleware gives CryptoTokenKit to grant a session it is
/// holding for someone else. That is what the probe usually lost to: the
/// system or another vendor's token driver probing the same card, which on
/// macOS may be refused outright rather than waited for.
inline constexpr Agent::ResolveRetryBudget kResolveRetryBudget{
    .maxRetries = std::numeric_limits<int>::max(),
    .firstDelay = std::chrono::milliseconds{50},
    .growth = 2,
    .maxDelay = std::chrono::milliseconds{1000},
    .totalBudget = std::chrono::milliseconds{10000},
};

/// The one failed open worth asking about again: a session refused while
/// someone else holds the card. Any other failure (no card, a protocol fault,
/// an unavailable reader) will not pass by waiting, so the card is published
/// at once with nothing known about it.
[[nodiscard]] bool isRefusedSession(const LibreSCRS::SmartCard::OpenError& failure) noexcept;

} // namespace detail

} // namespace LibreSCRS::Darwin
