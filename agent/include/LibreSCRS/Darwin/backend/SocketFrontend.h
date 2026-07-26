// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Agent/wire/Messages.h>
#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <LibreSCRS/Agent/Identity.h>
#include <LibreSCRS/Agent/PresenceTypes.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h> // Operations::SignedArtifact
#include <LibreSCRS/Auth/AuthRequirement.h>           // LibreSCRS::Auth::PreReadAuthMethod (applyCardResolution)

#include <cstdint>
#include <chrono>
#include <functional>
#include <map>
#include <string>

namespace LibreSCRS::Agent {
class AgentCore;
}

namespace LibreSCRS::Darwin {

// The inbound dispatch glue — the macOS twin of LibreLinux's AgentFrontend +
// Card1/Manager1/Config1/Pkcs11_1 objects, collapsed into one loop-thread
// dispatcher (there are no persistent per-card wire objects on macOS; the
// transport's presence snapshot replaces them). Registered as the transport's
// request sink; every request is dispatched ON THE LOOP THREAD to the neutral
// LibreAgent::Core:
//   - ReadIdentity/GetPhoto/ReadCertificates/Sign -> mint a SocketOperationChannel
//     + OperationManager::publish, reply OpStarted;
//   - ListCredentials/ManagePin/ActivateSigningKey -> the same publish path
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
    SocketFrontend(SocketTransport& transport, Agent::AgentCore& core, std::string version);

    SocketFrontend(const SocketFrontend&) = delete;
    SocketFrontend& operator=(const SocketFrontend&) = delete;

    // Register with the transport as the inbound-request sink. Call once at
    // startup (after the transport is created, before the loop starts serving).
    void start();

    // Presence entry points, wired to the core ObjectRegistry observers in
    // main.cpp. Safe to call from the monitor thread — each marshals to the loop.
    void onReaderPublished(const Agent::ReaderState& reader);
    void onCardPublished(const Agent::CardState& card);
    void onWithdrawn(Agent::ObjectId object);
    void onReaderPropertiesChanged(Agent::ObjectId reader, const Agent::PropertyDelta& delta);

    // ConfigStore::setOnChanged -> Config1.Changed event. Loop-safe.
    void emitConfigChanged(const std::string& key);

    // CardKeyTracker::onKeyRemoved -> broker lease revoke (paired with the cache
    // scrub in main.cpp). The cardKey is the per-insertion card ObjectId.
    void onCardRemovedForLease(Agent::ObjectId cardKey);

    // A client dropped off the socket: evict its owned op/sign-recovery state so
    // the recovery store cannot grow for the process lifetime and a reused caller
    // token cannot inherit a prior client's artifacts. Wired as a third
    // onClientDisconnect handler in main.cpp.
    void onClientDisconnected(const Agent::CallerToken& caller);

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
    void handlePkPublicKey(std::uint64_t connId, std::uint64_t req, const Agent::Wire::PkPublicKey& msg,
                           const Agent::CallerToken& caller);
    void handlePkSignRaw(std::uint64_t connId, std::uint64_t req, const Agent::Wire::PkSignRaw& msg,
                         const Agent::CallerToken& caller);
    void handlePkDecrypt(std::uint64_t connId, std::uint64_t req, const Agent::Wire::PkDecrypt& msg,
                         const Agent::CallerToken& caller);

    // Reply helpers.
    void replyError(std::uint64_t connId, std::uint64_t req, Agent::Wire::SyncError code);
    void sendReplyOnLoop(std::uint64_t connId, Agent::Wire::CborValue message);

    // Best-effort human label for the requesting client (consent-prompt chrome).
    [[nodiscard]] std::string requesterLabel(const Agent::CallerToken& caller) const;

    // Presence: the deferred held-session capability resolve (loop thread).
    void scheduleCardResolve(const Agent::CardState& card);
    // The core's OWN vocabulary, not the wire mirror: this feeds
    // A::CardState::preReadAuth (never crosses the CBOR wire from here —
    // SocketTransport::publishCard does that conversion). @p cardType is the
    // single held-session candidate's pluginId (empty if ambiguous/no match),
    // resolved alongside caps/preAuth at the same deferred point.
    void applyCardResolution(Agent::CardState card, std::uint32_t caps, LibreSCRS::Auth::PreReadAuthMethod preAuth,
                             const std::string& cardType);

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

    // reader ObjectId -> human reader name, for the card-resolve worker hop.
    std::map<std::uint64_t, std::string> m_readerNames;

    // Cards awaiting their held-session resolve, keyed by card ObjectId value.
    struct PendingCard
    {
        Agent::CardState card;
        int attempts{0};
    };
    std::map<std::uint64_t, PendingCard> m_pendingCards;
    static constexpr int kMaxResolveAttempts{3};
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
};

} // namespace LibreSCRS::Darwin
