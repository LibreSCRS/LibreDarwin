// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Per-op emit channel over the socket. Progress/Finished/typed-result CBOR
// events, marshaled from the worker thread to the loop. Photo/Sign artifacts
// become anonymous mkstemp+unlink fds passed via SCM_RIGHTS (no memfd_create on
// Darwin); a materialization failure fails the result closed.
#include <LibreSCRS/Darwin/backend/SocketOperationChannel.h>

#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Darwin/backend/wire/AnonFd.h>
#include <LibreSCRS/Agent/wire/Messages.h>
#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <LibreSCRS/Agent/backend/Logging.h>

#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/CertSnapshot.h>

#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace LibreSCRS::Darwin {

namespace log = Agent::log;

namespace {

namespace A = LibreSCRS::Agent;
namespace Ops = LibreSCRS::Agent::Operations;

std::string_view fieldTypeName(A::FieldType t)
{
    switch (t) {
    case A::FieldType::Text:
        return "text";
    case A::FieldType::Date:
        return "date";
    case A::FieldType::Binary:
        return "binary";
    case A::FieldType::Photo:
        return "binary"; // stripped from Identity; never emitted here
    }
    return "text";
}

// CardReadSnapshot -> wire IdentityResult (photos stripped; they ride GetPhoto).
A::Wire::IdentityResult toIdentityResult(const A::CardReadSnapshot& snap)
{
    A::Wire::IdentityResult out;
    for (const auto& group : snap.groups) {
        std::map<std::string, A::Wire::IdentityField> fields;
        for (const auto& f : group.fields) {
            if (f.type == A::FieldType::Photo) {
                continue; // Identity1 omits photos
            }
            A::Wire::IdentityField cell;
            cell.labelKey = f.labelKey;
            cell.labelFallback = f.labelFallback;
            cell.type = std::string(fieldTypeName(f.type));
            if (f.type == A::FieldType::Binary) {
                cell.value = f.binaryValue;
            } else {
                cell.value = f.textValue;
            }
            fields.emplace(f.fieldKey, std::move(cell));
        }
        if (!fields.empty()) {
            out.fields.emplace(group.groupKey, std::move(fields));
        }
    }
    return out;
}

// CertSnapshot -> wire CertInfo (grouped (ssv) fields, all string values).
A::Wire::CertInfo toCertInfo(const A::CertSnapshot& c)
{
    A::Wire::CertInfo out;
    out.certId = c.certId;
    out.signingCapable = c.signingCapable;
    out.keyUsageBits = c.keyUsageBits;
    out.ekus = c.ekuOids;
    out.chainSubjectCns = c.chainSubjectCns;
    out.trustStatus = c.trustStatus;
    for (const auto& group : c.fields) {
        std::map<std::string, A::Wire::CertField> fields;
        for (const auto& f : group.fields) {
            A::Wire::CertField cell;
            cell.labelKey = f.labelKey;
            cell.labelFallback = f.labelFallback;
            cell.value = f.textValue; // cert fields are all Text
            fields.emplace(f.fieldKey, std::move(cell));
        }
        out.fields.emplace(group.groupKey, std::move(fields));
    }
    return out;
}

// A::CredentialRecord -> the wire mirror: a plain field-for-field copy. Both
// sides are std-only value types with identical field names/types by
// construction (LibreAgent's WireParityChecks statically asserts it), so
// there is no LM-facing conversion here — just the wire-shape hop.
A::Wire::CredentialRecord toWireCredentialRecord(const A::CredentialRecord& r)
{
    A::Wire::CredentialRecord out;
    out.id = r.id;
    out.label = r.label;
    out.kind = r.kind;
    out.state = r.state;
    out.retriesLeft = r.retriesLeft;
    out.retriesMax = r.retriesMax;
    out.usesLeft = r.usesLeft;
    out.usesMax = r.usesMax;
    out.unblocksLeft = r.unblocksLeft;
    out.minLength = r.minLength;
    out.maxLength = r.maxLength;
    out.canChange = r.canChange;
    out.unblockable = r.unblockable;
    out.unblockStyle = r.unblockStyle;
    out.activatable = r.activatable;
    out.keyActivationPending = r.keyActivationPending;
    out.keyActivatable = r.keyActivatable;
    out.recovery = r.recovery;
    out.probeSafe = r.probeSafe;
    out.blockedGuidanceKey = r.blockedGuidanceKey;
    out.blockedGuidanceFallback = r.blockedGuidanceFallback;
    out.keyActivationGuidanceKey = r.keyActivationGuidanceKey;
    out.keyActivationGuidanceFallback = r.keyActivationGuidanceFallback;
    return out;
}

// A::CredentialOpResult -> the wire mirror. `outcome` crosses via static_cast:
// same enumerator values as A::CredentialOutcome (WireParityChecks pins them
// in lockstep), but no longer the same TYPE now that Wire::CredentialOutcome
// is its own std-only mirror.
A::Wire::CredentialOpResult toWireCredentialOpResult(const A::CredentialOpResult& r)
{
    A::Wire::CredentialOpResult out;
    out.outcome = static_cast<A::Wire::CredentialOutcome>(r.outcome);
    out.retriesLeft = r.retriesLeft;
    out.blocked = r.blocked;
    out.pinActivated = r.pinActivated;
    out.keyActivated = r.keyActivated;
    return out;
}

// Ops::CredentialResult -> wire CredentialsResult (op + the listing records, if
// any — a mutation's records are always empty).
A::Wire::CredentialsResult toWireCredentialsResult(const Ops::CredentialResult& r)
{
    A::Wire::CredentialsResult out;
    out.result = toWireCredentialOpResult(r.op);
    out.records.reserve(r.records.size());
    for (const auto& record : r.records) {
        out.records.push_back(toWireCredentialRecord(record));
    }
    return out;
}

// Exhaustiveness guard for the ResultPayload visit below: instantiated only
// inside a discarded if-constexpr branch, so it fires ONLY if a future
// ResultPayload arm reaches the final else without an explicit arm above it
// (compile-break honesty in place of an else-arm assumption).
template <class>
inline constexpr bool always_false_v = false;

} // namespace

SocketOperationChannel::SocketOperationChannel(SocketTransport& transport, std::uint64_t connId, std::uint64_t opId,
                                               std::shared_ptr<Ops::OperationState> state,
                                               SignArtifactSink onSignArtifact, OnFinished onFinished)
    : m_transport(transport), m_connId(connId), m_opId(opId), m_state(std::move(state)),
      m_onSignArtifact(std::move(onSignArtifact)), m_onFinished(std::move(onFinished))
{}

SocketOperationChannel::~SocketOperationChannel() = default;

void SocketOperationChannel::emitPropertiesChanged() noexcept
{
    // The encode + the posted std::function allocate inside a noexcept frame;
    // an allocation failure degrades to a dropped progress event, never
    // std::terminate.
    try {
        A::Wire::OpProgress ev;
        ev.op = m_opId;
        ev.phase = static_cast<Ops::OperationPhase>(m_state ? m_state->phase.load() : 0u);
        if (m_state) {
            ev.progress = m_state->progress.load();
            ev.indeterminate = m_state->isIndeterminate.load();
            ev.watchdogSecs = m_state->watchdogTimeoutSec.load();
        }
        const A::Wire::CborValue msg = A::Wire::toCbor(ev);
        const std::uint64_t connId = m_connId;
        SocketTransport* t = &m_transport;
        t->post([t, connId, msg] { t->sendTo(connId, msg); });
    } catch (...) {
        log::warn("op-channel: dropped OpProgress emit (encode/post failure)");
    }
}

void SocketOperationChannel::emitFinished(Ops::OperationStatus status, A::ErrorCode code, std::string_view msgKey,
                                          std::string_view msgFallback) noexcept
{
    try {
        A::Wire::OpFinished ev;
        ev.op = m_opId;
        ev.status = status;
        ev.code = code;
        ev.msgKey = std::string(msgKey);
        ev.msgFallback = std::string(msgFallback);
        const A::Wire::CborValue msg = A::Wire::toCbor(ev);
        const std::uint64_t connId = m_connId;
        SocketTransport* t = &m_transport;
        t->post([t, connId, msg] { t->sendTo(connId, msg); });
    } catch (...) {
        log::warn("op-channel: dropped OpFinished emit (encode/post failure)");
    }
    // Terminal: let the frontend prune its per-op ownership entry (the sink itself
    // is worker-safe — it captures only the transport + posts a drop-guarded loop
    // continuation). The prune runs even when the emit above was dropped, and is
    // guarded on its own so a posting failure cannot escape the noexcept frame.
    try {
        if (m_onFinished) {
            m_onFinished(m_opId);
        }
    } catch (...) {
        log::warn("op-channel: op-owner prune failed; entry lives until connection close");
    }
}

bool SocketOperationChannel::emitResult(const Ops::ResultPayload& result) noexcept
try {
    A::Wire::OpResultReady ev;
    ev.op = m_opId;
    std::vector<A::Wire::UniqueFd> fds;

    bool ok = true;
    std::visit(
        [&](const auto& arm) {
            using T = std::decay_t<decltype(arm)>;
            if constexpr (std::is_same_v<T, A::CardReadSnapshot>) {
                ev.result = toIdentityResult(arm);
            } else if constexpr (std::is_same_v<T, std::vector<A::CertSnapshot>>) {
                A::Wire::CertListResult clr;
                for (const auto& c : arm) {
                    clr.certs.push_back(toCertInfo(c));
                }
                ev.result = std::move(clr);
            } else if constexpr (std::is_same_v<T, Ops::PhotoResult>) {
                A::Wire::PhotoResult pr;
                for (const auto& photo : arm) {
                    auto fd = wire::anonFdFromBytes(photo.bytes);
                    if (!fd) {
                        ok = false;
                        return;
                    }
                    pr.photos.push_back(A::Wire::PhotoItem{photo.key, static_cast<std::uint64_t>(fds.size())});
                    fds.push_back(std::move(*fd));
                }
                ev.result = std::move(pr);
            } else if constexpr (std::is_same_v<T, Ops::SignedArtifact>) {
                auto fd = wire::anonFdFromBytes(arm.bytes);
                if (!fd) {
                    ok = false;
                    return;
                }
                A::Wire::SignResult sr;
                sr.artifact = static_cast<std::uint64_t>(fds.size());
                sr.meta = A::Wire::SignMeta{arm.meta.format, arm.meta.level, arm.meta.tsaUsed, arm.meta.chainComplete};
                fds.push_back(std::move(*fd));
                ev.result = std::move(sr);
                if (m_onSignArtifact) {
                    m_onSignArtifact(m_opId, arm); // stash for GetSignResult recovery
                }
            } else if constexpr (std::is_same_v<T, Ops::CredentialResult>) {
                // Field-for-field hop onto the wire mirror types (LibreAgent's
                // WireParityChecks pins them in lockstep with the agent value
                // types below): the codec, not this channel, maps them to
                // their wire tokens/keys. Delivered inline, exactly like
                // Identity/Certificates — no fd, no seal step.
                ev.result = toWireCredentialsResult(arm);
            } else {
                static_assert(always_false_v<T>, "SocketOperationChannel::emitResult: unhandled ResultPayload arm");
            }
        },
        result);

    if (!ok) {
        return false; // REQUIRED fd materialization failed
    }

    const A::Wire::CborValue msg = A::Wire::toCbor(ev);
    const std::uint64_t connId = m_connId;
    SocketTransport* t = &m_transport;
    // Move the fds into the posted send; sendTo dups them into the peer.
    auto shared = std::make_shared<std::vector<A::Wire::UniqueFd>>(std::move(fds));
    t->post([t, connId, msg, shared] { t->sendTo(connId, msg, std::move(*shared)); });
    return true;
} catch (...) {
    // Marshalling/encode/post allocation failed inside a noexcept frame: the
    // result cannot be delivered, so fail the op closed (same contract arm as a
    // failed REQUIRED fd materialization) rather than terminate or emit a
    // half-result. UniqueFd destructors close any already-materialized fds.
    log::warn("op-channel: dropped OpResultReady emit (encode/post failure); failing op closed");
    return false;
}

} // namespace LibreSCRS::Darwin
