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
#include <LibreSCRS/Darwin/backend/wire/Messages.h>
#include <LibreSCRS/Darwin/backend/wire/UniqueFd.h>

#include <LibreSCRS/Agent/value/CardReadSnapshot.h>
#include <LibreSCRS/Agent/value/CertSnapshot.h>

#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace LibreSCRS::Darwin {
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
wire::IdentityResult toIdentityResult(const A::CardReadSnapshot& snap)
{
    wire::IdentityResult out;
    for (const auto& group : snap.groups) {
        std::map<std::string, wire::IdentityField> fields;
        for (const auto& f : group.fields) {
            if (f.type == A::FieldType::Photo) {
                continue; // Identity1 omits photos
            }
            wire::IdentityField cell;
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
wire::CertInfo toCertInfo(const A::CertSnapshot& c)
{
    wire::CertInfo out;
    out.certId = c.certId;
    out.signingCapable = c.signingCapable;
    out.keyUsageBits = c.keyUsageBits;
    out.ekus = c.ekuOids;
    out.chainSubjectCns = c.chainSubjectCns;
    out.trustStatus = c.trustStatus;
    for (const auto& group : c.fields) {
        std::map<std::string, wire::CertField> fields;
        for (const auto& f : group.fields) {
            wire::CertField cell;
            cell.labelKey = f.labelKey;
            cell.labelFallback = f.labelFallback;
            cell.value = f.textValue; // cert fields are all Text
            fields.emplace(f.fieldKey, std::move(cell));
        }
        out.fields.emplace(group.groupKey, std::move(fields));
    }
    return out;
}

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
    wire::OpProgress ev;
    ev.op = m_opId;
    ev.phase = static_cast<Ops::OperationPhase>(m_state ? m_state->phase.load() : 0u);
    if (m_state) {
        ev.progress = m_state->progress.load();
        ev.indeterminate = m_state->isIndeterminate.load();
        ev.watchdogSecs = m_state->watchdogTimeoutSec.load();
    }
    const wire::CborValue msg = wire::toCbor(ev);
    const std::uint64_t connId = m_connId;
    SocketTransport* t = &m_transport;
    t->post([t, connId, msg] { t->sendTo(connId, msg); });
}

void SocketOperationChannel::emitFinished(Ops::OperationStatus status, A::ErrorCode code, std::string_view msgKey,
                                          std::string_view msgFallback) noexcept
{
    wire::OpFinished ev;
    ev.op = m_opId;
    ev.status = status;
    ev.code = code;
    ev.msgKey = std::string(msgKey);
    ev.msgFallback = std::string(msgFallback);
    const wire::CborValue msg = wire::toCbor(ev);
    const std::uint64_t connId = m_connId;
    SocketTransport* t = &m_transport;
    t->post([t, connId, msg] { t->sendTo(connId, msg); });
    // Terminal: let the frontend prune its per-op ownership entry (the sink itself
    // is worker-safe — it captures only the transport + posts a drop-guarded loop
    // continuation).
    if (m_onFinished) {
        m_onFinished(m_opId);
    }
}

bool SocketOperationChannel::emitResult(const Ops::ResultPayload& result) noexcept
{
    wire::OpResultReady ev;
    ev.op = m_opId;
    std::vector<wire::UniqueFd> fds;

    bool ok = true;
    std::visit(
        [&](const auto& arm) {
            using T = std::decay_t<decltype(arm)>;
            if constexpr (std::is_same_v<T, A::CardReadSnapshot>) {
                ev.result = toIdentityResult(arm);
            } else if constexpr (std::is_same_v<T, std::vector<A::CertSnapshot>>) {
                wire::CertListResult clr;
                for (const auto& c : arm) {
                    clr.certs.push_back(toCertInfo(c));
                }
                ev.result = std::move(clr);
            } else if constexpr (std::is_same_v<T, Ops::PhotoResult>) {
                wire::PhotoResult pr;
                for (const auto& photo : arm) {
                    auto fd = wire::anonFdFromBytes(photo.bytes);
                    if (!fd) {
                        ok = false;
                        return;
                    }
                    pr.photos.push_back(wire::PhotoItem{photo.key, static_cast<std::uint64_t>(fds.size())});
                    fds.push_back(std::move(*fd));
                }
                ev.result = std::move(pr);
            } else { // SignedArtifact
                auto fd = wire::anonFdFromBytes(arm.bytes);
                if (!fd) {
                    ok = false;
                    return;
                }
                wire::SignResult sr;
                sr.artifact = static_cast<std::uint64_t>(fds.size());
                sr.meta = wire::SignMeta{arm.meta.format, arm.meta.level, arm.meta.tsaUsed, arm.meta.chainComplete};
                fds.push_back(std::move(*fd));
                ev.result = std::move(sr);
                if (m_onSignArtifact) {
                    m_onSignArtifact(m_opId, arm); // stash for GetSignResult recovery
                }
            }
        },
        result);

    if (!ok) {
        return false; // REQUIRED fd materialization failed
    }

    const wire::CborValue msg = wire::toCbor(ev);
    const std::uint64_t connId = m_connId;
    SocketTransport* t = &m_transport;
    // Move the fds into the posted send; sendTo dups them into the peer.
    auto shared = std::make_shared<std::vector<wire::UniqueFd>>(std::move(fds));
    t->post([t, connId, msg, shared] { t->sendTo(connId, msg, std::move(*shared)); });
    return true;
}

} // namespace LibreSCRS::Darwin
