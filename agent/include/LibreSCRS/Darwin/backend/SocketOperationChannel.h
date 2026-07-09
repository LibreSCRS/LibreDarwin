// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/OperationState.h>           // OperationState
#include <LibreSCRS/Agent/backend/OperationChannel.h> // Operations::OperationChannel, ResultPayload

#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>

namespace LibreSCRS::Darwin {

class SocketTransport;

// macOS OperationChannel backend: the per-operation emit-only channel the
// lifecycle core drives, bound to one client's operation over the socket. The
// Linux twin is a D-Bus Operation1 adaptor that seals large results into a
// memfd; macOS delivers Identity/Certificates INLINE and Photo/Sign artifacts as
// SCM_RIGHTS fds materialized from an ANONYMOUS shm_open object (Darwin has no
// memfd_create). emitResult returns false only when that REQUIRED fd
// materialization fails (the core then finishes Error/CommunicationError).
//
// The core drives emit* from the per-reader WORKER thread; the transport's
// sendTo is loop-affine, so every emit marshals to the loop via transport.post
// (the connection may be gone by then — sendTo no-ops safely).
class SocketOperationChannel final : public Agent::Operations::OperationChannel
{
public:
    // Notified (on the worker thread) with a Sign artifact's bytes + meta so the
    // frontend can stash it for the grace-window GetSignResult recovery. Empty
    // for the non-Sign ops.
    using SignArtifactSink = std::function<void(std::uint64_t opId, const Agent::Operations::SignedArtifact&)>;

    // Notified (on the worker thread) when the op reaches its terminal Finished,
    // so the frontend can prune its per-op ownership entry (mirrors the core's
    // forgetOpById prune-on-completion). Empty when the frontend does not track it.
    using OnFinished = std::function<void(std::uint64_t opId)>;

    SocketOperationChannel(SocketTransport& transport, std::uint64_t connId, std::uint64_t opId,
                           std::shared_ptr<Agent::Operations::OperationState> state,
                           SignArtifactSink onSignArtifact = {}, OnFinished onFinished = {});
    ~SocketOperationChannel() override;

    void emitPropertiesChanged() noexcept override;
    void emitFinished(Agent::Operations::OperationStatus status, Agent::ErrorCode code, std::string_view msgKey,
                      std::string_view msgFallback) noexcept override;
    [[nodiscard]] bool emitResult(const Agent::Operations::ResultPayload& result) noexcept override;

private:
    SocketTransport& m_transport;
    std::uint64_t m_connId;
    std::uint64_t m_opId;
    std::shared_ptr<Agent::Operations::OperationState> m_state;
    SignArtifactSink m_onSignArtifact;
    OnFinished m_onFinished;
};

} // namespace LibreSCRS::Darwin
