// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/AgentTransport.h>

#include <chrono>
#include <functional>

namespace LibreSCRS::Darwin {

// macOS AgentTransport backend: the client membrane + its dispatch thread over
// the App-Group `0600` AF_UNIX socket. It owns the CBOR framing, the SCM_RIGHTS
// fd-passing, and the ObjectId<->socket-handle mapping; the neutral core never
// touches wire paths. The Linux twin is LibreLinux's D-Bus ObjectManager +
// sd-event backend; here it is a GCD dispatch source over the listening socket
// (launchd socket-activated).
//
// TODO(P1b) implement-macos-backend: socket listen/accept, per-connection peer
// audit_token capture, CBOR encode of publish/withdraw/property deltas, the
// worker->loop post via dispatch_async, and the connection-invalidation ->
// onClientDisconnect fan-out (registration order is the contract:
// OperationManager auto-cancel, then Pkcs11Broker lease revoke).
class SocketTransport final : public Agent::AgentTransport
{
public:
    SocketTransport();
    ~SocketTransport() override;

    SocketTransport(const SocketTransport&) = delete;
    SocketTransport& operator=(const SocketTransport&) = delete;

    void publishReader(const Agent::ReaderState& reader) override;
    void publishCard(const Agent::CardState& card) override;
    void withdraw(Agent::ObjectId object) override;
    void updateProperties(Agent::ObjectId reader, const Agent::PropertyDelta& delta) override;

    void post(std::function<void()> fn) override;
    void postAfter(std::chrono::microseconds delay, std::function<void()> fn) override;

    void onClientDisconnect(std::function<void(Agent::CallerToken)> handler) override;
};

} // namespace LibreSCRS::Darwin
