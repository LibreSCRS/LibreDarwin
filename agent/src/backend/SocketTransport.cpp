// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SKELETON — bodies are stubs (TODO P1b: implement-macos-backend). Signatures
// track LibreAgent::AgentTransport; behaviour lands with the socket transport.
#include <LibreSCRS/Darwin/backend/SocketTransport.h>

namespace LibreSCRS::Darwin {

SocketTransport::SocketTransport() = default;
SocketTransport::~SocketTransport() = default;

void SocketTransport::publishReader(const Agent::ReaderState&)
{
    // TODO(P1b): CBOR-encode a ReaderAdded/PropertyChanged event; push to subscribers.
}

void SocketTransport::publishCard(const Agent::CardState&)
{
    // TODO(P1b): CBOR-encode a CardAdded event; push to subscribers.
}

void SocketTransport::withdraw(Agent::ObjectId)
{
    // TODO(P1b): CBOR-encode a Reader/CardRemoved event.
}

void SocketTransport::updateProperties(Agent::ObjectId, const Agent::PropertyDelta&)
{
    // TODO(P1b): CBOR-encode a PropertyChanged{handle, iface, props} event.
}

void SocketTransport::post(std::function<void()>)
{
    // TODO(P1b): dispatch_async onto the transport's serial queue.
}

void SocketTransport::postAfter(std::chrono::microseconds, std::function<void()>)
{
    // TODO(P1b): dispatch_after on the transport's serial queue.
}

void SocketTransport::onClientDisconnect(std::function<void(Agent::CallerToken)>)
{
    // TODO(P1b): append the handler; fire on connection invalidation in
    // registration order (OperationManager auto-cancel, then Pkcs11Broker lease revoke).
}

} // namespace LibreSCRS::Darwin
