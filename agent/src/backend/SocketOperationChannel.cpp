// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SKELETON — stub (TODO P1b: implement-macos-backend).
#include <LibreSCRS/Darwin/backend/SocketOperationChannel.h>

namespace LibreSCRS::Darwin {

SocketOperationChannel::SocketOperationChannel() = default;
SocketOperationChannel::~SocketOperationChannel() = default;

void SocketOperationChannel::emitPropertiesChanged() noexcept
{
    // TODO(P1b): CBOR-encode OpProgress{opId, phase}; push to the op's client.
}

void SocketOperationChannel::emitFinished(Agent::Operations::OperationStatus /*status*/, Agent::ErrorCode /*code*/,
                                          std::string_view /*msgKey*/, std::string_view /*msgFallback*/) noexcept
{
    // TODO(P1b): CBOR-encode OpFinished{opId, status, errorCode, msgKey, msgFallback}.
}

bool SocketOperationChannel::emitResult(const Agent::Operations::ResultPayload& /*result*/) noexcept
{
    // TODO(P1b): CBOR-encode the typed result; large artifacts (SignedArtifact,
    // PhotoResult) ride SCM_RIGHTS fds. macOS delivers inline -> no seal step can
    // fail, so this returns true (see the OperationChannel contract note).
    return true;
}

} // namespace LibreSCRS::Darwin
