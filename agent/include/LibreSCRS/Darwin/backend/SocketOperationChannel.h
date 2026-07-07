// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/OperationChannel.h> // Operations::OperationChannel

#include <string_view>

namespace LibreSCRS::Darwin {

// macOS OperationChannel backend: the per-operation emit-only channel the
// lifecycle core drives, bound to one client's operation over the socket. The
// Linux twin seals large results (photo / signed doc) into a memfd; macOS
// delivers results INLINE over the socket (bounded payloads) or by SCM_RIGHTS fd
// for large artifacts — so emitResult never fails a "seal step" and returns true
// (see the OperationChannel contract note).
//
// TODO(P1b) implement-macos-backend: CBOR-encode OpProgress (emitPropertiesChanged),
// OpFinished (status/errorCode/msgKey/msgFallback), and the typed ResultPayload
// arms; carry the recovery payload for GetOpResult within the grace window.
class SocketOperationChannel final : public Agent::Operations::OperationChannel
{
public:
    SocketOperationChannel();
    ~SocketOperationChannel() override;

    void emitPropertiesChanged() noexcept override;
    void emitFinished(Agent::Operations::OperationStatus status, Agent::ErrorCode code, std::string_view msgKey,
                      std::string_view msgFallback) noexcept override;
    [[nodiscard]] bool emitResult(const Agent::Operations::ResultPayload& result) noexcept override;
};

} // namespace LibreSCRS::Darwin
