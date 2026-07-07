// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SKELETON — CBOR framing helpers land with formalize-wire-contract-schema (the
// CDDL + WireContractGuard) and the transport in P1b.
#include <LibreSCRS/Darwin/backend/wire/Framing.h>

namespace LibreSCRS::Darwin::wire {

// TODO(P1b): encodeFrame / decodeFrame (bounded by kMaxFrameBytes, fail-closed),
// and the sendmsg/recvmsg SCM_RIGHTS helpers (SOCK_CLOEXEC socket; FD_CLOEXEC set
// via fcntl on each received fd — no MSG_CMSG_CLOEXEC on Darwin).

} // namespace LibreSCRS::Darwin::wire
