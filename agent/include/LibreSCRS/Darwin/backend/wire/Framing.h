// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace LibreSCRS::Darwin::wire {

// macOS socket framing (design §4.1). A frame is a `uint32` little-endian length
// prefix + a CBOR (RFC 8949) body; a CDDL schema (RFC 8610) + a WireContractGuard
// test pin the message shapes. File descriptors (signed artifact / photo) ride
// SCM_RIGHTS ancillary data and are referenced from the CBOR body by an `fd`
// index — mirroring D-Bus `h`/UNIX_FDS. The socket is SOCK_CLOEXEC; set
// FD_CLOEXEC on each received fd via fcntl(fd, F_SETFD, FD_CLOEXEC) after
// recvmsg (MSG_CMSG_CLOEXEC is Linux-only, absent on Darwin); a max-frame cap
// fails malformed input closed (the browser-loaded facade is untrusted).
//
// This header fixes the ONE protocol constant set + the frame API shape; the
// CBOR codec + the message-type table land with the CDDL schema in
// formalize-wire-contract-schema, and the transport that drives it in P1b.

inline constexpr std::uint32_t kProtocolVersion = 1;

// Frames larger than this are rejected before allocation. Artifacts ride fds, so
// message bodies stay small.
inline constexpr std::size_t kMaxFrameBytes = 1u << 20; // 1 MiB

// A decoded inbound frame: the CBOR body plus any fds received out-of-band in the
// same SCM_RIGHTS message, in wire order (the body references them by index).
struct Frame
{
    std::vector<std::uint8_t> body;
    std::vector<int> fds; // owned; RAII-closed by the transport on drop
};

// TODO(P1b) formalize-wire-contract-schema + implement-macos-backend:
//   - std::vector<std::uint8_t> encodeFrame(std::span<const std::uint8_t> body);
//   - std::expected<Frame, DecodeError> decodeFrame(...);  // bounded, fail-closed
//   - sendmsg/recvmsg helpers carrying SCM_RIGHTS; SOCK_CLOEXEC on the socket,
//     and FD_CLOEXEC set via fcntl on each received fd (no MSG_CMSG_CLOEXEC on Darwin).

} // namespace LibreSCRS::Darwin::wire
