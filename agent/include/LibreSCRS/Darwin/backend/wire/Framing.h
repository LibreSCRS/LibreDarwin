// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/wire/UniqueFd.h>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

namespace LibreSCRS::Darwin::wire {

// macOS socket framing. A frame is a `uint32` little-endian body
// length + a `uint32` little-endian fd count + a CBOR (RFC 8949) body; the CDDL
// schema (agent/wire/librescrs-agent.cddl) + the WireContractGuard pin the
// message shapes. File descriptors (signed artifact / photo / sign input) ride
// SCM_RIGHTS ancillary data and are referenced from the CBOR body by an `fd`
// index. The fd-count header lets a streaming reader attribute exactly that many
// SCM_RIGHTS fds to each frame (the D-Bus UNIX_FDS approach) — without it, fds
// received mid-stream cannot be robustly matched to a frame. The socket is
// SOCK_CLOEXEC; FD_CLOEXEC is set on each received fd via fcntl(fd, F_SETFD,
// FD_CLOEXEC) after recvmsg (MSG_CMSG_CLOEXEC is Linux-only, absent on Darwin). A
// max-frame cap fails malformed input closed (the browser-loaded facade is
// untrusted).

inline constexpr std::uint32_t kProtocolVersion = 1;

// The fixed frame header: [uint32 bodyLen LE][uint32 fdCount LE].
inline constexpr std::size_t kFrameHeaderBytes = 2 * sizeof(std::uint32_t);

// Frames larger than this are rejected before allocation. Artifacts ride fds, so
// message bodies stay small.
inline constexpr std::size_t kMaxFrameBytes = 1u << 20; // 1 MiB

// Max ancillary fds accepted on one frame (defence-in-depth; results carry at
// most a small number of artifact/photo fds).
inline constexpr std::size_t kMaxFrameFds = 8;

enum class FrameError : std::uint8_t {
    PeerClosed, // EOF before a complete frame
    Oversize,   // declared body length > kMaxFrameBytes
    Io,         // sendmsg / recvmsg failed
    TooManyFds, // declared/received fd count > kMaxFrameFds
    FdMismatch, // received fewer SCM_RIGHTS fds than the header declared
    WouldBlock, // a non-blocking socket had no complete frame ready (see note)
};

// A decoded inbound frame: the CBOR body plus the fds received out-of-band in the
// SCM_RIGHTS message, in wire order (the body references them by index). The fds
// are owned (closed on drop).
struct Frame
{
    std::vector<std::uint8_t> body;
    std::vector<UniqueFd> fds;
};

// [uint32 bodyLen LE][uint32 fdCount LE][body]. fdCount is the number of fds the
// caller will pass alongside this frame (0 for most messages).
[[nodiscard]] std::vector<std::uint8_t> encodeFrame(std::span<const std::uint8_t> body, std::uint32_t fdCount = 0);

// Blocking send of exactly one frame plus optional passed fds (SCM_RIGHTS) in a
// single sendmsg. `passFds` are duplicated into the peer; the caller keeps
// ownership of its copies. Bodies over kMaxFrameBytes fail closed.
[[nodiscard]] std::expected<void, FrameError> sendFrame(int fd, std::span<const std::uint8_t> body,
                                                        std::span<const int> passFds = {});

// Blocking receive of exactly one frame. Harvests exactly the header-declared fd
// count from SCM_RIGHTS and sets FD_CLOEXEC on each via fcntl (no MSG_CMSG_CLOEXEC
// on Darwin). Enforces kMaxFrameBytes / kMaxFrameFds before allocating.
//
// BLOCKING CONTRACT: sendFrame/recvFrame are for BLOCKING sockets — the
// agent-owned prompter channel (a worker thread) and the tests. The
// dispatch_source-driven CLIENT transport (Task 5) uses NON-blocking sockets and
// a stateful FrameReassembler (accumulate header + body across readiness
// callbacks) rather than this synchronous loop; on a non-blocking socket
// recvFrame reports WouldBlock rather than misclassifying EAGAIN as Io.
[[nodiscard]] std::expected<Frame, FrameError> recvFrame(int fd);

} // namespace LibreSCRS::Darwin::wire
