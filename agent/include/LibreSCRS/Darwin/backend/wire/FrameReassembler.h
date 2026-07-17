// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/wire/Framing.h>

#include <cstdint>
#include <deque>
#include <vector>

namespace LibreSCRS::Darwin::wire {

enum class PumpStatus : std::uint8_t {
    Ok,         // read what was available (EAGAIN); `frames` may be non-empty
    PeerClosed, // clean EOF from the peer
    Error,      // protocol / I/O error (`error` is set); the connection is dead
};

struct PumpResult
{
    std::vector<Frame> frames;
    PumpStatus status{PumpStatus::Ok};
    FrameError error{FrameError::Io}; // meaningful iff status == Error
};

// Non-blocking streaming frame reader for the dispatch_source client transport.
// One instance per connection. On read-readiness the transport calls
// pump(fd): it drains what is available (non-blocking recvmsg), harvests
// SCM_RIGHTS fds (with FD_CLOEXEC), and returns every complete frame, attributing
// exactly the header-declared fd count to each frame from an in-order fd FIFO
// (the D-Bus UNIX_FDS model). Fails closed on oversize, fd-count violations, or a
// body that completes with fewer fds than declared. All limits (kMaxFrameBytes,
// kMaxFrameFds) are enforced.
class FrameReassembler
{
public:
    FrameReassembler() = default;
    FrameReassembler(const FrameReassembler&) = delete;
    FrameReassembler& operator=(const FrameReassembler&) = delete;

    [[nodiscard]] PumpResult pump(int fd);

private:
    // Extract as many complete frames as the buffer + fd FIFO allow. Sets
    // out.status/error on a protocol violation.
    void extract(PumpResult& out);

    std::vector<std::uint8_t> m_buffer; // accumulated bytes (header + partial body)
    std::deque<UniqueFd> m_fds;         // received fds not yet attributed to a frame
};

} // namespace LibreSCRS::Darwin::wire
