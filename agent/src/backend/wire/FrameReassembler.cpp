// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Non-blocking streaming frame reassembly. pump() drains a readable socket into
// an accumulation buffer + an fd FIFO, then extracts complete frames, giving each
// exactly its header-declared fd count (D-Bus UNIX_FDS model). Fail-closed on any
// limit violation; every received fd gets FD_CLOEXEC before it is owned.
#include <LibreSCRS/Darwin/backend/wire/FrameReassembler.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>

namespace LibreSCRS::Darwin::wire {
namespace {
std::uint32_t getU32Le(const std::uint8_t* p)
{
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

// The fd FIFO holds at most one pending frame plus one incoming frame's worth of
// descriptors; beyond that a peer is flooding fds without completing frames.
constexpr std::size_t kMaxPendingFds = 2 * kMaxFrameFds;

// The buffer holds at most one in-flight frame (header + body); anything larger
// is a malformed / oversize stream.
constexpr std::size_t kMaxBufferBytes = kFrameHeaderBytes + kMaxFrameBytes;
} // namespace

PumpResult FrameReassembler::pump(int fd)
{
    PumpResult out;

    for (;;) {
        std::array<std::uint8_t, 4096> chunk{};
        iovec iov{};
        iov.iov_base = chunk.data();
        iov.iov_len = chunk.size();

        alignas(struct cmsghdr) std::array<std::uint8_t, CMSG_SPACE(sizeof(int) * kMaxFrameFds)> control{};
        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.data();
        msg.msg_controllen = static_cast<socklen_t>(control.size());

        const ssize_t r = ::recvmsg(fd, &msg, 0);
        if (r == 0) {
            out.status = PumpStatus::PeerClosed;
            break;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break; // drained for now
            }
            out.status = PumpStatus::Error;
            out.error = FrameError::Io;
            break;
        }

        // Harvest fds (FD_CLOEXEC; no MSG_CMSG_CLOEXEC on Darwin).
        for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) {
                continue;
            }
            const std::size_t payload = c->cmsg_len - CMSG_LEN(0);
            const std::size_t count = payload / sizeof(int);
            const auto* fds = reinterpret_cast<const int*>(CMSG_DATA(c));
            for (std::size_t i = 0; i < count; ++i) {
                ::fcntl(fds[i], F_SETFD, FD_CLOEXEC);
                m_fds.emplace_back(fds[i]);
            }
        }
        if (msg.msg_flags & MSG_CTRUNC) {
            out.status = PumpStatus::Error;
            out.error = FrameError::Io;
            break;
        }
        if (m_fds.size() > kMaxPendingFds) {
            out.status = PumpStatus::Error;
            out.error = FrameError::TooManyFds;
            break;
        }

        m_buffer.insert(m_buffer.end(), chunk.begin(), chunk.begin() + r);
        if (m_buffer.size() > kMaxBufferBytes) {
            out.status = PumpStatus::Error;
            out.error = FrameError::Oversize;
            break;
        }
    }

    // Extract complete frames regardless of why the read loop ended (a clean EOF
    // may still leave fully-buffered frames to deliver before the close).
    if (out.status != PumpStatus::Error) {
        extract(out);
    }
    return out;
}

void FrameReassembler::extract(PumpResult& out)
{
    std::size_t pos = 0;
    while (m_buffer.size() - pos >= kFrameHeaderBytes) {
        const std::uint8_t* h = m_buffer.data() + pos;
        const std::uint32_t bodyLen = getU32Le(h);
        const std::uint32_t fdCount = getU32Le(h + sizeof(std::uint32_t));

        if (bodyLen > kMaxFrameBytes) {
            out.status = PumpStatus::Error;
            out.error = FrameError::Oversize;
            break;
        }
        if (fdCount > kMaxFrameFds) {
            out.status = PumpStatus::Error;
            out.error = FrameError::TooManyFds;
            break;
        }
        if (m_buffer.size() - pos < kFrameHeaderBytes + bodyLen) {
            break; // body not fully arrived yet
        }
        // The frame's bytes are all here; its fds (attached to the first byte)
        // must therefore already be in the FIFO.
        if (m_fds.size() < fdCount) {
            out.status = PumpStatus::Error;
            out.error = FrameError::FdMismatch;
            break;
        }

        Frame f;
        const std::uint8_t* bodyStart = h + kFrameHeaderBytes;
        f.body.assign(bodyStart, bodyStart + bodyLen);
        for (std::uint32_t i = 0; i < fdCount; ++i) {
            f.fds.push_back(std::move(m_fds.front()));
            m_fds.pop_front();
        }
        out.frames.push_back(std::move(f));
        pos += kFrameHeaderBytes + bodyLen;
    }
    if (pos > 0) {
        m_buffer.erase(m_buffer.begin(), m_buffer.begin() + static_cast<std::ptrdiff_t>(pos));
    }
}

} // namespace LibreSCRS::Darwin::wire
