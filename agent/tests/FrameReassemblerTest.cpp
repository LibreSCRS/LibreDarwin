// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The non-blocking streaming reassembler: partial frames across pumps, multiple
// frames in one read, fd-bearing frames (FD_CLOEXEC + correct attribution),
// clean EOF, and fail-closed on oversize / fd-count violations. Driven over a
// non-blocking socketpair.
#include <LibreSCRS/Darwin/backend/wire/FrameReassembler.h>
#include <LibreSCRS/Darwin/backend/wire/Framing.h>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <vector>

using namespace LibreSCRS::Darwin::wire;

namespace {

struct NbSocketPair
{
    int fds[2]{-1, -1};
    NbSocketPair()
    {
        EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        // Reader end non-blocking (the reassembler expects EAGAIN when drained).
        ::fcntl(fds[1], F_SETFL, ::fcntl(fds[1], F_GETFL) | O_NONBLOCK);
    }
    ~NbSocketPair()
    {
        if (fds[0] >= 0) {
            ::close(fds[0]);
        }
        if (fds[1] >= 0) {
            ::close(fds[1]);
        }
    }
    int writer() const
    {
        return fds[0];
    }
    int reader() const
    {
        return fds[1];
    }
};

std::vector<std::uint8_t> body(std::initializer_list<std::uint8_t> b)
{
    return std::vector<std::uint8_t>(b);
}

TEST(FrameReassembler, SingleFrameInOneRead)
{
    NbSocketPair sp;
    const auto framed = encodeFrame(body({1, 2, 3}), 0);
    ASSERT_EQ(::write(sp.writer(), framed.data(), framed.size()), static_cast<ssize_t>(framed.size()));

    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    EXPECT_EQ(r.status, PumpStatus::Ok);
    ASSERT_EQ(r.frames.size(), 1u);
    EXPECT_EQ(r.frames[0].body, body({1, 2, 3}));
    EXPECT_TRUE(r.frames[0].fds.empty());
}

TEST(FrameReassembler, TwoFramesInOneRead)
{
    NbSocketPair sp;
    auto a = encodeFrame(body({0xAA}), 0);
    const auto b = encodeFrame(body({0xBB, 0xCC}), 0);
    a.insert(a.end(), b.begin(), b.end());
    ASSERT_EQ(::write(sp.writer(), a.data(), a.size()), static_cast<ssize_t>(a.size()));

    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    ASSERT_EQ(r.frames.size(), 2u);
    EXPECT_EQ(r.frames[0].body, body({0xAA}));
    EXPECT_EQ(r.frames[1].body, body({0xBB, 0xCC}));
}

TEST(FrameReassembler, PartialFrameAcrossPumps)
{
    NbSocketPair sp;
    const auto framed = encodeFrame(body({9, 8, 7, 6}), 0);
    // Write the header + first body byte, pump (incomplete), then the rest.
    ASSERT_EQ(::write(sp.writer(), framed.data(), kFrameHeaderBytes + 1), static_cast<ssize_t>(kFrameHeaderBytes + 1));

    FrameReassembler ra;
    auto r1 = ra.pump(sp.reader());
    EXPECT_EQ(r1.status, PumpStatus::Ok);
    EXPECT_TRUE(r1.frames.empty()); // not complete yet

    ASSERT_EQ(::write(sp.writer(), framed.data() + kFrameHeaderBytes + 1, framed.size() - kFrameHeaderBytes - 1),
              static_cast<ssize_t>(framed.size() - kFrameHeaderBytes - 1));
    auto r2 = ra.pump(sp.reader());
    ASSERT_EQ(r2.frames.size(), 1u);
    EXPECT_EQ(r2.frames[0].body, body({9, 8, 7, 6}));
}

TEST(FrameReassembler, FdBearingFrameAttributesFdWithCloexec)
{
    NbSocketPair sp;
    int pipefd[2]{-1, -1};
    ASSERT_EQ(::pipe(pipefd), 0);
    // Send one frame declaring 1 fd, with the pipe read end over SCM_RIGHTS.
    const std::array<int, 1> pass{pipefd[0]};
    ASSERT_TRUE(sendFrame(sp.writer(), body({0x42}), pass).has_value());

    FrameReassembler ra;
    auto r = ra.pump(sp.reader());
    ASSERT_EQ(r.frames.size(), 1u);
    ASSERT_EQ(r.frames[0].fds.size(), 1u);
    const int got = r.frames[0].fds[0].get();
    EXPECT_TRUE(::fcntl(got, F_GETFD) & FD_CLOEXEC);

    // The received fd is a working dup of the pipe read end.
    const char payload = 'Q';
    ASSERT_EQ(::write(pipefd[1], &payload, 1), 1);
    char c = 0;
    ASSERT_EQ(::read(got, &c, 1), 1);
    EXPECT_EQ(c, 'Q');
    ::close(pipefd[0]);
    ::close(pipefd[1]);
}

TEST(FrameReassembler, PeerClosedReported)
{
    NbSocketPair sp;
    ::close(sp.fds[0]); // writer gone
    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    EXPECT_EQ(r.status, PumpStatus::PeerClosed);
    EXPECT_TRUE(r.frames.empty());
}

TEST(FrameReassembler, OversizeBodyFailsClosed)
{
    NbSocketPair sp;
    // A header declaring a body larger than the cap, no body bytes.
    const std::uint32_t huge = static_cast<std::uint32_t>(kMaxFrameBytes) + 1;
    std::array<std::uint8_t, kFrameHeaderBytes> hdr{static_cast<std::uint8_t>(huge & 0xFF),
                                                    static_cast<std::uint8_t>((huge >> 8) & 0xFF),
                                                    static_cast<std::uint8_t>((huge >> 16) & 0xFF),
                                                    static_cast<std::uint8_t>((huge >> 24) & 0xFF),
                                                    0,
                                                    0,
                                                    0,
                                                    0};
    ASSERT_EQ(::write(sp.writer(), hdr.data(), hdr.size()), static_cast<ssize_t>(hdr.size()));
    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    EXPECT_EQ(r.status, PumpStatus::Error);
    EXPECT_EQ(r.error, FrameError::Oversize);
}

TEST(FrameReassembler, DeclaredFdCountWithoutFdsFailsClosed)
{
    NbSocketPair sp;
    // Header declares 1 fd but the frame is written with no SCM_RIGHTS ancillary.
    const auto framed = encodeFrame(body({0x00}), 1);
    ASSERT_EQ(::write(sp.writer(), framed.data(), framed.size()), static_cast<ssize_t>(framed.size()));
    FrameReassembler ra;
    const auto r = ra.pump(sp.reader());
    EXPECT_EQ(r.status, PumpStatus::Error);
    EXPECT_EQ(r.error, FrameError::FdMismatch);
}

} // namespace
