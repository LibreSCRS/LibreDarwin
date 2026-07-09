// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Frame length prefixing + SCM_RIGHTS fd-passing with FD_CLOEXEC, over a
// socketpair. Oversize + fd-count limits fail closed.
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

struct SocketPair
{
    int fds[2]{-1, -1};
    SocketPair()
    {
        EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    }
    ~SocketPair()
    {
        if (fds[0] >= 0) {
            ::close(fds[0]);
        }
        if (fds[1] >= 0) {
            ::close(fds[1]);
        }
    }
};

TEST(Framing, HeaderIsLittleEndianLengthPlusFdCount)
{
    const std::vector<std::uint8_t> body{0xAA, 0xBB, 0xCC};
    const auto framed = encodeFrame(body, 0);
    ASSERT_EQ(framed.size(), kFrameHeaderBytes + body.size());
    EXPECT_EQ(framed[0], 3u); // bodyLen LE
    EXPECT_EQ(framed[1], 0u);
    EXPECT_EQ(framed[2], 0u);
    EXPECT_EQ(framed[3], 0u);
    EXPECT_EQ(framed[4], 0u); // fdCount LE == 0
    EXPECT_EQ(framed[5], 0u);
    EXPECT_EQ(framed[6], 0u);
    EXPECT_EQ(framed[7], 0u);
    EXPECT_EQ(framed[8], 0xAA); // body
}

TEST(Framing, FdCountHeaderReflectsPassedFds)
{
    const std::vector<std::uint8_t> body{0x01};
    const auto framed = encodeFrame(body, 1);
    EXPECT_EQ(framed[4], 1u); // fdCount LE == 1
}

TEST(Framing, BodyRoundTripsOverSocketPair)
{
    SocketPair sp;
    const std::vector<std::uint8_t> body{1, 2, 3, 4, 5};
    ASSERT_TRUE(sendFrame(sp.fds[0], body).has_value());
    const auto frame = recvFrame(sp.fds[1]);
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(frame->body, body);
    EXPECT_TRUE(frame->fds.empty());
}

TEST(Framing, PassesAnFdWithCloexecSet)
{
    SocketPair sp;
    int pipefd[2]{-1, -1};
    ASSERT_EQ(::pipe(pipefd), 0);

    const std::vector<std::uint8_t> body{0x42};
    const std::array<int, 1> toPass{pipefd[0]};
    ASSERT_TRUE(sendFrame(sp.fds[0], body, toPass).has_value());

    auto frame = recvFrame(sp.fds[1]);
    ASSERT_TRUE(frame.has_value());
    ASSERT_EQ(frame->fds.size(), 1u);
    const int received = frame->fds[0].get();

    // FD_CLOEXEC must be set on the received fd (no MSG_CMSG_CLOEXEC on Darwin).
    const int flags = ::fcntl(received, F_GETFD);
    ASSERT_GE(flags, 0);
    EXPECT_TRUE(flags & FD_CLOEXEC);

    // The received fd is a working dup of the pipe read end.
    const char payload = 'Z';
    ASSERT_EQ(::write(pipefd[1], &payload, 1), 1);
    char got = 0;
    ASSERT_EQ(::read(received, &got, 1), 1);
    EXPECT_EQ(got, 'Z');

    ::close(pipefd[0]);
    ::close(pipefd[1]);
}

TEST(Framing, OversizeLengthFailsClosed)
{
    SocketPair sp;
    // Send a full 8-byte header declaring a body larger than kMaxFrameBytes.
    const std::uint32_t huge = static_cast<std::uint32_t>(kMaxFrameBytes) + 1;
    std::array<std::uint8_t, kFrameHeaderBytes> hdr{static_cast<std::uint8_t>(huge & 0xFF),
                                                    static_cast<std::uint8_t>((huge >> 8) & 0xFF),
                                                    static_cast<std::uint8_t>((huge >> 16) & 0xFF),
                                                    static_cast<std::uint8_t>((huge >> 24) & 0xFF),
                                                    0,
                                                    0,
                                                    0,
                                                    0}; // fdCount == 0
    ASSERT_EQ(::write(sp.fds[0], hdr.data(), hdr.size()), static_cast<ssize_t>(kFrameHeaderBytes));
    const auto frame = recvFrame(sp.fds[1]);
    ASSERT_FALSE(frame.has_value());
    EXPECT_EQ(frame.error(), FrameError::Oversize);
}

TEST(Framing, FdMismatchFailsClosed)
{
    SocketPair sp;
    // Header declares 1 fd but none are sent via SCM_RIGHTS.
    const std::vector<std::uint8_t> body{0x42};
    auto framed = encodeFrame(body, 1); // fdCount = 1, no ancillary
    ASSERT_EQ(::write(sp.fds[0], framed.data(), framed.size()), static_cast<ssize_t>(framed.size()));
    const auto frame = recvFrame(sp.fds[1]);
    ASSERT_FALSE(frame.has_value());
    EXPECT_EQ(frame.error(), FrameError::FdMismatch);
}

TEST(Framing, TooManyFdsFailsClosed)
{
    SocketPair sp;
    const std::vector<std::uint8_t> body{0x00};
    std::vector<int> tooMany(kMaxFrameFds + 1, sp.fds[0]);
    const auto r = sendFrame(sp.fds[0], body, tooMany);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), FrameError::TooManyFds);
}

TEST(Framing, SendOversizeBodyFailsClosed)
{
    SocketPair sp;
    const std::vector<std::uint8_t> tooBig(kMaxFrameBytes + 1, 0);
    const auto r = sendFrame(sp.fds[0], tooBig);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error(), FrameError::Oversize);
}

TEST(Framing, PeerClosedFailsClosed)
{
    SocketPair sp;
    ::close(sp.fds[0]); // peer gone
    const auto frame = recvFrame(sp.fds[1]);
    ASSERT_FALSE(frame.has_value());
    EXPECT_EQ(frame.error(), FrameError::PeerClosed);
}

} // namespace
