// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// LOCAL_PEERTOKEN peer-credential capture over a connected AF_UNIX socket. Both
// socketpair ends are this process, so the captured pid is our own.
#include <LibreSCRS/Darwin/backend/PeerIdentity.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

using namespace LibreSCRS::Darwin;

namespace {

TEST(PeerIdentity, CapturesOwnPidOverSocketPair)
{
    int fds[2]{-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    const auto creds = capturePeerCredentials(fds[0]);
    ASSERT_TRUE(creds.has_value());
    EXPECT_EQ(creds->pid, ::getpid());
    EXPECT_GT(creds->pidVersion, 0u);
    EXPECT_FALSE(creds->label().empty());

    ::close(fds[0]);
    ::close(fds[1]);
}

TEST(PeerIdentity, FailsClosedOnANonSocketFd)
{
    // A pipe fd is not a socket; LOCAL_PEERTOKEN must fail (nullopt), never
    // default-trust.
    int pipefd[2]{-1, -1};
    ASSERT_EQ(::pipe(pipefd), 0);
    const auto creds = capturePeerCredentials(pipefd[0]);
    EXPECT_FALSE(creds.has_value());
    ::close(pipefd[0]);
    ::close(pipefd[1]);
}

} // namespace
