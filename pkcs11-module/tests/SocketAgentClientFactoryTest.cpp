// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The module's factory installs the peer check: a socket served by anything
// that is not the agent -- here, this test binary -- is refused before a byte
// is sent on it.
#include "SocketAgentClientFactory.h"

#include <gtest/gtest.h>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

namespace {

TEST(SocketAgentClientFactory, RefusesASocketTheAgentDoesNotServe)
{
    char dir[] = "/tmp/librescrs-pkcs11-factory-XXXXXX";
    ASSERT_NE(::mkdtemp(dir), nullptr);
    const std::string path = std::string(dir) + "/agent.sock";

    const int listener = ::socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(listener, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(listener, 4), 0);

    // Accept one connection and count what arrives on it. Whatever does arrive
    // is answered by closing, so a client that did send waits for nothing.
    bool accepted = false;
    long received = 0;
    std::thread server([&] {
        pollfd p{listener, POLLIN, 0};
        if (::poll(&p, 1, 10'000) != 1)
            return;
        const int c = ::accept(listener, nullptr, nullptr);
        if (c < 0)
            return;
        accepted = true;
        char buf[256];
        const ssize_t n = ::read(c, buf, sizeof(buf));
        if (n > 0)
            received = n;
        ::close(c);
    });

    const auto client = LibreSCRS::Pkcs11Agent::makeAgentClientAt(path);
    server.join();

    EXPECT_TRUE(accepted) << "the client never connected, so nothing was checked";
    EXPECT_FALSE(client->connected());
    EXPECT_EQ(received, 0) << "bytes reached a server that is not the agent";

    ::close(listener);
    ::unlink(path.c_str());
    ::rmdir(dir);
}

} // namespace
