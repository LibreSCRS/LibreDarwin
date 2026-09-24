// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <sys/stat.h>

#include <optional>
#include <string>

namespace LibreSCRS::Darwin {

// The filesystem identity (device + inode) of the socket file a listener
// bound. Both socket servers (the agent transport and the prompter) record it
// right after bind() and compare it with what the path names now: a mismatch
// means someone unlinked the file and bound their own socket there, so new
// clients reach them and the server must bind again.
//
// Taken from the PATH, not from fstat() on the listen fd: on macOS fstat() of
// an AF_UNIX socket reports the socket object (st_dev -1, its own inode
// number), never the inode bind() created. lstat() so a symlink planted on the
// path counts as a replacement rather than being followed.
struct SocketPathIdentity
{
    dev_t dev{0};
    ino_t ino{0};

    [[nodiscard]] static std::optional<SocketPathIdentity> of(const std::string& path) noexcept
    {
        struct stat st{};
        if (::lstat(path.c_str(), &st) != 0 || !S_ISSOCK(st.st_mode)) {
            return std::nullopt;
        }
        return SocketPathIdentity{st.st_dev, st.st_ino};
    }

    // False when the path is gone, is no longer a socket, or is another inode.
    [[nodiscard]] bool stillNames(const std::string& path) const noexcept
    {
        const auto now = of(path);
        return now && now->dev == dev && now->ino == ino;
    }
};

// The listening socket a fd refers to, by the kernel socket object fstat()
// reports (st_ino of a socket names the socket, see above). Taken when a
// server asks GCD to cancel its accept source and checked again when the
// cancel handler runs: the listen fd must still be open, and still this
// listener, at both points -- closing it anywhere but the cancel handler
// breaks that, whether the handle was emptied or the number closed (and
// perhaps reused for another socket) behind its back.
struct ListenSocketObject
{
    int fd{-1};
    ino_t ino{0};

    [[nodiscard]] static std::optional<ListenSocketObject> of(int fd) noexcept
    {
        struct stat st{};
        // (No SO_ACCEPTCONN probe: macOS getsockopt refuses it, ENOPROTOOPT.)
        if (fd < 0 || ::fstat(fd, &st) != 0 || !S_ISSOCK(st.st_mode)) {
            return std::nullopt;
        }
        return ListenSocketObject{fd, st.st_ino};
    }

    [[nodiscard]] bool stillHeldBy(int currentFd) const noexcept
    {
        const auto now = of(currentFd);
        return currentFd == fd && now && now->ino == ino;
    }
};

} // namespace LibreSCRS::Darwin
