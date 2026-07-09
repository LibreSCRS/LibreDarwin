// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <unistd.h>

#include <utility>

namespace LibreSCRS::Darwin::wire {

// Move-only RAII owner of a file descriptor: closes on destruction, so received
// SCM_RIGHTS fds and self-opened sockets/artifacts cannot leak. -1 is the empty
// state. Mirrors the role of the Linux backend's UnixFd without pulling sdbus.
class UniqueFd
{
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept : m_fd(fd) {}

    UniqueFd(UniqueFd&& other) noexcept : m_fd(other.m_fd)
    {
        other.m_fd = -1;
    }
    UniqueFd& operator=(UniqueFd&& other) noexcept
    {
        if (this != &other) {
            reset();
            m_fd = other.m_fd;
            other.m_fd = -1;
        }
        return *this;
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    ~UniqueFd()
    {
        reset();
    }

    [[nodiscard]] int get() const noexcept
    {
        return m_fd;
    }
    [[nodiscard]] bool valid() const noexcept
    {
        return m_fd >= 0;
    }
    explicit operator bool() const noexcept
    {
        return valid();
    }

    // Relinquish ownership without closing (e.g. handing the fd to a struct that
    // will own it, or returning it to the caller).
    [[nodiscard]] int release() noexcept
    {
        return std::exchange(m_fd, -1);
    }

    void reset(int fd = -1) noexcept
    {
        if (m_fd >= 0 && m_fd != fd) {
            ::close(m_fd);
        }
        m_fd = fd;
    }

private:
    int m_fd{-1};
};

} // namespace LibreSCRS::Darwin::wire
