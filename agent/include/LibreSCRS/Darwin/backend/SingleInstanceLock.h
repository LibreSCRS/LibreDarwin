// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <sys/types.h>

#include <cstdint>
#include <expected>
#include <string>

namespace LibreSCRS::Darwin {

// Why a socket server (the agent transport, the prompter) did not start.
// AnotherInstance is its own kind because the process answers it differently:
// it is not a fault of this instance, and the other one is serving.
struct ServerStartError
{
    enum class Kind : std::uint8_t {
        AnotherInstance, // another process holds the socket path's instance lock
        Failed,          // anything else: lock file, socket, bind, listen
    };
    Kind kind{Kind::Failed};
    std::string message;
};

// One server per socket path. Both socket servers unlink whatever their path
// names before they bind, and both bind again when the path is replaced, so
// two legitimate instances on one path would take it from each other on every
// guard tick, forever. The lock stops the second one before it touches the
// path: an exclusive, non-blocking flock() on `<socketPath>.lock`, taken
// BEFORE the unlink and bind and held until the server is gone. A process
// that does not take the lock (an impostor) is still answered by the
// replaced-path guard.
//
// The lock file is created 0600 without following a symlink, is close-on-exec
// (a spawned child never inherits the lock), and is removed by its holder on
// release. Removing it is safe because acquire() checks, after the lock is
// granted, that the path still names the file it locked; a lock won on a file
// its previous holder had just removed is dropped and taken again.
class SingleInstanceLock
{
public:
    [[nodiscard]] static std::expected<SingleInstanceLock, ServerStartError> acquire(const std::string& socketPath);

    [[nodiscard]] static std::string lockPathFor(const std::string& socketPath)
    {
        return socketPath + ".lock";
    }

    SingleInstanceLock(SingleInstanceLock&& other) noexcept = default;
    SingleInstanceLock& operator=(SingleInstanceLock&& other) noexcept;
    SingleInstanceLock(const SingleInstanceLock&) = delete;
    SingleInstanceLock& operator=(const SingleInstanceLock&) = delete;
    // Removes the lock file (only while it is still the one locked), then
    // releases the lock by closing the fd.
    ~SingleInstanceLock();

private:
    SingleInstanceLock(Agent::Wire::UniqueFd fd, std::string lockPath, dev_t dev, ino_t ino);
    void release() noexcept;

    Agent::Wire::UniqueFd m_fd;
    std::string m_lockPath;
    dev_t m_dev{0};
    ino_t m_ino{0};
};

} // namespace LibreSCRS::Darwin
