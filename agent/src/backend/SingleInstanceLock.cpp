// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Darwin/backend/SingleInstanceLock.h>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <utility>

namespace LibreSCRS::Darwin {
namespace {

// A lock won on a file its holder removed in the same instant is retried; more
// than a handful of such races in a row is not a race any more.
constexpr int kAcquireAttempts = 8;

bool pathNames(const std::string& path, dev_t dev, ino_t ino) noexcept
{
    struct stat st{};
    return ::lstat(path.c_str(), &st) == 0 && st.st_dev == dev && st.st_ino == ino;
}

} // namespace

std::expected<SingleInstanceLock, ServerStartError> SingleInstanceLock::acquire(const std::string& socketPath)
{
    const std::string lockPath = lockPathFor(socketPath);
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(lockPath).parent_path(), ec);
    for (int attempt = 0; attempt < kAcquireAttempts; ++attempt) {
        Agent::Wire::UniqueFd fd(::open(lockPath.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (!fd) {
            return std::unexpected(ServerStartError{ServerStartError::Kind::Failed,
                                                    std::format("open({}): {}", lockPath, std::strerror(errno))});
        }
        struct stat st{};
        if (::fstat(fd.get(), &st) != 0 || !S_ISREG(st.st_mode)) {
            return std::unexpected(
                ServerStartError{ServerStartError::Kind::Failed, std::format("{} is not a regular file", lockPath)});
        }
        if (::flock(fd.get(), LOCK_EX | LOCK_NB) != 0) {
            if (errno == EWOULDBLOCK) {
                return std::unexpected(
                    ServerStartError{ServerStartError::Kind::AnotherInstance,
                                     std::format("another instance holds {}; it is serving {}", lockPath, socketPath)});
            }
            return std::unexpected(ServerStartError{ServerStartError::Kind::Failed,
                                                    std::format("flock({}): {}", lockPath, std::strerror(errno))});
        }
        // Granted -- but on the file the path names NOW? The previous holder
        // removes the file just before it lets go, so the lock may have been
        // won on a file nobody can find any more.
        if (pathNames(lockPath, st.st_dev, st.st_ino)) {
            return SingleInstanceLock(std::move(fd), lockPath, st.st_dev, st.st_ino);
        }
    }
    return std::unexpected(ServerStartError{ServerStartError::Kind::Failed,
                                            std::format("{} kept being replaced while locking", lockPath)});
}

SingleInstanceLock::SingleInstanceLock(Agent::Wire::UniqueFd fd, std::string lockPath, dev_t dev, ino_t ino)
    : m_fd(std::move(fd)), m_lockPath(std::move(lockPath)), m_dev(dev), m_ino(ino)
{}

SingleInstanceLock& SingleInstanceLock::operator=(SingleInstanceLock&& other) noexcept
{
    if (this != &other) {
        release();
        m_fd = std::move(other.m_fd);
        m_lockPath = std::move(other.m_lockPath);
        m_dev = other.m_dev;
        m_ino = other.m_ino;
    }
    return *this;
}

SingleInstanceLock::~SingleInstanceLock()
{
    release();
}

void SingleInstanceLock::release() noexcept
{
    if (!m_fd) {
        return;
    }
    // Remove first, while still holding the lock: a contender that opened the
    // old file meanwhile wins a lock on a removed file, sees that, and retries.
    if (pathNames(m_lockPath, m_dev, m_ino)) {
        ::unlink(m_lockPath.c_str());
    }
    m_fd.reset(); // closing the last descriptor releases the flock
}

} // namespace LibreSCRS::Darwin
