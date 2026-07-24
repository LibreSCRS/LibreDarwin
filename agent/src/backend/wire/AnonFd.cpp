// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Darwin/backend/wire/AnonFd.h> // brings in the UniqueFd using-declaration (Agent::Wire::UniqueFd)
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <string>
#include <vector>

namespace LibreSCRS::Darwin::wire {

std::optional<UniqueFd> anonFdFromBytes(std::span<const std::uint8_t> bytes)
{
    const char* tmpDir = std::getenv("TMPDIR");
    std::string tmpl = (tmpDir != nullptr && *tmpDir != '\0') ? std::string(tmpDir) : std::string("/tmp/");
    if (tmpl.back() != '/') {
        tmpl.push_back('/');
    }
    tmpl += "lda-XXXXXX";
    std::vector<char> path(tmpl.begin(), tmpl.end());
    path.push_back('\0');

    const int fd = ::mkstemp(path.data());
    if (fd < 0) {
        return std::nullopt;
    }
    UniqueFd owned(fd);
    ::unlink(path.data()); // anonymous from here
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    // Write the whole buffer, tolerating short writes + EINTR (POSIX permits a
    // pwrite to transfer fewer bytes than requested).
    std::size_t off = 0;
    while (off < bytes.size()) {
        const ssize_t w = ::pwrite(fd, bytes.data() + off, bytes.size() - off, static_cast<off_t>(off));
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::nullopt;
        }
        if (w == 0) {
            return std::nullopt; // no progress -> fail closed
        }
        off += static_cast<std::size_t>(w);
    }
    ::lseek(fd, 0, SEEK_SET);
    return owned;
}

} // namespace LibreSCRS::Darwin::wire
