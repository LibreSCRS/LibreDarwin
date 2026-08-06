// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Shared App-Group path resolution for the agent-owned binaries: the real
// (sandbox-bypass) home directory and the group container derived from it.
#include <LibreSCRS/Darwin/backend/AppGroupPaths.h>

#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h> // kAppGroup

#include <pwd.h>
#include <unistd.h>

#include <cstdlib>

namespace LibreSCRS::Darwin {

std::filesystem::path realHomeDir()
{
    if (struct passwd* pw = getpwuid(getuid()); pw != nullptr && pw->pw_dir != nullptr) {
        return std::filesystem::path(pw->pw_dir);
    }
    const char* home = std::getenv("HOME");
    return (home != nullptr && *home != '\0') ? std::filesystem::path(home) : std::filesystem::temp_directory_path();
}

std::filesystem::path appGroupContainerDir()
{
    if (const char* over = std::getenv("LIBRESCRS_AGENT_CONTAINER"); over != nullptr && *over != '\0') {
        return std::filesystem::path(over);
    }
    return realHomeDir() / "Library" / "Group Containers" / kAppGroup;
}

} // namespace LibreSCRS::Darwin
