// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The App-Group container is compiled in. This binary links the same
// AppGroupPaths object the shipped agent and prompter link, so a variable that
// moved the container here would move it there too: `launchctl setenv` reaches
// every job the user's launchd starts, and the container is where both sockets
// live.
#include <LibreSCRS/Darwin/backend/AppGroupPaths.h>
#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h> // kAppGroup

#include <gtest/gtest.h>

#include <pwd.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>

namespace {

using namespace LibreSCRS::Darwin;

// Derived here from the passwd database, not from realHomeDir(), so the
// expectation does not share the code under test.
std::filesystem::path canonicalContainer()
{
    const struct passwd* pw = getpwuid(getuid());
    EXPECT_NE(pw, nullptr);
    return std::filesystem::path(pw != nullptr ? pw->pw_dir : "") / "Library" / "Group Containers" / kAppGroup;
}

TEST(AppGroupPathsProduction, ContainerIsTheCanonicalPath)
{
    unsetenv("LIBRESCRS_AGENT_CONTAINER");
    EXPECT_EQ(appGroupContainerDir(), canonicalContainer());
}

TEST(AppGroupPathsProduction, ContainerVariableIsIgnored)
{
    const std::filesystem::path decoy = std::filesystem::temp_directory_path() / "librescrs-decoy-container";
    ASSERT_EQ(setenv("LIBRESCRS_AGENT_CONTAINER", decoy.c_str(), 1), 0);

    const std::filesystem::path got = appGroupContainerDir();
    unsetenv("LIBRESCRS_AGENT_CONTAINER");

    EXPECT_NE(got, decoy);
    EXPECT_EQ(got, canonicalContainer());
}

} // namespace
