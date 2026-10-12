// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The App-Group container is compiled in. This binary links the same
// AppGroupPaths object the shipped agent and prompter link, so a variable that
// moved the container here would move it there too: `launchctl setenv` reaches
// every job the user's launchd starts, and the container is where both sockets
// live.
#include <LibreSCRS/Darwin/backend/AppGroupPaths.h>
#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h>

#include <gtest/gtest.h>

#include <pwd.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <string>

namespace {

using namespace LibreSCRS::Darwin;

// Derived here from the passwd database, not from realHomeDir(), and with the
// group's rule restated rather than taken from appGroup(), so the expectation
// does not share the code under test.
std::filesystem::path canonicalContainer()
{
    const struct passwd* pw = getpwuid(getuid());
    EXPECT_NE(pw, nullptr);
    const auto team = configuredTeamId();
    const std::string group = team ? *team + ".org.librescrs.LibreMac" : "group.org.librescrs.LibreMac";
    return std::filesystem::path(pw != nullptr ? pw->pw_dir : "") / "Library" / "Group Containers" / group;
}

TEST(AppGroupPathsProduction, AgentSocketIsInTheCanonicalContainer)
{
    unsetenv("LIBRESCRS_AGENT_CONTAINER");
    EXPECT_EQ(agentSocketPath(), canonicalContainer() / "agent.sock");
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
