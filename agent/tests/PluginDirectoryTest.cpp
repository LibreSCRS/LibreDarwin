// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The plugin-directory cascade and what the daemon says about it.
//
// The daemon resolved a directory and loaded plugins in silence, so a machine
// with no plugins in any of the three candidate locations looked exactly like a
// machine holding an unsupported card: the menu bar reported "card not usable"
// for a card PC/SC read fine, and nothing anywhere named the directory that had
// been tried. These cases pin both halves of the fix — the cascade reports which
// source won AND why the earlier ones lost, and loading nothing is a warning.
#include <LibreSCRS/Darwin/backend/PluginDirectory.h>

#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Plugin/CardPluginService.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

namespace fs = std::filesystem;

using LibreSCRS::Darwin::PluginDirCandidate;
using LibreSCRS::Darwin::PluginDirInputs;
using LibreSCRS::Darwin::PluginDirResolution;
using LibreSCRS::Darwin::pluginLoadReportLines;
using LibreSCRS::Darwin::reportPluginLoad;
using LibreSCRS::Darwin::resolvePluginDir;

using Source = PluginDirCandidate::Source;
using Verdict = PluginDirCandidate::Verdict;
using Level = LibreSCRS::Agent::log::Level;
using LoadOutcome = LibreSCRS::Plugin::LoadOutcome;

// A directory that removes itself, so a case can hand the cascade a real
// on-disk layout instead of a mocked filesystem.
class TempDir
{
public:
    explicit TempDir(const std::string& tag)
        : root(fs::temp_directory_path() / ("ld-plugindir-" + tag + "-" + std::to_string(::getpid())))
    {
        fs::remove_all(root);
        fs::create_directories(root);
    }
    ~TempDir()
    {
        fs::remove_all(root);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    [[nodiscard]] const fs::path& path() const noexcept
    {
        return root;
    }

private:
    fs::path root;
};

// Every line the report produced, joined — cases assert on what the operator
// reading the log can see, not on line indices.
std::string joined(const std::vector<std::pair<Level, std::string>>& lines)
{
    std::string all;
    for (const auto& [level, text] : lines) {
        all += text;
        all += '\n';
    }
    return all;
}

bool hasLevel(const std::vector<std::pair<Level, std::string>>& lines, Level wanted)
{
    for (const auto& [level, text] : lines) {
        if (level == wanted) {
            return true;
        }
    }
    return false;
}

// --- the cascade ---------------------------------------------------------

TEST(PluginDirectory, EnvironmentOverrideWinsAndIsTheOnlyCandidate)
{
    const auto resolution = resolvePluginDir(PluginDirInputs{.environment = "/opt/plugins",
                                                             .executable = fs::path("/Apps/X.app/Contents/MacOS/agent"),
                                                             .compiledDefault = "/usr/local/lib/librescrs/plugins"});

    EXPECT_EQ(resolution.dir, fs::path("/opt/plugins"));
    ASSERT_EQ(resolution.candidates.size(), 1U);
    EXPECT_EQ(resolution.candidates.front().source, Source::Environment);
    EXPECT_EQ(resolution.candidates.front().verdict, Verdict::Chosen);
}

TEST(PluginDirectory, BundleRelativeDirectoryIsTakenWhenTheEnvironmentIsUnset)
{
    TempDir bundle("bundle");
    const fs::path macOsDir = bundle.path() / "Contents" / "MacOS";
    const fs::path plugIns = bundle.path() / "Contents" / "PlugIns" / "librescrs";
    fs::create_directories(macOsDir);
    fs::create_directories(plugIns);

    const auto resolution = resolvePluginDir(PluginDirInputs{.environment = "",
                                                             .executable = macOsDir / "librescrs-agent",
                                                             .compiledDefault = "/usr/local/lib/librescrs/plugins"});

    EXPECT_EQ(fs::canonical(resolution.dir), fs::canonical(plugIns));
    ASSERT_EQ(resolution.candidates.size(), 2U);
    EXPECT_EQ(resolution.candidates[0].source, Source::Environment);
    EXPECT_EQ(resolution.candidates[0].verdict, Verdict::Unset);
    EXPECT_EQ(resolution.candidates[1].source, Source::BundleRelative);
    EXPECT_EQ(resolution.candidates[1].verdict, Verdict::Chosen);
}

TEST(PluginDirectory, CompiledDefaultIsTheTerminalFallbackAndRecordsWhyTheOthersLost)
{
    TempDir tree("nobundle");
    const fs::path exe = tree.path() / "build" / "agent" / "librescrs-agent";
    fs::create_directories(exe.parent_path());

    const auto resolution = resolvePluginDir(
        PluginDirInputs{.environment = "", .executable = exe, .compiledDefault = "/usr/local/lib/librescrs/plugins"});

    EXPECT_EQ(resolution.dir, fs::path("/usr/local/lib/librescrs/plugins"));
    ASSERT_EQ(resolution.candidates.size(), 3U);
    EXPECT_EQ(resolution.candidates[0].verdict, Verdict::Unset);
    EXPECT_EQ(resolution.candidates[1].source, Source::BundleRelative);
    EXPECT_EQ(resolution.candidates[1].verdict, Verdict::NotADirectory);
    // The rejected path has to be recorded, not just the fact of rejection — the
    // whole point is that the log can name what it looked for.
    EXPECT_FALSE(resolution.candidates[1].path.empty());
    EXPECT_EQ(resolution.candidates[2].source, Source::CompiledDefault);
    EXPECT_EQ(resolution.candidates[2].verdict, Verdict::Chosen);
}

TEST(PluginDirectory, AnUnknownExecutablePathLeavesTheBundleCandidateUnset)
{
    const auto resolution = resolvePluginDir(
        PluginDirInputs{.environment = "", .executable = std::nullopt, .compiledDefault = "/usr/local/lib/x"});

    EXPECT_EQ(resolution.dir, fs::path("/usr/local/lib/x"));
    ASSERT_EQ(resolution.candidates.size(), 3U);
    EXPECT_EQ(resolution.candidates[1].source, Source::BundleRelative);
    EXPECT_EQ(resolution.candidates[1].verdict, Verdict::Unset);
    EXPECT_TRUE(resolution.candidates[1].path.empty());
}

TEST(PluginDirectory, TheChosenDirectoryIsAlwaysTheLastCandidate)
{
    for (const std::string& env : {std::string("/opt/plugins"), std::string()}) {
        const auto resolution = resolvePluginDir(
            PluginDirInputs{.environment = env, .executable = std::nullopt, .compiledDefault = "/usr/local/lib/x"});
        ASSERT_FALSE(resolution.candidates.empty());
        EXPECT_EQ(resolution.candidates.back().verdict, Verdict::Chosen);
        EXPECT_EQ(resolution.candidates.back().path, resolution.dir);
    }
}

// --- what gets said about it ---------------------------------------------

TEST(PluginDirectoryReport, ZeroPluginsIsAWarningNamingTheDirectory)
{
    const auto resolution = resolvePluginDir(
        PluginDirInputs{.environment = "", .executable = std::nullopt, .compiledDefault = "/usr/local/lib/librescrs"});

    const auto lines = pluginLoadReportLines(resolution, 0, {});

    EXPECT_TRUE(hasLevel(lines, Level::Warn)) << "loading nothing must not be reported at info severity";
    EXPECT_NE(joined(lines).find("/usr/local/lib/librescrs"), std::string::npos)
        << "the directory that produced nothing has to be named:\n"
        << joined(lines);
}

TEST(PluginDirectoryReport, NamesTheSourceThatWonAndThePathsThatLost)
{
    TempDir tree("report");
    const fs::path exe = tree.path() / "build" / "librescrs-agent";
    fs::create_directories(exe.parent_path());
    const auto resolution = resolvePluginDir(
        PluginDirInputs{.environment = "", .executable = exe, .compiledDefault = "/usr/local/lib/librescrs"});

    const std::string text = joined(pluginLoadReportLines(resolution, 0, {}));

    EXPECT_NE(text.find("LIBRESCRS_PLUGIN_DIR"), std::string::npos)
        << "the environment override has to be named as tried-and-unset:\n"
        << text;
    EXPECT_NE(text.find("PlugIns"), std::string::npos) << "the bundle path that was looked for has to appear:\n"
                                                       << text;
}

TEST(PluginDirectoryReport, LoadedPluginsAreInformationalAndCounted)
{
    const auto resolution = resolvePluginDir(
        PluginDirInputs{.environment = "/opt/plugins", .executable = std::nullopt, .compiledDefault = "/unused"});
    const std::vector<LoadOutcome> report{
        LoadOutcome{.soPath = "/opt/plugins/a.dylib", .pluginId = "a", .status = LoadOutcome::Status::Loaded},
        LoadOutcome{.soPath = "/opt/plugins/b.dylib", .pluginId = "b", .status = LoadOutcome::Status::Loaded}};

    const auto lines = pluginLoadReportLines(resolution, 2, report);

    EXPECT_FALSE(hasLevel(lines, Level::Warn)) << "a healthy load must not warn:\n" << joined(lines);
    EXPECT_NE(joined(lines).find('2'), std::string::npos) << "the count has to be reported:\n" << joined(lines);
}

TEST(PluginDirectoryReport, AFileThatFailedToLoadIsNamedWithItsDiagnostic)
{
    const auto resolution = resolvePluginDir(
        PluginDirInputs{.environment = "/opt/plugins", .executable = std::nullopt, .compiledDefault = "/unused"});
    const std::vector<LoadOutcome> report{LoadOutcome{.soPath = "/opt/plugins/broken.dylib",
                                                      .pluginId = "",
                                                      .status = LoadOutcome::Status::AbiMismatch,
                                                      .diagnostic = "expected ABI 8 got 6"}};

    const std::string text = joined(pluginLoadReportLines(resolution, 0, report));

    EXPECT_NE(text.find("broken.dylib"), std::string::npos) << text;
    EXPECT_NE(text.find("expected ABI 8 got 6"), std::string::npos) << text;
}

// --- end to end, against a real registry over a real directory -----------

TEST(PluginDirectoryReport, AnEmptyDirectoryReachesTheLogAsAWarning)
{
    TempDir empty("empty");
    std::vector<std::pair<Level, std::string>> captured;
    LibreSCRS::Agent::log::init(
        [&captured](Level level, std::string_view line) { captured.emplace_back(level, std::string(line)); });

    const auto resolution = resolvePluginDir(PluginDirInputs{
        .environment = empty.path().string(), .executable = std::nullopt, .compiledDefault = "/unused"});
    const LibreSCRS::Plugin::CardPluginService service(resolution.dir);
    reportPluginLoad(resolution, service);

    LibreSCRS::Agent::log::resetForTest();

    ASSERT_FALSE(captured.empty()) << "resolving a plugin directory must not be silent";
    EXPECT_TRUE(hasLevel(captured, Level::Warn));
    EXPECT_NE(joined(captured).find(empty.path().string()), std::string::npos) << joined(captured);
}

TEST(PluginDirectoryReport, AnUnloadableFileInTheDirectoryReachesTheLog)
{
    TempDir dir("broken");
    {
        std::ofstream bogus(dir.path() / "not-a-plugin.dylib", std::ios::binary);
        bogus << "this is not a mach-o";
    }
    std::vector<std::pair<Level, std::string>> captured;
    LibreSCRS::Agent::log::init(
        [&captured](Level level, std::string_view line) { captured.emplace_back(level, std::string(line)); });

    const auto resolution = resolvePluginDir(
        PluginDirInputs{.environment = dir.path().string(), .executable = std::nullopt, .compiledDefault = "/unused"});
    const LibreSCRS::Plugin::CardPluginService service(resolution.dir);
    reportPluginLoad(resolution, service);

    LibreSCRS::Agent::log::resetForTest();

    EXPECT_NE(joined(captured).find("not-a-plugin.dylib"), std::string::npos)
        << "a file that failed to load has to be named:\n"
        << joined(captured);
}

} // namespace
