// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Darwin/backend/PluginDirectory.h>

#include <LibreSCRS/Plugin/CardPluginService.h>

#include <mach-o/dyld.h>

#include <cstdint>
#include <format>
#include <system_error>

namespace LibreSCRS::Darwin {
namespace {

namespace fs = std::filesystem;

using Level = LibreSCRS::Agent::log::Level;
using LoadOutcome = LibreSCRS::Plugin::LoadOutcome;
using Source = PluginDirCandidate::Source;
using Verdict = PluginDirCandidate::Verdict;

// Every line carries this prefix so the whole plugin story can be pulled out of
// the unified log with one filter.
constexpr std::string_view kTag = "card plugins";

std::string_view sourceName(Source source)
{
    switch (source) {
    case Source::Environment:
        return "LIBRESCRS_PLUGIN_DIR";
    case Source::BundleRelative:
        return "the bundled plugin directory";
    case Source::CompiledDefault:
        return "the compiled-in default";
    }
    return "an unknown source";
}

std::string_view statusName(LoadOutcome::Status status)
{
    switch (status) {
    case LoadOutcome::Status::Loaded:
        return "loaded";
    case LoadOutcome::Status::DlopenFailed:
        return "dlopen failed";
    case LoadOutcome::Status::MissingFactory:
        return "no plugin entry points";
    case LoadOutcome::Status::AbiMismatch:
        return "plugin ABI mismatch";
    case LoadOutcome::Status::FactoryThrew:
        return "the plugin factory failed";
    }
    return "unknown failure";
}

// Why a candidate that was probed did not supply the directory. Only the losing
// candidates reach this — the chosen one is announced by the caller.
std::string rejectionLine(const PluginDirCandidate& candidate)
{
    switch (candidate.source) {
    case Source::Environment:
        return std::format("{}: LIBRESCRS_PLUGIN_DIR is not set", kTag);
    case Source::BundleRelative:
        return candidate.verdict == Verdict::Unset
                   ? std::format("{}: no bundled plugin directory — this binary's own path is unknown", kTag)
                   : std::format("{}: no bundled plugin directory at {}", kTag, candidate.path.string());
    case Source::CompiledDefault:
        break; // terminal fallback: it is always the chosen one, never rejected
    }
    return std::format("{}: {} did not supply a directory", kTag, sourceName(candidate.source));
}

} // namespace

PluginDirResolution resolvePluginDir(const PluginDirInputs& inputs)
{
    PluginDirResolution resolution;

    if (!inputs.environment.empty()) {
        resolution.dir = fs::path(inputs.environment);
        resolution.candidates.push_back(
            {.source = Source::Environment, .path = resolution.dir, .verdict = Verdict::Chosen});
        return resolution;
    }
    resolution.candidates.push_back({.source = Source::Environment, .path = {}, .verdict = Verdict::Unset});

    // The host bundle layout: Contents/MacOS/librescrs-agent alongside
    // Contents/PlugIns/librescrs. Normalised so the log names the directory that
    // was looked for rather than an unreadable path with a `..` in the middle.
    if (inputs.executable) {
        const fs::path bundled = (inputs.executable->parent_path() / ".." / "PlugIns" / "librescrs").lexically_normal();
        std::error_code ec;
        if (fs::is_directory(bundled, ec)) {
            resolution.dir = bundled;
            resolution.candidates.push_back(
                {.source = Source::BundleRelative, .path = bundled, .verdict = Verdict::Chosen});
            return resolution;
        }
        resolution.candidates.push_back(
            {.source = Source::BundleRelative, .path = bundled, .verdict = Verdict::NotADirectory});
    } else {
        resolution.candidates.push_back({.source = Source::BundleRelative, .path = {}, .verdict = Verdict::Unset});
    }

    resolution.dir = inputs.compiledDefault;
    resolution.candidates.push_back(
        {.source = Source::CompiledDefault, .path = resolution.dir, .verdict = Verdict::Chosen});
    return resolution;
}

std::optional<fs::path> currentExecutablePath()
{
    std::uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size); // first call: report the required size
    std::vector<char> buf(size);
    if (_NSGetExecutablePath(buf.data(), &size) != 0) {
        return std::nullopt;
    }
    std::error_code ec;
    fs::path resolved = fs::canonical(fs::path(buf.data()), ec);
    return ec ? fs::path(buf.data()) : resolved;
}

std::vector<std::pair<Level, std::string>>
pluginLoadReportLines(const PluginDirResolution& resolution, std::size_t loaded, std::span<const LoadOutcome> report)
{
    std::vector<std::pair<Level, std::string>> lines;

    for (const auto& candidate : resolution.candidates) {
        if (candidate.verdict == Verdict::Chosen) {
            lines.emplace_back(Level::Info, std::format("{}: using {} ({})", kTag, candidate.path.string(),
                                                        sourceName(candidate.source)));
            continue;
        }
        lines.emplace_back(Level::Info, rejectionLine(candidate));
    }

    // Zero is the state that cost an hour of misdiagnosis: every card then reports
    // as unusable, which is exactly what an unsupported card looks like.
    if (loaded == 0) {
        lines.emplace_back(Level::Warn, std::format("{}: loaded 0 plugins from {} — no card can be used until this "
                                                    "directory holds plugins",
                                                    kTag, resolution.dir.string()));
    } else {
        lines.emplace_back(Level::Info,
                           std::format("{}: loaded {} plugins from {}", kTag, loaded, resolution.dir.string()));
    }

    for (const auto& outcome : report) {
        if (outcome.status == LoadOutcome::Status::Loaded) {
            continue;
        }
        std::string line =
            std::format("{}: {} was not loaded ({})", kTag, outcome.soPath.string(), statusName(outcome.status));
        if (!outcome.diagnostic.empty()) {
            line += std::format(": {}", outcome.diagnostic);
        }
        lines.emplace_back(Level::Warn, std::move(line));
    }

    return lines;
}

void reportPluginLoad(const PluginDirResolution& resolution, const LibreSCRS::Plugin::CardPluginService& service)
{
    for (const auto& [level, line] : pluginLoadReportLines(resolution, service.size(), service.loadReport())) {
        switch (level) {
        case Level::Info:
            LibreSCRS::Agent::log::info(line);
            break;
        case Level::Warn:
            LibreSCRS::Agent::log::warn(line);
            break;
        case Level::Error:
            LibreSCRS::Agent::log::error(line);
            break;
        }
    }
}

} // namespace LibreSCRS::Darwin
