// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief Where the daemon looks for card plugins, and what it says about it.
///
/// Resolution is a three-step cascade and every step can come up empty on a
/// machine that is otherwise healthy, so the outcome is returned as a record of
/// what was tried rather than a bare path: a directory that yielded no plugins
/// is indistinguishable, from the user's seat, from a card nothing supports.

#include <LibreSCRS/Agent/backend/Logging.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Plugin {
class CardPluginService;
struct LoadOutcome;
} // namespace LibreSCRS::Plugin

namespace LibreSCRS::Darwin {

/// @brief One candidate location for the plugin directory, with the reason it
///        was or was not taken.
struct PluginDirCandidate
{
    /// @brief The candidate locations, in the order they are probed.
    enum class Source : std::uint8_t {
        Environment,     ///< `LIBRESCRS_PLUGIN_DIR`
        BundleRelative,  ///< `<exe>/../PlugIns/librescrs` — the host bundle layout
        CompiledDefault, ///< the compiled-in install prefix; the terminal fallback
    };

    /// @brief What became of this candidate.
    enum class Verdict : std::uint8_t {
        Chosen,        ///< this is the directory the daemon will use
        Unset,         ///< the source produced no path at all
        NotADirectory, ///< it produced a path, but nothing is there
    };

    Source source{};
    /// @brief The path this source produced. Empty iff @ref Verdict::Unset.
    std::filesystem::path path;
    Verdict verdict{};
};

/// @brief The chosen plugin directory together with the full probe trail.
///
/// The last entry of @ref candidates is always the chosen one, and its path is
/// always @ref dir — the fallback is terminal, so resolution cannot come up
/// empty even when nothing exists on disk.
struct PluginDirResolution
{
    std::filesystem::path dir;
    std::vector<PluginDirCandidate> candidates;
};

/// @brief The three inputs to the cascade, injected so it can be exercised
///        without a real bundle on disk or a mutated environment.
struct PluginDirInputs
{
    /// @brief `LIBRESCRS_PLUGIN_DIR`; empty when unset.
    std::string environment;
    /// @brief The running binary's own path; `nullopt` when it cannot be found.
    std::optional<std::filesystem::path> executable;
    /// @brief The compiled-in install prefix.
    std::filesystem::path compiledDefault;
};

/// @brief Run the cascade: environment override, then the bundled `PlugIns`
///        directory next to the executable if it exists, then the compiled-in
///        default.
[[nodiscard]] PluginDirResolution resolvePluginDir(const PluginDirInputs& inputs);

/// @brief The running executable's own path via `_NSGetExecutablePath`
///        (there is no `/proc` on Darwin), canonicalised when possible.
/// @return `nullopt` if the path cannot be determined.
[[nodiscard]] std::optional<std::filesystem::path> currentExecutablePath();

/// @brief The lines describing a resolution and its load outcome, in order,
///        each carrying the severity it should be emitted at.
///
/// Split out from @ref reportPluginLoad so the wording and — above all — the
/// severity of the zero-plugin case are testable without a loadable plugin
/// binary on disk.
///
/// @param loaded Number of plugins the registry actually loaded.
/// @param report The registry's per-file load report.
[[nodiscard]] std::vector<std::pair<LibreSCRS::Agent::log::Level, std::string>>
pluginLoadReportLines(const PluginDirResolution& resolution, std::size_t loaded,
                      std::span<const LibreSCRS::Plugin::LoadOutcome> report);

/// @brief Emit @ref pluginLoadReportLines for @p service over the log facade.
void reportPluginLoad(const PluginDirResolution& resolution, const LibreSCRS::Plugin::CardPluginService& service);

} // namespace LibreSCRS::Darwin
