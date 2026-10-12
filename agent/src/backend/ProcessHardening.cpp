// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Process hardening for the secret-holding agent and prompter. See the header
// for the placement contract (each binary's main() only).
#include <LibreSCRS/Darwin/backend/ProcessHardening.h>

#include <crt_externs.h>
#include <sys/ptrace.h>
#include <sys/resource.h>

#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

namespace LibreSCRS::Darwin {

bool hardenSecretProcess() noexcept
{
    // PT_DENY_ATTACH: subsequent ptrace attaches fail; an ALREADY-attached
    // tracer kills the process — intended when someone debugs the live process.
    const int denied = ::ptrace(PT_DENY_ATTACH, 0, nullptr, 0);
    const rlimit noCore{0, 0};
    const int limited = ::setrlimit(RLIMIT_CORE, &noCore);
    return denied == 0 && limited == 0;
}

void restrictEnvironment(std::span<const std::string_view> keep)
{
    // Collect first: unsetenv rewrites the array being walked.
    std::vector<std::string> drop;
    for (char** entry = *_NSGetEnviron(); entry != nullptr && *entry != nullptr; ++entry) {
        const std::string_view pair{*entry};
        const std::string_view name = pair.substr(0, pair.find('='));
        if (std::ranges::find(keep, name) == keep.end()) {
            drop.emplace_back(name);
        }
    }
    for (const auto& name : drop) {
        ::unsetenv(name.c_str());
    }
}

} // namespace LibreSCRS::Darwin
