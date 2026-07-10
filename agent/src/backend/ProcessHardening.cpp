// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Process hardening for the secret-holding agent daemon. See the header for
// the placement contract (daemon main() only).
#include <LibreSCRS/Darwin/backend/ProcessHardening.h>

#include <sys/ptrace.h>
#include <sys/resource.h>

namespace LibreSCRS::Darwin {

bool hardenAgentProcess() noexcept
{
    // PT_DENY_ATTACH: subsequent ptrace attaches fail; an ALREADY-attached
    // tracer kills the process — intended when someone debugs the live daemon.
    const int denied = ::ptrace(PT_DENY_ATTACH, 0, nullptr, 0);
    const rlimit noCore{0, 0};
    const int limited = ::setrlimit(RLIMIT_CORE, &noCore);
    return denied == 0 && limited == 0;
}

} // namespace LibreSCRS::Darwin
