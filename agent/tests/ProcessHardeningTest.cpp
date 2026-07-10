// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Process hardening is asserted in a fork()ed child so PT_DENY_ATTACH never
// applies to the TEST process (debugging the suite must stay possible). A
// spawned-tracer PT_ATTACH probe is deliberately omitted: attach behaviour on
// macOS depends on SIP/entitlements and is not CI-stable; ptrace(PT_DENY_ATTACH)
// returning 0 (checked via the hardenAgentProcess result) is the kernel-level
// acknowledgement.
#include <LibreSCRS/Darwin/backend/ProcessHardening.h>

#include <gtest/gtest.h>

#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

TEST(ProcessHardening, ChildDropsCoreLimitAndDeniesAttach)
{
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        // Child: async-signal-safe calls only, then _exit with a failure code.
        if (!LibreSCRS::Darwin::hardenAgentProcess()) {
            ::_exit(1); // ptrace or setrlimit rejected
        }
        rlimit lim{};
        if (::getrlimit(RLIMIT_CORE, &lim) != 0) {
            ::_exit(2);
        }
        if (lim.rlim_cur != 0 || lim.rlim_max != 0) {
            ::_exit(3); // core dumps still possible
        }
        ::_exit(0);
    }
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}
