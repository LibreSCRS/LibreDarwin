// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Process hardening is asserted in a fork()ed child so PT_DENY_ATTACH never
// applies to the TEST process (debugging the suite must stay possible). A
// spawned-tracer PT_ATTACH probe is deliberately omitted: attach behaviour on
// macOS depends on SIP/entitlements and is not CI-stable; ptrace(PT_DENY_ATTACH)
// returning 0 (checked via the hardenSecretProcess result) is the kernel-level
// acknowledgement.
#include <LibreSCRS/Darwin/backend/ProcessHardening.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <string_view>

#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

TEST(ProcessHardening, ChildDropsCoreLimitAndDeniesAttach)
{
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        // Child: async-signal-safe calls only, then _exit with a failure code.
        if (!LibreSCRS::Darwin::hardenSecretProcess()) {
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

// The agent keeps only the variables it names. Checked in a fork()ed child so
// the test process keeps its own environment.
TEST(ProcessHardening, ChildKeepsOnlyTheNamedEnvironment)
{
    const pid_t child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        ::setenv("HOME", "/kept/home", 1);
        ::setenv("TZ", "UTC", 1);
        ::setenv("LIBRESCRS_PKCS11_MODULE", "/tmp/foreign.dylib", 1);
        ::setenv("OPENSC_CONF", "/tmp/foreign.conf", 1);
        ::setenv("OPENSSL_MODULES", "/tmp/foreign", 1);
        ::setenv("SSL_CERT_DIR", "/tmp/foreign", 1);
        ::setenv("HOMEX", "/tmp/foreign", 1); // shares a prefix with a kept name
        ::unsetenv("TMPDIR");

        // The list the agent's main() passes; the expectations below are
        // written for exactly HOME, TMPDIR and TZ.
        constexpr std::string_view expected[] = {"HOME", "TMPDIR", "TZ"};
        if (!std::ranges::equal(LibreSCRS::Darwin::kAgentEnvironment, expected)) {
            ::_exit(4); // the agent's list changed; these expectations no longer cover it
        }
        LibreSCRS::Darwin::restrictEnvironment(LibreSCRS::Darwin::kAgentEnvironment);

        for (const char* gone :
             {"LIBRESCRS_PKCS11_MODULE", "OPENSC_CONF", "OPENSSL_MODULES", "SSL_CERT_DIR", "HOMEX"}) {
            if (::getenv(gone) != nullptr) {
                ::_exit(1); // a variable nobody named survived
            }
        }
        const char* home = ::getenv("HOME");
        const char* tz = ::getenv("TZ");
        if (home == nullptr || std::string_view{home} != "/kept/home" || tz == nullptr ||
            std::string_view{tz} != "UTC") {
            ::_exit(2); // a named variable was dropped or changed
        }
        if (::getenv("TMPDIR") != nullptr) {
            ::_exit(3); // a named but unset variable appeared
        }
        ::_exit(0);
    }
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 0);
}
