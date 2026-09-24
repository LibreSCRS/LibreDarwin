// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The prompter holds the typed secret, so it must be hardened before any window
// exists. Two halves: (1) hardenSecretProcess() in a fork()ed child — never in
// the test process, which must stay debuggable — observed from outside: a probe
// that tries to attach to the hardened child is killed by the kernel with
// SIGSEGV, while the same probe against an unhardened child is merely refused;
// (2) PrompterComposition::run() calls its hooks in the order harden -> selfCheck -> appInit
// -> bind -> runLoop, so the step that creates NSApplication (and later the
// window) can never run before the hardening.
#include "PrompterComposition.h"

#include <LibreSCRS/Darwin/backend/ProcessHardening.h>

#include <gtest/gtest.h>

#include <csignal>
#include <expected>
#include <string>
#include <vector>

#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

namespace Composition = LibreSCRS::Darwin::PrompterComposition;

// Child exit codes, reported to the parent through the pipe before pause().
constexpr char kChildReady = 'R';
constexpr char kHardenFailed = 'H';
constexpr char kCoreLimitNotZero = 'C';

// Forks a child that optionally hardens itself, checks RLIMIT_CORE, reports one
// byte and waits to be killed. Async-signal-safe calls only in the child.
pid_t spawnTarget(bool harden, char& report)
{
    int fds[2];
    if (::pipe(fds) != 0) {
        return -1;
    }
    const pid_t child = ::fork();
    if (child == 0) {
        ::close(fds[0]);
        char status = kChildReady;
        if (harden) {
            rlimit lim{};
            if (!LibreSCRS::Darwin::hardenSecretProcess()) {
                status = kHardenFailed;
            } else if (::getrlimit(RLIMIT_CORE, &lim) != 0 || lim.rlim_cur != 0 || lim.rlim_max != 0) {
                status = kCoreLimitNotZero;
            }
        }
        (void)::write(fds[1], &status, 1);
        for (;;) {
            ::pause();
        }
    }
    ::close(fds[1]);
    report = 0;
    if (child > 0 && ::read(fds[0], &report, 1) != 1) {
        report = 0;
    }
    ::close(fds[0]);
    return child;
}

// Forks a probe that tries to attach to `target` and returns its wait status.
// A probe that survives exits 0 (attach refused with an error) or 1 (attach
// succeeded, which it then undoes).
int probeAttach(pid_t target)
{
    const pid_t probe = ::fork();
    if (probe == 0) {
        if (::ptrace(PT_ATTACHEXC, target, nullptr, 0) == 0) {
            (void)::ptrace(PT_DETACH, target, nullptr, 0);
            ::_exit(1);
        }
        ::_exit(0);
    }
    int status = 0;
    if (probe < 0 || ::waitpid(probe, &status, 0) != probe) {
        return -1;
    }
    return status;
}

void reap(pid_t child)
{
    ::kill(child, SIGKILL);
    int status = 0;
    (void)::waitpid(child, &status, 0);
}

} // namespace

TEST(PrompterHardening, HardenedChildDropsCoreLimitAndKillsAnAttachingProbe)
{
    char report = 0;
    const pid_t hardened = spawnTarget(true, report);
    ASSERT_GT(hardened, 0);
    EXPECT_EQ(report, kChildReady) << "H = ptrace/setrlimit rejected, C = core dumps still possible";

    const int status = probeAttach(hardened);
    reap(hardened);
    ASSERT_TRUE(WIFSIGNALED(status)) << "probe was not killed; wait status " << status;
    EXPECT_EQ(WTERMSIG(status), SIGSEGV);
}

// The control that gives the assertion above its meaning: without the
// hardening the same probe is refused (or succeeds) but is never killed.
TEST(PrompterHardening, UnhardenedChildLeavesTheProbeAlive)
{
    char report = 0;
    const pid_t plain = spawnTarget(false, report);
    ASSERT_GT(plain, 0);
    EXPECT_EQ(report, kChildReady);

    const int status = probeAttach(plain);
    reap(plain);
    EXPECT_TRUE(WIFEXITED(status)) << "wait status " << status;
}

namespace {

struct Recorder
{
    std::vector<std::string> calls;
    std::vector<std::string> warnings;

    Composition::Hooks hooks(bool hardenResult = true, std::expected<void, std::string> bindResult = {},
                             bool selfCheckResult = true)
    {
        return Composition::Hooks{
            .harden =
                [this, hardenResult] {
                    calls.emplace_back("harden");
                    return hardenResult;
                },
            .selfCheck =
                [this, selfCheckResult] {
                    calls.emplace_back("selfCheck");
                    return selfCheckResult;
                },
            .appInit = [this] { calls.emplace_back("appInit"); },
            .bind =
                [this, bindResult] {
                    calls.emplace_back("bind");
                    return bindResult;
                },
            .runLoop = [this] { calls.emplace_back("runLoop"); },
            .warn = [this](const std::string& message) { warnings.push_back(message); },
        };
    }
};

} // namespace

TEST(PrompterComposition, HardensBeforeTheApplicationExistsAndBeforeTheSocketIsBound)
{
    Recorder recorder;
    EXPECT_EQ(Composition::run(recorder.hooks()), 0);
    EXPECT_EQ(recorder.calls, (std::vector<std::string>{"harden", "selfCheck", "appInit", "bind", "runLoop"}));
    EXPECT_TRUE(recorder.warnings.empty());
}

TEST(PrompterComposition, IncompleteHardeningIsReportedAndDoesNotReorderTheRest)
{
    Recorder recorder;
    EXPECT_EQ(Composition::run(recorder.hooks(false)), 0);
    EXPECT_EQ(recorder.calls, (std::vector<std::string>{"harden", "selfCheck", "appInit", "bind", "runLoop"}));
    ASSERT_EQ(recorder.warnings.size(), 1u);
}

TEST(PrompterComposition, FailedBindExitsNonZeroWithoutRunningTheLoop)
{
    Recorder recorder;
    EXPECT_NE(Composition::run(recorder.hooks(true, std::unexpected(std::string("bind refused")))), 0);
    EXPECT_EQ(recorder.calls, (std::vector<std::string>{"harden", "selfCheck", "appInit", "bind"}));
    ASSERT_EQ(recorder.warnings.size(), 1u);
    EXPECT_NE(recorder.warnings.front().find("bind refused"), std::string::npos);
}

TEST(PrompterComposition, FailedSelfCheckExitsTwoBeforeTheApplicationOrTheSocket)
{
    // A build that names a team id but was not signed by that team refuses to
    // start, with the cause, instead of standing up a window its agent would
    // then refuse to talk to.
    Recorder recorder;
    EXPECT_EQ(Composition::run(recorder.hooks(true, {}, false)), 2);
    EXPECT_EQ(recorder.calls, (std::vector<std::string>{"harden", "selfCheck"}));
    ASSERT_EQ(recorder.warnings.size(), 1u);
    EXPECT_NE(recorder.warnings.front().find("not signed by that team"), std::string::npos);
}
