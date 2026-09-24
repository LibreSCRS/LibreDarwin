// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <expected>
#include <functional>
#include <string>

// The prompter's startup order, kept out of PrompterMain.mm so it can be tested
// without AppKit: main() supplies the real steps, a test supplies recorders.
namespace LibreSCRS::Darwin::PrompterComposition {

struct Hooks
{
    // Deny debugger attach and core dumps (hardenSecretProcess). Runs first,
    // before anything that could come to hold a secret exists; false means the
    // hardening is incomplete, which is reported through `warn` and is not fatal
    // (the agent treats it the same way).
    std::function<bool()> harden;
    // Create the application object (NSApplication, activation policy). The
    // window that will hold the typed secret belongs to it.
    std::function<void()> appInit;
    // Build and start the socket server; an error is reported and ends the
    // process before the run loop starts.
    std::function<std::expected<void, std::string>()> bind;
    // Run until the process ends.
    std::function<void()> runLoop;
    std::function<void(const std::string&)> warn;
};

// Calls harden -> appInit -> bind -> runLoop and returns the process exit code:
// 0 after the run loop returns, 1 when bind failed (the run loop never starts).
int run(const Hooks& hooks);

} // namespace LibreSCRS::Darwin::PrompterComposition
