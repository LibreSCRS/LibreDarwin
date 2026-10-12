// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <span>
#include <string_view>

namespace LibreSCRS::Darwin {

// Anti-debug + no-core hardening for the two processes that hold a secret in
// plaintext: the agent (CAN/PIN, live PACE/SM keys) and the prompter (the
// secret as it is typed). The Linux twin sets PR_SET_DUMPABLE=0.
// ptrace(PT_DENY_ATTACH) refuses same-uid debugger attach and RLIMIT_CORE=0
// disables core dumps. This covers ad-hoc/dev builds; the hardened-runtime
// get-task-allow=false is the production backstop.
//
// Call it first in each binary's main(), before anything secret-bearing (for
// the prompter: before NSApplication and any window) exists — never from a
// library constructor, so test binaries linking this library stay attachable.
// Returns false when either call failed.
//
// Residual, not closed by this: in the prompter the typed secret passes
// through AppKit's NSSecureTextField buffer and the NSString copies made when
// it is read (PromptWindow.mm, readSecret). Those buffers are owned by AppKit
// and cannot be scrubbed; this hardening keeps other processes and crash dumps
// away from them, it does not erase them.
bool hardenSecretProcess() noexcept;

// Removes every environment variable not named in `keep`. `launchctl setenv`
// reaches every job in the user's launchd, and the code linked into the agent
// reads variables that name a PKCS#11 module, an OpenSC or OpenSSL
// configuration, a provider directory or trust anchors -- each a way to put
// someone else's code or roots into the process that receives the PIN. Keeping
// a list of what is needed closes the ones nobody has listed yet.
//
// Call it first in main(), before anything reads the environment. It cannot
// undo what was read before main(): the loader's DYLD_* (refused by the
// hardened runtime of a release bundle; the dev agent sets them on purpose)
// and the few variables libSystem reads at start-up.
void restrictEnvironment(std::span<const std::string_view> keep);

// What the agent keeps when it calls restrictEnvironment. TZ names zone data, not code.
inline constexpr std::string_view kAgentEnvironment[] = {"HOME", "TMPDIR", "TZ"};

} // namespace LibreSCRS::Darwin
