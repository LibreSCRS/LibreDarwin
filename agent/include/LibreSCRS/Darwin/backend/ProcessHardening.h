// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

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

} // namespace LibreSCRS::Darwin
