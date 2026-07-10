// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

namespace LibreSCRS::Darwin {

// Anti-debug + no-core hardening for the agent process, which holds plaintext
// CAN/PIN and live PACE/SM keys (the Linux twin sets PR_SET_DUMPABLE=0):
// ptrace(PT_DENY_ATTACH) refuses same-uid debugger attach and RLIMIT_CORE=0
// disables core dumps. This covers ad-hoc/dev builds; the hardened-runtime
// get-task-allow=false is the production backstop. Call from the DAEMON's
// main() only — never from a library constructor — so test binaries linking
// the backend stay attachable. Returns false when either call failed.
bool hardenAgentProcess() noexcept;

} // namespace LibreSCRS::Darwin
