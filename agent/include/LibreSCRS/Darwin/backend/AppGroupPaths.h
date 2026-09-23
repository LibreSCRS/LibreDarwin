// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <filesystem>

namespace LibreSCRS::Darwin {

// The REAL user home directory, bypassing $HOME. Under App Sandbox, $HOME is
// silently redirected to the process's private container
// (~/Library/Containers/<bundle-id>/Data), NOT the shared App-Group container —
// so a sandboxed process that trusted $HOME would materialize its socket/cache/
// config under a path its peers can never reach. getpwuid(getuid()) reads the
// real passwd-database home, which the sandbox does not redirect. Falls back to
// $HOME (then the temp dir) if the passwd lookup fails.
[[nodiscard]] std::filesystem::path realHomeDir();

// The shared App-Group container (kAppGroup) BOTH agent-owned binaries must
// resolve identically: the agent binds agent.sock + connects prompter.sock
// here, and the prompter serves prompter.sock from the same place — any drift
// in the group id or the sandbox-bypass rationale would silently split the two
// binaries. There is no override: the location is where the host, the token
// extension and both binaries meet, and a variable that moved it would move
// the agent's sockets for anyone able to set the user's environment.
[[nodiscard]] std::filesystem::path appGroupContainerDir();

} // namespace LibreSCRS::Darwin
