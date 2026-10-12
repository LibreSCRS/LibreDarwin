// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Internal to the module: not exported (the module exports C_GetFunctionList
// and nothing else), here so a test can point the factory at a socket of its
// own and see the peer check refuse it.
#pragma once

#include <LibreSCRS/Agent/pkcs11/AgentClient.h>

#include <memory>
#include <string>

namespace LibreSCRS::Pkcs11Agent {

/// @brief The module's client for the agent socket at @p socketPath, with the
///        check that the process serving it is the agent this build trusts.
///        makeAgentClient() is this at the agent's own socket path.
[[nodiscard]] std::unique_ptr<AgentClient> makeAgentClientAt(std::string socketPath);

} // namespace LibreSCRS::Pkcs11Agent
