// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

namespace LibreSCRS::Darwin {

// The agent's environment step, called first in its main(). LibreMiddleware's
// trace switches are read once per process; this has the logging facade read
// them now, then keeps only kAgentEnvironment (ProcessHardening.h). A trace
// switch turns on diagnostics that by the facade's contract never carry a
// card's answer, a PIN or decrypted data; unlike the variables cut here, it
// names no code, no configuration and no trust anchor. Lives in the agent
// backend, not beside restrictEnvironment, because it reaches the middleware.
void prepareAgentEnvironment();

} // namespace LibreSCRS::Darwin
