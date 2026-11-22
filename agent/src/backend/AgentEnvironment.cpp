// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Darwin/backend/AgentEnvironment.h>

#include <LibreSCRS/Darwin/backend/ProcessHardening.h>
#include <LibreSCRS/Logging.h>

namespace LibreSCRS::Darwin {

void prepareAgentEnvironment()
{
    // Asking about one channel latches all of them (the facade's "read once").
    (void)LibreSCRS::log::traceEnabled(LibreSCRS::log::TraceChannel::Probe);
    restrictEnvironment(kAgentEnvironment);
}

} // namespace LibreSCRS::Darwin
