// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Logging.h> // log::LogSink, log::Level

namespace LibreSCRS::Darwin {

// macOS LogSink backend: the sink installed once into LibreMiddleware's facade
// (log::init(makeOsLogSink(), category)), which the agent core logs through as
// well, so the middleware's own lines and the agent's reach the unified logging
// system (os_log) alike, with a severity mapped from log::Level. The Linux twin
// is a journald syslog-priority-prefixed std::clog.
//
// The implementation maps Level{Trace,Info,Warn,Error} onto
// os_log_with_type(OS_LOG_TYPE_{DEBUG,INFO,DEFAULT,ERROR}) under a dedicated
// os_log_t subsystem ("rs.librescrs.agent"); it never logs secrets or clear PII.
[[nodiscard]] LibreSCRS::log::LogSink makeOsLogSink();

} // namespace LibreSCRS::Darwin
