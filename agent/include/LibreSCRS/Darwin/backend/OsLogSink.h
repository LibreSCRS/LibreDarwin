// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/backend/Logging.h> // log::LogSink, log::Level

namespace LibreSCRS::Darwin {

// macOS LogSink backend: an injected sink (log::init(makeOsLogSink(), category))
// that routes the core's formatted log lines to the unified logging system
// (os_log) with a severity mapped from log::Level. The Linux twin is a journald
// syslog-priority-prefixed std::clog. Mirrors LibreMiddleware's Qt-free logging
// practice.
//
// The implementation maps Level{Info,Warn,Error} onto
// os_log_with_type(OS_LOG_TYPE_{INFO,DEFAULT,ERROR}) under a dedicated
// os_log_t subsystem ("rs.librescrs.agent"); it never logs secrets or clear PII.
[[nodiscard]] Agent::log::LogSink makeOsLogSink();

} // namespace LibreSCRS::Darwin
