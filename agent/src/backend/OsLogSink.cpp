// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// macOS LogSink backend: routes the core's formatted log lines to the unified
// logging system (os_log) under the subsystem "rs.librescrs.agent", category
// "backend", mapping log::Level{Info,Warn,Error} onto
// os_log_with_type(OS_LOG_TYPE_{INFO,DEFAULT,ERROR}). The Linux twin is a
// journald syslog-priority-prefixed std::clog; this mirrors LibreMiddleware's
// Qt-free logging practice. The core's logging discipline keeps secrets/clear
// PII out of log lines (same contract as the Linux journald sink), so the line
// is emitted %{public}.
#include <LibreSCRS/Darwin/backend/OsLogSink.h>

#include <os/log.h>

#include <string>
#include <string_view>

namespace LibreSCRS::Darwin {

Agent::log::LogSink makeOsLogSink()
{
    // One process-lifetime os_log handle (intentionally never released — it lives
    // for the whole agent process, like the Linux std::clog stream).
    static os_log_t handle = os_log_create("rs.librescrs.agent", "backend");

    return [](Agent::log::Level level, std::string_view line) {
        os_log_type_t type = OS_LOG_TYPE_INFO;
        switch (level) {
        case Agent::log::Level::Info:
            type = OS_LOG_TYPE_INFO;
            break;
        case Agent::log::Level::Warn:
            type = OS_LOG_TYPE_DEFAULT;
            break;
        case Agent::log::Level::Error:
            type = OS_LOG_TYPE_ERROR;
            break;
        }
        // os_log needs a NUL-terminated C string; the line is already a fully
        // formatted, non-secret diagnostic from the core log facade.
        const std::string buffer(line);
        os_log_with_type(handle, type, "%{public}s", buffer.c_str());
    };
}

} // namespace LibreSCRS::Darwin
