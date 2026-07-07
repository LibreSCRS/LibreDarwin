// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SKELETON — a std::clog placeholder sink (TODO P1b: switch to os_log).
#include <LibreSCRS/Darwin/backend/OsLogSink.h>

#include <iostream>
#include <string_view>

namespace LibreSCRS::Darwin {

Agent::log::LogSink makeOsLogSink()
{
    // TODO(P1b): route to os_log_with_type under os_log_t("rs.librescrs.agent"),
    // mapping Level{Info,Warn,Error} -> OS_LOG_TYPE_{INFO,DEFAULT,ERROR}. Never
    // log secrets or clear PII. Placeholder writes a prefixed line to std::clog.
    return [](Agent::log::Level level, std::string_view line) {
        const char* tag = level == Agent::log::Level::Error  ? "ERR "
                          : level == Agent::log::Level::Warn ? "WARN"
                                                             : "INFO";
        std::clog << "[rs.librescrs.agent] " << tag << ' ' << line << '\n';
    };
}

} // namespace LibreSCRS::Darwin
