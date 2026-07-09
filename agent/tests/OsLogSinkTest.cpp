// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Smoke test for the os_log LogSink. os_log has no public readback, so this
// only asserts the sink is constructible, non-empty, and that emitting each
// severity does not throw / crash (the actual lines land in the unified log).
#include <LibreSCRS/Darwin/backend/OsLogSink.h>

#include <gtest/gtest.h>

namespace {

TEST(OsLogSink, ProducesANonEmptySink)
{
    auto sink = LibreSCRS::Darwin::makeOsLogSink();
    ASSERT_TRUE(static_cast<bool>(sink));
}

TEST(OsLogSink, EmitsEverySeverityWithoutThrowing)
{
    auto sink = LibreSCRS::Darwin::makeOsLogSink();
    EXPECT_NO_THROW(sink(LibreSCRS::Agent::log::Level::Info, "os_log sink smoke: info"));
    EXPECT_NO_THROW(sink(LibreSCRS::Agent::log::Level::Warn, "os_log sink smoke: warn"));
    EXPECT_NO_THROW(sink(LibreSCRS::Agent::log::Level::Error, "os_log sink smoke: error"));
}

} // namespace
