// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SystemLifecycle event routing: injected events drive the handler exactly as a
// real notification would; start()/stop() are idempotent + crash-free without a
// running CFRunLoop. The real notifications (sleep/lock/user-switch) are
// exercised in the hardware acceptance gate. Card/reader hotplug is deliberately
// NOT a lifecycle event (it is PC/SC, handled by the core MonitorService), so
// there is no hotplug enumerator to double-handle.
#include <LibreSCRS/Darwin/backend/SystemLifecycle.h>

#include <gtest/gtest.h>

#include <IOKit/IOMessage.h>

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <vector>

using LibreSCRS::Darwin::drivePowerCallbackForTest;
using LibreSCRS::Darwin::SystemLifecycle;
using Event = SystemLifecycle::Event;

TEST(SystemLifecycle, InjectedEventReachesHandler)
{
    std::vector<Event> seen;
    SystemLifecycle lifecycle([&](Event e) { seen.push_back(e); });

    lifecycle.injectForTest(Event::Suspend);
    lifecycle.injectForTest(Event::Resume);
    lifecycle.injectForTest(Event::ScreenLock);
    lifecycle.injectForTest(Event::ScreenUnlock);
    lifecycle.injectForTest(Event::SessionResign);
    lifecycle.injectForTest(Event::SessionActive);
    lifecycle.injectForTest(Event::PowerOff);

    ASSERT_EQ(seen.size(), 7u);
    EXPECT_EQ(seen[0], Event::Suspend);
    EXPECT_EQ(seen[1], Event::Resume);
    EXPECT_EQ(seen[2], Event::ScreenLock);
    EXPECT_EQ(seen[3], Event::ScreenUnlock);
    EXPECT_EQ(seen[4], Event::SessionResign);
    EXPECT_EQ(seen[5], Event::SessionActive);
    EXPECT_EQ(seen[6], Event::PowerOff);
}

// What the agent hands the core's quiesce policy for each event. A sleep and a
// switch away must name the reasons that forget the secrets and the sessions;
// a lock names the one that only re-asks for the PIN; the rest quiesce nothing
// (PowerOff stops the agent through SIGTERM instead). Every event is listed, so
// an event added without a decision here fails to be named rather than
// quiescing silently.
TEST(SystemLifecycle, EachEventQuiescesForItsOwnReason)
{
    using LibreSCRS::Agent::QuiesceReason;
    using LibreSCRS::Darwin::quiesceReasonFor;
    struct Row
    {
        Event event;
        std::optional<QuiesceReason> reason;
    };
    const Row rows[] = {
        {.event = Event::Suspend, .reason = QuiesceReason::SystemSleep},
        {.event = Event::Resume, .reason = std::nullopt},
        {.event = Event::ScreenLock, .reason = QuiesceReason::ScreenLocked},
        {.event = Event::ScreenUnlock, .reason = std::nullopt},
        {.event = Event::SessionResign, .reason = QuiesceReason::SessionInactive},
        {.event = Event::SessionActive, .reason = std::nullopt},
        {.event = Event::PowerOff, .reason = std::nullopt},
    };
    ASSERT_EQ(std::size(rows), static_cast<std::size_t>(Event::PowerOff) + 1);
    for (std::size_t i = 0; i < std::size(rows); ++i) {
        ASSERT_EQ(static_cast<std::size_t>(rows[i].event), i) << "one row per event, in declaration order";
        EXPECT_EQ(quiesceReasonFor(rows[i].event), rows[i].reason) << "event " << i;
    }
}

TEST(SystemLifecycle, StartStopAreIdempotentAndCrashFree)
{
    int calls = 0;
    SystemLifecycle lifecycle([&](Event) { ++calls; });
    // Registers the NSWorkspace/IOKit observers; without a running CFRunLoop they
    // simply never fire. Must not crash, and must be idempotent.
    lifecycle.start();
    lifecycle.start();
    lifecycle.stop();
    lifecycle.stop();
    // No real notification fired, so the handler was never called.
    EXPECT_EQ(calls, 0);
}

TEST(SystemLifecycle, HandlerlessInjectIsSafe)
{
    SystemLifecycle lifecycle({});
    // A null handler must be a no-op, not a crash.
    lifecycle.injectForTest(Event::Suspend);
    SUCCEED();
}

TEST(SystemLifecycle, CanSystemSleepIsAcknowledgedWithoutSuspend)
{
    // The idle-sleep QUERY must be answered (never veto) — an unanswered query
    // delays every system idle sleep by the ~30 s PM timeout — and must NOT
    // scrub (no Suspend; that stays on the will-sleep path).
    std::vector<Event> seen;
    SystemLifecycle lifecycle([&](Event e) { seen.push_back(e); });

    std::uintptr_t acked = 0;
    EXPECT_TRUE(drivePowerCallbackForTest(lifecycle, kIOMessageCanSystemSleep, 0xBEEF, acked));
    EXPECT_EQ(acked, 0xBEEFu); // the messageArgument was passed through to the ack
    EXPECT_TRUE(seen.empty());
}

TEST(SystemLifecycle, WillSleepAcknowledgesAndSuspends)
{
    std::vector<Event> seen;
    SystemLifecycle lifecycle([&](Event e) { seen.push_back(e); });

    std::uintptr_t acked = 0;
    EXPECT_TRUE(drivePowerCallbackForTest(lifecycle, kIOMessageSystemWillSleep, 0xCAFE, acked));
    EXPECT_EQ(acked, 0xCAFEu);
    ASSERT_EQ(seen.size(), 1u);
    EXPECT_EQ(seen[0], Event::Suspend);
}

TEST(SystemLifecycle, PoweredOnResumesWithoutAck)
{
    std::vector<Event> seen;
    SystemLifecycle lifecycle([&](Event e) { seen.push_back(e); });

    std::uintptr_t acked = 0;
    EXPECT_FALSE(drivePowerCallbackForTest(lifecycle, kIOMessageSystemHasPoweredOn, 0x1, acked));
    EXPECT_EQ(acked, 0u);
    ASSERT_EQ(seen.size(), 1u);
    EXPECT_EQ(seen[0], Event::Resume);
}
