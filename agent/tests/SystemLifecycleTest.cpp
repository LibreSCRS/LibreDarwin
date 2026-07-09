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

#include <vector>

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
