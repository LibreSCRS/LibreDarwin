// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Objective-C++ implementation of the macOS lifecycle subscriber. Uses
// NSWorkspace (sleep/wake/session/power-off), DistributedNotificationCenter (the
// private com.apple.screenIsLocked / …Unlocked — best-effort), and IOKit
// (IORegisterForSystemPower, pumped on the main run loop) so a will-sleep is seen
// even if the NSWorkspace path is delayed. Every observer forwards to the C++
// handler on the main thread.
#include <LibreSCRS/Darwin/backend/SystemLifecycle.h>

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

#include <vector>

namespace LibreSCRS::Darwin {

namespace {

// Heap refcon for the IOKit power callback (anon-namespace type so the callback
// can access it, unlike the private nested Impl): the owner to notify + the root
// port to acknowledge the sleep on. Owned by Impl; rootPort is filled in after
// IORegisterForSystemPower returns (the callback only fires on real sleep, later).
struct IoRefcon
{
    SystemLifecycle* owner{nullptr};
    io_connect_t rootPort{0};
};

// IOKit system-power callback: acknowledge sleep immediately (we do NOT delay the
// sleep — the scrub is fast and cooperative) and forward the will-sleep as a
// Suspend.
void ioPowerCallback(void* refcon, io_service_t /*service*/, natural_t messageType, void* messageArgument)
{
    auto* rc = static_cast<IoRefcon*>(refcon);
    switch (messageType) {
    case kIOMessageSystemWillSleep:
        if (rc->owner != nullptr) {
            rc->owner->injectForTest(SystemLifecycle::Event::Suspend);
        }
        // Allow the sleep to proceed without delay.
        IOAllowPowerChange(rc->rootPort, reinterpret_cast<intptr_t>(messageArgument));
        break;
    case kIOMessageSystemHasPoweredOn:
        if (rc->owner != nullptr) {
            rc->owner->injectForTest(SystemLifecycle::Event::Resume);
        }
        break;
    default:
        break;
    }
}

} // namespace

struct SystemLifecycle::Impl
{
    std::unique_ptr<IoRefcon> ioRefcon; // owner + rootPort for the IOKit callback
    std::vector<id> tokens;             // NSNotificationCenter observer tokens
    io_connect_t rootPort{0};           // IORegisterForSystemPower connection
    IONotificationPortRef ioPort{nullptr};
    io_object_t ioNotifier{0};
    bool started{false};
};

SystemLifecycle::SystemLifecycle(Handler handler) : m_handler(std::move(handler)), m_impl(std::make_unique<Impl>())
{
    m_impl->ioRefcon = std::make_unique<IoRefcon>();
    m_impl->ioRefcon->owner = this;
}

SystemLifecycle::~SystemLifecycle()
{
    stop();
}

void SystemLifecycle::injectForTest(Event event)
{
    if (m_handler) {
        m_handler(event);
    }
}

void SystemLifecycle::start()
{
    if (m_impl->started) {
        return;
    }
    m_impl->started = true;

    // NSWorkspace notifications (sleep/wake, fast-user-switch, power-off) fire on
    // the main run loop. Each block forwards the mapped Event to the C++ handler.
    NSNotificationCenter* ws = [[NSWorkspace sharedWorkspace] notificationCenter];
    auto observe = [&](NSNotificationName name, Event event) {
        id token = [ws addObserverForName:name
                                   object:nil
                                    queue:[NSOperationQueue mainQueue]
                               usingBlock:^(NSNotification*) {
                                 this->injectForTest(event);
                               }];
        m_impl->tokens.push_back(token);
    };
    observe(NSWorkspaceWillSleepNotification, Event::Suspend);
    observe(NSWorkspaceDidWakeNotification, Event::Resume);
    observe(NSWorkspaceSessionDidResignActiveNotification, Event::SessionResign);
    observe(NSWorkspaceSessionDidBecomeActiveNotification, Event::SessionActive);
    observe(NSWorkspaceWillPowerOffNotification, Event::PowerOff);

    // Screen lock/unlock ride the PRIVATE distributed notifications — best-effort
    // hardening (may be silently absent on a future macOS; the lease idle/hard-max
    // caps already bound exposure). Degrade gracefully.
    NSDistributedNotificationCenter* dc = [NSDistributedNotificationCenter defaultCenter];
    auto observeDist = [&](NSString* name, Event event) {
        id token = [dc addObserverForName:name
                                   object:nil
                                    queue:[NSOperationQueue mainQueue]
                               usingBlock:^(NSNotification*) {
                                 this->injectForTest(event);
                               }];
        m_impl->tokens.push_back(token);
    };
    observeDist(@"com.apple.screenIsLocked", Event::ScreenLock);
    observeDist(@"com.apple.screenIsUnlocked", Event::ScreenUnlock);

    // IOKit system-power: a second, lower-level will-sleep source (the NSWorkspace
    // path can be delayed under load). Pumped on the main run loop.
    m_impl->rootPort =
        IORegisterForSystemPower(m_impl->ioRefcon.get(), &m_impl->ioPort, ioPowerCallback, &m_impl->ioNotifier);
    if (m_impl->rootPort != MACH_PORT_NULL) {
        m_impl->ioRefcon->rootPort = m_impl->rootPort;
        CFRunLoopAddSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(m_impl->ioPort),
                           kCFRunLoopCommonModes);
    }
}

void SystemLifecycle::stop() noexcept
{
    if (!m_impl || !m_impl->started) {
        return;
    }
    m_impl->started = false;

    NSNotificationCenter* ws = [[NSWorkspace sharedWorkspace] notificationCenter];
    NSDistributedNotificationCenter* dc = [NSDistributedNotificationCenter defaultCenter];
    for (id token : m_impl->tokens) {
        [ws removeObserver:token];
        [dc removeObserver:token];
    }
    m_impl->tokens.clear();

    if (m_impl->rootPort != MACH_PORT_NULL) {
        if (m_impl->ioPort != nullptr) {
            CFRunLoopRemoveSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(m_impl->ioPort),
                                  kCFRunLoopCommonModes);
        }
        IODeregisterForSystemPower(&m_impl->ioNotifier);
        IOServiceClose(m_impl->rootPort);
        IONotificationPortDestroy(m_impl->ioPort);
        m_impl->rootPort = 0;
        m_impl->ioPort = nullptr;
        m_impl->ioNotifier = 0;
    }
}

} // namespace LibreSCRS::Darwin
