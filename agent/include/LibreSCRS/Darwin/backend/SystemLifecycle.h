// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/QuiesceReason.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace LibreSCRS::Darwin {

// macOS power/session lifecycle subscriber. The neutral core has no concept of
// system sleep or a screen lock; this backend piece subscribes to the platform
// notifications and drives the injected reaction handler, which hands the
// event's quiesce reason (quiesceReasonFor below) to the core's one quiesce
// policy and broadcasts AgentQuiesced with the same reason.
//
// Sleep teardown is REQUIRED, not merely prudent: a USB reader loses power on
// sleep, so the PC/SC + SM (PACE) session is invalid after wake and the next op
// MUST re-open + re-PACE. Screen lock is best-effort hardening (the private
// com.apple.screenIsLocked notification) on top of the lease idle/hard-max caps.
//
// THREADING: the real notifications deliver on the main CFRunLoop thread, so the
// handler runs there; it MUST marshal any loop-affine transport work via post().
// start() needs a live CFRunLoopRun(). The handler is also driven by
// injectForTest for hermetic unit tests (no real notifications).
class SystemLifecycle
{
public:
    enum class Event : std::uint8_t {
        Suspend,       // system will sleep -> SystemSleep (session invalid after wake)
        Resume,        // system did wake -> next op re-acquires (no quiesce)
        ScreenLock,    // screen locked -> ScreenLocked (re-PIN next op)
        ScreenUnlock,  // screen unlocked -> no-op
        SessionResign, // fast-user-switch away -> SessionInactive (another user is active)
        SessionActive, // fast-user-switch back -> no-op
        PowerOff,      // logout / power off -> terminal quiesce (like SIGTERM)
    };
    using Handler = std::function<void(Event)>;

    explicit SystemLifecycle(Handler handler);
    ~SystemLifecycle();
    SystemLifecycle(const SystemLifecycle&) = delete;
    SystemLifecycle& operator=(const SystemLifecycle&) = delete;

    // Register for the macOS power/session notifications. Idempotent.
    void start();
    // Deregister all observers. Idempotent + noexcept (safe in a destructor).
    void stop() noexcept;

    // Test hook: drive the handler with @p event exactly as a real notification
    // would (no platform registration needed).
    void injectForTest(Event event);

private:
    Handler m_handler;
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// The reason @p event quiesces card access, which the agent hands to
// AgentCore::quiesce() and then announces; nullopt for an event that leaves
// the agent as it is (wake, unlock, switching back -- the next operation
// re-acquires) and for PowerOff, which stops the agent instead. What each
// reason forgets is the core's policy, not this host's.
[[nodiscard]] constexpr std::optional<Agent::QuiesceReason> quiesceReasonFor(SystemLifecycle::Event event) noexcept
{
    using Event = SystemLifecycle::Event;
    switch (event) {
    case Event::Suspend:
        return Agent::QuiesceReason::SystemSleep;
    case Event::SessionResign:
        return Agent::QuiesceReason::SessionInactive;
    case Event::ScreenLock:
        return Agent::QuiesceReason::ScreenLocked;
    case Event::Resume:
    case Event::ScreenUnlock:
    case Event::SessionActive:
    case Event::PowerOff:
        break;
    }
    return std::nullopt;
}

// Test hook (keeps this header IOKit-free): drive the private IOKit power
// callback with @p messageType / @p messageArgument against a fake ack sink.
// Returns true when the callback acknowledged the message; @p ackedArgument
// then carries the messageArgument it acknowledged (untouched otherwise).
bool drivePowerCallbackForTest(SystemLifecycle& owner, std::uint32_t messageType, std::uintptr_t messageArgument,
                               std::uintptr_t& ackedArgument);

} // namespace LibreSCRS::Darwin
