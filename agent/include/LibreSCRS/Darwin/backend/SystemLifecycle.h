// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <cstdint>
#include <functional>
#include <memory>

namespace LibreSCRS::Darwin {

// macOS power/session lifecycle subscriber. The neutral core has no concept of
// system sleep or a screen lock; this backend piece subscribes to the platform
// notifications and drives the injected reaction handler, which composes the
// core's neutral scrub entry points (cancel in-flight ops + invalidate the
// per-reader CardSession, scrub the CredentialCache, revoke PKCS#11 leases) and
// broadcasts AgentQuiesced.
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
        Suspend,       // system will sleep -> full scrub (session invalid after wake)
        Resume,        // system did wake -> next op re-acquires (no scrub)
        ScreenLock,    // screen locked -> revoke PKCS#11 leases only (re-PIN next op)
        ScreenUnlock,  // screen unlocked -> no-op
        SessionResign, // fast-user-switch away -> full scrub (another user is active)
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

// Test hook (keeps this header IOKit-free): drive the private IOKit power
// callback with @p messageType / @p messageArgument against a fake ack sink.
// Returns true when the callback acknowledged the message; @p ackedArgument
// then carries the messageArgument it acknowledged (untouched otherwise).
bool drivePowerCallbackForTest(SystemLifecycle& owner, std::uint32_t messageType, std::uintptr_t messageArgument,
                               std::uintptr_t& ackedArgument);

} // namespace LibreSCRS::Darwin
