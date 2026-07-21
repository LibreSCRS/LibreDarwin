// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

namespace LibreSCRS::Darwin {

// The AppKit secure-credential window (NSSecureTextField). showPrompt and
// showChangePrompt marshal to the MAIN thread (dispatch_sync) so they are safe
// to call from the server's worker queue; they read the entered secrets out of
// the fields BEFORE tearing the window down (read-before-hide) and scrub the
// fields. dismiss() aborts the active modal so an in-flight
// showPrompt/showChangePrompt returns Cancelled (the CancelCurrent path).
class PromptWindow
{
public:
    PromptWindow();
    ~PromptWindow();
    PromptWindow(const PromptWindow&) = delete;
    PromptWindow& operator=(const PromptWindow&) = delete;

    [[nodiscard]] wire::PromptReply showPrompt(const wire::PromptRequest& req);
    // The multi-secret change modal (RequestSecrets, kind "change_pin"): three
    // secure fields — current / new / confirm — with per-role length gating on
    // OK. The confirm entry is validation-only and never leaves the window;
    // kinds this window does not implement return Error without any UI.
    [[nodiscard]] wire::MultiPromptReply showChangePrompt(const wire::RequestSecrets& req);
    void dismiss();

private:
    struct Impl;
    Impl* m_impl;
};

} // namespace LibreSCRS::Darwin
