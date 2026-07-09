// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

namespace LibreSCRS::Darwin {

// The AppKit secure-credential window (NSSecureTextField). showPrompt marshals to
// the MAIN thread (dispatch_sync) so it is safe to call from the server's accept
// thread; it reads the entered secret out of the field BEFORE tearing the window
// down (read-before-hide) and scrubs the field. dismiss() aborts the active modal
// so an in-flight showPrompt returns Cancelled (the CancelCurrent path).
class PromptWindow
{
public:
    PromptWindow();
    ~PromptWindow();
    PromptWindow(const PromptWindow&) = delete;
    PromptWindow& operator=(const PromptWindow&) = delete;

    [[nodiscard]] wire::PromptReply showPrompt(const wire::PromptRequest& req);
    void dismiss();

private:
    struct Impl;
    Impl* m_impl;
};

} // namespace LibreSCRS::Darwin
