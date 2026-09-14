// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <cstdint>
#include <string>
#include <vector>

#ifdef __OBJC__
@class NSString;
#endif

namespace LibreSCRS::Darwin {

#ifdef __OBJC__
// Every word the prompter's dialogs show goes through here. The prompter runs
// from Contents/MacOS of the host application's bundle, so `[NSBundle
// mainBundle]` IS that application and its catalogue is the one the holder
// already reads the rest of the app in; @p key is looked up there and @p
// fallback -- today's English, byte for byte -- is what shows when the lookup
// finds nothing, which is what happens outside a bundle (a development or
// build-directory prompter). Declared here, beside the dialogs, because the
// device-owner confirmation in ConfirmAuthorizer.mm is the second dialog and
// must resolve its sentence the same way.
NSString* localized(const char* key, const std::string& fallback);
#endif

// The AppKit secure-credential surface: ONE non-modal floating panel per
// prompt, held in a registry keyed by the prompt id. Several prompts stand at
// once — a second reader's request opens beside the first instead of queueing
// behind it — and each panel counts its own entry budget down on screen,
// answering Timeout when it runs out.
//
// Threading: showPrompt and showChangePrompt build their panel on the MAIN
// thread and then block the CALLING thread on that panel's own semaphore until
// the panel is answered, dismissed, or expires. They are meant for the server's
// concurrent worker queue and refuse the main thread — the thread that has to
// run the panel — with an Error reply rather than waiting there for a signal
// that could then never come. dismiss / dismissAll / liveIds are safe from any
// thread, the main one included.
//
// The entered secrets are read out of the fields BEFORE the panel comes down
// (read-before-hide) and the fields are scrubbed on every outcome.
class PromptWindow
{
public:
    PromptWindow();
    ~PromptWindow();
    PromptWindow(const PromptWindow&) = delete;
    PromptWindow& operator=(const PromptWindow&) = delete;

    [[nodiscard]] wire::PromptReply showPrompt(const wire::PromptRequest& req);
    // The multi-secret change panel (RequestSecrets, kind "change_pin"): three
    // secure fields — current / new / confirm — with per-role length gating on
    // OK. The confirm entry is validation-only and never leaves the panel;
    // kinds this window does not implement return Error without any UI.
    [[nodiscard]] wire::MultiPromptReply showChangePrompt(const wire::RequestSecrets& req);
    // Close the panel @p promptId names and answer its caller Cancelled.
    // Idempotent, and a no-op when nothing matches. Precisely:
    //   - a NON-EMPTY id closes the panel carrying that id AND any panel raised
    //     without an id at all. Both sides must know an address for one to be
    //     matched by it, so an unmatchable id must not be able to strand a
    //     panel that has none — least of all the change panel, which this wire
    //     gives no deadline to close itself with.
    //   - an EMPTY id — an unaddressed dismissal, all a caller that speaks no
    //     ids can send — closes the OLDEST unaddressed panel, and only that
    //     one. It is cancelling the one prompt it knows about, not the screen.
    void dismiss(const std::string& promptId);
    // Close EVERY panel still standing, whatever it is addressed by, answering
    // each caller Cancelled, and return how many were closed. The count is what
    // separates "nothing was standing" from "the sweep did nothing", which is
    // otherwise the same silence.
    [[nodiscard]] std::uint32_t dismissAll();
    // The ids of the panels standing right now, one entry per panel: two panels
    // raised without an id both appear as an empty string, because that is what
    // they are addressed by.
    [[nodiscard]] std::vector<std::string> liveIds() const;

private:
    struct Impl;
    Impl* m_impl;
};

} // namespace LibreSCRS::Darwin
