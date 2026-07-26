// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AppKit credential window. An NSAlert with a NSSecureTextField accessory, run
// modally on the main thread. The secret is read out of the field before the
// window is dismissed, then the field is scrubbed. The change variant stacks
// three secure fields (current / new / confirm) behind the same discipline.
#include "PromptWindow.h"

#import <AppKit/AppKit.h>
#include <dispatch/dispatch.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

namespace LibreSCRS::Darwin {

struct PromptWindow::Impl
{
    NSAlert* activeAlert{nil}; // non-nil while a modal is up (main-thread only)
};

PromptWindow::PromptWindow() : m_impl(new Impl) {}

PromptWindow::~PromptWindow()
{
    delete m_impl;
}

namespace {
NSString* nsstr(const std::string& s)
{
    return [NSString stringWithUTF8String:s.c_str()];
}

// Recognised `lastError` msgKey (mirrors
// LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key on the agent's LM
// dependency; duplicated here as a documented literal, the same
// cross-binary vocabulary convention the Linux PromptDialog.cpp uses for its
// own copy of this same string — this file has no LM dependency to share the
// constant with). The only source of a retry `lastError` today is the
// eMRTD read flows' AuthFailed path (CredentialCache::markCredentialWrong).
constexpr const char* kErrorPreReadAuthFailed = "librescrs.error.preRead.authFailed";

// Retry-context inline error line (req.attempt > 0 -- a genuine re-prompt
// after the card rejected the value collected last time for this card): nil
// on the first-ever prompt for a card (attempt == 0). An unrecognised or
// empty lastError key still returns a generic retry line rather than
// leaking the raw wire key to the user, mirroring the Linux
// PromptDialog.cpp retryErrorText() helper. No attempts counter is ever
// rendered -- parity with the GUI's inline-error-without-a-counter bar.
NSString* retryErrorLine(std::uint32_t attempt, const std::string& lastError)
{
    if (attempt == 0) {
        return nil;
    }
    if (lastError.empty() || lastError == kErrorPreReadAuthFailed) {
        return @"The value you entered was not accepted. Please try again.";
    }
    return @"Your previous entry was not accepted. Please try again.";
}

// Shared informative-text chrome (retry error / description / requester /
// artifact) — identical for the single-secret and change prompts;
// `retryError` is nil for the change prompt (RequestSecrets carries no
// retry context -- change_pin is never a CAN/MRZ retry) and shown FIRST,
// immediately above the rest of the informative text, mirroring the Linux
// PromptDialog placing its retry label above the input widget.
NSString* informativeText(const std::string& description, const std::string& requester, const std::string& artifact,
                          NSString* retryError)
{
    NSMutableString* info = [NSMutableString string];
    if (retryError.length) {
        [info appendString:retryError];
    }
    if (!description.empty()) {
        [info appendFormat:@"%@%@", info.length ? @"\n" : @"", nsstr(description)];
    }
    if (!requester.empty()) {
        [info appendFormat:@"%@Requested by: %@", info.length ? @"\n" : @"", nsstr(requester)];
    }
    if (!artifact.empty()) {
        [info appendFormat:@"%@Document: %@", info.length ? @"\n" : @"", nsstr(artifact)];
    }
    return info;
}

// The change modal's OK gate, pure so it is testable by inspection: current
// within the primary bounds AND new within the new bounds AND confirm equal
// to new. Lengths are UTF-8 byte counts — the unit that crosses the wire. A
// zero bound is "unset" on the wire (the request codec omits zero fields):
// min 0 imposes no lower limit and max 0 no upper limit, so unknown card
// policy degrades to "let the card decide" rather than a permanently
// disabled OK.
bool withinBounds(std::size_t len, std::uint32_t minLen, std::uint32_t maxLen)
{
    return len >= minLen && (maxLen == 0 || len <= maxLen);
}

bool changeInputsAcceptable(const wire::RequestSecrets& req, std::size_t currentLen, std::size_t newLen,
                            bool confirmMatchesNew)
{
    return withinBounds(currentLen, req.primaryMinLength, req.primaryMaxLength) &&
           withinBounds(newLen, req.newMinLength, req.newMaxLength) && confirmMatchesNew;
}

std::size_t utf8Length(NSString* value)
{
    return static_cast<std::size_t>([value lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
}

// One captioned secure-entry row inside the change modal's accessory view;
// `y` is the FIELD's bottom edge (AppKit origin is bottom-left, so rows are
// laid out bottom-up: caption 16 pt above a 24 pt field, 2 pt apart).
NSSecureTextField* addSecureRow(NSView* accessory, NSString* caption, CGFloat y, CGFloat width)
{
    NSTextField* label = [NSTextField labelWithString:caption];
    label.frame = NSMakeRect(0, y + 26, width, 16);
    label.font = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
    [accessory addSubview:label];
    NSSecureTextField* field = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, y, width, 24)];
    [accessory addSubview:field];
    return field;
}
} // namespace

wire::PromptReply PromptWindow::showPrompt(const wire::PromptRequest& req)
{
    __block wire::PromptReply reply;
    reply.status = wire::PromptReplyStatus::Error;
    Impl* impl = m_impl;

    dispatch_sync(dispatch_get_main_queue(), ^{
      @autoreleasepool {
          [NSApp activateIgnoringOtherApps:YES];
          NSAlert* alert = [[NSAlert alloc] init];
          const char* kindLabel = req.kind == wire::PromptKind::Can   ? "Card Access Number (CAN)"
                                  : req.kind == wire::PromptKind::Mrz ? "Machine-Readable Zone (MRZ)"
                                                                      : "PIN";
          alert.messageText =
              req.title.empty() ? [NSString stringWithFormat:@"Enter your %s", kindLabel] : nsstr(req.title);
          alert.informativeText =
              informativeText(req.description, req.requester, req.artifact, retryErrorLine(req.attempt, req.lastError));
          [alert addButtonWithTitle:@"OK"];
          [alert addButtonWithTitle:@"Cancel"];

          NSSecureTextField* field = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 260, 24)];
          alert.accessoryView = field;
          [alert.window setInitialFirstResponder:field];

          impl->activeAlert = alert;
          const NSModalResponse resp = [alert runModal];
          impl->activeAlert = nil;

          if (resp == NSAlertFirstButtonReturn) {
              // Read-before-hide: pull the secret out of the field NOW, then scrub.
              // Documented residual: the NSSecureTextField/NSString internals
              // (autoreleased, immutable) cannot be deterministically zeroed from
              // here; their lifetime is minimised (autoreleasepool around this
              // block) and everything downstream — reply.secret, the CBOR tree,
              // the encoded frame — is zeroed after send (sendPromptReplyScrubbed).
              // The reply itself leaves by explicit move, so the __block byref
              // storage keeps no unscrubbed copy of the secret.
              NSString* value = field.stringValue;
              const char* utf8 = value.UTF8String;
              const std::size_t len = utf8 != nullptr ? std::strlen(utf8) : 0;
              reply.status = wire::PromptReplyStatus::Ok;
              reply.secret.assign(utf8, utf8 + len);
              field.stringValue = @"";
          } else {
              reply.status = wire::PromptReplyStatus::Cancelled;
          }
      }
    });
    return std::move(reply);
}

wire::MultiPromptReply PromptWindow::showChangePrompt(const wire::RequestSecrets& req)
{
    __block wire::MultiPromptReply reply;
    reply.status = wire::PromptReplyStatus::Error;
    // Fail closed on a flow this window does not implement (`kind` is an open
    // discriminator at the wire layer): no UI, no secrets.
    if (req.kind != "change_pin") {
        reply.userMessage = "unsupported RequestSecrets kind";
        return reply;
    }
    Impl* impl = m_impl;

    dispatch_sync(dispatch_get_main_queue(), ^{
      @autoreleasepool {
          [NSApp activateIgnoringOtherApps:YES];
          NSAlert* alert = [[NSAlert alloc] init];
          alert.messageText = req.title.empty() ? @"Change your PIN" : nsstr(req.title);
          // RequestSecrets carries no retry context (change_pin is never a
          // CAN/MRZ retry) -- nil, same as the single-secret path's
          // first-ever prompt.
          alert.informativeText = informativeText(req.description, req.requester, req.artifact, nil);
          [alert addButtonWithTitle:@"OK"];
          [alert addButtonWithTitle:@"Cancel"];

          const CGFloat width = 260;
          NSView* accessory = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, width, 142)];
          NSSecureTextField* currentField = addSecureRow(accessory, @"Current PIN", 100, width);
          NSSecureTextField* newField = addSecureRow(accessory, @"New PIN", 50, width);
          NSSecureTextField* confirmField = addSecureRow(accessory, @"Confirm new PIN", 0, width);
          currentField.nextKeyView = newField;
          newField.nextKeyView = confirmField;
          confirmField.nextKeyView = currentField;
          alert.accessoryView = accessory;
          [alert.window setInitialFirstResponder:currentField];

          // Per-role length gating: OK stays disabled until every field
          // passes changeInputsAcceptable (current within the primary bounds,
          // new within the new bounds, confirm equal to new). The equality
          // check is the confirm entry's ONLY consumer — its value never
          // leaves the window.
          NSButton* okButton = alert.buttons.firstObject;
          bool (^inputsAcceptable)(void) = ^{
            return changeInputsAcceptable(req, utf8Length(currentField.stringValue), utf8Length(newField.stringValue),
                                          [confirmField.stringValue isEqualToString:newField.stringValue]);
          };
          okButton.enabled = inputsAcceptable();
          NSNotificationCenter* center = [NSNotificationCenter defaultCenter];
          NSMutableArray<id>* observers = [NSMutableArray array];
          for (NSSecureTextField* field in @[ currentField, newField, confirmField ]) {
              [observers addObject:[center addObserverForName:NSControlTextDidChangeNotification
                                                       object:field
                                                        queue:nil
                                                   usingBlock:^(NSNotification* note) {
                                                     (void)note;
                                                     okButton.enabled = inputsAcceptable();
                                                   }]];
          }

          impl->activeAlert = alert;
          const NSModalResponse resp = [alert runModal];
          impl->activeAlert = nil;
          for (id token in observers) {
              [center removeObserver:token];
          }

          if (resp == NSAlertFirstButtonReturn) {
              // Read-before-hide: pull BOTH secrets out of their fields NOW,
              // then scrub. Documented residual: the NSSecureTextField/
              // NSString internals (autoreleased, immutable) cannot be
              // deterministically zeroed from here; their lifetime is
              // minimised (autoreleasepool around this block) and everything
              // downstream — reply.primary/reply.secondary, the CBOR tree,
              // the encoded frame — is zeroed after send
              // (sendPromptReplyScrubbed). The reply itself leaves by explicit
              // move, so the __block byref storage keeps no unscrubbed copies.
              NSString* currentValue = currentField.stringValue;
              const char* currentUtf8 = currentValue.UTF8String;
              const std::size_t currentLen = currentUtf8 != nullptr ? std::strlen(currentUtf8) : 0;
              NSString* newValue = newField.stringValue;
              const char* newUtf8 = newValue.UTF8String;
              const std::size_t newLen = newUtf8 != nullptr ? std::strlen(newUtf8) : 0;
              reply.status = wire::PromptReplyStatus::Ok;
              reply.primary.assign(currentUtf8, currentUtf8 + currentLen);
              reply.secondary.assign(newUtf8, newUtf8 + newLen);
          } else {
              reply.status = wire::PromptReplyStatus::Cancelled;
          }
          // Clear ALL THREE fields after the read, on BOTH outcomes. The
          // confirm entry was never read into the reply — validation was its
          // only consumer — but its buffer holds a copy of the new PIN, so
          // its residual is cleared explicitly too.
          currentField.stringValue = @"";
          newField.stringValue = @"";
          confirmField.stringValue = @"";
      }
    });
    return std::move(reply);
}

void PromptWindow::dismiss()
{
    Impl* impl = m_impl;
    // GCD main-queue blocks are NOT drained while [NSAlert runModal] spins the
    // modal run loop (NSModalPanelRunLoopMode excludes the common-modes source
    // that services the main queue), so a dispatch_async(main) abort would only
    // run AFTER the modal ends — too late by definition. Enqueue directly on
    // the main CFRunLoop in the modal mode (plus common modes for the no-modal
    // case) and wake it. The block is idempotent: activeAlert is nil once the
    // modal ended, so double-scheduling across modes is harmless.
    void (^abortBlock)(void) = ^{
      if (impl->activeAlert != nil) {
          [NSApp abortModal]; // runModal returns != FirstButton -> Cancelled
      }
    };
    CFRunLoopRef mainLoop = CFRunLoopGetMain();
    CFRunLoopPerformBlock(mainLoop, (__bridge CFStringRef)NSModalPanelRunLoopMode, abortBlock);
    CFRunLoopPerformBlock(mainLoop, kCFRunLoopCommonModes, abortBlock);
    CFRunLoopWakeUp(mainLoop);
}

} // namespace LibreSCRS::Darwin
