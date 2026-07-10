// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AppKit credential window. An NSAlert with a NSSecureTextField accessory, run
// modally on the main thread. The secret is read out of the field before the
// window is dismissed, then the field is scrubbed.
#include "PromptWindow.h"

#import <AppKit/AppKit.h>
#include <dispatch/dispatch.h>

#include <cstring>

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
          NSMutableString* info = [NSMutableString string];
          if (!req.description.empty()) {
              [info appendString:nsstr(req.description)];
          }
          if (!req.requester.empty()) {
              [info appendFormat:@"%@Requested by: %@", info.length ? @"\n" : @"", nsstr(req.requester)];
          }
          if (!req.artifact.empty()) {
              [info appendFormat:@"%@Document: %@", info.length ? @"\n" : @"", nsstr(req.artifact)];
          }
          alert.informativeText = info;
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
    return reply;
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
