// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The only file in this repository that touches LocalAuthentication. The card
// PIN is never involved: it authorizes use of a key and nothing else, so a
// change to what the agent trusts is answered by the device owner instead.
#include "ConfirmAuthorizer.h"

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

#include <dispatch/dispatch.h>

#include <string>
#include <utility>

namespace LibreSCRS::Darwin {

namespace {

std::string toStdString(NSString* s, const char* fallback)
{
    const char* utf8 = s.UTF8String;
    return (utf8 != nullptr) ? std::string(utf8) : std::string(fallback);
}

} // namespace

wire::ConfirmReply confirmWithDeviceOwner(const wire::ConfirmAction& req)
{
    @autoreleasepool {
        LAContext* ctx = [[LAContext alloc] init];
        NSError* canErr = nil;
        // deviceOwnerAuthentication, NOT ...WithBiometrics: it falls back to
        // the account password, which is the direct analogue of the Linux
        // policy's auth_self. Biometrics alone would fail closed on any Mac
        // with no enrolled finger -- including the one this was measured on.
        if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&canErr]) {
            return wire::ConfirmReply{wire::PromptReplyStatus::Error,
                                      toStdString(canErr.localizedDescription, "authentication unavailable")};
        }

        // The prompt names WHAT is being asked and WHO claims to be asking.
        // Claimed, never verified: the public SecTask path cannot prove it,
        // and the human is the one deciding -- so the wording must not lend
        // the name an authority it does not have.
        NSString* reason =
            [NSString stringWithFormat:@"%s (requested by “%s”)", req.description.c_str(), req.requester.c_str()];

        __block wire::PromptReplyStatus status = wire::PromptReplyStatus::Error;
        __block std::string message;
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
            localizedReason:reason
                      reply:^(BOOL success, NSError* error) {
                        if (success) {
                            status = wire::PromptReplyStatus::Ok;
                        } else {
                            // Every non-success is a refusal: fail closed,
                            // never retry silently. Cancel is told apart only
                            // so the caller can word it as the user's own act
                            // rather than as a failure.
                            status = (error.code == LAErrorUserCancel) ? wire::PromptReplyStatus::Cancelled
                                                                       : wire::PromptReplyStatus::Error;
                            message = toStdString(error.localizedDescription, "");
                        }
                        dispatch_semaphore_signal(done);
                      }];
        // No timeout, deliberately: the dialog has none either, and inventing
        // one here would turn "the human has not answered yet" into a refusal
        // while the dialog is still on screen. This blocks the worker queue,
        // never the serial queue that serves the socket.
        dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
        dispatch_release(done);
        return wire::ConfirmReply{status, std::move(message)};
    }
}

} // namespace LibreSCRS::Darwin
