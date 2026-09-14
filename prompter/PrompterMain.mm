// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// librescrs-prompter: the agent-owned secure credential window helper. The
// server serves the private prompter.sock on its own GCD queues (peer-
// authenticating the agent); the AppKit run loop on the main thread raises one
// floating panel per prompt and keeps running while they stand, so a
// cross-connection CancelCurrent can dismiss any of them at any time.
#include "PromptWindow.h"
#include "ConfirmAuthorizer.h"
#include "PrompterServer.h"

#include <LibreSCRS/Darwin/backend/AppGroupPaths.h>
#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h>

#import <AppKit/AppKit.h>

#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

// The default socket lives in the shared App-Group container, resolved by the
// SAME helper the agent uses (AppGroupPaths — sandbox-bypass home + group id
// in one place, so the two binaries cannot drift apart silently).
std::string prompterSocketPath()
{
    if (const char* env = std::getenv("LIBRESCRS_PROMPTER_SOCK")) {
        return env;
    }
    return (LibreSCRS::Darwin::appGroupContainerDir() / "prompter.sock").string();
}

// The connecting peer must be the agent. By DEFAULT the peer's code-signing
// identity is verified: its SecTask signing identifier must match the agent's
// (LIBRESCRS_AGENT_SIGNING_ID overrides the built-in expectation for
// repackaged deployments) AND it must carry our App-Group entitlement, which
// Apple provisions per Team ID — the shared PeerCodeSigning gate. The ONLY way
// to skip verification is the explicit development opt-out
// LIBRESCRS_PROMPTER_ALLOW_UNVERIFIED_PEER=1 (unsigned local builds; the 0600
// socket still restricts connections to our uid). Never set it in production:
// with it, any same-uid process can raise the PIN window and receive the
// typed secret.
LibreSCRS::Darwin::PrompterServer::PeerAuthorized makePeerAuth()
{
    if (const char* optOut = std::getenv("LIBRESCRS_PROMPTER_ALLOW_UNVERIFIED_PEER");
        optOut != nullptr && std::string_view(optOut) == "1") {
        return [](const LibreSCRS::Darwin::PeerCredentials&) {
            return true; // development opt-out: any identifiable same-uid peer
        };
    }
    LibreSCRS::Darwin::ExpectedPeerIdentity expected{.signingId = std::string(LibreSCRS::Darwin::kAgentSigningId),
                                                     .appGroup = std::string(LibreSCRS::Darwin::kAppGroup)};
    if (const char* env = std::getenv("LIBRESCRS_AGENT_SIGNING_ID"); env != nullptr && *env != '\0') {
        expected.signingId = env;
    }
    return [expected](const LibreSCRS::Darwin::PeerCredentials& creds) -> bool {
        return LibreSCRS::Darwin::matchesExpectedPeer(LibreSCRS::Darwin::resolvePeerCodeSigning(creds), expected);
    };
}

} // namespace

int main(int /*argc*/, char** /*argv*/)
{
    @autoreleasepool {
        // LSUIElement (no Dock icon / menu bar); the windows are transient
        // floating panels, and nothing here ever runs a modal loop.
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

        auto window = std::make_shared<LibreSCRS::Darwin::PromptWindow>();

        LibreSCRS::Darwin::PrompterServer server(
            prompterSocketPath(),
            [window](const LibreSCRS::Darwin::wire::PromptRequest& req) { return window->showPrompt(req); },
            [window](const LibreSCRS::Darwin::wire::RequestSecrets& req) { return window->showChangePrompt(req); },
            [window](const std::string& promptId) { window->dismiss(promptId); },
            // Not a window of ours: the confirmation is the platform's own
            // device-owner prompt, so there is nothing here to dismiss and
            // nothing that could collect a secret.
            [](const LibreSCRS::Darwin::wire::ConfirmAction& req) {
                return LibreSCRS::Darwin::confirmWithDeviceOwner(req);
            },
            [window]() {
                // Name the prompts before sweeping them. A reset happens when a
                // fresh agent meets panels a previous one left standing, so the
                // count that goes back on the wire is the one thing it can say
                // — and the ids are the only record of WHICH prompts they were,
                // which is what a person reading the log after an agent restart
                // is actually looking for. An id is an address the agent minted,
                // never anything the holder typed.
                const std::vector<std::string> closing = window->liveIds();
                NSMutableString* ids = [NSMutableString string];
                for (const std::string& id : closing) {
                    [ids appendFormat:@"%@%s", ids.length ? @", " : @"", id.empty() ? "<unaddressed>" : id.c_str()];
                }
                NSLog(@"librescrs-prompter: reset closing %lu prompt(s): %@",
                      static_cast<unsigned long>(closing.size()), ids.length ? ids : @"(none)");
                return window->dismissAll();
            },
            makePeerAuth());

        if (auto started = server.start(); !started) {
            NSLog(@"librescrs-prompter: %s", started.error().c_str());
            return 1;
        }
        [NSApp run]; // the socket server lives on its GCD queues inside `server`
    }
    return 0;
}
