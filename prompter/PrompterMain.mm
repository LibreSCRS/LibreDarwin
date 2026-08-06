// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// librescrs-prompter: the agent-owned secure credential window helper. The
// server serves the private prompter.sock on its own GCD queues (peer-
// authenticating the agent); the AppKit run loop on the main thread shows the
// modal on demand, and a cross-connection CancelCurrent can dismiss it.
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
        // LSUIElement (no Dock icon / menu bar); the window is a transient modal.
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

        auto window = std::make_shared<LibreSCRS::Darwin::PromptWindow>();

        LibreSCRS::Darwin::PrompterServer server(
            prompterSocketPath(),
            [window](const LibreSCRS::Darwin::wire::PromptRequest& req) { return window->showPrompt(req); },
            [window](const LibreSCRS::Darwin::wire::RequestSecrets& req) { return window->showChangePrompt(req); },
            [window] { window->dismiss(); },
            // Not a window of ours: the confirmation is the platform's own
            // device-owner prompt, so there is nothing here to dismiss and
            // nothing that could collect a secret.
            [](const LibreSCRS::Darwin::wire::ConfirmAction& req) {
                return LibreSCRS::Darwin::confirmWithDeviceOwner(req);
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
