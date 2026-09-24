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
#include "PrompterComposition.h"
#include "PrompterServer.h"

#include <LibreSCRS/Darwin/backend/AppGroupPaths.h>
#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h>
#include <LibreSCRS/Darwin/backend/PeerPolicy.h>
#include <LibreSCRS/Darwin/backend/ProcessHardening.h>

#import <AppKit/AppKit.h>

#include <expected>
#include <memory>
#include <string>
#include <vector>

namespace {

// The socket lives in the shared App-Group container, resolved by the SAME
// helper the agent uses (AppGroupPaths — sandbox-bypass home + group id in one
// place, so the two binaries cannot drift apart silently).
std::string prompterSocketPath()
{
    return (LibreSCRS::Darwin::appGroupContainerDir() / "prompter.sock").string();
}

// The connecting peer must be the agent: its SecTask signing identifier must
// match the agent's, it must carry our App-Group entitlement, and with a team id
// configured it must satisfy the designated requirement — the shared
// PeerCodeSigning gate (PeerPolicy.h). There is no opt-out and no override of
// the expected identity: with one, any same-uid process could raise the PIN
// window and receive the typed secret.
LibreSCRS::Darwin::PrompterServer::PeerAuthorized makePeerAuth()
{
    return [expected = LibreSCRS::Darwin::expectedAgentIdentity()](const LibreSCRS::Darwin::PeerCredentials& creds) {
        return LibreSCRS::Darwin::matchesExpectedPeer(LibreSCRS::Darwin::resolvePeerCodeSigning(creds, expected.teamId),
                                                      expected);
    };
}

// The real startup steps, in the order PrompterComposition::run() calls them
// (tested there without AppKit). The server lives in `state` so it outlives
// bind() and is torn down only when main() returns.
LibreSCRS::Darwin::PrompterComposition::Hooks defaultHooks()
{
    struct State
    {
        std::unique_ptr<LibreSCRS::Darwin::PrompterServer> server;
    };
    auto state = std::make_shared<State>();
    return LibreSCRS::Darwin::PrompterComposition::Hooks{
        .harden = LibreSCRS::Darwin::hardenSecretProcess,
        .selfCheck = [] { return LibreSCRS::Darwin::selfMatchesConfiguredTeam(LibreSCRS::Darwin::kPrompterSigningId); },
        .appInit =
            [] {
                // LSUIElement (no Dock icon / menu bar); the windows are
                // transient floating panels, and nothing here ever runs a modal
                // loop.
                [NSApplication sharedApplication];
                [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
            },
        .bind = [state]() -> std::expected<void, std::string> {
            auto window = std::make_shared<LibreSCRS::Darwin::PromptWindow>();
            state->server = std::make_unique<LibreSCRS::Darwin::PrompterServer>(
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
                    // Name the prompts before sweeping them. A reset happens
                    // when a fresh agent meets panels a previous one left
                    // standing, so the count that goes back on the wire is the
                    // one thing it can say — and the ids are the only record of
                    // WHICH prompts they were, which is what a person reading
                    // the log after an agent restart is actually looking for.
                    // An id is an address the agent minted, never anything the
                    // holder typed.
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
            state->server->setWarn(
                [](const std::string& message) { NSLog(@"librescrs-prompter: %s", message.c_str()); });
            return state->server->start();
        },
        .runLoop = [] { [NSApp run]; }, // the socket server lives on its GCD queues
        .warn = [](const std::string& message) { NSLog(@"librescrs-prompter: %s", message.c_str()); },
    };
}

} // namespace

int main(int /*argc*/, char** /*argv*/)
{
    @autoreleasepool {
        return LibreSCRS::Darwin::PrompterComposition::run(defaultHooks());
    }
}
