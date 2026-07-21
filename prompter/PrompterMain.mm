// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// librescrs-prompter: the agent-owned secure credential window helper. The
// server serves the private prompter.sock on its own GCD queues (peer-
// authenticating the agent); the AppKit run loop on the main thread shows the
// modal on demand, and a cross-connection CancelCurrent can dismiss it.
#include "PromptWindow.h"
#include "PrompterServer.h"

#import <AppKit/AppKit.h>
#import <Security/Security.h>

#include <pwd.h>
#include <unistd.h>

#include <cstdlib>
#include <memory>
#include <optional>
#include <string>

namespace {

// The REAL user home directory, bypassing $HOME. Under App Sandbox, $HOME is
// silently redirected to the process's private container, not the shared
// App-Group container the agent also binds into — see the twin comment in
// agent/src/main.cpp (realHomeDir). getpwuid(getuid()) reads the real
// passwd-database home, which the sandbox does not redirect.
std::string realHomeDir()
{
    if (struct passwd* pw = getpwuid(getuid()); pw != nullptr && pw->pw_dir != nullptr) {
        return pw->pw_dir;
    }
    const char* home = std::getenv("HOME");
    return home ? home : "";
}

std::string prompterSocketPath()
{
    if (const char* env = std::getenv("LIBRESCRS_PROMPTER_SOCK")) {
        return env;
    }
    return realHomeDir() + "/Library/Group Containers/group.org.librescrs.LibreMac/prompter.sock";
}

// The connecting peer must be the agent. If LIBRESCRS_AGENT_SIGNING_ID is set, we
// require the peer's SecTask signing identifier to match it (production);
// otherwise (dev) we only require an identifiable same-user peer (the 0600 socket
// already restricts to our uid). The real deployment sets the env from the
// agent's bundle id.
LibreSCRS::Darwin::PrompterServer::PeerAuthorized makePeerAuth()
{
    std::optional<std::string> expected;
    if (const char* env = std::getenv("LIBRESCRS_AGENT_SIGNING_ID")) {
        expected = env;
    }
    return [expected](const LibreSCRS::Darwin::PeerCredentials& creds) -> bool {
        if (!expected) {
            return true; // dev: any identifiable same-uid peer
        }
        SecTaskRef task = SecTaskCreateWithAuditToken(nullptr, creds.auditToken);
        if (task == nullptr) {
            return false;
        }
        bool ok = false;
        CFErrorRef err = nullptr;
        if (CFStringRef sid = SecTaskCopySigningIdentifier(task, &err)) {
            char buf[256];
            if (CFStringGetCString(sid, buf, sizeof(buf), kCFStringEncodingUTF8)) {
                ok = (*expected == buf);
            }
            CFRelease(sid);
        }
        if (err != nullptr) {
            CFRelease(err);
        }
        CFRelease(task);
        return ok;
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
            [window] { window->dismiss(); }, makePeerAuth());

        if (auto started = server.start(); !started) {
            NSLog(@"librescrs-prompter: %s", started.error().c_str());
            return 1;
        }
        [NSApp run]; // the socket server lives on its GCD queues inside `server`
    }
    return 0;
}
