// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// librescrs-agent — the macOS broker-host daemon entry point (launchd LaunchAgent).
//
// SKELETON. This sketches the wiring the macOS backend performs around
// LibreAgent::AgentCore; the AgentCore construction + run loop land in P1b
// (implement-macos-backend), which is why the body below is a TODO scaffold.
//
// Target shape (mirrors LibreLinux/agent/src/main.cpp on the D-Bus backend):
//   1. log::init(makeOsLogSink(), "rs.librescrs.agent").
//   2. Construct the backend collaborators the core BORROWS/OWNS:
//        SocketTransport         transport;   // AgentTransport
//        SecCodeAuthorizer       authorizer;  // Authorizer
//        auto prompter = std::make_shared<MacPrompterClient>();
//        CapabilityResolver      resolver{...};   // owned here (process entry)
//   3. Construct the owning aggregate:
//        AgentCore core{resolver, transport, authorizer, prompter,
//                       configFile, cacheRoot, resolveReaderCard, resolveCardKey};
//      where configFile/cacheRoot live under the App-Group container and the two
//      seams map the socket handle <-> reader token / card key.
//   4. Bring up the launchd socket-activated listener and run the dispatch loop;
//      on SIGTERM call core.requestCryptoShutdown() then quiesce.

#include <LibreSCRS/Darwin/backend/MacPrompterClient.h>
#include <LibreSCRS/Darwin/backend/OsLogSink.h>
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
#include <LibreSCRS/Darwin/backend/SocketOperationChannel.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>

#include <LibreSCRS/Agent/backend/Logging.h>

int main()
{
    LibreSCRS::Agent::log::init(LibreSCRS::Darwin::makeOsLogSink(), "rs.librescrs.agent");
    LibreSCRS::Agent::log::info("librescrs-agent (macOS) skeleton — TODO(P1b): backend wiring not yet implemented");

    // TODO(P1b) implement-macos-backend: construct the backend collaborators +
    // AgentCore per the header comment above, then run the dispatch loop.
    return 0;
}
