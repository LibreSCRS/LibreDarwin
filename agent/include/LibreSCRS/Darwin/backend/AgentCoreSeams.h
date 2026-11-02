// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

// The macOS reader-routing seams AgentCore consults, answered from the
// transport's self-consistent presence snapshot: the twin of LibreLinux's
// AgentCoreSeams.h. The transport MUST outlive the AgentCore that stores
// these. Header-only, so main.cpp composes them and the tests drive the same
// functions production does -- and the same goes for the one step that answers
// a system lifecycle event with the core's quiesce.

#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Darwin/backend/SystemLifecycle.h>

#include <LibreSCRS/Agent/AgentCore.h>                   // ResolveReaderCard, ReaderCard
#include <LibreSCRS/Agent/operations/PromptSerializer.h> // Operations::ReaderIdentityForCard
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>         // Pkcs11Broker::ResolveCardKeySeam
#include <LibreSCRS/Agent/value/ReaderLabels.h>          // identityForCardIn

#include <cstdlib>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace LibreSCRS::Darwin {

// Reader wire handle -> {readerId, readerName, cardKey}, or nullopt when the
// reader is unknown or holds no card. Loop thread (reader-addressed requests
// arrive there).
[[nodiscard]] inline Agent::ResolveReaderCard makeResolveReaderCard(const SocketTransport& transport)
{
    return [&transport](const std::string& readerHandle) -> std::optional<Agent::ReaderCard> {
        const auto rc = transport.readerCard(readerHandle);
        if (!rc || rc->cardKey.empty()) {
            return std::nullopt;
        }
        return Agent::ReaderCard{.readerId = rc->readerId, .readerName = rc->readerName, .cardKey = rc->cardKey};
    };
}

// Reader wire handle -> the card's opaque ObjectId (the lease key's card
// component), recovered from the per-insertion card key the reader currently
// holds; nullopt when no card is present. Loop thread.
[[nodiscard]] inline Agent::Pkcs11Broker::ResolveCardKeySeam makeResolveCardKey(const SocketTransport& transport)
{
    return [&transport](const std::string& readerHandle) -> std::optional<Agent::ObjectId> {
        const auto rc = transport.readerCard(readerHandle);
        if (!rc || rc->cardKey.empty()) {
            return std::nullopt;
        }
        return Agent::ObjectId{std::strtoull(rc->cardKey.c_str(), nullptr, 10)};
    };
}

// The seam the prompt gate stamps every dialog from. Takes a fresh snapshot per
// call, from whichever reader worker thread asks: a reader unplugged
// mid-operation must not leave a stale name on the next prompt.
[[nodiscard]] inline Agent::Operations::ReaderIdentityForCard
makeResolveReaderIdentity(const SocketTransport& transport)
{
    return [&transport](const std::string& cardKey) {
        return Agent::identityForCardIn(transport.presenceRoster(), cardKey);
    };
}

// The composition step: hand the core's prompt gate the identity lookup above.
// Set once, before any operation can run -- the core reads it from reader
// worker threads and never re-assigns it. One function so main.cpp and the
// test rig perform the same step: the daemon went without it for a long time,
// and every prompt named no reader, because nothing but production composed
// the two.
inline void installReaderIdentityResolver(Agent::AgentCore& core, const SocketTransport& transport)
{
    core.promptSerializer().setReaderIdentityResolver(makeResolveReaderIdentity(transport));
}

// The composition step for a system lifecycle event. The event names its
// reason (quiesceReasonFor) and the core forgets what that reason says
// (AgentCore::quiesce), under @p stateMutex because the monitor mutates the
// registry the quiesce reads on its own thread; then every client hears the
// same reason, marshaled onto the transport loop. Wake, unlock and switching
// back name no reason and change nothing -- the next operation re-acquires.
// PowerOff stops the agent through @p stop instead. One function, so main.cpp
// and the tests run the same step rather than a test re-stating it. The core,
// the mutex and the transport MUST outlive the handler.
[[nodiscard]] inline SystemLifecycle::Handler makeLifecycleHandler(Agent::AgentCore& core, std::mutex& stateMutex,
                                                                   SocketTransport& transport,
                                                                   std::function<void()> stop)
{
    return [&core, &stateMutex, &transport, stop = std::move(stop)](SystemLifecycle::Event event) {
        if (event == SystemLifecycle::Event::PowerOff) {
            stop();
            return;
        }
        const auto reason = quiesceReasonFor(event);
        if (!reason) {
            return;
        }
        {
            const std::lock_guard<std::mutex> lk(stateMutex);
            core.quiesce(*reason);
        }
        SocketTransport* trp = &transport;
        trp->post([trp, quiesced = *reason] { trp->broadcastQuiesced(quiesced); });
    };
}

} // namespace LibreSCRS::Darwin
