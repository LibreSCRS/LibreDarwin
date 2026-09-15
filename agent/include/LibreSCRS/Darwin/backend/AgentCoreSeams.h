// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

// The macOS reader-routing seams AgentCore consults, answered from the
// transport's self-consistent presence snapshot: the twin of LibreLinux's
// AgentCoreSeams.h. The transport MUST outlive the AgentCore that stores
// these. Header-only, so main.cpp composes them and the tests drive the same
// functions production does.

#include <LibreSCRS/Darwin/backend/SocketTransport.h>

#include <LibreSCRS/Agent/AgentCore.h>                   // ResolveReaderCard, ReaderCard
#include <LibreSCRS/Agent/operations/PromptSerializer.h> // Operations::ReaderIdentityForCard
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>         // Pkcs11Broker::ResolveCardKeySeam
#include <LibreSCRS/Agent/value/ReaderLabels.h>          // ReaderIdentity, readerIdentities

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <optional>
#include <string>

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

// Card key -> the identity of the reader holding it, or an empty identity when
// no reader in @p roster holds that card. The LABELLING is the neutral core's
// (readerIdentities, roster-aware because a dual-interface unit is only
// distinguishable across the whole set); all this adds is the inverse only the
// host can compute, since the host mints the card key.
[[nodiscard]] inline Agent::ReaderIdentity identityForCardIn(const SocketTransport::PresenceRoster& roster,
                                                             const std::string& cardKey)
{
    // An empty key must not match a reader that holds no card, or every
    // unresolvable prompt would borrow the first empty reader's name.
    if (cardKey.empty()) {
        return {};
    }
    const auto it = std::ranges::find(roster.cardKeys, cardKey);
    if (it == roster.cardKeys.end()) {
        return {};
    }
    const auto index = static_cast<std::size_t>(std::distance(roster.cardKeys.begin(), it));
    const auto identities = Agent::readerIdentities(roster.readerNames);
    return index < identities.size() ? identities[index] : Agent::ReaderIdentity{};
}

// The hold gate: whether the reader holding @p cardKey is the CONTACT slot of a
// dual-interface unit. That is the one slot the agent keeps powered (a bare
// power hold on the reader) so the same single-chip card's contactless twin
// stops flapping. A single-interface reader classifies as Unknown and a CL
// slot as Contactless, so neither is ever held. Same snapshot semantics as
// identityForCardIn: one roster read, no per-entry locking.
[[nodiscard]] inline bool isContactSlotOfDualInterfaceUnit(const SocketTransport::PresenceRoster& roster,
                                                           const std::string& cardKey)
{
    return identityForCardIn(roster, cardKey).iface == Agent::ReaderInterface::Contact;
}

// The seam the prompt gate stamps every dialog from. Takes a fresh snapshot per
// call, from whichever reader worker thread asks: a reader unplugged
// mid-operation must not leave a stale name on the next prompt.
[[nodiscard]] inline Agent::Operations::ReaderIdentityForCard
makeResolveReaderIdentity(const SocketTransport& transport)
{
    return [&transport](const std::string& cardKey) { return identityForCardIn(transport.presenceRoster(), cardKey); };
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

} // namespace LibreSCRS::Darwin
