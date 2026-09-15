// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The host's half of "which reader is this dialog for" and "which slot gets a
// power hold": the per-insertion card key is minted here, so only this side can
// invert it to a reader. The LABELLING is the agent core's (readerIdentities)
// and stays there; these seams only do the lookup, and the tests drive the
// same functions production does. The twin of LibreLinux's
// ReaderIdentitySeamTest, over the same three reader names, so the two hosts
// are proven against one roster.

#include <LibreSCRS/Darwin/backend/AgentCoreSeams.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

using LibreSCRS::Agent::ReaderIdentity;
using LibreSCRS::Agent::ReaderInterface;
using LibreSCRS::Darwin::identityForCardIn;
using LibreSCRS::Darwin::isContactSlotOfDualInterfaceUnit;
using LibreSCRS::Darwin::SocketTransport;

namespace {

// The three names as pcsc-lite reports them on the development bench. The two
// OMNIKEY slots SHARE a serial: only the bracketed product string and the slot
// number separate them, which is what a naive shortening collapses into two
// identical dialogs. The card keys are the stringified per-insertion ObjectIds
// SocketTransport mints (CardRouting::cardKey), or empty for an empty slot.
SocketTransport::PresenceRoster deskRoster()
{
    SocketTransport::PresenceRoster roster;
    roster.readerNames = {
        "Gemalto PC Twin Reader (69988A87) 02 00",
        "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422 Smartcard Reader] (IM0O2C00NF10456904) 01 00",
        "HID Global OMNIKEY 5422 Smartcard Reader [OMNIKEY 5422CL Smartcard Reader] (IM0O2C00NF10456904) 00 00"};
    roster.cardKeys = {"1", "", "3"};
    return roster;
}

} // namespace

TEST(AgentCoreSeams, ResolvesTheSlotThatActuallyHoldsTheCard)
{
    const auto roster = deskRoster();

    const ReaderIdentity contactless = identityForCardIn(roster, "3");
    const ReaderIdentity gemalto = identityForCardIn(roster, "1");

    EXPECT_EQ(contactless.full, roster.readerNames[2]);
    EXPECT_EQ(gemalto.full, roster.readerNames[0]);
    EXPECT_NE(contactless.model, gemalto.model);
}

TEST(AgentCoreSeams, DistinguishesTheTwoSlotsOfADualInterfaceUnit)
{
    // Requires the whole roster: whether a unit is dual-interface is only
    // decidable across the set, which is why the derivation takes the list.
    const auto roster = deskRoster();

    const ReaderIdentity contactless = identityForCardIn(roster, "3");

    EXPECT_EQ(contactless.iface, ReaderInterface::Contactless);
    EXPECT_FALSE(contactless.model.empty());
}

TEST(AgentCoreSeams, AnUnknownCardKeyResolvesToAnEmptyIdentity)
{
    EXPECT_EQ(identityForCardIn(deskRoster(), "9"), ReaderIdentity{});
}

TEST(AgentCoreSeams, AnEmptyCardKeyNeverMatchesAReaderHoldingNoCard)
{
    // A reader with no card carries an empty key in the roster. An empty key
    // must not match it, or every unresolvable prompt would be labelled with
    // whichever empty reader happened to come first.
    EXPECT_EQ(identityForCardIn(deskRoster(), ""), ReaderIdentity{});
}

// The hold gate: only the CONTACT slot of a dual-interface unit is held. The
// single-interface Gemalto is Unknown, the OMNIKEY CL slot is Contactless, an
// unknown or empty key resolves to nothing.
TEST(AgentCoreSeams, OnlyTheContactSlotOfADualInterfaceUnitIsHeld)
{
    auto roster = deskRoster();
    roster.cardKeys[1] = "2"; // a card now sits in the OMNIKEY contact slot

    EXPECT_TRUE(isContactSlotOfDualInterfaceUnit(roster, "2")) << "OMNIKEY contact slot";
    EXPECT_FALSE(isContactSlotOfDualInterfaceUnit(roster, "3")) << "OMNIKEY CL slot";
    EXPECT_FALSE(isContactSlotOfDualInterfaceUnit(roster, "1")) << "single-interface Gemalto";
    EXPECT_FALSE(isContactSlotOfDualInterfaceUnit(roster, "9")) << "unknown card key";
    EXPECT_FALSE(isContactSlotOfDualInterfaceUnit(roster, "")) << "empty key never matches";
}

// What this platform actually reports. macOS's PC/SC layer publishes the bare
// USB product string -- measured on the development Mac as the name below --
// with no pcsc-lite " (serial) ifd slot" tail, and the core's classifier
// (readerIdentities) recognises a dual-interface unit only through a serial two
// names share. Such a name therefore carries no unit identity, and the hold
// stays OFF: a reader that cannot be classified is never held, because a hold
// on a contactless slot would be the wrong failure. The two names the OMNIKEY
// 5422 gets on macOS are not yet measured; when they are, they belong here,
// whichever way they classify.
TEST(AgentCoreSeams, ABareProductStringCarriesNoUnitIdentityAndIsNeverHeld)
{
    SocketTransport::PresenceRoster roster;
    roster.readerNames = {"Gemalto USB SmartCard Reader"};
    roster.cardKeys = {"1"};

    const ReaderIdentity identity = identityForCardIn(roster, "1");
    EXPECT_EQ(identity.full, roster.readerNames[0]);
    EXPECT_FALSE(identity.model.empty()) << "the model falls back to the raw name, never empty";
    EXPECT_EQ(identity.iface, ReaderInterface::Unknown);
    EXPECT_FALSE(isContactSlotOfDualInterfaceUnit(roster, "1"));
}
