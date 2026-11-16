// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "SecretLength.h"

#include <gtest/gtest.h>

// The inputs below are the ones PromptWindow.mm hands the gates: the bounds
// exactly as the request carried them (0 when the wire omitted the key) and
// the field's UTF-8 bytes. What this does not cover is the AppKit wiring: that
// refreshOkGate calls these functions, that every edit of a field calls
// refreshOkGate, and that the field's text reaches them.

using LibreSCRS::Darwin::ChangeBounds;
using LibreSCRS::Darwin::changeEntriesAcceptable;
using LibreSCRS::Darwin::pinBounds;
using LibreSCRS::Darwin::secretEntryAcceptable;
using LibreSCRS::Darwin::wire::PromptKind;

TEST(SecretLength, PinBoundsDefaultToFourToEightWhenTheRequestOmitsThem)
{
    const auto b = pinBounds(0, 0);
    EXPECT_EQ(b.min, 4u);
    EXPECT_EQ(b.max, 8u);
    EXPECT_EQ(pinBounds(6, 0).min, 6u);
    EXPECT_EQ(pinBounds(6, 0).max, 8u);
    EXPECT_EQ(pinBounds(0, 12).min, 4u);
    EXPECT_EQ(pinBounds(0, 12).max, 12u);
}

TEST(SecretLength, InvertedBoundsReadAsMaxEqualsMin)
{
    EXPECT_EQ(pinBounds(6, 4).max, 6u);
    // An omitted maximum under a larger minimum is the same inversion.
    EXPECT_EQ(pinBounds(10, 0).max, 10u);
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Pin, "123456", 6, 4));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "1234", 6, 4));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "1234567", 6, 4));
}

TEST(SecretLength, PinWithoutBoundsIsHeldToFourToEight)
{
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "123", 0, 0));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Pin, "1234", 0, 0));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Pin, "12345678", 0, 0));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "123456789", 0, 0));
}

TEST(SecretLength, PinObeysTheBoundsTheRequestCarried)
{
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "12345", 6, 12));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Pin, "123456789012", 6, 12));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "1234567890123", 6, 12));
}

TEST(SecretLength, PinIsDigitsOnly)
{
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "12a4", 4, 8));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "12 4", 4, 8));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "12-4", 4, 8));
    // Four characters but eight bytes: not four digits.
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "\xD9\xA1\xD9\xA2\xD9\xA3\xD9\xA4", 4, 8));
}

TEST(SecretLength, CanIsExactlySixDigitsWhateverBoundsTheRequestCarried)
{
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Can, "12345", 0, 0));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Can, "123456", 0, 0));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Can, "1234567", 0, 0));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Can, "123456", 4, 8));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Can, "12345", 4, 8));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Can, "12345a", 0, 0));
}

TEST(SecretLength, EmptyIsNeverAnAnswer)
{
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, "", 0, 0));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Can, "", 0, 0));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Mrz, "", 0, 0));
    EXPECT_FALSE(changeEntriesAcceptable(ChangeBounds{0, 0, 0, 0}, "", "", ""));
}

TEST(SecretLength, MrzKeepsItsNonEmptyRuleWhateverTheRequestCarried)
{
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Mrz, "P<UTOERIKSSON<<ANNA", 0, 0));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Mrz, "x", 4, 8));
}

TEST(SecretLength, ChangePanelHoldsEachFieldToItsOwnBoundsAndDigits)
{
    const ChangeBounds b{4, 8, 6, 8};
    EXPECT_TRUE(changeEntriesAcceptable(b, "1234", "123456", "123456"));
    // current too short for the primary bounds, new within the new ones
    EXPECT_FALSE(changeEntriesAcceptable(b, "123", "123456", "123456"));
    // new too short for the NEW minimum although the primary one would take it
    EXPECT_FALSE(changeEntriesAcceptable(b, "1234", "12345", "12345"));
    EXPECT_FALSE(changeEntriesAcceptable(b, "1234", "123456789", "123456789"));
    EXPECT_FALSE(changeEntriesAcceptable(b, "1234", "123456", "123457"));
    EXPECT_FALSE(changeEntriesAcceptable(b, "12a4", "123456", "123456"));
    EXPECT_FALSE(changeEntriesAcceptable(b, "1234", "12345a", "12345a"));
}

TEST(SecretLength, ChangePanelWithoutBoundsIsHeldToFourToEight)
{
    const ChangeBounds none{0, 0, 0, 0};
    EXPECT_FALSE(changeEntriesAcceptable(none, "123", "1234", "1234"));
    EXPECT_TRUE(changeEntriesAcceptable(none, "1234", "12345678", "12345678"));
    EXPECT_FALSE(changeEntriesAcceptable(none, "1234", "123456789", "123456789"));
}
