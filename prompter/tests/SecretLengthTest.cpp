// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "SecretLength.h"

#include <gtest/gtest.h>

using LibreSCRS::Darwin::lengthWithinBounds;
using LibreSCRS::Darwin::secretEntryAcceptable;
using LibreSCRS::Darwin::wire::PromptKind;

TEST(SecretLength, PinBelowMinimumKeepsOkOff)
{
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, 3, 4, 8));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Pin, 4, 4, 8));
}

TEST(SecretLength, PinAboveMaximumKeepsOkOff)
{
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Pin, 8, 4, 8));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, 9, 4, 8));
}

TEST(SecretLength, CanObeysTheSameBounds)
{
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Can, 5, 6, 6));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Can, 6, 6, 6));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Can, 7, 6, 6));
}

TEST(SecretLength, EmptyIsNeverAnAnswer)
{
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, 0, 0, 0));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Can, 0, 0, 8));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Mrz, 0, 0, 0));
}

TEST(SecretLength, UnsetBoundsLetTheCardDecide)
{
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Pin, 1, 0, 0));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Pin, 40, 0, 0));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Pin, 40, 4, 0));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, 9, 0, 8));
}

TEST(SecretLength, InvertedBoundsReadAsMaxEqualsMin)
{
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Pin, 6, 6, 4));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, 4, 6, 4));
    EXPECT_FALSE(secretEntryAcceptable(PromptKind::Pin, 7, 6, 4));
}

TEST(SecretLength, MrzKeepsItsNonEmptyRuleWhateverTheRequestCarried)
{
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Mrz, 1, 0, 0));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Mrz, 90, 4, 8));
    EXPECT_TRUE(secretEntryAcceptable(PromptKind::Mrz, 2, 30, 30));
}

TEST(SecretLength, ChangeFlowBoundsHelperIsUnchanged)
{
    EXPECT_TRUE(lengthWithinBounds(0, 0, 0));
    EXPECT_FALSE(lengthWithinBounds(3, 4, 8));
    EXPECT_FALSE(lengthWithinBounds(9, 4, 8));
}
