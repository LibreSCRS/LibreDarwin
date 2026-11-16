// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
// What the prompt window's OK button accepts, kept out of AppKit so it can be
// tested. The rules are the Linux prompter's, field for field:
//   - PIN: digits only, length within [min, max]. A bound the request omits (0
//     on this wire, which omits zero fields) is 4 for the minimum and 8 for the
//     maximum; an inverted pair is read as max == min.
//   - CAN: exactly six digits, whatever bounds the request carried.
//   - MRZ: one free-form field, accepted when not empty.
// An empty entry is never an answer: the agent reads it as a cancellation.
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace LibreSCRS::Darwin {

inline constexpr std::uint32_t kDefaultPinMinLength = 4;
inline constexpr std::uint32_t kDefaultPinMaxLength = 8;
inline constexpr std::size_t kCanLength = 6;

struct LengthBounds
{
    std::uint32_t min;
    std::uint32_t max;
};

// The bounds a PIN field is held to for the values a request carried.
[[nodiscard]] constexpr LengthBounds pinBounds(std::uint32_t requestedMin, std::uint32_t requestedMax) noexcept
{
    LengthBounds b{requestedMin != 0 ? requestedMin : kDefaultPinMinLength,
                   requestedMax != 0 ? requestedMax : kDefaultPinMaxLength};
    if (b.max < b.min) {
        b.max = b.min;
    }
    return b;
}

[[nodiscard]] constexpr bool allDigits(std::string_view entry) noexcept
{
    for (const char c : entry) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

// A PIN entry (UTF-8 bytes): digits only and within the bounds. Digits are one
// byte each, so the byte count is the character count.
[[nodiscard]] constexpr bool pinEntryAcceptable(std::string_view entry, std::uint32_t requestedMin,
                                                std::uint32_t requestedMax) noexcept
{
    const LengthBounds b = pinBounds(requestedMin, requestedMax);
    return entry.size() >= b.min && entry.size() <= b.max && allDigits(entry);
}

// May OK be enabled for a single-secret entry? The bounds are those the
// request carried, as received.
[[nodiscard]] constexpr bool secretEntryAcceptable(wire::PromptKind kind, std::string_view entry,
                                                   std::uint32_t requestedMin, std::uint32_t requestedMax) noexcept
{
    switch (kind) {
    case wire::PromptKind::Mrz:
        return !entry.empty();
    case wire::PromptKind::Can:
        return entry.size() == kCanLength && allDigits(entry);
    default:
        return pinEntryAcceptable(entry, requestedMin, requestedMax);
    }
}

// The change panel's bounds, as the request carried them.
struct ChangeBounds
{
    std::uint32_t primaryMin;
    std::uint32_t primaryMax;
    std::uint32_t newMin;
    std::uint32_t newMax;
};

// May OK be enabled for the change panel? The current PIN within the primary
// bounds, the new PIN within the new bounds (both digits only) and the
// confirmation equal to the new one.
[[nodiscard]] constexpr bool changeEntriesAcceptable(const ChangeBounds& bounds, std::string_view current,
                                                     std::string_view newer, std::string_view confirm) noexcept
{
    return pinEntryAcceptable(current, bounds.primaryMin, bounds.primaryMax) &&
           pinEntryAcceptable(newer, bounds.newMin, bounds.newMax) && confirm == newer;
}

} // namespace LibreSCRS::Darwin
