// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
// The length rule behind the prompt window's OK button, kept out of AppKit so
// it can be tested. Lengths are UTF-8 byte counts, the unit that crosses the
// wire.
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace LibreSCRS::Darwin {

// A zero bound is "unset" on the wire (the request codec omits zero fields):
// min 0 imposes no lower limit and max 0 no upper limit, so an unknown card
// policy degrades to "let the card decide" rather than a permanently disabled
// OK.
[[nodiscard]] constexpr bool lengthWithinBounds(std::size_t len, std::uint32_t minLen, std::uint32_t maxLen) noexcept
{
    return len >= minLen && (maxLen == 0 || len <= maxLen);
}

// May OK be enabled for a single-secret entry of @p len bytes? An empty entry
// is never an answer (the agent reads it as a cancellation). PIN and CAN also
// obey the bounds the request carried, as the Linux prompter does; an inverted
// pair is read as max == min, as it is there. MRZ is one free-form field with
// no per-character bounds, so it keeps the non-empty rule only.
[[nodiscard]] constexpr bool secretEntryAcceptable(wire::PromptKind kind, std::size_t len, std::uint32_t minLen,
                                                   std::uint32_t maxLen) noexcept
{
    if (kind == wire::PromptKind::Mrz) {
        return len > 0;
    }
    if (maxLen != 0 && maxLen < minLen) {
        maxLen = minLen;
    }
    return lengthWithinBounds(len, std::max<std::uint32_t>(minLen, 1), maxLen);
}

} // namespace LibreSCRS::Darwin
