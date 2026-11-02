// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
// How the prompt names who is asking. The agent sends the signing identifier
// the requesting peer claims and no words around it, because the agent has no
// catalogue. One requester needs a word: the token extension acts for
// whichever application used the Keychain, so its identifier alone would name
// the bridge and hide that there is an application behind it. That word is the
// catalogue's, with the identifier substituted into it.
#include <optional>
#include <string_view>

namespace LibreSCRS::Darwin {

/// The signing identifier of LibreMac's token extension, the system's Keychain
/// bridge: every application that signs through the Keychain reaches the agent
/// as this one process.
inline constexpr std::string_view kTokenExtensionSigningId = "org.librescrs.LibreMac.LibreMacToken";

struct RequesterWording
{
    const char* key;      ///< catalogue key; its one %@ is the identifier
    const char* fallback; ///< the English shown outside a bundle, same %@
};

[[nodiscard]] constexpr std::optional<RequesterWording> wordingForRequester(std::string_view requester) noexcept
{
    if (requester == kTokenExtensionSigningId) {
        return RequesterWording{"prompter_requester_keychain", "%@ (Keychain)"};
    }
    return std::nullopt;
}

} // namespace LibreSCRS::Darwin
