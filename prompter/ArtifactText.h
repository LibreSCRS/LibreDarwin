// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
// How the prompt names what the agent is about to do, by the request's
// category token. A token the agent mints for a raw card operation reads as
// that operation; anything else is a document name and is shown as one.
#include <optional>
#include <string_view>

namespace LibreSCRS::Darwin {

struct ArtifactOperation
{
    const char* key;      ///< catalogue key
    const char* fallback; ///< the English shown outside a bundle
};

[[nodiscard]] constexpr std::optional<ArtifactOperation> operationForArtifact(std::string_view artifact) noexcept
{
    if (artifact == "pkcs11") {
        return ArtifactOperation{"prompter_operation_pkcs11", "Cryptographic token operation"};
    }
    if (artifact == "pkcs11-derive") {
        return ArtifactOperation{"prompter_operation_pkcs11_derive", "Key agreement with the card key"};
    }
    return std::nullopt;
}

} // namespace LibreSCRS::Darwin
