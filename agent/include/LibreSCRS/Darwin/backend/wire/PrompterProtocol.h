// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/wire/Cbor.h>

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <variant>
#include <vector>

// The private agent<->prompter wire protocol (mirrors org.librescrs.Prompter1).
// A tiny CBOR request/reply over the 0600 prompter.sock. LM-free (wire-core) so
// the agent-owned prompter helper reuses it without linking the card stack. The
// secret returns INLINE over the local 0600 socket (no dbus-daemon buffer to
// bypass; scrubbed into a Secure::String on receipt, buffer zeroed).

namespace LibreSCRS::Darwin::wire {

enum class PromptKind : std::uint8_t { Pin, Can, Mrz };

// Prompter1 status vocabulary. "unauthorized" is the fail-closed rejection of a
// non-agent caller (a same-uid process trying to drive the prompter directly).
enum class PromptReplyStatus : std::uint8_t { Ok, Cancelled, Error, Unauthorized };

enum class PrompterParseError : std::uint8_t {
    NotDecodable,
    NotAMap,
    MissingField,
    WrongType,
    UnknownMessage,
    BadEnum,
};

// RequestSecret (agent -> prompter): ask the user for one secret value.
struct PromptRequest
{
    PromptKind kind{PromptKind::Pin};
    std::string title;
    std::string description;
    std::string requester; // human-readable client identity (the named requester)
    std::string artifact;  // filename / hash being acted on
    std::uint32_t minLength{0};
    std::uint32_t maxLength{0};
    bool operator==(const PromptRequest&) const = default;
};

// CancelCurrent (agent -> prompter): dismiss the current modal. Idempotent.
struct PromptCancel
{
    bool operator==(const PromptCancel&) const = default;
};

using PrompterRequest = std::variant<PromptRequest, PromptCancel>;

// The reply (prompter -> agent). `secret` is present iff status == Ok.
struct PromptReply
{
    PromptReplyStatus status{PromptReplyStatus::Error};
    std::vector<std::uint8_t> secret;
    std::string userMessage;
};

// --- encode (build the CBOR body; the caller frames it) ----------------------
[[nodiscard]] CborValue toCbor(const PromptRequest& r);
[[nodiscard]] CborValue toCbor(const PromptCancel&);
[[nodiscard]] CborValue toCbor(const PromptReply& r);

// --- decode (strict; fail closed) --------------------------------------------
[[nodiscard]] std::expected<PrompterRequest, PrompterParseError>
parsePrompterRequest(std::span<const std::uint8_t> body);
[[nodiscard]] std::expected<PromptReply, PrompterParseError> parsePromptReply(std::span<const std::uint8_t> body);

} // namespace LibreSCRS::Darwin::wire
