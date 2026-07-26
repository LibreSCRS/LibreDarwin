// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/Cbor.h>

#include <cstddef>
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
// bypass; scrubbed into a Secure::String on receipt, buffer zeroed). The
// multi-secret change flow (RequestSecrets) returns BOTH secrets inline the
// same way.

namespace LibreSCRS::Darwin::wire {

using LibreSCRS::Agent::Wire::CborValue;

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
    SecretTooLarge,
};

// Upper bound for an inline prompter secret (PIN/CAN/MRZ are tens of bytes);
// mirrors the Linux SecretMemfdReader::kMaxSecretBytes bound. parsePromptReply
// rejects anything larger fail-closed.
inline constexpr std::size_t kMaxSecretBytes = 8 * 1024;

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
    // The UNTRUSTED per-document display names of a Card1.SignBatch consent
    // (BatchSignFlow's PromptOptions::artifacts) — distinct from `artifact`
    // above, which stays the agent-owned TRUSTED category token for the whole
    // request ("signature-batch" for a batch). Empty for every prompt that is
    // not a batch sign. Mirrors LibreLinux's Prompter1 `artifacts` (as)
    // RequestSecret option.
    std::vector<std::string> artifacts;
    // Retry context for a re-prompt after the card rejected the CAN/MRZ
    // collected last time for the SAME card (CredentialCache::
    // markCredentialWrong / applyRetryContext on the agent core): `attempt`
    // numbers this prompt (2 = second attempt, ...), `lastError` carries the
    // msgKey of the failure that triggered the retry. Both stay at their
    // default (0 / empty) on the first-ever prompt for a card. Mirrors
    // LibreLinux's Prompter1 `attempt`/`last_error` RequestSecret options;
    // out of scope for RequestSecrets (change_pin is never a CAN/MRZ retry).
    std::uint32_t attempt{0};
    std::string lastError;
    bool operator==(const PromptRequest&) const = default;
};

// CancelCurrent (agent -> prompter): dismiss the current modal. Idempotent.
struct PromptCancel
{
    bool operator==(const PromptCancel&) const = default;
};

// RequestSecrets (agent -> prompter): ask the user for a linked secret pair in
// one modal — the current credential plus its replacement. `kind` is an open
// flow discriminator at the wire layer ("change_pin" today); the server
// rejects kinds it does not implement. Per-role bounds: primary* applies to
// the CURRENT credential field, new* to both the new and confirm fields. The
// confirm value never crosses the wire.
struct RequestSecrets
{
    std::string kind; // "change_pin"
    std::string title;
    std::string description;
    std::string requester; // human-readable client identity (the named requester)
    std::string artifact;  // display label for what the change applies to
    std::uint32_t primaryMinLength{0};
    std::uint32_t primaryMaxLength{0};
    std::uint32_t newMinLength{0};
    std::uint32_t newMaxLength{0};
    bool operator==(const RequestSecrets&) const = default;
};

using PrompterRequest = std::variant<PromptRequest, PromptCancel, RequestSecrets>;

// The reply (prompter -> agent). `secret` is present iff status == Ok.
struct PromptReply
{
    PromptReplyStatus status{PromptReplyStatus::Error};
    std::vector<std::uint8_t> secret;
    std::string userMessage;
};

// The multi-secret reply (prompter -> agent). Both secrets are present iff
// status == Ok: `primary` carries the CURRENT credential, `secondary` the NEW
// one — inline over the same 0600 socket, scrubbed on receipt like the
// single-secret reply.
struct MultiPromptReply
{
    PromptReplyStatus status{PromptReplyStatus::Error};
    std::vector<std::uint8_t> primary;   // current credential; present iff Ok
    std::vector<std::uint8_t> secondary; // new credential; present iff Ok
    std::string userMessage;
};

// --- encode (build the CBOR body; the caller frames it) ----------------------
[[nodiscard]] CborValue toCbor(const PromptRequest& r);
[[nodiscard]] CborValue toCbor(const PromptCancel&);
[[nodiscard]] CborValue toCbor(const RequestSecrets& r);
[[nodiscard]] CborValue toCbor(const PromptReply& r);
[[nodiscard]] CborValue toCbor(const MultiPromptReply& r);

// --- decode (strict; fail closed) --------------------------------------------
[[nodiscard]] std::expected<PrompterRequest, PrompterParseError>
parsePrompterRequest(std::span<const std::uint8_t> body);
// Rejects a secret over kMaxSecretBytes (SecretTooLarge). Scrubs its own
// decoded intermediates on every exit; the caller still owns (and must zero)
// the raw frame body and the returned reply.secret after use.
[[nodiscard]] std::expected<PromptReply, PrompterParseError> parsePromptReply(std::span<const std::uint8_t> body);
// Multi-secret variant: rejects EITHER secret over kMaxSecretBytes
// (SecretTooLarge), per secret. Scrubs its own decoded intermediates on every
// exit; the caller still owns (and must zero) the raw frame body — it carries
// BOTH secrets — and the returned reply.primary / reply.secondary after use.
[[nodiscard]] std::expected<MultiPromptReply, PrompterParseError>
parseMultiPromptReply(std::span<const std::uint8_t> body);

// Encode + send one prompter reply on a connected fd, then zero every
// secret-bearing buffer this side created: the CBOR tree copy, the encoded
// frame body, and reply.secret itself. Send failures are best-effort (the
// peer just times out); the scrub always runs. Shared by every prompter send
// path.
void sendPromptReplyScrubbed(int connFd, PromptReply& reply) noexcept;
// Multi-secret overload: same encode-send-zero core, then zeroes BOTH
// reply.primary and reply.secondary.
void sendPromptReplyScrubbed(int connFd, MultiPromptReply& reply) noexcept;

// --- display -----------------------------------------------------------------
// Render the UNTRUSTED per-document display names of a batch-sign consent
// (PromptRequest::artifacts) into a plain, inert block for the prompt window,
// shown BELOW the trusted "Requested by" framing. Each name is neutralized --
// control characters, including the newlines a crafted filename could use to
// forge a line that mimics the agent-vouched chrome, become spaces -- and elided
// to a bounded, UTF-8-valid length. At most @p maxItems (0 = unlimited) names
// are listed, with a "(+N more)" tail. An empty names list yields an empty
// string (no batch, nothing to show).
[[nodiscard]] std::string formatUntrustedArtifactList(const std::vector<std::string>& names, std::size_t maxItems);

} // namespace LibreSCRS::Darwin::wire
