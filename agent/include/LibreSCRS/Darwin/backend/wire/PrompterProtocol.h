// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/Cbor.h>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
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

// The contract this tree implements, carried as the "v" key on every request
// and on every reply.
//
// Why a version at all: the prompter is a long-lived per-user helper and
// SURVIVES an agent restart, so a new agent routinely meets an older helper. A
// helper that cannot be told to close what the previous agent left behind, or
// that answers a timed-out window as a cancellation, is a helper the agent has
// to recognise rather than guess at. Bump this whenever a message the agent
// DEPENDS ON changes shape.
//   1 -- RequestSecret / RequestSecrets / ConfirmAction / CancelCurrent, no
//        deadlines, no "timeout" reply word, no Reset, no "v"
//   2 -- entry deadlines, the "timeout" reply word, Reset/ResetDone, and "v"
inline constexpr std::uint32_t kPrompterProtocolVersion = 2;

enum class PromptKind : std::uint8_t { Pin, Can, Mrz };

// Prompter1 status vocabulary. "unauthorized" is the fail-closed rejection of a
// non-agent caller (a same-uid process trying to drive the prompter directly).
// APPEND new values, never insert: the numeric values are compiled into every
// consumer of this header.
enum class PromptReplyStatus : std::uint8_t {
    Ok,
    Cancelled,
    Error,
    Unauthorized,
    // The prompter closed the window because the holder's entry time ran out.
    // Distinct from Cancelled deliberately: telling someone they cancelled what
    // the clock took from them is the confusion this word removes.
    Timeout,
};

enum class PrompterParseError : std::uint8_t {
    NotDecodable,
    NotAMap,
    MissingField,
    WrongType,
    UnknownMessage,
    BadEnum,
    SecretTooLarge,
    // The request announced a protocol NEWER than kPrompterProtocolVersion.
    // Refused by name rather than parsed on a best-effort basis: a message this
    // build cannot fully read must not be half-honoured.
    UnsupportedVersion,
};

// Upper bound for an inline prompter secret (PIN/CAN/MRZ are tens of bytes);
// mirrors the Linux SecretMemfdReader::kMaxSecretBytes bound. parsePromptReply
// rejects anything larger fail-closed.
inline constexpr std::size_t kMaxSecretBytes = 8 * 1024;

// The closed vocabulary of PromptRequest::readerInterface, mirroring
// LibreLinux's PrompterWire kReaderInterface* tokens word for word so the two
// hosts speak one vocabulary. A CLOSED set and never prose: LibreAgent has no
// localisation, so any English wording it composed would arrive already
// written and no prompter could say it in the holder's language. The agent
// keeps the judgement (which slot is which); the prompter keeps the words.
//
// "unknown" never reaches the wire -- toCbor spells it as ABSENCE (below), and
// an unrecognised token a future agent sends is read by the prompter as
// unknown. The token exists so a host's switch over the core's ReaderInterface
// enum can stay exhaustive with no `default:`.
inline constexpr const char* kReaderInterfaceContact = "contact";
inline constexpr const char* kReaderInterfaceContactless = "contactless";
inline constexpr const char* kReaderInterfaceUnknown = "unknown";

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
    // The prompt this request raises, as the agent addresses it. The prompt
    // gate is keyed by card, so a later dismissal has to name one window.
    std::string promptId;
    // The window counts the first down and answers Timeout; the second is the
    // budget of the alternative entry (MRZ under a CAN prompt). Both are
    // DURATIONS in milliseconds from the moment the window is SHOWN -- not
    // absolute times, so the two processes need no shared clock, and not an
    // increment on each other. 0 means "no deadline set" and is spelled as
    // ABSENCE on the wire: a prompter predating these keys reads nothing, and
    // must never read an absent deadline as an instant expiry.
    std::uint32_t deadlineMs{0};
    std::uint32_t altDeadlineMs{0};
    // Which reader raised this prompt, as three flat keys. More than one
    // credential window can stand at once, so a dialog that does not name its
    // reader leaves the holder guessing which secret authorises which card --
    // and on a dual-interface unit whose two PC/SC names SHARE a serial, the
    // qualifier is the only thing separating two otherwise identical dialogs.
    //
    // All three are agent-owned and TRUSTED, unlike `artifacts`: the agent owns
    // the reader roster and is the only layer that can tell a dual-interface
    // unit's two slots apart. The prompter renders them and parses none of
    // them. Flat here and one embedded fact on the core seam
    // (PromptOptions::reader): flattening is the host's marshalling concern.
    //
    // `readerModel` is the shortened model, e.g. "OMNIKEY 5422", with no
    // interface wording composed into it. `readerInterface` is one of the
    // kReaderInterface* tokens above, or empty. `readerFull` is the literal
    // PC/SC name -- long enough to push the entry field off a small screen, so
    // it belongs behind a details affordance rather than in the chrome.
    //
    // Each is spelled as ABSENCE when it has nothing to say, like every other
    // optional field here, so a prompter predating these keys reads nothing.
    // NOT a protocol-version bump: nothing the agent DEPENDS ON changed shape
    // -- a helper that ignores these keys shows a dialog without a reader line,
    // which is exactly what every helper did before this.
    std::string readerModel;
    std::string readerInterface;
    std::string readerFull;
    bool operator==(const PromptRequest&) const = default;
};

// CancelCurrent (agent -> prompter): dismiss the window `promptId` names.
// Idempotent. An empty id is an unaddressed dismissal -- what a caller that
// knows no id can send, and what the server treats as "the current modal".
struct PromptCancel
{
    std::string promptId;
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
    // Addressed like the single-secret prompt: a change modal is a window the
    // agent may have to dismiss by name.
    std::string promptId;
    bool operator==(const RequestSecrets&) const = default;
};

// ConfirmAction (agent -> prompter): ask the human to confirm a change that is
// NOT a card operation. Answered by the platform's device-owner authentication
// (Touch ID or the account password), never by the card PIN -- the PIN
// authorizes use of the key and nothing else. `kind` is an open flow
// discriminator ("configure_trust" today); the server rejects kinds it does not
// implement. `requester` is the CLAIMED caller identity: the public SecTask
// path cannot report a verified one, so the copy must not present it as
// verified.
struct ConfirmAction
{
    std::string kind; // "configure_trust"
    std::string title;
    std::string description;
    // The catalogue id of `description`, travelling BESIDE the sentence rather
    // than instead of it: the agent has no catalogue of its own, so it writes
    // the English sentence it always wrote and names it, and the prompter --
    // which runs inside the host application's bundle -- looks the name up in
    // that bundle's catalogue and falls back to the sentence when it is not
    // there. Empty means "no key": render `description` as it arrived.
    std::string descriptionKey;
    std::string requester;
    std::string artifact; // the change being asked for
    bool operator==(const ConfirmAction&) const = default;
};

// Reset (agent -> prompter): close every window this prompter still has
// standing and forget the state behind them. The helper outlives the agent that
// installed it, so a fresh agent meets windows it never raised and cannot
// address by id -- this is how it clears them. Idempotent; carries nothing,
// because "everything" needs no argument.
struct PromptReset
{
    bool operator==(const PromptReset&) const = default;
};

using PrompterRequest = std::variant<PromptRequest, PromptCancel, RequestSecrets, ConfirmAction, PromptReset>;

// The reply (prompter -> agent). `secret` is present iff status == Ok.
struct PromptReply
{
    PromptReplyStatus status{PromptReplyStatus::Error};
    std::vector<std::uint8_t> secret;
    std::string userMessage;
    // The protocol the ANSWERING helper speaks, read off the "v" key. Empty
    // when the reply carried none, which names a helper older than that key
    // rather than guessing a version for it. The explicit default also keeps
    // every pre-existing positional brace-init of this aggregate free of
    // -Wmissing-field-initializers, so appending here stays source-compatible.
    std::optional<std::uint32_t> protocolVersion = std::nullopt;
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
    // The protocol the answering helper speaks; read the same way, and for the
    // same reason, as PromptReply::protocolVersion above.
    std::optional<std::uint32_t> protocolVersion = std::nullopt;
};

// The confirmation reply (prompter -> agent). Deliberately carries NO secret
// field: this path must be structurally incapable of transporting one, which is
// why it is not PromptReply with an unused buffer. Nothing here needs scrubbing
// for the same reason.
struct ConfirmReply
{
    PromptReplyStatus status{PromptReplyStatus::Error};
    std::string userMessage;
    // The protocol the answering helper speaks; read the same way, and for the
    // same reason, as PromptReply::protocolVersion above.
    std::optional<std::uint32_t> protocolVersion = std::nullopt;
};

// ResetDone (prompter -> agent): the answer to Reset, saying how many windows
// it actually closed. The count is what separates "there was nothing standing"
// from "the helper ignored the verb", which is otherwise the same silence.
// Alone among the replies it exposes no protocolVersion reader, and needs none:
// the encoder stamps the version onto this message like every other, but a
// helper old enough to be refused on it is one that does not know the verb and
// therefore answers nothing at all -- so the only ResetDone there is to read a
// version off already came from a helper new enough to have one.
struct ResetDone
{
    std::uint32_t closed{0};
};

// --- encode (build the CBOR body; the caller frames it) ----------------------
[[nodiscard]] CborValue toCbor(const PromptRequest& r);
[[nodiscard]] CborValue toCbor(const PromptCancel& r);
[[nodiscard]] CborValue toCbor(const RequestSecrets& r);
[[nodiscard]] CborValue toCbor(const PromptReply& r);
[[nodiscard]] CborValue toCbor(const MultiPromptReply& r);
[[nodiscard]] CborValue toCbor(const ConfirmAction& r);
[[nodiscard]] CborValue toCbor(const ConfirmReply& r);
[[nodiscard]] CborValue toCbor(const PromptReset& r);
[[nodiscard]] CborValue toCbor(const ResetDone& r);

// --- decode (strict; fail closed) --------------------------------------------
// Reads only the keys it knows, so a key added by a newer agent is ignored
// rather than fatal -- except the announced protocol itself: a request whose
// "v" is NEWER than kPrompterProtocolVersion is refused as UnsupportedVersion,
// because a message this build cannot fully read must not be half-honoured. An
// absent "v" is the first protocol and is accepted.
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
// Confirmation variant. Refuses outright any message that carries a secret
// field -- the struct having none only constrains this side, so the check is
// what makes the no-secret guarantee belong to the path. Scrubs its own
// decoded intermediates on every exit for the same reason: what arrives is
// not this side's to trust, and decoding has already copied it. An unknown
// status token fails closed like every other reply here, which on this path
// means the change is refused.
[[nodiscard]] std::expected<ConfirmReply, PrompterParseError> parseConfirmReply(std::span<const std::uint8_t> body);
// The Reset answer. Carries no secret and no status vocabulary -- only the
// count of windows the helper closed.
[[nodiscard]] std::expected<ResetDone, PrompterParseError> parseResetDone(std::span<const std::uint8_t> body);

// Encode + send one prompter reply on a connected fd, then zero every
// secret-bearing buffer this side created: the CBOR tree copy, the encoded
// frame body, and reply.secret itself. Send failures are best-effort (the
// peer just times out); the scrub always runs. Shared by every prompter send
// path.
void sendPromptReplyScrubbed(int connFd, PromptReply& reply) noexcept;
// Multi-secret overload: same encode-send-zero core, then zeroes BOTH
// reply.primary and reply.secondary.
void sendPromptReplyScrubbed(int connFd, MultiPromptReply& reply) noexcept;
// Confirmation reply: same encode-and-send core, but nothing to scrub
// afterwards -- the message has no secret field. Named without "Scrubbed" so
// the absence is visible at the call site rather than implied.
void sendConfirmReply(int connFd, const ConfirmReply& reply) noexcept;
// The Reset answer: same encode-and-send core, nothing to scrub -- the message
// carries a count and nothing else.
void sendResetDone(int connFd, const ResetDone& reply) noexcept;

// --- display -----------------------------------------------------------------
// What a batch-sign consent list comes to: the listed names, and how many the
// cap left out.
struct UntrustedArtifactList
{
    // One "  <bullet> <name>" line per listed name, newline-separated, with no
    // leading and no trailing newline. Empty when there is nothing to list.
    std::string block;
    // How many names the cap left out. Zero when every name is listed. It is a
    // COUNT rather than a rendered sentence because the sentence around it is a
    // word in the holder's language, and this layer has no catalogue.
    std::size_t omitted{0};
};

// Render the UNTRUSTED per-document display names of a batch-sign consent
// (PromptRequest::artifacts) into a plain, inert list for the prompt window,
// shown BELOW the trusted "Requested by" framing. Each name is neutralized --
// control characters, including the newlines a crafted filename could use to
// forge a line that mimics the agent-vouched chrome, become spaces -- and elided
// to a bounded, UTF-8-valid length. At most @p maxItems (0 = unlimited) names
// are listed; the rest are counted in `omitted`. An empty names list yields an
// empty block and nothing omitted (no batch, nothing to show).
//
// No prose of any kind comes out of here: the heading above the list and the
// sentence that says how many were left out are words the holder reads in their
// own language, and the window takes both from the application's catalogue.
[[nodiscard]] UntrustedArtifactList formatUntrustedArtifactList(const std::vector<std::string>& names,
                                                                std::size_t maxItems);

} // namespace LibreSCRS::Darwin::wire
