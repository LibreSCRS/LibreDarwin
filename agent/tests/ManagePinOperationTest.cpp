// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Darwin-side behaviour test for the credential-management operation adaptors.
// Each seam is a Fake and the op runs synchronously on the test thread via
// runOnWorker(); no bus, prompter, or card is involved. Pins the wire-ordering
// contract these thin adaptors own on top of the shared LibreAgent flows:
//  - ManagePin (cancelled prompt): exactly ONE Credentials1.Result (outcome
//    userCancelled, empty records) is emitted BEFORE finish(Cancelled, None).
//  - ManagePin (wrong PIN): the emitted Result carries invalidPin + retriesLeft,
//    and finish maps the outcome via errorCodeFor to (Error, CredentialWrong).
//  - ListCredentials (failed list): the typed Result is available for EVERY
//    completed attempt — a failed list emits Result (outcome unspecified,
//    empty records) BEFORE Finished(Error), mirroring the mutations.

#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/CardSessionHolder.h>
#include <LibreSCRS/Agent/operations/PinChangeFlow.h> // PinManageRequest
#include <LibreSCRS/Agent/operations/PromptSerializer.h>
#include "operations/ListCredentialsOperation.h"
#include "operations/ManagePinOperation.h"

#include <LibreSCRS/Agent/OperationState.h>
#include <LibreSCRS/Agent/backend/OperationChannel.h> // OperationChannel, ResultPayload, CredentialResult
#include <LibreSCRS/Agent/value/CredentialRecord.h>   // CredentialSnapshot, CredentialOutcome
#include <LibreSCRS/Agent/value/ErrorTaxonomy.h>      // ErrorCode
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardMap.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <gtest/gtest.h>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

using namespace LibreSCRS::Agent;
using namespace LibreSCRS::Agent::Operations;

namespace {

struct EmittedFinish
{
    std::uint32_t status;
    std::uint32_t errorCode;
};

// Records the ordered wire events (Result then Finished) plus the payloads so a
// test can assert BOTH the strict Result-before-Finished ordering and the
// contents. Only the CredentialResult arm is captured — the ops under test emit
// no other arm.
class FakeCredentialChannel final : public OperationChannel
{
public:
    enum class Event { Result, Finish };

    void emitPropertiesChanged() noexcept override {}
    void emitFinished(OperationStatus status, ErrorCode code, std::string_view, std::string_view) noexcept override
    {
        events.push_back(Event::Finish);
        finishes.push_back({static_cast<std::uint32_t>(status), static_cast<std::uint32_t>(code)});
    }
    bool emitResult(const ResultPayload& result) noexcept override
    {
        if (const auto* cred = std::get_if<CredentialResult>(&result)) {
            events.push_back(Event::Result);
            results.push_back(*cred);
        }
        return true;
    }

    std::vector<Event> events;
    std::vector<CredentialResult> results;
    std::vector<EmittedFinish> finishes;
};

// Programmable double over the multi-secret prompter: requestPinChange returns
// the seeded PIN-change result; the single-secret surface is unused by these
// tests (an open failure precedes any prompt; the change path uses the change
// modal only).
class FakePrompter final : public PrompterClientBase
{
public:
    PinChangePromptResult pinChangeResult{PromptStatus::Error, std::nullopt, std::nullopt, "unseeded"};

    PromptResult requestPin(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestCan(const PromptOptions&) override
    {
        return {};
    }
    PromptResult requestMrz(const PromptOptions&) override
    {
        return {};
    }
    PinChangePromptResult requestPinChange(const PromptOptions&) override
    {
        return pinChangeResult;
    }
};

// Programmable double over the CredentialManager seam: changePIN returns the
// seeded PINResult (default Unsupported, the answer of a bare card). list is
// implemented only to satisfy the pure interface — the change flow drives the
// mutation off the passed-in snapshot, not a fresh list.
class FakeCredentialManager final : public CredentialManager
{
public:
    LibreSCRS::Plugin::PINResult changePinResult{.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};

    CredentialListing list(LibreSCRS::SmartCard::CardSession&, const CandidateList&) override
    {
        return {};
    }
    LibreSCRS::Plugin::PINResult changePIN(LibreSCRS::SmartCard::CardSession&, const CandidateList&, std::string_view,
                                           const LibreSCRS::Secure::String&, const LibreSCRS::Secure::String&) override
    {
        return changePinResult;
    }
    LibreSCRS::Plugin::PINResult activateTransportPin(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                                      std::string_view, const LibreSCRS::Secure::String&,
                                                      const LibreSCRS::Secure::String&) override
    {
        return {.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};
    }
    LibreSCRS::Plugin::PINResult activateSigningKey(LibreSCRS::SmartCard::CardSession&, const CandidateList&,
                                                    const LibreSCRS::Secure::String&) override
    {
        return {.outcome = LibreSCRS::Plugin::PINResultOutcome::Unsupported};
    }
};

// A holder over a detached test session; failWith drives an acquire failure so a
// flow observes an open error the same way the shared LibreAgent flow tests do.
inline std::unique_ptr<CardSessionHolder> makeHolder(std::optional<LibreSCRS::SmartCard::OpenError> failWith)
{
    auto factory = [failWith = std::move(failWith)](const std::string& r)
        -> std::expected<std::shared_ptr<LibreSCRS::SmartCard::CardSession>, LibreSCRS::SmartCard::OpenError> {
        if (failWith) {
            return std::unexpected{*failWith};
        }
        return LibreSCRS::SmartCard::detail::makeDetachedCardSession(r);
    };
    auto resolver = [](std::span<const std::uint8_t>, LibreSCRS::SmartCard::CardSession&) { return CandidateList{}; };
    return std::make_unique<CardSessionHolder>("FakeReader", std::move(factory), std::move(resolver),
                                               std::make_shared<LibreSCRS::SmartCard::CardMap>());
}

// A single-record snapshot: a changeable UserPIN addressed by id "user:0x01", so
// a change request resolves to a canChange record and the change flow prompts +
// drives the seam.
CredentialSnapshot makeSnapshot()
{
    CredentialRecord r;
    r.id = "user:0x01";
    r.label = "UserPIN";
    r.kind = "user";
    r.state = "operational";
    r.retriesLeft = 3;
    r.minLength = 4;
    r.maxLength = 8;
    r.canChange = true;
    CredentialSnapshot s;
    s.records.push_back(std::move(r));
    s.version = 1;
    return s;
}

LibreSCRS::Plugin::PINResult pinResult(LibreSCRS::Plugin::PINResultOutcome outcome,
                                       std::optional<int> retriesLeft = std::nullopt, bool blocked = false)
{
    LibreSCRS::Plugin::PINResult r;
    r.outcome = outcome;
    r.retriesLeft = retriesLeft;
    r.blocked = blocked;
    return r;
}

PinManageRequest changeReq()
{
    return PinManageRequest{.cardKey = "card-A", .pinId = "user:0x01", .verb = "change", .activateKey = false};
}

} // namespace

// A cancelled change prompt still emits exactly one Credentials1.Result (outcome
// userCancelled, empty records) BEFORE Finished, and finishes Cancelled/None:
// cancellation is a finish STATUS, never an error code.
TEST(ManagePinOperation, CancelledPromptEmitsUserCancelledResultThenFinishesCancelled)
{
    auto holder = makeHolder(std::nullopt);
    FakeCredentialManager credentials;
    FakePrompter prompter;
    prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Cancelled, std::nullopt, std::nullopt, ""};
    PromptSerializer serializer;
    CredentialCache credCache;
    CredentialSnapshotCache snapshotCache;
    CardReadCache readCache;

    auto channel = std::make_unique<FakeCredentialChannel>();
    auto* raw = channel.get();

    auto state = std::make_shared<OperationState>();
    ManagePinOperation op(std::move(channel),
                          ManagePinOperation::Deps{
                              .holder = holder.get(),
                              .credentials = credentials,
                              .prompter = prompter,
                              .serializer = serializer,
                              .credCache = credCache,
                              .snapshotCache = snapshotCache,
                              .readCache = readCache,
                              .cardKey = "card-A",
                              .readerName = "FakeReader",
                              .requester = "test",
                              .artifact = "credentials",
                              .request = changeReq(),
                              .snapshot = makeSnapshot(),
                          },
                          state);
    op.runOnWorker();

    ASSERT_EQ(raw->events.size(), 2u);
    EXPECT_EQ(raw->events[0], FakeCredentialChannel::Event::Result) << "the Result must precede Finished";
    EXPECT_EQ(raw->events[1], FakeCredentialChannel::Event::Finish);

    ASSERT_EQ(raw->results.size(), 1u) << "exactly one Result for the completed attempt";
    EXPECT_EQ(raw->results[0].op.outcome, CredentialOutcome::UserCancelled);
    EXPECT_TRUE(raw->results[0].records.empty()) << "a mutation carries no record listing";

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Cancelled));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::None));
}

// A wrong current PIN: the emitted Result carries the invalidPin outcome with the
// card's retriesLeft, and finish maps the outcome via errorCodeFor to
// (Error, CredentialWrong) — the retries count rides the Result, not the code.
TEST(ManagePinOperation, WrongPinEmitsInvalidPinResultThenFinishesCredentialWrong)
{
    auto holder = makeHolder(std::nullopt);
    FakeCredentialManager credentials;
    credentials.changePinResult = pinResult(LibreSCRS::Plugin::PINResultOutcome::InvalidPin, 2);
    FakePrompter prompter;
    prompter.pinChangeResult = PinChangePromptResult{PromptStatus::Ok, LibreSCRS::Secure::String{"0000"},
                                                     LibreSCRS::Secure::String{"2222"}, ""};
    PromptSerializer serializer;
    CredentialCache credCache;
    CredentialSnapshotCache snapshotCache;
    CardReadCache readCache;

    auto channel = std::make_unique<FakeCredentialChannel>();
    auto* raw = channel.get();

    auto state = std::make_shared<OperationState>();
    ManagePinOperation op(std::move(channel),
                          ManagePinOperation::Deps{
                              .holder = holder.get(),
                              .credentials = credentials,
                              .prompter = prompter,
                              .serializer = serializer,
                              .credCache = credCache,
                              .snapshotCache = snapshotCache,
                              .readCache = readCache,
                              .cardKey = "card-A",
                              .readerName = "FakeReader",
                              .requester = "test",
                              .artifact = "credentials",
                              .request = changeReq(),
                              .snapshot = makeSnapshot(),
                          },
                          state);
    op.runOnWorker();

    ASSERT_EQ(raw->events.size(), 2u);
    EXPECT_EQ(raw->events[0], FakeCredentialChannel::Event::Result) << "the Result must precede Finished";
    EXPECT_EQ(raw->events[1], FakeCredentialChannel::Event::Finish);

    ASSERT_EQ(raw->results.size(), 1u);
    EXPECT_EQ(raw->results[0].op.outcome, CredentialOutcome::InvalidPin);
    EXPECT_EQ(raw->results[0].op.retriesLeft, std::optional<int>{2}) << "retriesLeft rides the Result payload";

    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_EQ(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Error));
    EXPECT_EQ(raw->finishes[0].errorCode, static_cast<std::uint32_t>(ErrorCode::CredentialWrong));
}

// A failed list (session open failure) still emits the typed Credentials1
// Result — outcome unspecified, empty records — BEFORE Finished(Error): the
// contract promises the payload for EVERY completed attempt, so a client never
// has to guess a failure class from a Result-less terminal.
TEST(ListCredentialsOperation, FailedListEmitsUnspecifiedResultThenFinishesError)
{
    auto holder = makeHolder(LibreSCRS::SmartCard::OpenError{LibreSCRS::SmartCard::OpenError::Kind::ReaderUnavailable,
                                                             LibreSCRS::LocalizedText{}, std::nullopt});
    FakeCredentialManager credentials;
    FakePrompter prompter;
    PromptSerializer serializer;
    CredentialCache credCache;
    CredentialSnapshotCache snapshotCache;

    auto channel = std::make_unique<FakeCredentialChannel>();
    auto* raw = channel.get();

    auto state = std::make_shared<OperationState>();
    ListCredentialsOperation op(std::move(channel),
                                ListCredentialsOperation::Deps{
                                    .holder = holder.get(),
                                    .credentials = credentials,
                                    .prompter = prompter,
                                    .serializer = serializer,
                                    .credCache = credCache,
                                    .snapshotCache = snapshotCache,
                                    .cardKey = "card-A",
                                    .readerName = "FakeReader",
                                    .requester = "test",
                                    .artifact = "credentials",
                                },
                                state);
    op.runOnWorker();

    ASSERT_EQ(raw->events.size(), 2u);
    EXPECT_EQ(raw->events[0], FakeCredentialChannel::Event::Result) << "the Result must precede Finished";
    EXPECT_EQ(raw->events[1], FakeCredentialChannel::Event::Finish);
    ASSERT_EQ(raw->results.size(), 1u) << "exactly one Result for the completed attempt";
    EXPECT_EQ(raw->results[0].op.outcome, CredentialOutcome::Unspecified);
    EXPECT_TRUE(raw->results[0].records.empty()) << "a failed list carries no records";
    ASSERT_EQ(raw->finishes.size(), 1u);
    EXPECT_NE(raw->finishes[0].status, static_cast<std::uint32_t>(OperationStatus::Ok));
}
