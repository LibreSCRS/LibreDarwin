// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SocketOperationChannel over a real transport + client: OpProgress/OpFinished
// events and a Sign result whose artifact rides an SCM_RIGHTS fd (shm_open) the
// client reads back.
#include <LibreSCRS/Darwin/backend/SocketOperationChannel.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Agent/wire/Cbor.h>
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Agent/wire/Messages.h>

#include <gtest/gtest.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <vector>

using namespace LibreSCRS::Darwin;
namespace Ops = ::LibreSCRS::Agent::Operations;
namespace A = ::LibreSCRS::Agent;

// Allocation-failure injection (this test binary only). A replacement global
// operator new/delete pair routes through std::malloc/std::free; setting
// g_failNextAlloc makes the NEXT allocation on THIS thread throw a real
// std::bad_alloc — driving the channel's noexcept emit guards the same way a
// production allocation failure would. thread_local keeps the transport loop
// thread unaffected. The matching deletes keep alloc/dealloc pairing
// consistent (malloc/free) under ASan.
namespace {
thread_local bool g_failNextAlloc = false;
} // namespace

void* operator new(std::size_t size)
{
    if (g_failNextAlloc) {
        g_failNextAlloc = false;
        throw std::bad_alloc();
    }
    if (void* p = std::malloc(size ? size : 1)) {
        return p;
    }
    throw std::bad_alloc();
}

void* operator new[](std::size_t size)
{
    return ::operator new(size);
}

void operator delete(void* p) noexcept
{
    std::free(p);
}

void operator delete[](void* p) noexcept
{
    std::free(p);
}

void operator delete(void* p, std::size_t) noexcept
{
    std::free(p);
}

void operator delete[](void* p, std::size_t) noexcept
{
    std::free(p);
}

namespace {

std::string uniquePath()
{
    return "/tmp/ld-oc-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()) + ".sock";
}

int connectClient(const std::string& path)
{
    const int c = ::socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    EXPECT_EQ(::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    return c;
}

// Establish a connection, return (transport, client fd, connId).
struct Wired
{
    std::unique_ptr<SocketTransport> tr;
    int client{-1};
    std::uint64_t connId{0};
    std::string path;
};

Wired wireUp()
{
    Wired w;
    w.path = uniquePath();
    w.tr = std::move(*SocketTransport::create(w.path));

    std::mutex m;
    std::condition_variable cv;
    std::atomic<std::uint64_t> id{0};
    w.tr->setRequestSink([&](SocketTransport::Inbound&& in) {
        id.store(in.connId);
        cv.notify_all();
    });
    w.client = connectClient(w.path);
    const auto hello = A::Wire::toCbor(A::Wire::RequestEnvelope{1, A::Wire::Hello{1, std::nullopt}}).encode();
    EXPECT_TRUE(A::Wire::sendFrame(w.client, hello).has_value());
    std::unique_lock<std::mutex> lk(m);
    cv.wait_for(lk, std::chrono::seconds(2), [&] { return id.load() != 0; });
    w.connId = id.load();
    return w;
}

A::Wire::CborValue recvEvent(int client)
{
    auto frame = A::Wire::recvFrame(client);
    EXPECT_TRUE(frame.has_value());
    auto decoded = A::Wire::decode(frame->body);
    EXPECT_TRUE(decoded.has_value());
    return *decoded;
}

TEST(SocketOperationChannel, EmitsProgressAndFinished)
{
    Wired w = wireUp();
    ASSERT_NE(w.connId, 0u);
    auto state = std::make_shared<Ops::OperationState>();
    state->phase.store(static_cast<std::uint32_t>(Ops::OperationPhase::Signing));
    SocketOperationChannel channel(*w.tr, w.connId, 77, state);

    channel.emitPropertiesChanged();
    const auto progress = recvEvent(w.client);
    EXPECT_EQ(*progress.find("t")->asText(), "OpProgress");
    EXPECT_EQ(progress.find("op")->asUInt(), 77u);
    EXPECT_EQ(progress.find("phase")->asUInt(), static_cast<std::uint64_t>(Ops::OperationPhase::Signing));

    channel.emitFinished(Ops::OperationStatus::Ok, LibreSCRS::Agent::ErrorCode::None, "k", "f");
    const auto finished = recvEvent(w.client);
    EXPECT_EQ(*finished.find("t")->asText(), "OpFinished");
    EXPECT_EQ(finished.find("status")->asUInt(), static_cast<std::uint64_t>(Ops::OperationStatus::Ok));

    ::close(w.client);
    w.tr.reset();
    std::filesystem::remove(w.path);
}

TEST(SocketOperationChannel, AllocationFailureInEmitIsDroppedNotFatal)
{
    Wired w = wireUp();
    ASSERT_NE(w.connId, 0u);
    auto state = std::make_shared<Ops::OperationState>();
    std::vector<std::uint64_t> pruned;
    SocketOperationChannel channel(*w.tr, w.connId, 42, state, {}, [&](std::uint64_t op) { pruned.push_back(op); });

    // A real bad_alloc inside the noexcept emitFinished: no terminate, the
    // event is dropped, and the terminal op-owner prune still fires.
    g_failNextAlloc = true;
    channel.emitFinished(Ops::OperationStatus::Error, LibreSCRS::Agent::ErrorCode::CommunicationError, "k", "f");
    EXPECT_FALSE(g_failNextAlloc); // the guarded body did allocate (and threw)
    ASSERT_EQ(pruned.size(), 1u);
    EXPECT_EQ(pruned[0], 42u);

    g_failNextAlloc = true;
    channel.emitPropertiesChanged();
    EXPECT_FALSE(g_failNextAlloc);

    // emitResult under allocation failure fails the op closed (false) rather
    // than emitting a half-result.
    Ops::SignedArtifact artifact;
    artifact.bytes = {'x'};
    artifact.meta = Ops::SignMeta{"pades", "b-b", false, false};
    const Ops::ResultPayload payload{artifact};
    g_failNextAlloc = true;
    EXPECT_FALSE(channel.emitResult(payload));
    g_failNextAlloc = false;

    // The channel and transport stay usable: a subsequent valid emit is the
    // FIRST event the client sees — the dropped emits never reached the wire.
    channel.emitFinished(Ops::OperationStatus::Ok, LibreSCRS::Agent::ErrorCode::None, "k2", "f2");
    const auto finished = recvEvent(w.client);
    EXPECT_EQ(*finished.find("t")->asText(), "OpFinished");
    EXPECT_EQ(finished.find("status")->asUInt(), static_cast<std::uint64_t>(Ops::OperationStatus::Ok));
    EXPECT_EQ(*finished.find("msgKey")->asText(), "k2");
    ASSERT_EQ(pruned.size(), 2u);

    ::close(w.client);
    w.tr.reset();
    std::filesystem::remove(w.path);
}

TEST(SocketOperationChannel, SignResultRidesAnScmRightsFd)
{
    Wired w = wireUp();
    ASSERT_NE(w.connId, 0u);
    auto state = std::make_shared<Ops::OperationState>();
    SocketOperationChannel channel(*w.tr, w.connId, 9, state);

    Ops::SignedArtifact artifact;
    artifact.bytes = {'S', 'I', 'G', 'N', 'E', 'D'};
    artifact.meta = Ops::SignMeta{"pades", "b-lta", true, false};
    EXPECT_TRUE(channel.emitResult(Ops::ResultPayload{artifact}));

    auto frame = A::Wire::recvFrame(w.client);
    ASSERT_TRUE(frame.has_value());
    ASSERT_EQ(frame->fds.size(), 1u); // one artifact fd
    const auto decoded = A::Wire::decode(frame->body);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded->find("t")->asText(), "OpResultReady");
    const auto* res = decoded->find("result");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(*res->find("kind")->asText(), "Sign");
    EXPECT_EQ(res->find("artifact")->asUInt(), 0u); // fd-index 0

    // Read the artifact bytes back from the passed fd.
    const int fd = frame->fds[0].get();
    char buf[16] = {0};
    const ssize_t n = ::pread(fd, buf, sizeof(buf), 0);
    ASSERT_EQ(n, 6);
    EXPECT_EQ(std::string(buf, 6), "SIGNED");

    ::close(w.client);
    w.tr.reset();
    std::filesystem::remove(w.path);
}

// A batch of 3 rows — 2 signed, 1 failed mid-batch (the halt shape) — rides
// 3 SCM_RIGHTS fds in row order; the failed row's fd is a REAL, valid,
// zero-length descriptor (never omitted, never -1), mirroring the wire's
// pinned zero-length-sealed-memfd convention for a failed row. Twin of
// SignResultRidesAnScmRightsFd above, generalized to N rows.
TEST(SocketOperationChannel, SignBatchResultRidesScmRightsFdsIncludingAZeroLengthFailedRow)
{
    Wired w = wireUp();
    ASSERT_NE(w.connId, 0u);
    auto state = std::make_shared<Ops::OperationState>();
    SocketOperationChannel channel(*w.tr, w.connId, 30, state);

    Ops::BatchSignResult rows;
    rows.push_back(Ops::BatchSignedRow{
        .displayName = "a.pdf",
        .bytes = {'A', 'A'},
        .meta = Ops::SignMeta{"pades", "b-lta", true, false},
        .code = A::ErrorCode::None,
    });
    rows.push_back(Ops::BatchSignedRow{
        .displayName = "b.pdf",
        .bytes = {'B', 'B', 'B'},
        .meta = Ops::SignMeta{"pades", "b-lta", true, false},
        .code = A::ErrorCode::None,
    });
    rows.push_back(Ops::BatchSignedRow{
        .displayName = "c.pdf",
        .bytes = {}, // failed row: never signed
        .meta = Ops::SignMeta{},
        .code = A::ErrorCode::CredentialWrong,
    });
    EXPECT_TRUE(channel.emitResult(Ops::ResultPayload{rows}));

    auto frame = A::Wire::recvFrame(w.client);
    ASSERT_TRUE(frame.has_value());
    ASSERT_EQ(frame->fds.size(), 3u); // one fd per row, in row order
    const auto decoded = A::Wire::decode(frame->body);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded->find("t")->asText(), "OpResultReady");
    const auto* res = decoded->find("result");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(*res->find("kind")->asText(), "SignBatch");
    const auto* rowsVal = res->find("rows");
    ASSERT_NE(rowsVal, nullptr);
    const auto* rowsArr = rowsVal->asArray();
    ASSERT_NE(rowsArr, nullptr);
    ASSERT_EQ(rowsArr->size(), 3u);

    // Row 0: signed, fd-index 0, 2 bytes.
    EXPECT_EQ(*(*rowsArr)[0].find("displayName")->asText(), "a.pdf");
    EXPECT_EQ((*rowsArr)[0].find("artifact")->asUInt(), 0u);
    EXPECT_EQ((*rowsArr)[0].find("errorCode")->asUInt(), static_cast<std::uint64_t>(A::ErrorCode::None));
    char buf0[4] = {0};
    ASSERT_EQ(::pread(frame->fds[0].get(), buf0, sizeof(buf0), 0), 2);
    EXPECT_EQ(std::string(buf0, 2), "AA");

    // Row 2: the failed row — a REAL, valid fd that reads back ZERO bytes,
    // never an invalid/-1 descriptor.
    EXPECT_EQ(*(*rowsArr)[2].find("displayName")->asText(), "c.pdf");
    EXPECT_EQ((*rowsArr)[2].find("artifact")->asUInt(), 2u);
    EXPECT_EQ((*rowsArr)[2].find("errorCode")->asUInt(), static_cast<std::uint64_t>(A::ErrorCode::CredentialWrong));
    const int failedFd = frame->fds[2].get();
    ASSERT_GE(failedFd, 0);
    char probe[1] = {0};
    EXPECT_EQ(::pread(failedFd, probe, sizeof(probe), 0), 0) << "the failed row's fd must be real and zero-length";

    ::close(w.client);
    w.tr.reset();
    std::filesystem::remove(w.path);
}

// Failed-mutation payload (InvalidPin, retriesLeft=2, blocked=false, records
// empty): the frame decodes to the A::Wire::CredentialsResult shape and
// delivery is inline (no fd) with emitResult returning true.
TEST(SocketOperationChannel, CredentialsResultInvalidPinMutationDecodes)
{
    Wired w = wireUp();
    ASSERT_NE(w.connId, 0u);
    auto state = std::make_shared<Ops::OperationState>();
    SocketOperationChannel channel(*w.tr, w.connId, 21, state);

    A::CredentialOpResult op;
    op.outcome = A::CredentialOutcome::InvalidPin;
    op.retriesLeft = 2;
    op.blocked = false;
    const Ops::CredentialResult payload{op, {}};
    EXPECT_TRUE(channel.emitResult(Ops::ResultPayload{payload}));

    auto frame = A::Wire::recvFrame(w.client);
    ASSERT_TRUE(frame.has_value());
    EXPECT_TRUE(frame->fds.empty()); // inline delivery: no fd, no seal step
    const auto decoded = A::Wire::decode(frame->body);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded->find("t")->asText(), "OpResultReady");
    EXPECT_EQ(decoded->find("op")->asUInt(), 21u);

    const auto* res = decoded->find("result");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(*res->find("kind")->asText(), "Credentials");

    const auto* credOp = res->find("result");
    ASSERT_NE(credOp, nullptr);
    EXPECT_EQ(*credOp->find("outcome")->asText(), "invalidPin");
    EXPECT_EQ(credOp->find("retriesLeft")->asUInt(), 2u);
    EXPECT_EQ(*credOp->find("blocked")->asBool(), false);
    EXPECT_EQ(credOp->find("pinActivated"), nullptr); // omitted: nullopt on the source

    const auto* recordsVal = res->find("records");
    ASSERT_NE(recordsVal, nullptr);
    const auto* records = recordsVal->asArray();
    ASSERT_NE(records, nullptr);
    EXPECT_TRUE(records->empty());

    ::close(w.client);
    w.tr.reset();
    std::filesystem::remove(w.path);
}

// Ok listing payload (2 records): the frame decodes with the records intact.
TEST(SocketOperationChannel, CredentialsResultOkListingCarriesRecords)
{
    Wired w = wireUp();
    ASSERT_NE(w.connId, 0u);
    auto state = std::make_shared<Ops::OperationState>();
    SocketOperationChannel channel(*w.tr, w.connId, 22, state);

    A::CredentialOpResult op;
    op.outcome = A::CredentialOutcome::Ok;

    A::CredentialRecord user;
    user.id = "user:0x11";
    user.label = "User PIN";
    user.kind = "user";
    user.state = "operational";
    user.retriesLeft = 3;

    A::CredentialRecord sign;
    sign.id = "sign:0x12";
    sign.label = "Signing PIN";
    sign.kind = "sign";
    sign.state = "blocked";

    const Ops::CredentialResult payload{op, {user, sign}};
    EXPECT_TRUE(channel.emitResult(Ops::ResultPayload{payload}));

    auto frame = A::Wire::recvFrame(w.client);
    ASSERT_TRUE(frame.has_value());
    const auto decoded = A::Wire::decode(frame->body);
    ASSERT_TRUE(decoded.has_value());

    const auto* res = decoded->find("result");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(*res->find("kind")->asText(), "Credentials");
    const auto* credOp = res->find("result");
    ASSERT_NE(credOp, nullptr);
    EXPECT_EQ(*credOp->find("outcome")->asText(), "ok");

    const auto* recordsVal = res->find("records");
    ASSERT_NE(recordsVal, nullptr);
    const auto* records = recordsVal->asArray();
    ASSERT_NE(records, nullptr);
    ASSERT_EQ(records->size(), 2u);
    EXPECT_EQ(*(*records)[0].find("id")->asText(), "user:0x11");
    EXPECT_EQ(*(*records)[0].find("label")->asText(), "User PIN");
    EXPECT_EQ(*(*records)[0].find("kind")->asText(), "user");
    EXPECT_EQ(*(*records)[0].find("state")->asText(), "operational");
    EXPECT_EQ((*records)[0].find("retriesLeft")->asUInt(), 3u);
    EXPECT_EQ(*(*records)[1].find("id")->asText(), "sign:0x12");
    EXPECT_EQ(*(*records)[1].find("kind")->asText(), "sign");
    EXPECT_EQ(*(*records)[1].find("state")->asText(), "blocked");

    ::close(w.client);
    w.tr.reset();
    std::filesystem::remove(w.path);
}

// Ordering: the result frame is enqueued before a subsequent emitFinished
// frame, so the client observes OpResultReady strictly before OpFinished.
TEST(SocketOperationChannel, CredentialsResultEnqueuedBeforeFinished)
{
    Wired w = wireUp();
    ASSERT_NE(w.connId, 0u);
    auto state = std::make_shared<Ops::OperationState>();
    SocketOperationChannel channel(*w.tr, w.connId, 23, state);

    A::CredentialOpResult op;
    op.outcome = A::CredentialOutcome::Ok;
    const Ops::CredentialResult payload{op, {}};
    EXPECT_TRUE(channel.emitResult(Ops::ResultPayload{payload}));
    channel.emitFinished(Ops::OperationStatus::Ok, A::ErrorCode::None, "k", "f");

    const auto first = recvEvent(w.client);
    EXPECT_EQ(*first.find("t")->asText(), "OpResultReady");
    EXPECT_EQ(first.find("op")->asUInt(), 23u);

    const auto second = recvEvent(w.client);
    EXPECT_EQ(*second.find("t")->asText(), "OpFinished");
    EXPECT_EQ(second.find("op")->asUInt(), 23u);

    ::close(w.client);
    w.tr.reset();
    std::filesystem::remove(w.path);
}

} // namespace
