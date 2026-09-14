// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// ImportCscaMasterList end-to-end over the App-Group socket -- the socket
// host's counterpart of the D-Bus host's anchor-import suite, over the same
// shared import library, asserting the two properties that do NOT travel with
// that library because they belong to the verb and to the host, not to the
// import:
//
//   * ORDER: authorise, then rate-limit, then read the descriptor. A refused
//     caller must not be able to make the agent read anything at all, and an
//     implementation with the checks reversed returns the very same error
//     name -- so the tests here assert the SIDE EFFECT. A descriptor over
//     SCM_RIGHTS shares one open file description with the sender, so the
//     offset the agent would advance by reading is the offset this process can
//     still see; and a PIPE is refused by the read path under a different name
//     than the gates raise, so the name alone says which check ran first.
//     SocketFrontendTest holds the authorise half of this order; the rate-limit
//     half and the pipe form are here.
//
//   * RECONCILIATION reports and does not tidy: a remembered report the cache
//     no longer bears out is dropped when the frontend is built, a report the
//     cache does bear out survives, and in neither case is a byte of the cache
//     touched. The library owns WHAT is stale; this host owns WHEN to ask --
//     and, by omission, whether to ask at all, which is the thing no library
//     test can see.
//
// Every list is minted in-process by the agent's own fixture archive. No
// master list is redistributed here.

#include "SocketRig.h"
#include "SyntheticMasterList.h" // LibreAgent::TestSupport

#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/config/ConfigStore.h>
#include <LibreSCRS/Agent/operations/RateLimiter.h>
#include <LibreSCRS/Agent/trust/CscaAnchorImport.h>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace LibreSCRS::Darwin;
using namespace LibreSCRS::Darwin::TestSupport;
namespace Agent = ::LibreSCRS::Agent;
// Not `using namespace ...::Test`: inside a TEST() body an unqualified `Test::`
// resolves to gtest's own base class, which is a confusing way to fail.
namespace fixture = LibreSCRS::Agent::Test;
namespace fs = std::filesystem;

namespace {

// An instant a publisher might have signed at.
constexpr std::int64_t kSignedEarlier = 1'700'000'000;

// A number no count on this wire can reach, so a missing or mistyped key fails
// an equality on it rather than reading as zero.
constexpr std::uint64_t kNoValue = std::numeric_limits<std::uint64_t>::max();

std::vector<std::uint8_t> aValidMasterList()
{
    return fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                   fixture::makeIndependentSigner())
        .der;
}

std::string_view asView(const std::vector<std::uint8_t>& bytes)
{
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

// Drive the import of an already-open descriptor (index 0 of the frame's
// SCM_RIGHTS vector) and hand back the decoded reply; errName() on it is empty
// when the list was accepted.
Agent::Wire::CborValue importFd(Rig& rig, std::uint64_t req, int fd)
{
    const std::array<int, 1> fds{fd};
    return rig.roundTrip(req, Agent::Wire::ImportCscaMasterList{0}, fds);
}

// Import @p bytes from a fresh regular file, closed afterwards.
Agent::Wire::CborValue importBytes(Rig& rig, std::uint64_t req, const std::vector<std::uint8_t>& bytes)
{
    const int fd = makeInputFile(asView(bytes));
    if (fd < 0) {
        ADD_FAILURE() << "could not stage the input file";
        return {};
    }
    auto reply = importFd(rig, req, fd);
    ::close(fd);
    return reply;
}

// Readers over a reply map, or over the CscaAnchorState map inside GetConfig:
// the import reply and the served state speak the same keys, and a test that
// reads both through one pair of hands cannot compare them through two.
std::uint64_t uintOf(const Agent::Wire::CborValue& map, const char* key)
{
    const auto* v = map.find(key);
    return v != nullptr ? v->asUInt().value_or(kNoValue) : kNoValue;
}

std::optional<std::int64_t> intOf(const Agent::Wire::CborValue& map, const char* key)
{
    const auto* v = map.find(key);
    return v != nullptr ? v->asInt() : std::nullopt;
}

std::string textOf(const Agent::Wire::CborValue& map, const char* key)
{
    const auto* v = map.find(key);
    return (v != nullptr && v->asText() != nullptr) ? *v->asText() : std::string{};
}

std::optional<bool> boolOf(const Agent::Wire::CborValue& map, const char* key)
{
    const auto* v = map.find(key);
    return v != nullptr ? v->asBool() : std::nullopt;
}

// The CscaAnchorState entry of GetConfig -- what a client that has just
// connected reads, and this host's counterpart of the D-Bus property. An
// EMPTY map is this wire's "nothing installed"; no map at all is a broken
// reply, and fails here rather than reading as either answer.
Agent::Wire::CborValue anchorState(Rig& rig, std::uint64_t req)
{
    const auto reply = rig.roundTrip(req, Agent::Wire::GetConfig{});
    const auto* entries = reply.find("entries");
    const auto* state = entries != nullptr ? entries->find("CscaAnchorState") : nullptr;
    if (state == nullptr || state->asMap() == nullptr) {
        ADD_FAILURE() << "GetConfig served no CscaAnchorState map";
        return {};
    }
    return *state;
}

bool nothingInstalled(const Agent::Wire::CborValue& state)
{
    const auto* map = state.asMap();
    return map != nullptr && map->empty();
}

// The rate limiter keys on the caller token, and this transport mints one per
// CONNECTION ("conn:<n>", sequential from 1). Rig::roundTrip opens a fresh
// connection per call, so for the ONE round trip that follows the budget is
// spent on the limiter directly, for the first connection's token -- the same
// shape as the Sign gates in SocketFrontendTest. What that proves is that the
// handler consults the limiter with the connection's token; that a refused
// import COUNTS is proved over a held connection, further down.
void exhaustFirstConnection(Rig& rig)
{
    const Agent::CallerToken caller{"conn:1"};
    for (std::size_t i = 0; i < Agent::Operations::RateLimiter::kMaxPerWindow; ++i) {
        ASSERT_TRUE(rig.core->rateLimiter().allow(caller)) << "the budget ran out before it was spent";
    }
}

// A one-shot gate between the test thread and the confirmation worker: the
// worker parks inside the provider until the test opens it, and the test parks
// until the worker has arrived. The flag beside the condition variable is what
// keeps an open that happens before the wait from being lost.
class Latch
{
public:
    void open()
    {
        {
            const std::lock_guard lock(m_mutex);
            m_open = true;
        }
        m_cv.notify_all();
    }

    [[nodiscard]] bool wait(std::chrono::milliseconds budget)
    {
        std::unique_lock lock(m_mutex);
        return m_cv.wait_for(lock, budget, [this] { return m_open; });
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_open{false};
};

// The agent's log facade, captured for the length of one case. The line this
// file cares about is emitted on the confirmation worker, so the lines are held
// under a mutex; resetForTest() runs from the destructor so a failing assertion
// cannot leave the facade writing into a vector that has gone.
class CapturedLog
{
public:
    CapturedLog()
    {
        Agent::log::init([this](Agent::log::Level, std::string_view line) {
            const std::lock_guard lock(m_mutex);
            m_lines.emplace_back(line);
        });
    }

    ~CapturedLog()
    {
        Agent::log::resetForTest();
    }

    CapturedLog(const CapturedLog&) = delete;
    CapturedLog& operator=(const CapturedLog&) = delete;

    // Polled rather than waited on: the facade calls the sink under a lock of
    // its own, and there is no notification here to hang a condition variable
    // off without reaching into it.
    [[nodiscard]] bool waitForLine(std::string_view needle, std::chrono::milliseconds budget)
    {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        for (;;) {
            if (joined().find(needle) != std::string::npos) {
                return true;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    [[nodiscard]] std::string joined() const
    {
        const std::lock_guard lock(m_mutex);
        std::string all;
        for (const auto& line : m_lines) {
            all += line;
            all += '\n';
        }
        return all;
    }

private:
    mutable std::mutex m_mutex;
    std::vector<std::string> m_lines;
};

} // namespace

// --- order: authorise, rate-limit, THEN read -------------------------------

TEST(CscaImportSocket, RefusedCallerIsTurnedAwayBeforeTheDescriptorIsEvenInspected)
{
    DenyAllAuthorizer deny;
    Rig rig(&deny);

    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0);
    // Write end closed first, so an implementation broken twice over -- gates
    // reordered AND the fstat guard gone -- reads EOF and fails, rather than
    // blocking the loop thread until the ctest timeout.
    ::close(pipeFds[1]);

    // A pipe is refused by the read path under its own name, from the fstat
    // that keeps a blocking read off the loop thread -- and WITHOUT a read, so
    // the offset technique cannot see this case. NotAuthorized coming back
    // therefore proves the authorizer ran first: had the descriptor been
    // inspected before the caller was judged, this would be the read path's
    // refusal instead.
    EXPECT_EQ(errName(importFd(rig, 1, pipeFds[0])), "NotAuthorized");
    ::close(pipeFds[0]);
}

TEST(CscaImportSocket, RateLimitedCallerNeverAdvancesTheDescriptor)
{
    Rig rig; // allow-all: the limiter is the only gate left to refuse
    exhaustFirstConnection(rig);
    if (::testing::Test::HasFatalFailure()) {
        return;
    }

    const int fd = makeInputFile(asView(aValidMasterList()));
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::lseek(fd, 0, SEEK_CUR), 0) << "the descriptor must start where a read would be visible";

    EXPECT_EQ(errName(importFd(rig, 1, fd)), "RateLimited");

    // The proof. An implementation that ingested the list and only then asked
    // the limiter answers RateLimited just the same, and fails on exactly this
    // line. That the measurement itself moves when a read is allowed to happen
    // is held next door, by SocketFrontendTest's authorised-import companion.
    EXPECT_EQ(::lseek(fd, 0, SEEK_CUR), 0) << "an over-budget caller made the agent read the descriptor";
    ::close(fd);
}

TEST(CscaImportSocket, RateLimitPrecedesTheDescriptorInspection)
{
    Rig rig;
    exhaustFirstConnection(rig);
    if (::testing::Test::HasFatalFailure()) {
        return;
    }

    // Over budget, and handed a descriptor the read path rejects under a
    // different name before reading a byte. RateLimited coming back means the
    // limiter ran before even the fstat.
    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0);
    ::close(pipeFds[1]); // EOF, not a hang, if both the order and the guard were broken
    EXPECT_EQ(errName(importFd(rig, 1, pipeFds[0])), "RateLimited");
    ::close(pipeFds[0]);
}

// --- the human's veto ---------------------------------------------------------
//
// Installing country signing anchors is a trust change of the same size as
// naming a trust source or forgetting the anchors, and those two already stop
// at a person. The refusal name is NotAuthorized either way, so -- as with the
// authoriser -- the proof is the side effect: the descriptor untouched, the
// cache empty, nothing recorded. The refusal is also identical whichever
// sentence was shown, so what the person was asked is asserted here too: it is
// the only place an import wearing the generic settings wording would show.

TEST(CscaImportSocket, AnImportTheHumanDeclinesChangesNothing)
{
    Rig rig;
    LibreSCRS::Darwin::wire::ConfirmAction seen;
    rig.frontend->setConfirmProvider([&seen](const LibreSCRS::Darwin::wire::ConfirmAction& a) {
        seen = a;
        return LibreSCRS::Darwin::wire::ConfirmReply{LibreSCRS::Darwin::wire::PromptReplyStatus::Cancelled, ""};
    });

    const int fd = makeInputFile(asView(aValidMasterList()));
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::lseek(fd, 0, SEEK_CUR), 0);

    EXPECT_EQ(errName(importFd(rig, 1, fd)), "NotAuthorized");

    EXPECT_EQ(seen.kind, "configure_trust");
    EXPECT_EQ(seen.artifact, "CscaAnchorState");
    EXPECT_EQ(seen.description, "Install the country signing certificates from the offered file, replacing the ones "
                                "this computer checks passports against.")
        << "the person approving a master-list import read some other sentence";

    // The person said no before the agent touched what was handed over: the
    // offset the sender still shares with the agent has not moved.
    EXPECT_EQ(::lseek(fd, 0, SEEK_CUR), 0) << "a declined import read the master list";
    ::close(fd);

    EXPECT_FALSE(rig.core->configStore().cscaAnchorState().has_value()) << "a declined import was recorded";
    EXPECT_FALSE(Agent::Trust::AnchorCache{fs::path{rig.core->configStore().cscaCacheDir()}}.holdsAnchor())
        << "a declined import installed anchors";
}

// --- an answer that arrives after everything that asked for it is gone -------
//
// The block that waits for the person outlives whatever asked it: the person
// answers in their own time, and a teardown that waited for them would hang on
// a dialog nobody is looking at. What comes back after that must touch neither
// the frontend nor its transport nor anything the agent keeps on disk -- and
// must not be silent about having been dropped, because a discarded trust
// change and an applied one are otherwise indistinguishable from outside.

TEST(CscaImportSocket, AnAnswerThatArrivesAfterTheFrontendIsGoneIsDiscarded)
{
    // This case performs the hosts' teardown BY HAND below, which is what the
    // rig's own destructor does -- and the destructor tolerates that: it
    // quiesces only while it still holds a transport, and its removals run
    // either way. So the rig is an ordinary local, destroyed after the
    // assertions below, and it takes the socket and the state directory with
    // it.
    Rig rig;
    confirmEverything(rig);
    ASSERT_EQ(errName(importBytes(rig, 1, aValidMasterList())), "") << "a valid list was refused";

    const fs::path cacheDir{rig.core->configStore().cscaCacheDir()};
    ASSERT_TRUE(Agent::Trust::AnchorCache{cacheDir}.holdsAnchor()) << "the import installed no anchor to protect";

    CapturedLog log;

    // Shared rather than captured by reference: the provider lives on in the
    // dispatch block's copy of the confirmation function, and on a failing path
    // this frame unwinds while a worker may still be parked on them.
    const auto entered = std::make_shared<Latch>();
    const auto released = std::make_shared<Latch>();
    rig.frontend->setConfirmProvider([entered, released](const LibreSCRS::Darwin::wire::ConfirmAction&) {
        entered->open();
        // Bounded, so a case that never opens this fails rather than parking a
        // worker thread for the life of the binary.
        EXPECT_TRUE(released->wait(std::chrono::seconds(30))) << "the confirmation was never let go";
        return LibreSCRS::Darwin::wire::ConfirmReply{LibreSCRS::Darwin::wire::PromptReplyStatus::Ok, ""};
    });

    // Sent and deliberately never read: what this client is for is getting a
    // question in front of a person, not hearing the answer.
    Client client(rig.path);
    client.send(1, Agent::Wire::ForgetCscaAnchors{});
    if (!entered->wait(std::chrono::seconds(5))) {
        // Let the worker go before failing, so a parked block finishes rather
        // than sitting on the latch for the length of the binary.
        released->open();
        FAIL() << "the forget request never reached the confirmation";
    }

    // The hosts' order, by hand, with the person still holding the dialog open:
    // quiesce the loop, drain it, then release the frontend, the core and the
    // transport.
    rig.transport->quiesceLoop();
    dispatch_sync(rig.transport->loopQueue(), ^{
                  });
    rig.frontend.reset();
    rig.core.reset();
    rig.transport.reset();

    released->open();

    ASSERT_TRUE(log.waitForLine("answered after the frontend was gone", std::chrono::seconds(2)))
        << "a late answer was dropped without a word:\n"
        << log.joined();

    // The core is gone, so the disk is the only witness left -- and it still
    // holds what the import put there.
    EXPECT_TRUE(Agent::Trust::AnchorCache{cacheDir}.holdsAnchor()) << "a late answer forgot the anchors";
}

// The Linux suite spends the budget over the wire, one refused import at a
// time, which proves that an import refused on its CONTENT still counts against
// the caller. One connection held open carries one token for every frame, so
// the budget is spent here the way a real client would spend it.
TEST(CscaImportSocket, RefusedImportsSpendTheBudgetToo)
{
    Rig rig;
    confirmEverything(rig);
    Client client(rig.path);

    std::uint64_t req = 1;
    for (std::size_t i = 0; i < Agent::Operations::RateLimiter::kMaxPerWindow; ++i, ++req) {
        const int fd = makeInputFile(std::string_view{"\x01\x02\x03", 3});
        ASSERT_GE(fd, 0);
        client.send(req, Agent::Wire::ImportCscaMasterList{0}, std::array{fd});
        ::close(fd);
        // Refused on its content, which means it got past the limiter and
        // counted.
        EXPECT_EQ(errName(client.waitFor("Reply")), "InvalidRequest") << "call " << i;
    }

    // Over budget on the same connection, and handed a VALID list so that the
    // limiter is the only thing left that can refuse it.
    const int fd = makeInputFile(asView(aValidMasterList()));
    ASSERT_GE(fd, 0);
    client.send(req, Agent::Wire::ImportCscaMasterList{0}, std::array{fd});
    ::close(fd);
    EXPECT_EQ(errName(client.waitFor("Reply")), "RateLimited") << "refused imports did not count against the budget";
}

// --- descriptor discipline -------------------------------------------------

TEST(CscaImportSocket, NonRegularDescriptorIsRefused)
{
    Rig rig;
    confirmEverything(rig);

    int pipeFds[2] = {-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0);
    // Closed, so a broken implementation that read anyway sees EOF instead of
    // blocking the loop thread forever -- which is the very stall the fstat
    // rejection exists to prevent.
    ::close(pipeFds[1]);

    EXPECT_EQ(errName(importFd(rig, 1, pipeFds[0])), "InvalidRequest");
    ::close(pipeFds[0]);
}

TEST(CscaImportSocket, OversizeInputIsRefused)
{
    Rig rig;
    confirmEverything(rig);

    // Sparse: resize_file allocates no blocks on disk, and the file still reads
    // as one byte past the cap.
    const fs::path path = rig.tmp / "huge.ml";
    {
        std::ofstream create(path, std::ios::binary);
    }
    fs::resize_file(path, Agent::Trust::kMaxMasterListBytes + 1);
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0);

    EXPECT_EQ(errName(importFd(rig, 1, fd)), "InputTooLarge");
    ::close(fd);
}

// --- the accepted path -----------------------------------------------------

TEST(CscaImportSocket, AnchorStateIsEmptyUntilSomethingIsImported)
{
    Rig rig;
    EXPECT_TRUE(nothingInstalled(anchorState(rig, 1)))
        << "an agent that has imported nothing must not describe a trust store";
}

TEST(CscaImportSocket, AValidListIsImportedAndSummarised)
{
    Rig rig;
    confirmEverything(rig);

    // Three anchors from two countries, so the two counts cannot be confused.
    const auto list =
        fixture::signMasterList({fixture::makeCsca("CSCA One Old", "AA"), fixture::makeCsca("CSCA One New", "AA"),
                                 fixture::makeCsca("CSCA Two", "BB")},
                                fixture::makeIndependentSigner());

    const auto reply = importBytes(rig, 1, list.der);
    ASSERT_EQ(errName(reply), "") << "a valid list was refused";
    EXPECT_EQ(uintOf(reply, "anchors"), 3u);
    EXPECT_EQ(uintOf(reply, "issuers"), 2u);
    EXPECT_EQ(textOf(reply, "signer"), Agent::Trust::toHex(list.signerSpkiSha256));
    EXPECT_EQ(textOf(reply, "origin"), "import");
    EXPECT_GT(intOf(reply, "acceptedAt").value_or(0), 0);
    // Trusted on first import: nothing was compared, and the wire says so
    // rather than letting a client render "verified".
    EXPECT_EQ(boolOf(reply, "signerPinned"), std::optional{false});

    // The readable state a client shows carries the same answer.
    const auto state = anchorState(rig, 2);
    EXPECT_EQ(uintOf(state, "anchors"), 3u);
    EXPECT_EQ(uintOf(state, "issuers"), 2u);
    EXPECT_EQ(textOf(state, "signer"), Agent::Trust::toHex(list.signerSpkiSha256));
}

TEST(CscaImportSocket, AnAcceptedImportIsRememberedInTheConfiguration)
{
    Rig rig;
    confirmEverything(rig);

    const auto list =
        fixture::signMasterListDated({fixture::makeCsca("CSCA One", "AA"), fixture::makeCsca("CSCA Two", "BB")},
                                     fixture::makeIndependentSigner(), kSignedEarlier);
    ASSERT_EQ(errName(importBytes(rig, 1, list.der)), "");

    const auto recorded = rig.core->configStore().cscaAnchorState();
    ASSERT_TRUE(recorded.has_value()) << "the accepted import left no record in the agent's configuration";
    EXPECT_EQ(recorded->anchors, 2u);
    EXPECT_EQ(recorded->issuers, 2u);
    EXPECT_EQ(recorded->signer, Agent::Trust::toHex(list.signerSpkiSha256));
    EXPECT_FALSE(recorded->signerPinned) << "a first import establishes nothing, and the record must not claim it did";
    EXPECT_TRUE(recorded->replayRefusalActive);
    ASSERT_TRUE(recorded->signedAt.has_value());
    EXPECT_EQ(*recorded->signedAt, kSignedEarlier);
    EXPECT_EQ(recorded->origin, "import");

    // On DISK, not merely in memory. A second store over the same file is the
    // restart this record exists for: it is the only thing a client that has
    // just started could be answered from.
    Agent::Config::ConfigStore restarted(rig.tmp / "config.json", rig.tmp / "cache");
    EXPECT_EQ(restarted.cscaAnchorState(), recorded) << "the record did not survive a restart";
}

// --- a report the anchor cache does not bear out ----------------------------
//
// The record follows the CONFIGURATION file. What it describes is a directory
// of anchor files plus the cache's own state file, either of which a person may
// edit or delete; the configuration survives that, so the record goes on
// describing an agent that is no longer there. Both halves err in the
// OVERSTATING direction, which for a trust surface is the dangerous one:
// missing anchors leave the COUNTS false, and a missing cache state leaves the
// SIGNER false -- a pin claimed over an agent that now follows nobody.
//
// Reconciliation happens once, when the frontend is built, and asks only cheap
// questions: whether an anchor file exists at all, and whether the cache
// establishes a signer. Nothing is re-verified, and nothing in the cache is
// touched -- which is a property the last two cases here exist to hold on to.
//
// Each case builds a SECOND rig over the first one's state directory while the
// first is still alive: a rig removes its directory on the way out, so a second
// one built after the first had died would start from nothing and could not
// fail. The socket is fresh, the store is re-read from the same file and the
// frontend reconciles in its constructor -- a restart in everything but name.

TEST(CscaReconciliationSocket, ARememberedReportSurvivesARestartThatFindsItsAnchors)
{
    Rig first;
    confirmEverything(first);
    const auto list = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                              fixture::makeIndependentSigner());
    ASSERT_EQ(errName(importBytes(first, 1, list.der)), "");

    // Guards the three discards below against the cheap way to pass them: a
    // construction that cleared the report unconditionally is green over every
    // empty cache and fails only here, where the anchors are real.
    Rig second(nullptr, nullptr, first.tmp);
    confirmEverything(second);
    const auto state = anchorState(second, 1);
    ASSERT_FALSE(nothingInstalled(state)) << "a restart discarded a report whose anchors are still on disk";
    EXPECT_EQ(uintOf(state, "anchors"), 2u);
    EXPECT_EQ(textOf(state, "signer"), Agent::Trust::toHex(list.signerSpkiSha256));
}

TEST(CscaReconciliationSocket, AReportWhoseAnchorCacheWasWipedIsNotServedAsCurrent)
{
    Rig first;
    confirmEverything(first);
    const auto list = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                              fixture::makeIndependentSigner());
    ASSERT_EQ(errName(importBytes(first, 1, list.der)), "");
    ASSERT_FALSE(nothingInstalled(anchorState(first, 2)));

    // The whole cache directory, the way a person clearing out a cache would.
    // The configuration file is elsewhere and is untouched by it.
    std::error_code ec;
    fs::remove_all(fs::path{first.core->configStore().cscaCacheDir()}, ec);
    ASSERT_FALSE(ec);

    Rig second(nullptr, nullptr, first.tmp);
    confirmEverything(second);
    EXPECT_TRUE(nothingInstalled(anchorState(second, 1))) << "the agent served counts for anchors it no longer holds";
    EXPECT_FALSE(second.core->configStore().cscaAnchorState().has_value())
        << "the stale report is still in the configuration";

    // Where the pin actually lives, asserted rather than assumed: it went with
    // the cache, not with the report, so the next list is a first import again
    // -- trusted on sight, and saying so. A record that had been feeding the
    // pin would make this list a stranger's instead.
    const auto next = fixture::signMasterList({fixture::makeCsca("CSCA X", "XX")}, fixture::makeIndependentSigner());
    const auto reply = importBytes(second, 2, next.der);
    ASSERT_EQ(errName(reply), "");
    EXPECT_EQ(boolOf(reply, "signerPinned"), std::optional{false});
}

TEST(CscaReconciliationSocket, AReportWhosePinnedSignerIsGoneIsNotServedAsCurrent)
{
    Rig first;
    confirmEverything(first);
    const auto list = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                              fixture::makeIndependentSigner());
    ASSERT_EQ(errName(importBytes(first, 1, list.der)), "");
    ASSERT_EQ(textOf(anchorState(first, 2), "signer"), Agent::Trust::toHex(list.signerSpkiSha256));

    // The other half of the same fault, and the easy one to miss: only the
    // cache's own state file goes. The anchors stay, so the COUNTS a client
    // reads are still true -- and that is exactly why an implementation that
    // only asks "are there anchors" walks straight past this. What is no
    // longer true is the signer beside them: with nothing left to read the pin
    // from, the agent follows nobody, so "pinned to X" describes a trust
    // narrower than the one actually in force.
    const fs::path cacheDir{first.core->configStore().cscaCacheDir()};
    const Agent::Trust::AnchorCache cache{cacheDir};
    std::error_code ec;
    ASSERT_TRUE(fs::remove(cacheDir / "state", ec)) << "the fixture removed nothing";
    ASSERT_FALSE(ec);
    ASSERT_TRUE(fs::exists(cache.anchorsDirectory(), ec)) << "the fixture removed more than the state file";

    Rig second(nullptr, nullptr, first.tmp);
    confirmEverything(second);
    EXPECT_TRUE(nothingInstalled(anchorState(second, 1))) << "the agent named a publisher it no longer follows";
    EXPECT_FALSE(second.core->configStore().cscaAnchorState().has_value())
        << "the stale report is still in the configuration";

    // The reconciliation reports; it does not tidy. The anchors it just
    // declined to describe are still on disk, untouched.
    EXPECT_TRUE(fs::exists(cache.anchorsDirectory(), ec))
        << "the reconciliation deleted anchors it only had to stop describing";
    EXPECT_TRUE(cache.holdsAnchor()) << "the reconciliation emptied the anchors it only had to stop describing";

    // And the agent's behaviour agrees with what it now reports rather than
    // with what it used to: no pin left, so the next list is a first import
    // again, trusted on sight and saying so.
    const auto next = fixture::signMasterList({fixture::makeCsca("CSCA X", "XX")}, fixture::makeIndependentSigner());
    const auto reply = importBytes(second, 2, next.der);
    ASSERT_EQ(errName(reply), "");
    EXPECT_EQ(boolOf(reply, "signerPinned"), std::optional{false});
}

TEST(CscaReconciliationSocket, DiscardingAStaleReportLeavesTheSignerPinStanding)
{
    Rig first;
    confirmEverything(first);
    const auto publisher = fixture::makeIndependentSigner();
    const auto anchorA = fixture::makeCsca("CSCA A", "AA");
    const auto firstList = fixture::signMasterList({anchorA}, publisher);
    ASSERT_EQ(errName(importBytes(first, 1, firstList.der)), "");

    // Only the ANCHORS go. The cache's own state file stays, and that file is
    // what the pin and the rotation rule are read from -- so this is the case
    // that would expose a reconciliation which "helpfully" cleared the cache
    // too, or which had been serving the pin out of the configuration.
    const Agent::Trust::AnchorCache cache{fs::path{first.core->configStore().cscaCacheDir()}};
    std::error_code ec;
    fs::remove_all(cache.anchorsDirectory(), ec);
    ASSERT_FALSE(ec);

    Rig second(nullptr, nullptr, first.tmp);
    confirmEverything(second);
    EXPECT_TRUE(nothingInstalled(anchorState(second, 1))) << "counts were served for anchors that are gone";

    // A stranger is still refused. This host folds a changed publisher into
    // InvalidRequest -- to the caller every "this file will not do" is one
    // answer -- so the name alone is not the proof here; the store is: nothing
    // was recorded and nothing was installed.
    const auto stranger =
        fixture::signMasterList({fixture::makeCsca("CSCA X", "XX")}, fixture::makeIndependentSigner());
    EXPECT_EQ(errName(importBytes(second, 2, stranger.der)), "InvalidRequest")
        << "the wiped cache let a publisher this agent does not follow install anchors";
    EXPECT_FALSE(second.core->configStore().cscaAnchorState().has_value()) << "the stranger's list was recorded";
    EXPECT_FALSE(cache.holdsAnchor()) << "the stranger's anchors reached the cache";

    // ... and the publisher the agent DOES follow is recognised, not merely
    // observed. signerPinned true is the pin being read; a blanket refusal
    // above would satisfy the previous assertions on its own.
    const auto secondList = fixture::signMasterList({anchorA, fixture::makeCsca("CSCA B", "BB")}, publisher);
    const auto reply = importBytes(second, 3, secondList.der);
    ASSERT_EQ(errName(reply), "") << "the publisher this agent follows was refused";
    EXPECT_EQ(boolOf(reply, "signerPinned"), std::optional{true}) << "the pin was discarded along with the report";
}

// --- forgetting, over the socket ---------------------------------------------
//
// The shared library owns WHAT a forget is and in which order; SocketFrontendTest
// holds the verb's authorization and its empty case. What only a real import can
// show is here: that the reply describes what was actually destroyed, and that
// the verb re-opens the door the rotation rule closed.

TEST(CscaForgetSocket, ForgettingClearsTheAnchorsAndTheServedReport)
{
    Rig rig;
    confirmEverything(rig);

    const auto list = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA"), fixture::makeCsca("CSCA B", "BB")},
                                              fixture::makeIndependentSigner());
    ASSERT_EQ(errName(importBytes(rig, 1, list.der)), "");
    ASSERT_FALSE(nothingInstalled(anchorState(rig, 2)));

    const auto reply = rig.roundTrip(3, Agent::Wire::ForgetCscaAnchors{});
    // Not the envelope tag: a refusal is tagged "Reply" as well, and a gate on
    // the tag passed for every answer the verb could give.
    ASSERT_NE(reply.find("t"), nullptr) << "no reply frame";
    ASSERT_EQ(errName(reply), "") << "forgetting was refused";

    EXPECT_EQ(uintOf(reply, "anchorsForgotten"), 2u) << "the reply describes what was destroyed";
    EXPECT_EQ(boolOf(reply, "hadPinnedSigner"), std::optional{true})
        << "a publisher was being followed and the reply did not say so";
    EXPECT_TRUE(nothingInstalled(anchorState(rig, 4)))
        << "the property still serves a report for anchors that are gone";
    EXPECT_FALSE(Agent::Trust::AnchorCache{fs::path{rig.core->configStore().cscaCacheDir()}}.holdsAnchor())
        << "the anchors survived the verb whose whole purpose is to remove them";
}

// The reason the verb exists, asserted end to end over the socket: a publisher
// the agent refused before is taken in afterwards, and taken in as a first
// import.
TEST(CscaForgetSocket, AfterForgettingARefusedPublisherIsAcceptedAgain)
{
    Rig rig;
    confirmEverything(rig);

    const auto first = fixture::signMasterList({fixture::makeCsca("CSCA A", "AA")}, fixture::makeIndependentSigner());
    ASSERT_EQ(errName(importBytes(rig, 1, first.der)), "");

    const auto stranger =
        fixture::signMasterList({fixture::makeCsca("CSCA X", "XX")}, fixture::makeIndependentSigner());
    ASSERT_EQ(errName(importBytes(rig, 2, stranger.der)), "InvalidRequest") << "the fixture did not reproduce the trap";
    ASSERT_EQ(uintOf(anchorState(rig, 3), "anchors"), 1u) << "the refused list changed what a client reads";

    ASSERT_EQ(errName(rig.roundTrip(4, Agent::Wire::ForgetCscaAnchors{})), "") << "forgetting was refused";

    const auto reply = importBytes(rig, 5, stranger.der);
    ASSERT_EQ(errName(reply), "") << "the publisher refused before the forget is still refused after it";
    EXPECT_EQ(uintOf(reply, "anchors"), 1u);
    EXPECT_EQ(textOf(reply, "signer"), Agent::Trust::toHex(stranger.signerSpkiSha256));
    EXPECT_EQ(boolOf(reply, "signerPinned"), std::optional{false})
        << "a first import after a forget claimed the publisher had been established";
}
