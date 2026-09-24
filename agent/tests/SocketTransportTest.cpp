// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SocketTransport end-to-end over a real bound socket + a blocking client:
// accept + peer identity, inbound request -> sink, publish -> broadcast event,
// post marshaling, and the client-disconnect fan-out (registration order). The
// transport's own serial dispatch queue is serviced by GCD (no run loop needed);
// loop-affine calls are marshaled with dispatch_sync.
#include <LibreSCRS/Darwin/backend/AgentCoreSeams.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Agent/wire/Messages.h>

#include <gtest/gtest.h>

#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <format>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace LibreSCRS::Darwin;

namespace {

namespace Agent = ::LibreSCRS::Agent;

std::string uniqueSocketPath()
{
    // Short path (well under sun_path 104) for the test socket.
    return "/tmp/ld-tt-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()) + ".sock";
}

int connectClient(const std::string& path)
{
    const int c = ::socket(AF_UNIX, SOCK_STREAM, 0);
    EXPECT_GE(c, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    EXPECT_EQ(::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    return c;
}

// A synchronized latch for values produced on the loop thread.
template <class T>
struct Latch
{
    std::mutex m;
    std::condition_variable cv;
    std::vector<T> items;
    void push(T v)
    {
        std::lock_guard<std::mutex> lk(m);
        items.push_back(std::move(v));
        cv.notify_all();
    }
    bool waitFor(std::size_t n, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lk(m);
        return cv.wait_for(lk, timeout, [&] { return items.size() >= n; });
    }
};

TEST(SocketTransport, InboundRequestReachesSinkWithPeerToken)
{
    const std::string path = uniqueSocketPath();
    auto created = SocketTransport::create(path);
    ASSERT_TRUE(created.has_value()) << (created ? "" : created.error().message);
    auto tr = std::move(*created);

    Latch<std::pair<std::string, std::size_t>> sink; // (caller, request index)
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push({in.caller.str(), in.request.body.index()}); });

    const int client = connectClient(path);
    // Send a Hello request.
    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(Agent::Wire::sendFrame(client, helloBytes).has_value());

    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2)));
    {
        std::lock_guard<std::mutex> lk(sink.m);
        EXPECT_EQ(sink.items[0].first.rfind("conn:", 0), 0u); // caller is "conn:<n>"
        EXPECT_EQ(sink.items[0].second, 0u);                  // Hello is variant index 0
    }

    ::close(client);
    tr.reset();
    std::filesystem::remove(path);
}

TEST(SocketTransport, PublishBroadcastsEventToClient)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });

    const int client = connectClient(path);
    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(Agent::Wire::sendFrame(client, helloBytes).has_value());
    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2))); // connection is up

    // Publish a reader on the loop; the client should receive a ReaderAdded event.
    SocketTransport* trp = tr.get();
    dispatch_sync(tr->loopQueue(), ^{
      Agent::ReaderState r;
      r.id = Agent::ObjectId(7);
      r.name = "Test Reader";
      r.hasCard = false;
      trp->publishReader(r);
    });

    const auto frame = Agent::Wire::recvFrame(client);
    ASSERT_TRUE(frame.has_value());
    const auto decoded = Agent::Wire::decode(frame->body);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_NE(decoded->find("t"), nullptr);
    EXPECT_EQ(*decoded->find("t")->asText(), "ReaderAdded");
    const auto* reader = decoded->find("reader");
    ASSERT_NE(reader, nullptr);
    EXPECT_EQ(*reader->find("name")->asText(), "Test Reader");

    ::close(client);
    tr.reset();
    std::filesystem::remove(path);
}

TEST(SocketTransport, DisconnectFiresHandlersInRegistrationOrder)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });

    Latch<int> order;
    tr->onClientDisconnect([&](Agent::CallerToken) { order.push(1); });
    tr->onClientDisconnect([&](Agent::CallerToken) { order.push(2); });

    const int client = connectClient(path);
    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(Agent::Wire::sendFrame(client, helloBytes).has_value());
    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2)));

    ::close(client); // triggers EOF -> closeConnection -> fan-out
    ASSERT_TRUE(order.waitFor(2, std::chrono::seconds(2)));
    {
        std::lock_guard<std::mutex> lk(order.m);
        ASSERT_EQ(order.items.size(), 2u);
        EXPECT_EQ(order.items[0], 1); // registration order
        EXPECT_EQ(order.items[1], 2);
    }

    tr.reset();
    std::filesystem::remove(path);
}

TEST(SocketTransport, ConnectionCapRefusesTheExcessConnection)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });

    // Fill the cap: 32 registered connections, paced by the per-client sink
    // ack (a burst of raw connects would overflow the listen(16) backlog and
    // fail at connect() before the cap is even exercised).
    std::vector<int> clients;
    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();
    for (std::size_t i = 0; i < 32; ++i) {
        const int c = connectClient(path);
        ASSERT_TRUE(Agent::Wire::sendFrame(c, helloBytes).has_value());
        clients.push_back(c);
        ASSERT_TRUE(sink.waitFor(i + 1, std::chrono::seconds(5)));
    }

    // The 33rd connects at the kernel level (listen backlog) but the transport
    // refuses it at accept: the client observes EOF.
    const int excess = connectClient(path);
    timeval tv{5, 0};
    ::setsockopt(excess, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[8] = {0};
    EXPECT_EQ(::recv(excess, buf, sizeof(buf), 0), 0);

    ::close(excess);
    for (const int c : clients) {
        ::close(c);
    }
    tr.reset();
    std::filesystem::remove(path);
}

TEST(SocketTransport, WatchdogReapsOnlyThePartialFrameConnection)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));
    tr->setFirstFrameTimeoutForTest(std::chrono::milliseconds(50));

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });

    // A well-behaved client delivers its first frame inside the window.
    const int good = connectClient(path);
    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(Agent::Wire::sendFrame(good, helloBytes).has_value());
    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2)));

    // A slow-loris client sends half a length prefix and stalls.
    const int slow = connectClient(path);
    const std::uint8_t partial[2] = {0x10, 0x00};
    ASSERT_EQ(::send(slow, partial, sizeof(partial), 0), 2);

    // EOF on the stalled connection IS the watchdog event (no sleeps).
    timeval tv{5, 0};
    ::setsockopt(slow, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[8] = {0};
    EXPECT_EQ(::recv(slow, buf, sizeof(buf), 0), 0);

    // The good connection outlived the same window (its timer was cancelled on
    // the first frame): it still receives broadcasts.
    SocketTransport* trp = tr.get();
    dispatch_sync(tr->loopQueue(), ^{
      Agent::ReaderState r;
      r.id = Agent::ObjectId(9);
      r.name = "Survivor";
      r.hasCard = false;
      trp->publishReader(r);
    });
    const auto frame = Agent::Wire::recvFrame(good);
    ASSERT_TRUE(frame.has_value());
    const auto decoded = Agent::Wire::decode(frame->body);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded->find("t")->asText(), "ReaderAdded");

    ::close(good);
    ::close(slow);
    tr.reset();
    std::filesystem::remove(path);
}

TEST(SocketTransport, PostRunsOnTheLoop)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));

    Latch<int> ran;
    tr->post([&] { ran.push(1); });
    EXPECT_TRUE(ran.waitFor(1, std::chrono::seconds(2)));

    tr.reset();
    std::filesystem::remove(path);
}

// The presence roster the reader-identity seams read: every published
// reader's PC/SC name, index-aligned with the per-insertion key of the card it
// holds -- the stringified card ObjectId CardRouting and the CardKeyTracker
// use -- or empty for an empty slot. The key comes from the CARD objects
// (each names its reader), so it is present the moment publishCard returns
// and gone the moment the card is withdrawn, independent of the reader's
// HasCard/Card property flip that follows both.
TEST(SocketTransport, PresenceRosterAlignsEveryReaderWithTheKeyOfItsCard)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));
    SocketTransport* trp = tr.get();

    __block SocketTransport::PresenceRoster roster;
    dispatch_sync(tr->loopQueue(), ^{
      Agent::ReaderState a;
      a.id = Agent::ObjectId(7);
      a.name = "Reader A";
      trp->publishReader(a);
      Agent::CardState c;
      c.id = Agent::ObjectId(8);
      c.reader = Agent::ObjectId(7);
      trp->publishCard(c);
      Agent::ReaderState b;
      b.id = Agent::ObjectId(9);
      b.name = "Reader B";
      trp->publishReader(b);
      roster = trp->presenceRoster();
    });

    ASSERT_EQ(roster.readerNames.size(), 2u);
    ASSERT_EQ(roster.cardKeys.size(), roster.readerNames.size());
    // A __block variable cannot be captured by a lambda, so the lookup takes the
    // roster it reads. A miss yields an empty optional rather than an index one
    // past the end, so a failing roster fails on the name, not on a read past
    // the vector.
    const auto keyOf = [](const SocketTransport::PresenceRoster& r, const std::string& name) {
        const auto it = std::find(r.readerNames.begin(), r.readerNames.end(), name);
        return it == r.readerNames.end()
                   ? std::optional<std::string>{}
                   : std::optional<std::string>{r.cardKeys[static_cast<std::size_t>(it - r.readerNames.begin())]};
    };
    EXPECT_EQ(keyOf(roster, "Reader A"), "8") << "the card's ObjectId, stringified, not its wire handle";
    EXPECT_EQ(keyOf(roster, "Reader B"), "") << "an empty slot carries an empty key";

    // The card is withdrawn: the slot reads empty again.
    dispatch_sync(tr->loopQueue(), ^{
      trp->withdraw(Agent::ObjectId(8));
      roster = trp->presenceRoster();
    });
    ASSERT_EQ(roster.readerNames.size(), 2u);
    EXPECT_EQ(keyOf(roster, "Reader A"), "");

    // A withdrawn reader leaves the roster, both columns together.
    dispatch_sync(tr->loopQueue(), ^{
      trp->withdraw(Agent::ObjectId(9));
      roster = trp->presenceRoster();
    });
    ASSERT_EQ(roster.readerNames.size(), 1u);
    ASSERT_EQ(roster.cardKeys.size(), 1u);
    EXPECT_EQ(roster.readerNames[0], "Reader A");

    tr.reset();
    std::filesystem::remove(path);
}

// The three seams main.cpp composes over the live transport, driven through the
// same functions production installs -- not re-implemented in the test. The
// routing seams are loop-thread reads (a reader-addressed request arrives on
// the loop); the identity resolver is the one seam a reader WORKER thread
// calls, so it is exercised from the test thread, off the loop.
TEST(SocketTransport, ComposedSeamsResolveThroughTheLiveRoster)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));
    SocketTransport* trp = tr.get();

    __block std::string readerAHandle;
    __block std::string readerBHandle;
    __block std::optional<Agent::ReaderCard> readerACard;
    __block std::optional<Agent::ReaderCard> readerBCard;
    __block std::optional<Agent::ObjectId> readerAKey;
    __block std::optional<Agent::ObjectId> readerBKey;
    dispatch_sync(tr->loopQueue(), ^{
      Agent::ReaderState a;
      a.id = Agent::ObjectId(7);
      a.name = "Reader A";
      trp->publishReader(a);
      Agent::CardState c;
      c.id = Agent::ObjectId(8);
      c.reader = Agent::ObjectId(7);
      trp->publishCard(c);
      // The reader's HasCard/Card flip PresenceModel emits right after the card
      // object. readerCard() (the two routing seams) reads the reader's Card
      // property; the roster (the identity seam) reads the card objects. In
      // production the flip lands on the loop before the deferred resolve
      // publishes the card, so for the length of that resolve readerCard()
      // names a key the roster does not yet carry -- a reader-addressed prompt
      // in that window names no reader, which the design calls honest.
      trp->updateProperties(Agent::ObjectId(7), Agent::PropertyDelta{.hasCard = true, .card = Agent::ObjectId(8)});
      Agent::ReaderState b;
      b.id = Agent::ObjectId(9);
      b.name = "Reader B";
      trp->publishReader(b);
      for (const auto& rs : trp->currentState().readers) {
          (rs.name == "Reader A" ? readerAHandle : readerBHandle) = rs.handle;
      }
      readerACard = makeResolveReaderCard(*trp)(readerAHandle);
      readerBCard = makeResolveReaderCard(*trp)(readerBHandle);
      readerAKey = makeResolveCardKey(*trp)(readerAHandle);
      readerBKey = makeResolveCardKey(*trp)(readerBHandle);
    });

    ASSERT_TRUE(readerACard.has_value());
    EXPECT_EQ(readerACard->readerId, Agent::ObjectId(7));
    EXPECT_EQ(readerACard->readerName, "Reader A");
    EXPECT_EQ(readerACard->cardKey, "8");
    EXPECT_FALSE(readerBCard.has_value()) << "a reader holding no card resolves to nothing";
    ASSERT_TRUE(readerAKey.has_value());
    EXPECT_EQ(*readerAKey, Agent::ObjectId(8));
    EXPECT_FALSE(readerBKey.has_value());

    // Off the loop, as the prompt gate calls it.
    const auto resolveIdentity = makeResolveReaderIdentity(*tr);
    EXPECT_EQ(resolveIdentity("8").full, "Reader A");
    EXPECT_EQ(resolveIdentity("9"), Agent::ReaderIdentity{}) << "an unknown key names no reader";
    EXPECT_EQ(resolveIdentity(""), Agent::ReaderIdentity{}) << "an empty key never borrows an empty slot's name";

    tr.reset();
    std::filesystem::remove(path);
}

// The roster is the one presence read a reader worker makes while the loop
// keeps mutating presence. A reader thread snapshots it continuously while the
// loop withdraws and re-publishes one card; every snapshot must be a consistent
// state (sizes aligned, the untouched reader's key stable, the churning
// reader's key one of its two legal values) and BOTH legal values must be
// observed, or the reads never overlapped the mutations and the test proved
// nothing. This build has no thread sanitizer, so this exercises the
// cross-thread path rather than proving the mutex race-free.
TEST(SocketTransport, PresenceRosterIsReadableWhileTheLoopMutatesIt)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));
    SocketTransport* trp = tr.get();

    dispatch_sync(tr->loopQueue(), ^{
      Agent::ReaderState a;
      a.id = Agent::ObjectId(7);
      a.name = "Reader A";
      trp->publishReader(a);
      Agent::ReaderState b;
      b.id = Agent::ObjectId(9);
      b.name = "Reader B";
      trp->publishReader(b);
      // An ODD id: the churn below mints even ids only, and a publish of an
      // id already published would re-home that card rather than add one.
      Agent::CardState stable;
      stable.id = Agent::ObjectId(11);
      stable.reader = Agent::ObjectId(9);
      trp->publishCard(stable);
    });

    // The churn: a card comes and goes in reader A, one publish OR one withdraw
    // per loop turn so each state lasts a whole turn, re-posted while the
    // sampler is still running. A fresh even ObjectId per insertion, as the
    // presence model mints one per insert. Everything the loop touches outlives
    // the last step: the drain below runs after the stop.
    std::atomic<bool> running{true};
    std::uint64_t nextCard = 8; // loop thread only
    bool seated = false;        // loop thread only
    std::function<void()> churn;
    churn = [&churn, &running, &nextCard, &seated, trp] {
        if (!running.load()) {
            return;
        }
        if (seated) {
            trp->withdraw(Agent::ObjectId(nextCard));
            nextCard += 2;
        } else {
            Agent::CardState c;
            c.id = Agent::ObjectId(nextCard);
            c.reader = Agent::ObjectId(7);
            trp->publishCard(c);
        }
        seated = !seated;
        dispatch_async(trp->loopQueue(), ^{
          churn();
        });
    };
    std::atomic<bool> seenHeld{false};
    std::atomic<bool> seenEmpty{false};
    std::atomic<int> inconsistent{0};
    // The sampler starts BEFORE the churn is kicked, so it overlaps the
    // mutations from the first step even on a slow runner.
    std::thread sampler([&] {
        const auto start = std::chrono::steady_clock::now();
        while (!(seenHeld.load() && seenEmpty.load()) &&
               std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
            const auto roster = trp->presenceRoster();
            if (roster.readerNames.size() != roster.cardKeys.size() || roster.readerNames.size() != 2) {
                inconsistent.fetch_add(1);
                continue;
            }
            for (std::size_t i = 0; i < roster.readerNames.size(); ++i) {
                if (roster.readerNames[i] == "Reader B") {
                    if (roster.cardKeys[i] != "11") {
                        inconsistent.fetch_add(1);
                    }
                } else if (roster.readerNames[i] == "Reader A") {
                    if (roster.cardKeys[i].empty()) {
                        seenEmpty.store(true);
                        continue;
                    }
                    // Parsed without exceptions: a throw on this thread would
                    // end the whole binary instead of failing this test.
                    std::uint64_t key = 0;
                    const auto* end = roster.cardKeys[i].data() + roster.cardKeys[i].size();
                    const auto parsed = std::from_chars(roster.cardKeys[i].data(), end, key);
                    if (parsed.ec != std::errc{} || parsed.ptr != end || key % 2 != 0) {
                        inconsistent.fetch_add(1); // not a key the churn ever minted
                    } else {
                        seenHeld.store(true);
                    }
                } else {
                    inconsistent.fetch_add(1);
                }
            }
        }
    });
    dispatch_async(tr->loopQueue(), ^{
      churn();
    });
    sampler.join();
    running.store(false);
    dispatch_sync(tr->loopQueue(), ^{
                  }); // drain the last churn step

    EXPECT_EQ(inconsistent.load(), 0) << "every snapshot must be one consistent presence state";
    EXPECT_TRUE(seenHeld.load()) << "the sampler never saw reader A holding a card: reads did not overlap";
    EXPECT_TRUE(seenEmpty.load()) << "the sampler never saw reader A empty: reads did not overlap";

    tr.reset();
    std::filesystem::remove(path);
}

// The mirror image of a well-behaved client: this one never reads at all.
// Every broadcast piles onto the per-connection outQueue (enqueueSend's
// increment) with nothing ever popped back off, so the connection must be
// closed once the queue crosses the byte bound -- well before it could ever
// cross the frame-count bound at this frame size (~2 KiB/frame * 4096 frames
// would be ~8 MiB).
TEST(SocketTransport, OutboundQueueIsBounded)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));
    SocketTransport* trp = tr.get();

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });
    Latch<int> closed;
    tr->onClientDisconnect([&](Agent::CallerToken) { closed.push(1); });

    const int client = connectClient(path);
    // Minimal receive buffer: the kernel socket buffer fills almost at once,
    // so backpressure (WouldBlock) sets in fast and every following broadcast
    // piles directly onto the application-level queue.
    int rcvbuf = 1;
    ::setsockopt(client, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(Agent::Wire::sendFrame(client, helloBytes).has_value());
    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2)));

    const std::string bigKey(2048, 'x'); // ~2 KiB/frame
    // The exact bytes this one push puts on the wire (framing header + CBOR
    // overhead included), independent of the 2048-char key alone -- this is
    // what Connection::queuedBytes counts, so the tightness check below is
    // exact arithmetic, not a guess at encoding overhead.
    const std::size_t frameBytes =
        Agent::Wire::encodeFrame(Agent::Wire::toCbor(Agent::Wire::ConfigChanged{bigKey}).encode(), 0).size();
    // Mirrors SocketTransport.cpp's kMaxQueuedBytesPerConnection: duplicated
    // here the same way this file already duplicates kMaxConnections in
    // ConnectionCapRefusesTheExcessConnection, since the constant is
    // file-local to the production .cpp.
    constexpr std::size_t kExpectedMaxQueuedBytes = 4 * 1024 * 1024;

    bool sawClose = false;
    int framesPushedAtClose = -1;
    for (int i = 0; i < 4096 && !sawClose; ++i) {
        dispatch_sync(trp->loopQueue(), ^{
          trp->broadcastConfigChanged(bigKey);
        });
        std::lock_guard<std::mutex> lk(closed.m);
        if (!closed.items.empty()) {
            sawClose = true;
            framesPushedAtClose = i + 1;
        }
    }
    ASSERT_TRUE(sawClose) << "connection was never closed for a peer that never reads";
    // Tightness, not just eventual closure: a regression that silently
    // widened the bound (e.g. to 7 MiB) would still close *eventually* at
    // this frame size -- just past frame ~3529 instead of ~2017 -- and the
    // check above alone would stay green. The total ever pushed by the time
    // of closing is an UPPER bound on the connection's actual queued bytes at
    // that instant (never a lower one): SO_RCVBUF is pinned to the minimum,
    // but that minimum is an OS floor, not a true zero, so a handful of early
    // frames can still be sent-and-dequeued before backpressure fully
    // engages. kSlackFrames absorbs that noise while leaving an enormous
    // margin below what a bound silently widened to 7 MiB would need (~1500
    // MORE frames beyond the true 4 MiB point).
    constexpr std::size_t kSlackFrames = 128;
    const std::size_t maxExpectedFrames = kExpectedMaxQueuedBytes / frameBytes + 1 + kSlackFrames;
    EXPECT_LE(static_cast<std::size_t>(framesPushedAtClose), maxExpectedFrames)
        << "closed too late: " << framesPushedAtClose << " frames pushed (" << frameBytes
        << " bytes/frame), expected a close within " << kSlackFrames << " frames of "
        << (kExpectedMaxQueuedBytes / frameBytes + 1);

    // The client observes the close as EOF once it drains whatever the
    // kernel had already buffered.
    timeval tv{5, 0};
    ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char buf[256];
    ssize_t r = -1;
    do {
        r = ::recv(client, buf, sizeof(buf), 0);
    } while (r > 0);
    EXPECT_EQ(r, 0) << "closed connection observed as EOF, not an error";

    ::close(client);
    tr.reset();
    std::filesystem::remove(path);
}

// The mirror image of OutboundQueueIsBounded: a client that keeps reading
// must NEVER be closed for backpressure, no matter how much is broadcast at
// it, because the queue that matters is what is still WAITING to be sent, not
// the running total ever pushed. This is the test that catches a missing
// decrement: without it, queuedBytes only grows (exactly like the never-reads
// peer), so an actively-draining client would eventually cross the same bound
// and get wrongly disconnected.
TEST(SocketTransport, ReaderThatDrainsIsNeverClosed)
{
    const std::string path = uniqueSocketPath();
    auto tr = std::move(*SocketTransport::create(path));
    SocketTransport* trp = tr.get();

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });
    Latch<int> closed;
    tr->onClientDisconnect([&](Agent::CallerToken) { closed.push(1); });

    const int client = connectClient(path);
    // Bounded backstop against a regression this test cannot otherwise catch
    // cleanly: if a future bug keeps the connection OPEN but stops delivering
    // frames (e.g. silently dropping on overflow instead of closing), `paced`
    // below still goes false and the sentinel is never sent, but a plain
    // blocking recv() with no timeout would then wait in the kernel forever
    // -- a hung test process, not a red one (ctest has no per-case TIMEOUT
    // here). SO_RCVTIMEO turns that indefinite block into a bounded EAGAIN;
    // recvFrame (Framing.h) reports that as WouldBlock, which is a terminal
    // read error here, not something the loop below retries.
    timeval rcvTimeout{15, 0};
    ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &rcvTimeout, sizeof(rcvTimeout));

    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(Agent::Wire::sendFrame(client, helloBytes).has_value());
    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2)));

    // A background reader drains every frame as it arrives. It stops on a
    // named sentinel frame, the last one sent below, so "received every frame
    // including the last" is directly observable rather than inferred from a
    // timeout.
    std::atomic<bool> sawSentinel{false};
    std::atomic<int> received{0};
    std::thread reader([&] {
        while (!sawSentinel.load()) {
            const auto frame = Agent::Wire::recvFrame(client);
            if (!frame.has_value()) {
                // EOF, a real I/O error, or the SO_RCVTIMEO backstop tripping
                // (WouldBlock) -- none of these is retried; the counts and
                // `paced` below report the shortfall as a test failure.
                return;
            }
            received.fetch_add(1);
            const auto decoded = Agent::Wire::decode(frame->body);
            if (decoded.has_value()) {
                const auto* keyField = decoded->find("key");
                if (keyField != nullptr && keyField->asText() != nullptr && *keyField->asText() == "sentinel") {
                    sawSentinel.store(true);
                }
            }
        }
    });

    // Pace production against a sliding window of frames the reader has not
    // yet observed. Bursting the whole total in one go (no pacing) would
    // transiently back the queue up past both bounds even for a client that
    // reads as fast as it can -- one blocking recvFrame() at a time is
    // inherently slower than dispatch_sync issuing pushes back to back, so
    // the resulting "backlog" would be a property of this test's own
    // production rate, not of the client failing to drain. Keeping at most
    // kWindow frames outstanding at any time (comfortably under both
    // kMaxQueuedFrames and kMaxQueuedBytesPerConnection even at the larger
    // frame size below) is what "a client that drains its queue" means here;
    // the running TOTAL pushed across the test still comfortably exceeds
    // both bounds.
    constexpr int kWindow = 256;
    int pushed = 0;
    const auto waitForWindow = [&](int pushedSoFar) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (received.load() < pushedSoFar - kWindow) {
            if (std::chrono::steady_clock::now() >= deadline) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
        return true;
    };

    // > kMaxQueuedFrames (4096) small frames...
    constexpr int kSmallFrames = 4200;
    // Non-fatal + a manual break, not ASSERT_TRUE: the reader thread is
    // joinable and (if the connection was in fact wrongly closed) unjoined at
    // any early `return` would abort the process instead of failing the test
    // cleanly. A closed connection makes the client's next recvFrame() see
    // EOF almost immediately, so the reader still exits and join() below
    // still returns promptly even when paced goes false.
    bool paced = true;
    const std::string smallKey = "k";
    for (int i = 0; i < kSmallFrames && paced; ++i) {
        dispatch_sync(trp->loopQueue(), ^{
          trp->broadcastConfigChanged(smallKey);
        });
        ++pushed;
        paced = waitForWindow(pushed);
        EXPECT_TRUE(paced) << "reader fell behind the pacing window at frame " << pushed;
    }
    // ...plus > kMaxQueuedBytesPerConnection (4 MiB) of larger frames, all in
    // the same connection's lifetime.
    constexpr int kBigFrames = 900;
    const std::string bigKey(5000, 'y'); // 900 * ~5 KiB =~ 4.5 MiB
    for (int i = 0; i < kBigFrames && paced; ++i) {
        dispatch_sync(trp->loopQueue(), ^{
          trp->broadcastConfigChanged(bigKey);
        });
        ++pushed;
        paced = waitForWindow(pushed);
        EXPECT_TRUE(paced) << "reader fell behind the pacing window at frame " << pushed;
    }
    if (paced) {
        dispatch_sync(trp->loopQueue(), ^{
          trp->broadcastConfigChanged("sentinel");
        });
    } else {
        // Pacing already timed out (already reported above): don't wait out
        // the full SO_RCVTIMEO backstop too. A local shutdown(SHUT_RDWR)
        // makes the reader's in-flight (or next) recv() on this same fd
        // return immediately, regardless of what the peer does.
        ::shutdown(client, SHUT_RDWR);
    }

    reader.join();
    EXPECT_TRUE(sawSentinel.load()) << "the reader must observe every frame, including the last one";
    EXPECT_EQ(received.load(), kSmallFrames + kBigFrames + 1);
    {
        std::lock_guard<std::mutex> lk(closed.m);
        EXPECT_TRUE(closed.items.empty()) << "a client that drains its queue must never be closed for backpressure";
    }

    ::close(client);
    tr.reset();
    std::filesystem::remove(path);
}

// --- Replaced-path guard --------------------------------------------------

// Under $TMPDIR (per-user, ~50 bytes on macOS, so the path stays well under
// the 104-byte sun_path limit) -- never the App-Group container a live agent
// may be serving.
std::string tmpSocketPath(const char* tag)
{
    return (std::filesystem::temp_directory_path() /
            std::format("ld-{}-{}-{}.sock", tag, ::getpid(), std::rand() % 100000))
        .string();
}

// What an attacker does: unlink whatever the path names and bind a listener
// of its own there. A guard tick can land between the unlink and the bind and
// re-bind first (EADDRINUSE / EEXIST); an attacker tries again, and so does this.
// `attempts` counts the unlinks: each one is a replacement the server may see.
int bindImpostor(const std::string& path, int* attempts = nullptr)
{
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    for (int attempt = 0; attempt < 100; ++attempt) {
        ::unlink(path.c_str());
        if (attempts != nullptr) {
            ++*attempts;
        }
        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        EXPECT_GE(fd, 0);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            EXPECT_EQ(::listen(fd, 4), 0);
            return fd;
        }
        const int err = errno;
        ::close(fd);
        if (err != EADDRINUSE && err != EEXIST) {
            ADD_FAILURE() << "bind(" << path << "): " << std::strerror(err);
            return -1;
        }
    }
    ADD_FAILURE() << "bind(" << path << "): the path never came free";
    return -1;
}

bool hasPendingConnection(int listenFd, int timeoutMs)
{
    pollfd p{.fd = listenFd, .events = POLLIN, .revents = 0};
    return ::poll(&p, 1, timeoutMs) == 1 && (p.revents & POLLIN) != 0;
}

// The path names the new inode from bind() on, but connect() is refused until
// the server's listen() a moment later; retry through that window only.
int connectOnceListening(const std::string& path, std::chrono::milliseconds bound)
{
    const auto deadline = std::chrono::steady_clock::now() + bound;
    for (;;) {
        const int c = ::socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
        if (::connect(c, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            const timeval recvTimeout{.tv_sec = 20, .tv_usec = 0};
            ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &recvTimeout, sizeof(recvTimeout));
            return c;
        }
        const int err = errno;
        ::close(c);
        if (err != ECONNREFUSED || std::chrono::steady_clock::now() >= deadline) {
            ADD_FAILURE() << "connect(" << path << "): " << std::strerror(err);
            return -1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

bool waitUntil(const std::function<bool()>& pred, std::chrono::milliseconds bound)
{
    const auto deadline = std::chrono::steady_clock::now() + bound;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

// Collects the warn lines the transport logs, from whichever thread logs them.
struct WarnCapture
{
    std::mutex m;
    std::vector<std::string> lines;
    WarnCapture()
    {
        Agent::log::init(
            [this](Agent::log::Level level, std::string_view line) {
                if (level == Agent::log::Level::Warn) {
                    std::lock_guard<std::mutex> lk(m);
                    lines.emplace_back(line);
                }
            },
            "rs.librescrs.agent.test");
    }
    ~WarnCapture()
    {
        Agent::log::resetForTest();
    }
    std::size_t count(std::string_view needle)
    {
        std::lock_guard<std::mutex> lk(m);
        return static_cast<std::size_t>(
            std::ranges::count_if(lines, [&](const std::string& l) { return l.find(needle) != std::string::npos; }));
    }
};

constexpr std::string_view kReplacedLine = "socket path was replaced; re-binding";

// A same-uid process unlinks the socket file and binds its own listener at the
// path. The agent must notice and bind again, so a client connecting to the
// path afterwards reaches the AGENT (its sink sees the Hello), not the
// impostor -- twice, to show the guard keeps watching after it re-bound.
TEST(SocketTransport, RebindsWhenTheSocketPathIsReplaced)
{
    WarnCapture warnings;
    const std::string path = tmpSocketPath("rb");
    auto created = SocketTransport::create(path);
    ASSERT_TRUE(created.has_value()) << (created ? "" : created.error().message);
    auto tr = std::move(*created);
    tr->setPathGuardIntervalForTest(std::chrono::milliseconds(20));
    const auto closedAtCancel = tr->closedListenFdAtCancelForTest();

    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });
    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();

    int replacements = 0;
    for (std::size_t round = 1; round <= 2; ++round) {
        const int impostor = bindImpostor(path, &replacements);
        const auto impostorId = SocketPathIdentity::of(path);
        ASSERT_TRUE(impostorId.has_value());

        // The path names a socket again, and it is no longer the impostor's.
        ASSERT_TRUE(waitUntil(
            [&] {
                // ONE lstat: two would race the server's own unlink-then-bind.
                const auto now = SocketPathIdentity::of(path);
                return now && (now->dev != impostorId->dev || now->ino != impostorId->ino);
            },
            std::chrono::seconds(5)))
            << "round " << round << ": the transport never bound the replaced path again";

        const int client = connectOnceListening(path, std::chrono::seconds(2));
        ASSERT_GE(client, 0);
        ASSERT_TRUE(Agent::Wire::sendFrame(client, helloBytes).has_value());
        EXPECT_TRUE(sink.waitFor(round, std::chrono::seconds(2)))
            << "round " << round << ": a client on the path did not reach the transport";
        EXPECT_FALSE(hasPendingConnection(impostor, 0)) << "round " << round << ": the impostor got the client";
        ::close(client);
        ::close(impostor);
    }

    // One line per replacement: at least one per round, never more than the
    // impostor's unlinks, and none at all over further ticks on a steady path.
    const std::size_t settled = warnings.count(kReplacedLine);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(warnings.count(kReplacedLine), settled) << "a steady path was reported as replaced";
    EXPECT_GE(settled, 2u);
    EXPECT_LE(settled, static_cast<std::size_t>(replacements));

    tr.reset();
    // Every re-bind and the teardown cancelled an accept source; each cancel
    // handler must have found the listen fd still open.
    EXPECT_EQ(closedAtCancel->load(), 0u) << "the listen fd was closed outside its cancel handler";
    std::filesystem::remove(path);
}

// Shutdown removes the socket file only while it is still the one this
// process bound: a path someone else holds by then is theirs to keep. And the
// teardown's own cancel finds the listen fd still open.
TEST(SocketTransport, ShutdownUnlinksOnlyItsOwnSocketFile)
{
    {
        const std::string path = tmpSocketPath("sd");
        auto tr = std::move(*SocketTransport::create(path));
        const auto closedAtCancel = tr->closedListenFdAtCancelForTest();
        tr.reset();
        EXPECT_FALSE(SocketPathIdentity::of(path).has_value()) << "shutdown left its own socket file behind";
        EXPECT_EQ(closedAtCancel->load(), 0u) << "the listen fd was closed outside its cancel handler";
    }
    {
        const std::string path = tmpSocketPath("sd");
        auto tr = std::move(*SocketTransport::create(path)); // production 10 s guard: no re-bind in time
        const auto closedAtCancel = tr->closedListenFdAtCancelForTest();
        const int impostor = bindImpostor(path);
        const auto impostorId = SocketPathIdentity::of(path);
        ASSERT_TRUE(impostorId.has_value());
        tr.reset();
        EXPECT_TRUE(impostorId->stillNames(path)) << "shutdown unlinked a socket file another process holds";
        EXPECT_EQ(closedAtCancel->load(), 0u) << "the listen fd was closed outside its cancel handler";
        ::close(impostor);
        std::filesystem::remove(path);
    }
}

// A launchd-activated socket is launchd's file: the agent must not bind over
// it (that would sever the activation) and must not unlink it on shutdown.
TEST(SocketTransport, InheritedSocketPathIsNeverReclaimed)
{
    WarnCapture warnings;
    const std::string path = tmpSocketPath("ih");
    const int launchdFd = bindImpostor(path); // stands in for launchd's listener
    auto adopted = SocketTransport::adoptInherited(Agent::Wire::UniqueFd(launchdFd), path);
    ASSERT_TRUE(adopted.has_value()) << (adopted ? "" : adopted.error().message);
    auto tr = std::move(*adopted);
    tr->setPathGuardIntervalForTest(std::chrono::milliseconds(20));
    Latch<std::string> sink;
    tr->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });
    // A second name for launchd's socket, so a client can still reach the
    // transport after the path is taken -- every accept is a guard check too.
    const std::string alias = path + ".a";
    ASSERT_EQ(::link(path.c_str(), alias.c_str()), 0) << std::strerror(errno);

    const int other = bindImpostor(path);
    const auto otherId = SocketPathIdentity::of(path);
    ASSERT_TRUE(otherId.has_value());

    // An accept on the transport, then fifteen would-be guard ticks: nothing
    // may take the path back.
    const int viaAlias = connectClient(alias);
    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(Agent::Wire::sendFrame(viaAlias, helloBytes).has_value());
    ASSERT_TRUE(sink.waitFor(1, std::chrono::seconds(2))) << "the inherited socket stopped serving";
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(otherId->stillNames(path)) << "the transport bound over a path it does not own";
    const int client = connectClient(path);
    EXPECT_TRUE(hasPendingConnection(other, 2000)) << "a client on the path must reach whoever launchd gave it to";
    EXPECT_EQ(warnings.count(kReplacedLine), 0u);

    tr.reset();
    EXPECT_TRUE(otherId->stillNames(path)) << "shutdown unlinked a socket file the transport does not own";
    ::close(client);
    ::close(viaAlias);
    ::close(other);
    std::filesystem::remove(path);
    std::filesystem::remove(alias);
}

// --- Single instance per socket path ---------------------------------------

// A second agent on the same path (a manual run beside the launchd one) must
// refuse to start rather than take the path: two instances would unlink each
// other's socket on every guard tick, and both would own PC/SC on one card.
// The first keeps its socket file and keeps serving.
TEST(SocketTransport, SecondInstanceOnTheSamePathRefusesToStart)
{
    WarnCapture warnings;
    const std::string path = tmpSocketPath("si");
    auto created = SocketTransport::create(path);
    ASSERT_TRUE(created.has_value()) << (created ? "" : created.error().message);
    auto first = std::move(*created);
    first->setPathGuardIntervalForTest(std::chrono::milliseconds(20));
    Latch<std::string> sink;
    first->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });
    const auto firstId = SocketPathIdentity::of(path);
    ASSERT_TRUE(firstId.has_value());

    auto second = SocketTransport::create(path);
    ASSERT_FALSE(second.has_value()) << "a second instance started on a path another instance serves";
    EXPECT_EQ(second.error().kind, ServerStartError::Kind::AnotherInstance) << second.error().message;

    // Over several guard ticks: the path is still the first one's, and the
    // first never saw a replacement to answer.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_TRUE(firstId->stillNames(path)) << "the refused instance replaced the first one's socket file";
    EXPECT_EQ(warnings.count(kReplacedLine), 0u);

    const int client = connectClient(path);
    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(Agent::Wire::sendFrame(client, helloBytes).has_value());
    EXPECT_TRUE(sink.waitFor(1, std::chrono::seconds(2))) << "the first instance stopped serving";

    ::close(client);
    first.reset();
    std::filesystem::remove(path);
}

// The lock is released at shutdown, so the next instance starts; and the lock
// file does not outlive the instance that held it.
TEST(SocketTransport, NextInstanceStartsOnceThePreviousHasShutDown)
{
    const std::string path = tmpSocketPath("sn");
    {
        auto first = SocketTransport::create(path);
        ASSERT_TRUE(first.has_value()) << (first ? "" : first.error().message);
    }
    EXPECT_FALSE(std::filesystem::exists(path + ".lock")) << "shutdown left the lock file behind";
    auto created = SocketTransport::create(path);
    ASSERT_TRUE(created.has_value()) << (created ? "" : created.error().message);
    auto second = std::move(*created);
    Latch<std::string> sink;
    second->setRequestSink([&](SocketTransport::Inbound&& in) { sink.push(in.caller.str()); });
    const int client = connectClient(path);
    const auto helloBytes =
        Agent::Wire::toCbor(Agent::Wire::RequestEnvelope{1, Agent::Wire::Hello{1, std::nullopt}}).encode();
    ASSERT_TRUE(Agent::Wire::sendFrame(client, helloBytes).has_value());
    EXPECT_TRUE(sink.waitFor(1, std::chrono::seconds(2)));
    ::close(client);
    second.reset();
    EXPECT_FALSE(std::filesystem::exists(path + ".lock")) << "shutdown left the lock file behind";
    std::filesystem::remove(path);
}

// A symlink planted where the lock file goes is refused, not followed: the
// lock must not create or lock a file somewhere the planter chose.
TEST(SocketTransport, SymlinkAtTheLockPathIsRefused)
{
    const std::string path = tmpSocketPath("sl");
    const std::string target = path + ".target";
    ASSERT_EQ(::symlink(target.c_str(), (path + ".lock").c_str()), 0) << std::strerror(errno);
    auto created = SocketTransport::create(path);
    ASSERT_FALSE(created.has_value()) << "the transport started through a symlinked lock file";
    EXPECT_EQ(created.error().kind, ServerStartError::Kind::Failed) << created.error().message;
    EXPECT_FALSE(std::filesystem::exists(target)) << "the lock followed the symlink";
    EXPECT_FALSE(SocketPathIdentity::of(path).has_value()) << "a refused start bound the socket";
    std::filesystem::remove(path + ".lock");
}

} // namespace
