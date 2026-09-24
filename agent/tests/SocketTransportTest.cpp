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
#include <LibreSCRS/Agent/wire/Framing.h>
#include <LibreSCRS/Agent/wire/Messages.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <cstring>
#include <filesystem>
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
    ASSERT_TRUE(created.has_value()) << (created ? "" : created.error());
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
    bool sawClose = false;
    for (int i = 0; i < 4096 && !sawClose; ++i) {
        dispatch_sync(trp->loopQueue(), ^{
          trp->broadcastConfigChanged(bigKey);
        });
        std::lock_guard<std::mutex> lk(closed.m);
        sawClose = !closed.items.empty();
    }
    EXPECT_TRUE(sawClose) << "connection was never closed for a peer that never reads";

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
                return; // EOF/error -- the counts below will catch the shortfall
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

} // namespace
