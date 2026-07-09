// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// librescrs-agent — the macOS broker-host daemon (launchd LaunchAgent / SMAppService
// managed). Composition root: wires the App-Group socket transport, the SecCode
// authorizer, the agent-owned prompter client, and the plugin capability resolver
// around the neutral LibreAgent::AgentCore, then drives the process CFRunLoop while
// the transport's GCD queue services the socket and the MonitorBridge pumps card
// presence. Mirrors LibreLinux/agent AgentService on the D-Bus backend.
#include <LibreSCRS/Darwin/backend/MacPrompterClient.h>
#include <LibreSCRS/Darwin/backend/OsLogSink.h>
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
#include <LibreSCRS/Darwin/backend/SocketFrontend.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Darwin/backend/SystemLifecycle.h>

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/presence/MonitorBridge.h>
#include <LibreSCRS/Agent/presence/PluginCapabilityResolver.h>
#include <LibreSCRS/Plugin/CardPluginService.h>

#include <LibreSCRS/Darwin/backend/wire/Messages.h> // wire::QuiesceReason

#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>

#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#ifndef LIBREDARWIN_VERSION_STR
#define LIBREDARWIN_VERSION_STR "0.1.0"
#endif
#ifndef LIBREDARWIN_APP_GROUP
#define LIBREDARWIN_APP_GROUP "group.org.librescrs.LibreMac"
#endif
#ifndef LIBRESCRS_DEFAULT_PLUGIN_DIR
#define LIBRESCRS_DEFAULT_PLUGIN_DIR "/usr/local/lib/librescrs/plugins"
#endif

namespace {

namespace fs = std::filesystem;
namespace Agent = LibreSCRS::Agent;
namespace Darwin = LibreSCRS::Darwin;
namespace wire = LibreSCRS::Darwin::wire;

std::string envOr(const char* key, const std::string& fallback)
{
    const char* v = std::getenv(key);
    return (v != nullptr && *v != '\0') ? std::string(v) : fallback;
}

// The App-Group container the sandboxed host + CTK extension can reach. The agent
// (non-sandboxed) uses the absolute path directly. LIBRESCRS_AGENT_CONTAINER lets
// dev/test point elsewhere.
fs::path containerDir()
{
    if (const char* over = std::getenv("LIBRESCRS_AGENT_CONTAINER"); over != nullptr && *over != '\0') {
        return fs::path(over);
    }
    const char* home = std::getenv("HOME");
    const fs::path base = (home != nullptr && *home != '\0') ? fs::path(home) : fs::temp_directory_path();
    return base / "Library" / "Group Containers" / LIBREDARWIN_APP_GROUP;
}

// The macOS reader-routing seams AgentCore consults: reader wire handle ->
// {readerId, readerName, cardKey} / the card's ObjectId, answered from the
// transport's self-consistent presence snapshot (the twin of Linux's
// AgentCoreSeams). The transport MUST outlive the AgentCore that stores these.
Agent::ResolveReaderCard makeResolveReaderCard(const LibreSCRS::Darwin::SocketTransport& transport)
{
    return [&transport](const std::string& readerHandle) -> std::optional<Agent::ReaderCard> {
        const auto rc = transport.readerCard(readerHandle);
        if (!rc || rc->cardKey.empty()) {
            return std::nullopt;
        }
        return Agent::ReaderCard{.readerId = rc->readerId, .readerName = rc->readerName, .cardKey = rc->cardKey};
    };
}

Agent::Pkcs11Broker::ResolveCardKeySeam makeResolveCardKey(const LibreSCRS::Darwin::SocketTransport& transport)
{
    return [&transport](const std::string& readerHandle) -> std::optional<Agent::ObjectId> {
        const auto rc = transport.readerCard(readerHandle);
        if (!rc || rc->cardKey.empty()) {
            return std::nullopt;
        }
        return Agent::ObjectId{std::strtoull(rc->cardKey.c_str(), nullptr, 10)};
    };
}

} // namespace

int main()
{
    // Writing to a peer-closed socket must fail with EPIPE, never terminate the
    // daemon via SIGPIPE. Set process-wide as a belt-and-suspenders over the
    // per-fd SO_NOSIGPIPE the transport sets (covers the prompter socket too).
    ::signal(SIGPIPE, SIG_IGN);

    Agent::log::init(LibreSCRS::Darwin::makeOsLogSink(), "rs.librescrs.agent");

    const fs::path container = containerDir();
    std::error_code ec;
    fs::create_directories(container, ec);
    if (ec) {
        Agent::log::errorf("failed to create the App-Group container {}: {}", container.string(), ec.message());
        return 1;
    }
    const std::string socketPath = envOr("LIBRESCRS_AGENT_SOCK", (container / "agent.sock").string());
    const std::string prompterSocket = envOr("LIBRESCRS_PROMPTER_SOCK", (container / "prompter.sock").string());
    const fs::path configFile = container / "config.json";
    const fs::path cacheRoot = container / "cache";
    const fs::path pluginDir = envOr("LIBRESCRS_PLUGIN_DIR", LIBRESCRS_DEFAULT_PLUGIN_DIR);

    // [1] Platform primitives: the socket transport (self-binds the container
    // socket, D7) + the plugin capability resolver owned here at the entry point.
    auto created = LibreSCRS::Darwin::SocketTransport::create(socketPath);
    if (!created) {
        Agent::log::errorf("failed to bind the agent socket {}: {}", socketPath, created.error());
        return 1;
    }
    auto transport = std::move(*created);

    auto pluginService = std::make_shared<LibreSCRS::Plugin::CardPluginService>(pluginDir);
    Agent::PluginCapabilityResolver resolver(std::move(pluginService));

    // [2] Interface impls the core borrows: the SecCode identity gate + the
    // agent-owned prompter client. Default-allow posture (PIN-as-consent); the
    // trust tier is allow-list-gated (empty => file-seeded trust only), bound to
    // our app group so a self-signed peer cannot claim a listed signing id.
    LibreSCRS::Darwin::SecCodeAuthorizer authorizer(
        [&transport](const Agent::CallerToken& caller) { return transport->credentialsFor(caller); },
        LibreSCRS::Darwin::SecCodeAuthorizer::Policy{
            .trustTierSigningIds = {},
            .allowedSigningIds = {},
            .requiredAppGroup = std::string(LIBREDARWIN_APP_GROUP),
        });
    auto prompter = std::make_shared<LibreSCRS::Darwin::MacPrompterClient>(prompterSocket);

    // [3] The owning neutral-core aggregate.
    std::mutex stateMutex;
    Agent::AgentCore core(resolver, *transport, authorizer, prompter, configFile, cacheRoot,
                          makeResolveReaderCard(*transport), makeResolveCardKey(*transport));

    // [4] The inbound frontend (borrows the core; built after it). std::optional so
    // teardown can release it explicitly before the core it borrows.
    auto frontend = std::make_optional<LibreSCRS::Darwin::SocketFrontend>(*transport, core, LIBREDARWIN_VERSION_STR);
    frontend->start();

    // Wire the core registry's presence observers to the frontend (materialize +
    // deferred card resolve -> transport publish/broadcast).
    core.objectRegistry().setObservers(
        [&frontend](const Agent::ReaderState& r) { frontend->onReaderPublished(r); },
        [&frontend](const Agent::CardState& c) { frontend->onCardPublished(c); },
        [&frontend](Agent::ObjectId id) { frontend->onWithdrawn(id); },
        [&frontend](Agent::ObjectId r, const Agent::PropertyDelta& d) { frontend->onReaderPropertiesChanged(r, d); });

    // Card removal: scrub the credential/read caches under the per-insertion card
    // key (the card ObjectId, stringified — the key the typed-op deps + broker
    // seams use), revoke the card's PKCS#11 leases, and invalidate the reader's
    // shared CardSession so the next op re-opens against whatever card is next.
    core.cardKeyTracker().setOnKeyRemoved([&core, &frontend](Agent::ObjectId cardKey, const std::string& readerName) {
        const std::string key = std::to_string(cardKey.value());
        core.credentialCache().invalidate(key);
        core.cardReadCache().invalidate(key);
        if (frontend) {
            frontend->onCardRemovedForLease(cardKey);
        }
        core.operationManager().invalidateReaderSession(core.presenceModel().readerIdFor(readerName));
    });

    // A successful config mutation emits Config1.Changed to every subscriber.
    core.configStore().setOnChanged([&frontend](const std::string& key) {
        if (frontend) {
            frontend->emitConfigChanged(key);
        }
    });

    // Client disconnect: auto-cancel that caller's ops, THEN revoke its PKCS#11
    // leases (registration order is the contract), then evict the client's op
    // ownership + Sign recovery artifacts from the frontend.
    transport->onClientDisconnect(
        [&core](Agent::CallerToken caller) { core.operationManager().dispatchClientDisconnect(caller); });
    transport->onClientDisconnect([&core](Agent::CallerToken caller) { core.pkcs11().onClientDisconnected(caller); });
    transport->onClientDisconnect([&frontend](Agent::CallerToken caller) { frontend->onClientDisconnected(caller); });

    // The monitor pump: LM MonitorService -> PresenceModel + CardKeyTracker ->
    // registry observers -> frontend -> transport. A card already seated at start
    // fires onCardInserted synchronously from start(), so every collaborator above
    // must already exist (it does).
    Agent::MonitorBridge bridge(core.presenceModel(), core.cardKeyTracker(), stateMutex);
    bridge.start();

    Agent::log::infof("librescrs-agent ready on {} (version {})", socketPath, LIBREDARWIN_VERSION_STR);

    // System lifecycle: sleep / fast-user-switch away -> full scrub (the USB
    // reader loses power on sleep, so the PC/SC + PACE/SM session is invalid after
    // wake and MUST be re-opened); screen lock -> revoke PKCS#11 leases only
    // (re-PIN next op); wake / session active -> no-op (the next op re-acquires).
    // The registry read is serialised under stateMutex (the monitor mutates it on
    // its own thread); the neutral core scrubs have their own locks. The
    // AgentQuiesced broadcast is marshaled onto the loop.
    auto fullScrub = [&](wire::QuiesceReason reason) {
        {
            std::lock_guard<std::mutex> lk(stateMutex);
            core.credentialCache().clear();
            for (const auto& reader : core.objectRegistry().readers()) {
                core.operationManager().invalidateReaderSession(reader.id);
            }
            for (const auto& card : core.objectRegistry().cards()) {
                core.pkcs11().onCardRemoved(card.id);
            }
        }
        Darwin::SocketTransport* trp = transport.get();
        trp->post([trp, reason] { trp->broadcastQuiesced(reason); });
    };
    auto revokeLeasesOnly = [&](wire::QuiesceReason reason) {
        {
            std::lock_guard<std::mutex> lk(stateMutex);
            for (const auto& card : core.objectRegistry().cards()) {
                core.pkcs11().onCardRemoved(card.id);
            }
        }
        Darwin::SocketTransport* trp = transport.get();
        trp->post([trp, reason] { trp->broadcastQuiesced(reason); });
    };

    LibreSCRS::Darwin::SystemLifecycle lifecycle([&](LibreSCRS::Darwin::SystemLifecycle::Event event) {
        using Ev = LibreSCRS::Darwin::SystemLifecycle::Event;
        switch (event) {
        case Ev::Suspend:
            fullScrub(wire::QuiesceReason::SystemSleep);
            break;
        case Ev::SessionResign:
            fullScrub(wire::QuiesceReason::SessionInactive);
            break;
        case Ev::ScreenLock:
            revokeLeasesOnly(wire::QuiesceReason::ScreenLocked);
            break;
        case Ev::Resume:
        case Ev::ScreenUnlock:
        case Ev::SessionActive:
            // The next op re-acquires presence + re-PACEs from the cached CAN.
            break;
        case Ev::PowerOff:
            std::raise(SIGTERM); // route through the terminal quiesce below
            break;
        }
    });
    lifecycle.start();

    // Shutdown: a SIGTERM/SIGINT dispatch source on the main queue (drained by the
    // CFRunLoop) severs the inbound edge in order — stop the monitor (no new
    // presence), request crypto shutdown (in-flight workers bail at their
    // post-prompt gate), cancel any pending prompt (unblock a wedged worker),
    // sever the presence observers — then stops the run loop.
    bool quiesced = false;
    auto quiesce = [&]() {
        if (quiesced) {
            return;
        }
        quiesced = true;
        lifecycle.stop();
        bridge.stop();
        core.requestCryptoShutdown();
        prompter->cancel();
        core.objectRegistry().setObservers({}, {}, {}, {});
        CFRunLoopStop(CFRunLoopGetMain());
    };

    ::signal(SIGTERM, SIG_IGN);
    ::signal(SIGINT, SIG_IGN);
    dispatch_source_t sigterm =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, dispatch_get_main_queue());
    dispatch_source_t sigint =
        dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(sigterm, ^{
      quiesce();
    });
    dispatch_source_set_event_handler(sigint, ^{
      quiesce();
    });
    dispatch_resume(sigterm);
    dispatch_resume(sigint);

    CFRunLoopRun();

    // Ordered teardown: quiesce the loop (every subsequently-run posted block —
    // incl. a crypto worker's frontend-touching continuation — is dropped, not
    // run), drain any already-queued work, then release the frontend explicitly so
    // it dies before the core it borrows. The worker-side of every continuation
    // touches only the long-lived transport, so a still-running worker is safe.
    transport->quiesceLoop();
    dispatch_sync(transport->loopQueue(), ^{
                  });
    frontend.reset();

    dispatch_source_cancel(sigterm);
    dispatch_source_cancel(sigint);
    dispatch_release(sigterm);
    dispatch_release(sigint);

    Agent::log::info("librescrs-agent shutting down");
    return 0;
}
