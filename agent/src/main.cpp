// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// librescrs-agent — the macOS broker-host daemon (launchd LaunchAgent / SMAppService
// managed). Composition root: wires the App-Group socket transport, the SecCode
// authorizer, the agent-owned prompter client, and the plugin capability resolver
// around the neutral LibreAgent::AgentCore, then drives the process CFRunLoop while
// the transport's GCD queue services the socket and the MonitorBridge pumps card
// presence.
#include <LibreSCRS/Darwin/backend/AgentCoreSeams.h> // the reader-routing + identity seams the core consults
#include <LibreSCRS/Darwin/backend/AppGroupPaths.h>
#include <LibreSCRS/Darwin/backend/MacPrompterClient.h>
#include <LibreSCRS/Darwin/backend/OsLogSink.h>
#include <LibreSCRS/Darwin/backend/PeerPolicy.h>
#include <LibreSCRS/Darwin/backend/PluginDirectory.h>
#include <LibreSCRS/Darwin/backend/ProcessHardening.h>
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
#include <LibreSCRS/Darwin/backend/SocketFrontend.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Darwin/backend/SystemLifecycle.h>

#include "CardRemovalCaches.h" // invalidateCardRemovalCaches (shared with the removal test)
#include "FullScrubCaches.h"   // clearFullScrubCaches (shared with the scrub test)

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/trust/CscaAnchorImport.h>
#include <LibreSCRS/Agent/backend/Logging.h>
#include <LibreSCRS/Agent/pkcs11/Pkcs11Broker.h>
#include <LibreSCRS/Agent/presence/MonitorBridge.h>
#include <LibreSCRS/Agent/presence/PluginCapabilityResolver.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Trust/TrustStoreService.h>

#include <LibreSCRS/Agent/wire/Messages.h> // wire::QuiesceReason

#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>

#include <csignal>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#ifndef LIBREDARWIN_VERSION_STR
#define LIBREDARWIN_VERSION_STR "0.1.0"
#endif
#ifndef LIBRESCRS_DEFAULT_PLUGIN_DIR
#define LIBRESCRS_DEFAULT_PLUGIN_DIR "/usr/local/lib/librescrs/plugins"
#endif

namespace {

namespace fs = std::filesystem;
namespace Agent = LibreSCRS::Agent;
namespace Darwin = LibreSCRS::Darwin;
namespace wire = LibreSCRS::Agent::Wire;

// The command line the agent accepts: `--plugin-dir <path>` and nothing else.
// An argument rather than an environment variable, because `launchctl setenv`
// reaches every job the user's launchd starts and the plugins named here are
// loaded into the process that holds card secrets; ProgramArguments is written
// by whoever installs the job.
struct Arguments
{
    std::string pluginDir; // empty when not given
};

std::optional<Arguments> parseArguments(std::span<char* const> args)
{
    Arguments parsed;
    for (std::size_t i = 1; i < args.size(); ++i) {
        const std::string_view arg(args[i]);
        if (arg != "--plugin-dir") {
            Agent::log::errorf("unrecognised argument '{}' (usage: librescrs-agent [--plugin-dir <path>])", arg);
            return std::nullopt;
        }
        if (i + 1 >= args.size() || *args[i + 1] == '\0') {
            Agent::log::error("--plugin-dir needs a path (usage: librescrs-agent [--plugin-dir <path>])");
            return std::nullopt;
        }
        if (!parsed.pluginDir.empty()) {
            Agent::log::error("--plugin-dir given twice (usage: librescrs-agent [--plugin-dir <path>])");
            return std::nullopt;
        }
        parsed.pluginDir = args[++i];
    }
    return parsed;
}

} // namespace

int main(int argc, char** argv)
{
    // Deny debugger attach + core dumps BEFORE anything secret-bearing exists
    // (this process will hold plaintext CAN/PIN + live PACE/SM keys). Covers
    // ad-hoc/dev builds; hardened-runtime get-task-allow=false is the
    // production backstop. Lives here in main(), not in a library ctor, so
    // test binaries linking the backend stay attachable.
    const bool hardened = LibreSCRS::Darwin::hardenAgentProcess();

    // Writing to a peer-closed socket must fail with EPIPE, never terminate the
    // daemon via SIGPIPE. Set process-wide as a belt-and-suspenders over the
    // per-fd SO_NOSIGPIPE the transport sets (covers the prompter socket too).
    ::signal(SIGPIPE, SIG_IGN);

    Agent::log::init(LibreSCRS::Darwin::makeOsLogSink(), "rs.librescrs.agent");
    if (!hardened) {
        Agent::log::warn("process hardening incomplete (PT_DENY_ATTACH / RLIMIT_CORE=0 failed)");
    }

    const auto arguments = parseArguments(std::span<char* const>(argv, static_cast<std::size_t>(argc)));
    if (!arguments) {
        return 2;
    }

    // The App-Group container the sandboxed host + CTK extension can reach
    // (shared resolution with the prompter — AppGroupPaths).
    const fs::path container = Darwin::appGroupContainerDir();
    std::error_code ec;
    fs::create_directories(container, ec);
    if (ec) {
        Agent::log::errorf("failed to create the App-Group container {}: {}", container.string(), ec.message());
        return 1;
    }
    const std::string socketPath = (container / "agent.sock").string();
    const std::string prompterSocket = (container / "prompter.sock").string();
    const fs::path configFile = container / "config.json";
    const fs::path cacheRoot = container / "cache";
    const auto pluginDir =
        Darwin::resolvePluginDir(Darwin::PluginDirInputs{.override = arguments->pluginDir,
                                                         .executable = Darwin::currentExecutablePath(),
                                                         .compiledDefault = LIBRESCRS_DEFAULT_PLUGIN_DIR});

    // [1] Platform primitives: the socket transport (self-binds the container
    // socket) + the plugin capability resolver owned here at the entry point.
    auto created = LibreSCRS::Darwin::SocketTransport::create(socketPath);
    if (!created) {
        Agent::log::errorf("failed to bind the agent socket {}: {}", socketPath, created.error());
        return 1;
    }
    auto transport = std::move(*created);

    // Anchors the card plugins verify certificates against. Without a store the
    // eID plugin skips addTrustedCertificate and reports every verification as
    // unknown -- which is what this host did, and what the Linux host never did.
    // A failed create degrades to exactly that, but says so.
    std::shared_ptr<LibreSCRS::Trust::TrustStoreService> cardTrust;
    if (auto trustResult = LibreSCRS::Trust::TrustStoreService::create({}); trustResult) {
        cardTrust = std::move(*trustResult);
    } else {
        Agent::log::warnf("card verification anchors unavailable: {}", trustResult.error().userMessage.defaultText);
    }
    auto pluginService = std::make_shared<LibreSCRS::Plugin::CardPluginService>(
        pluginDir.dir, cardTrust ? cardTrust->trustStore() : nullptr);
    // Say which directory won, why the others lost, and how many plugins came out
    // of it. Zero is a warning: with no plugins loaded every card reports as
    // unusable, which from the outside is indistinguishable from a card nothing
    // supports — and nothing else in the process names the directory.
    Darwin::reportPluginLoad(pluginDir, *pluginService);
    // Copied, not moved: the resolver takes ownership and never hands the
    // service back, but the anchor directory cannot be published until the
    // config store exists, which is two steps down. Keeping a handle here is
    // cheaper than a resolver accessor nothing else would use.
    Agent::PluginCapabilityResolver resolver(pluginService);

    // [2] Interface impls the core borrows: the SecCode identity gate + the
    // agent-owned prompter client. Default-allow posture (PIN-as-consent); the
    // trust tier rests on the device-owner confirmation the frontend requires,
    // and the empty lists add no narrowing. The app group below is what an
    // allow-list would also require -- claimable by a self-signed peer too, so
    // it is hygiene, not a boundary (SecCodeAuthorizer.h says what it proves).
    LibreSCRS::Darwin::SecCodeAuthorizer authorizer(
        [&transport](const Agent::CallerToken& caller) { return transport->credentialsFor(caller); },
        LibreSCRS::Darwin::SecCodeAuthorizer::Policy{
            .trustTierSigningIds = {},
            .allowedSigningIds = {},
            .requiredAppGroup = std::string(Darwin::kAppGroup),
        });
    // The prompter client verifies the SERVING peer's code-signing identity (a
    // re-bound prompter.sock must not be able to inject a secret the agent
    // would burn a card retry counter on). There is no opt-out.
    auto prompter =
        std::make_shared<LibreSCRS::Darwin::MacPrompterClient>(prompterSocket, Darwin::makeDefaultPrompterVerifier());
    // The prompter helper outlives the agent that installed it, so this process
    // can come up beside windows a previous one raised -- windows it holds no id
    // for and nothing else will close. Clear them here, before anything below
    // can raise a prompt of its own. Bounded and silent on failure: a prompter
    // that is absent or wedged must not hold up the start-up.
    prompter->reset();

    // [3] The owning neutral-core aggregate.
    std::mutex stateMutex;
    Agent::AgentCore core(resolver, *transport, authorizer, prompter, configFile, cacheRoot,
                          makeResolveReaderCard(*transport), makeResolveCardKey(*transport));
    // The prompt gate stamps every dialog with the reader that holds the card
    // (model + contact/contactless slot), looked up in the transport's presence
    // roster. Before any operation can run; the rig performs the same step.
    installReaderIdentityResolver(core, *transport);

    // Tell the plugins where the country-signing anchors live, before any card
    // can be read against them. The DIRECTORY travels, never its contents, so a
    // master list imported later in this process's life is picked up by the
    // next read rather than needing a restart. The path comes from the
    // CONFIGURED cache directory: rebuilding it from the cache root would be
    // right for a default installation and quietly wrong for one that has set
    // CscaCacheDir, which imports into one directory and judges documents
    // against another with nothing on screen to say so.
    if (pluginService != nullptr) {
        const auto anchorDir = Agent::Trust::publishAnchorDirectory(*pluginService, core.configStore().cscaCacheDir());
        Agent::log::infof("country-signing anchors for card plugins: {}", anchorDir.string());
    }

    // [4] The inbound frontend (borrows the core; built after it). std::optional so
    // teardown can release it explicitly before the core it borrows.
    // The registry rides along so identity and photo reads get the LM-backed
    // credential depositor (see the frontend's constructor).
    auto frontend =
        std::make_optional<LibreSCRS::Darwin::SocketFrontend>(*transport, core, LIBREDARWIN_VERSION_STR, pluginService);
    // The human gate for trust-tier writes. The same prompter that collects
    // card secrets asks this one, over the same private socket — but through
    // the confirmation path, which carries no secret and cannot.
    frontend->setConfirmProvider([prompter](const LibreSCRS::Darwin::wire::ConfirmAction& action) {
        return prompter->requestConfirmation(action);
    });
    frontend->start();

    // Wire the core registry's presence observers to the frontend (materialize +
    // deferred card resolve -> transport publish/broadcast). EVERY long-lived
    // callback below guards the frontend optional the same way: the teardown
    // ordering (quiesce the loop, drain, THEN frontend.reset()) already keeps
    // them from running post-reset, but the uniform guard keeps that safety
    // independent of any future teardown reorder.
    core.objectRegistry().setObservers(
        [&frontend](const Agent::ReaderState& r) {
            if (frontend) {
                frontend->onReaderPublished(r);
            }
        },
        [&frontend](const Agent::CardState& c) {
            if (frontend) {
                frontend->onCardPublished(c);
            }
        },
        [&frontend](Agent::ObjectId id) {
            if (frontend) {
                frontend->onWithdrawn(id);
            }
        },
        [&frontend](Agent::ObjectId r, const Agent::PropertyDelta& d) {
            if (frontend) {
                frontend->onReaderPropertiesChanged(r, d);
            }
        });

    // Card removal: drop every per-card cache keyed on the per-insertion card
    // key (the card ObjectId, stringified — the key the typed-op deps + broker
    // seams use); the exact cache set lives in invalidateCardRemovalCaches(),
    // one source of truth shared with the removal regression test. Then revoke
    // the card's PKCS#11 leases and invalidate the reader's shared CardSession
    // so the next op re-opens against whatever card is next.
    core.cardKeyTracker().setOnKeyRemoved([&core, &frontend](Agent::ObjectId cardKey, const std::string& readerName) {
        const std::string key = std::to_string(cardKey.value());
        Agent::invalidateCardRemovalCaches(core.credentialCache(), core.cardReadCache(), core.credentialSnapshotCache(),
                                           key);
        if (frontend) {
            frontend->onCardRemovedForLease(cardKey);
        }
        // Release the power hold and invalidate the session through the shared
        // helper: the release is what its test pins; release-then-invalidate
        // is the documented convention.
        Agent::releaseReaderOnCardRemoved(core.operationManager(), core.presenceModel().readerIdFor(readerName));
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
    transport->onClientDisconnect([&frontend](Agent::CallerToken caller) {
        if (frontend) {
            frontend->onClientDisconnected(caller);
        }
    });

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
            // The exact cache set lives in clearFullScrubCaches(), one source
            // of truth shared with the scrub regression test.
            Agent::clearFullScrubCaches(core.credentialCache(), core.credentialSnapshotCache());
            // The power-hold FLAG is deliberately left where it is, unlike in
            // the card-removed hook: the worker drops the hold handle on this
            // invalidate (the reader loses power on sleep anyway) and renews
            // it on its next idle sweep if the card is still seated after
            // wake. A card gone by then clears the flag through the
            // card-removed hook; a reader re-enumerated by then is withdrawn
            // first, and the frontend stops its worker, flag and all.
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
        // One dismissal per prompt the agent raised: the gate is keyed by card,
        // so more than one window can be standing when the agent quiesces.
        for (const auto& promptId : core.promptSerializer().liveIds()) {
            prompter->cancel(promptId);
        }
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
