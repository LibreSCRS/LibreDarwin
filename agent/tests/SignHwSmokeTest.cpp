// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// P1b HARDWARE-ACCEPTANCE GATE (owner-present, PIN-guarded). Drives the FULL
// macOS backend end-to-end as a socket client: it constructs the real stack
// (SocketTransport + PluginCapabilityResolver + AgentCore + SocketFrontend +
// MonitorBridge) in-process against a live card, connects over the App-Group
// socket, and exercises Hello -> GetState -> ReadCertificates -> Sign.
//
// SKIPPED unless LIBRESCRS_HW=1, so CI/dev runs without a reader stay green.
//
// CREDENTIAL SAFETY (feedback_pin_guard_pattern): the signing PIN comes ONLY
// from the environment, never hardcoded. A wrong signing PIN decrements an
// irreversible on-card counter, so the sign phase ABORTS on the first auth
// failure (g_pinFailed) and never retries (SKIP_IF_PIN_FAILED). CAN/MRZ (PACE
// channel secrets, no lockout) also come from the environment.
//   LIBRESCRS_HW=1                 enable (else every test SKIPs)
//   LIBRESCRS_PLUGIN_DIR=<dir>     LM card plugins
//   LIBRESCRS_TEST_PIN=<pin>       the card's signing PIN (sign phase)
//   LIBRESCRS_TEST_CAN / _MRZ      PACE channel secret (as the card needs)
//   LIBRESCRS_PKCS11_MODULE=<so>   optional; the sign engine's LM PKCS#11
//                                  module. Auto-derived from LIBRESCRS_PLUGIN_DIR
//                                  when unset (see ensurePkcs11ModuleEnv).
#include <LibreSCRS/Darwin/backend/SocketFrontend.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>
#include <LibreSCRS/Darwin/backend/wire/Cbor.h>
#include <LibreSCRS/Darwin/backend/wire/Framing.h>
#include <LibreSCRS/Darwin/backend/wire/Messages.h>

#include <LibreSCRS/Agent/AgentCore.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
#include <LibreSCRS/Agent/backend/PrompterClientBase.h>
#include <LibreSCRS/Agent/presence/MonitorBridge.h>
#include <LibreSCRS/Agent/presence/PluginCapabilityResolver.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Secure/String.h>

#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

using namespace LibreSCRS::Darwin;
namespace Agent = ::LibreSCRS::Agent;

namespace {

// Irreversible-lockout guard: once a signing PIN VERIFY fails, never present a
// PIN again this run (protects the card's retry counter).
bool g_pinFailed = false;
#define SKIP_IF_PIN_FAILED()                                                                                           \
    if (g_pinFailed)                                                                                                   \
    GTEST_SKIP() << "aborted: a prior signing PIN attempt failed (preserving the retry counter)"

std::optional<std::string> env(const char* name)
{
    const char* v = std::getenv(name);
    return (v != nullptr && *v != '\0') ? std::optional<std::string>(v) : std::nullopt;
}

bool hwEnabled()
{
    return env("LIBRESCRS_HW").has_value();
}

// The signing engine loads the LM PKCS#11 module (librescrs-pkcs11.dylib) to
// drive the on-card sign; resolvePkcs11Module() searches paths RELATIVE TO THE
// EXECUTABLE, none of which match this in-tree test binary's location (the
// module lives under the LM install's lib/pkcs11/, not next to the test). A
// bundled agent (.app) colocates the module and needs no override; the in-tree
// smoke does. If LIBRESCRS_PKCS11_MODULE is not already set, derive it from the
// plugin dir (…/lib/librescrs/plugins → …/lib/pkcs11/librescrs-pkcs11.dylib) —
// the documented override escape hatch. Without it the sign fails
// SigningEngineError before ever reaching the card.
void ensurePkcs11ModuleEnv()
{
    if (env("LIBRESCRS_PKCS11_MODULE")) {
        return; // caller supplied an explicit path
    }
    const auto pluginDir = env("LIBRESCRS_PLUGIN_DIR");
    if (!pluginDir) {
        return; // nothing to derive from; resolvePkcs11Module falls back itself
    }
    const std::filesystem::path module =
        std::filesystem::path{*pluginDir}.parent_path().parent_path() / "pkcs11" / "librescrs-pkcs11.dylib";
    std::error_code ec;
    if (std::filesystem::exists(module, ec)) {
        ::setenv("LIBRESCRS_PKCS11_MODULE", module.c_str(), /*overwrite=*/0);
    }
}

// Env-backed prompter: PIN/CAN/MRZ come from the environment (never a GUI,
// never hardcoded). An unset secret returns Cancelled so the flow fails cleanly.
struct EnvPrompter final : Agent::Operations::PrompterClientBase
{
    static Agent::PromptResult fromEnv(const char* key)
    {
        if (const auto v = env(key)) {
            return {Agent::PromptStatus::Ok, LibreSCRS::Secure::String(*v), {}};
        }
        return {Agent::PromptStatus::Cancelled, std::nullopt, std::string("env ") + key + " unset"};
    }
    Agent::PromptResult requestPin(const Agent::PromptOptions&) override
    {
        return fromEnv("LIBRESCRS_TEST_PIN");
    }
    Agent::PromptResult requestCan(const Agent::PromptOptions&) override
    {
        return fromEnv("LIBRESCRS_TEST_CAN");
    }
    Agent::PromptResult requestMrz(const Agent::PromptOptions&) override
    {
        return fromEnv("LIBRESCRS_TEST_MRZ");
    }
};

std::string uniqueSocketPath()
{
    return "/tmp/ld-hw-" + std::to_string(::getpid()) + ".sock";
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

// The live in-process agent stack (real resolver + monitor, env prompter).
struct HwRig
{
    std::string path{uniqueSocketPath()};
    std::unique_ptr<SocketTransport> transport;
    Agent::PluginCapabilityResolver resolver;
    Agent::AllowAllAuthorizer authz;
    std::shared_ptr<EnvPrompter> prompter{std::make_shared<EnvPrompter>()};
    std::filesystem::path tmp{std::filesystem::temp_directory_path() / ("ld-hw-" + std::to_string(::getpid()))};
    std::optional<Agent::AgentCore> core;
    std::optional<SocketFrontend> frontend;
    std::optional<Agent::MonitorBridge> bridge;
    std::mutex stateMutex;

    HwRig()
        : resolver(std::make_shared<LibreSCRS::Plugin::CardPluginService>(
              std::filesystem::path{env("LIBRESCRS_PLUGIN_DIR").value_or("/usr/local/lib/librescrs/plugins")}))
    {
        ensurePkcs11ModuleEnv(); // the sign engine needs the LM PKCS#11 module resolvable
        std::filesystem::create_directories(tmp);
        transport = std::move(*SocketTransport::create(path));
        core.emplace(
            resolver, *transport, authz, prompter, tmp / "config.json", tmp / "cache",
            [](const std::string&) -> std::optional<Agent::ReaderCard> { return std::nullopt; },
            [](const std::string&) -> std::optional<Agent::ObjectId> { return std::nullopt; });
        frontend.emplace(*transport, *core, "0.1-hw");
        frontend->start();
        core->objectRegistry().setObservers(
            [this](const Agent::ReaderState& r) { frontend->onReaderPublished(r); },
            [this](const Agent::CardState& c) { frontend->onCardPublished(c); },
            [this](Agent::ObjectId id) { frontend->onWithdrawn(id); },
            [this](Agent::ObjectId r, const Agent::PropertyDelta& d) { frontend->onReaderPropertiesChanged(r, d); });
        bridge.emplace(core->presenceModel(), core->cardKeyTracker(), stateMutex);
        bridge->start();
    }

    ~HwRig()
    {
        // Mirror the daemon's ordered teardown (main.cpp): a gtest fatal
        // assertion can leave an operation in flight, and rushing the frontend
        // down while a worker's posted continuation is queued is a
        // use-after-free. Stop the monitor, cancel in-flight crypto, sever the
        // observers, quiesce the loop (drops every subsequently-run posted
        // block), drain it, and only then release the frontend the core
        // borrows.
        bridge.reset();
        core->requestCryptoShutdown();
        core->objectRegistry().setObservers({}, {}, {}, {});
        transport->quiesceLoop();
        dispatch_sync(transport->loopQueue(), ^{
                      });
        frontend.reset();
        core.reset();
        transport.reset();
        std::filesystem::remove(path);
        std::error_code ec;
        std::filesystem::remove_all(tmp, ec);
    }
};

// Send a request; return THE reply correlated by our request id ("req").
// Unsolicited event frames (presence/property broadcasts, "t"-tagged) and
// stale earlier replies ride the same stream and must be skipped — reading
// exactly one frame desyncs the whole session after the first broadcast.
wire::CborValue sendReq(int client, std::uint64_t req, wire::Request body, std::vector<int> fds = {})
{
    const auto bytes = wire::toCbor(wire::RequestEnvelope{req, std::move(body)}).encode();
    EXPECT_TRUE(wire::sendFrame(client, bytes, fds).has_value());
    for (int i = 0; i < 200; ++i) {
        const auto frame = wire::recvFrame(client);
        if (!frame) {
            break;
        }
        const auto decoded = wire::decode(frame->body);
        if (!decoded) {
            continue;
        }
        if (const auto* r = decoded->find("req"); r != nullptr && r->asUInt().value_or(0) == req) {
            return *decoded;
        }
    }
    ADD_FAILURE() << "no reply correlated to req=" << req;
    return wire::CborValue{};
}

// After an OpStarted reply, read event frames until OpFinished; return the
// terminal OpFinished map (and capture the last OpResultReady if seen).
wire::CborValue driveToFinished(int client, wire::CborValue* resultOut, std::vector<wire::UniqueFd>* resultFds)
{
    for (int i = 0; i < 200; ++i) {
        auto frame = wire::recvFrame(client);
        if (!frame) {
            break;
        }
        auto decoded = wire::decode(frame->body);
        if (!decoded || decoded->find("t") == nullptr) {
            continue;
        }
        const std::string tag = *decoded->find("t")->asText();
        if (tag == "OpResultReady") {
            if (resultOut != nullptr) {
                *resultOut = *decoded;
            }
            if (resultFds != nullptr) {
                *resultFds = std::move(frame->fds);
            }
        } else if (tag == "OpFinished") {
            return *decoded;
        }
    }
    return wire::CborValue{};
}

// Poll GetState until a card is present (the monitor pump is async), or timeout.
std::optional<std::string> waitForCard(int client)
{
    for (int i = 0; i < 40; ++i) {
        const auto reply = sendReq(client, 1000 + i, wire::GetState{});
        const auto* cards = reply.find("cards");
        if (cards != nullptr && cards->asArray() != nullptr && !cards->asArray()->empty()) {
            const auto& first = cards->asArray()->front();
            if (const auto* h = first.find("handle"); h != nullptr && h->asText() != nullptr) {
                return *h->asText();
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    return std::nullopt;
}

TEST(SignHwSmoke, PresenceReadAndSign)
{
    if (!hwEnabled()) {
        GTEST_SKIP() << "set LIBRESCRS_HW=1 (+ a reader/card) to run the P1b hardware gate";
    }
    HwRig rig;
    const int client = connectClient(rig.path);

    // Hello -> HelloAck.
    const auto hello = sendReq(client, 1, wire::Hello{1, std::string("hw-smoke")});
    ASSERT_NE(hello.find("agentVer"), nullptr);

    // Presence: wait for the monitor to surface a card.
    const auto card = waitForCard(client);
    if (!card) {
        ::close(client);
        GTEST_SKIP() << "no card detected on any reader within 10s";
    }

    // ReadCertificates -> pick a signing-capable cert id.
    const auto certReply = sendReq(client, 2, wire::ReadCertificates{*card});
    if (certReply.find("err") != nullptr) {
        ::close(client);
        GTEST_SKIP() << "card has no PKI capability (ReadCertificates rejected)";
    }
    ASSERT_NE(certReply.find("op"), nullptr) << "ReadCertificates should mint an op";
    wire::CborValue certResult;
    const auto certFinished = driveToFinished(client, &certResult, nullptr);
    ASSERT_NE(certFinished.find("status"), nullptr);

    // OpResultReady nests the typed payload under "result" (kind="Certificates",
    // certs=[…]) — see wire::toCbor(OpResultReady). Read the cert list there, not
    // at the frame's top level.
    std::string certId;
    std::string inventory; // dumped on skip — the triage evidence for a miss
    const auto* resultMap = certResult.find("result");
    const auto* certs = resultMap != nullptr ? resultMap->find("certs") : nullptr;
    if (certs != nullptr && certs->asArray() != nullptr) {
        for (const auto& c : *certs->asArray()) {
            const auto* sc = c.find("signingCapable");
            const auto* id = c.find("certId");
            const auto* ku = c.find("keyUsageBits");
            inventory += "\n  cert id=" + (id && id->asText() ? id->asText()->substr(0, 12) : std::string("?")) +
                         " signingCapable=" + ((sc && sc->asBool().value_or(false)) ? "true" : "false") +
                         " keyUsageBits=" + std::to_string(ku ? ku->asUInt().value_or(0) : 0);
            if (sc != nullptr && sc->asBool().value_or(false) && id != nullptr && id->asText() != nullptr) {
                certId = *id->asText();
                break;
            }
        }
    }
    if (certId.empty()) {
        ::close(client);
        GTEST_SKIP() << "no signing-capable certificate on the card; inventory:"
                     << (inventory.empty() ? " (empty cert list)" : inventory);
    }

    // Sign a small doc (PIN-guarded). PAdES over a minimal PDF prefix; the format
    // sniff needs only a bounded prefix, but a real PDF keeps the flow honest.
    SKIP_IF_PIN_FAILED();
    if (!env("LIBRESCRS_TEST_PIN")) {
        ::close(client);
        GTEST_SKIP() << "LIBRESCRS_TEST_PIN unset — sign phase INCONCLUSIVE";
    }
    const std::string pdf = "%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n";
    const std::filesystem::path docPath = rig.tmp / "doc.pdf";
    {
        FILE* f = std::fopen(docPath.c_str(), "wb");
        ASSERT_NE(f, nullptr);
        std::fwrite(pdf.data(), 1, pdf.size(), f);
        std::fclose(f);
    }
    const int docFd = ::open(docPath.c_str(), O_RDONLY);
    ASSERT_GE(docFd, 0);

    const auto signReply =
        sendReq(client, 3, wire::Sign{*card, certId, 0, wire::SignOpts{"pades", "b-b", "enveloped"}}, {docFd});
    ::close(docFd);
    ASSERT_EQ(signReply.find("err"), nullptr)
        << "Sign method-entry rejected: " << (signReply.find("err") ? "see err" : "");
    ASSERT_NE(signReply.find("op"), nullptr) << "Sign should mint an op";

    wire::CborValue signResult;
    std::vector<wire::UniqueFd> artifactFds;
    const auto signFinished = driveToFinished(client, &signResult, &artifactFds);
    ASSERT_NE(signFinished.find("status"), nullptr);
    const auto status = signFinished.find("status")->asUInt().value_or(999);

    // OperationStatus: 0=Ok, 1=Cancelled, 2=Error (see OperationPhase.h). An auth
    // failure trips the PIN guard so no further PIN is ever presented this run.
    if (status != 0) {
        const auto code = signFinished.find("code") ? signFinished.find("code")->asUInt().value_or(0) : 0;
        const auto* mk = signFinished.find("msgKey");
        const auto* mf = signFinished.find("msgFallback");
        // ErrorCode AuthFailed family -> latch the guard (conservative: any Error
        // on the sign path after a PIN was presented latches).
        g_pinFailed = true;
        FAIL() << "Sign did not finish Ok (status=" << status << ", code=" << code
               << ", msgKey=" << (mk && mk->asText() ? *mk->asText() : "?")
               << ", msg=" << (mf && mf->asText() ? *mf->asText() : "?")
               << "). PIN guard latched — re-run only after confirming the PIN.";
    }

    // Ok: the signed artifact rides an SCM_RIGHTS fd and must be non-empty.
    ASSERT_FALSE(artifactFds.empty()) << "Sign(Ok) must deliver an artifact fd";
    struct stat st{};
    ASSERT_EQ(::fstat(artifactFds.front().get(), &st), 0);
    EXPECT_GT(st.st_size, 0) << "signed artifact is empty";

    ::close(client);
}

} // namespace
