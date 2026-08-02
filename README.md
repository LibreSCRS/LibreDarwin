# LibreDarwin

The **macOS broker-host** of the LibreSCRS smart-card stack — the platform twin
of `LibreLinux`. It packages the single per-user card **agent** on macOS: the
launchd daemon, the macOS backend for the platform-neutral `LibreAgent::Core`
interfaces, the agent-owned credential prompter, and the card-less PKCS#11
facade.

```
LibreLinux : LibreKDE  ::  LibreDarwin : LibreMac
   (host)     (client)         (host)     (client)
```

The platform name (Linux / **Darwin**) names the **host** layer; the desktop
name (KDE / **Mac**) names the **LibreMiddleware-free client**. So `LibreDarwin`
holds everything that links LibreMiddleware or owns a secret; `LibreMac`
(menu-bar host + CryptoTokenKit extension) links **zero** LibreMiddleware and is
a thin client of this agent.

## What it owns

- **`agent/`** — the `librescrs-agent` launchd LaunchAgent: the single owner of
  the PC/SC connection, the warm PACE/SM channel, and every secret. Built on
  `LibreAgent::Core` (consumed via FetchContent or `find_package(CONFIG)`), it
  implements the five platform-backend interfaces for macOS:
  | LibreAgent interface | macOS backend (this repo) |
  |---|---|
  | `AgentTransport` | `SocketTransport` — App-Group `0600` AF_UNIX socket, CBOR framing, `SCM_RIGHTS` fd-passing, GCD dispatch |
  | `Authorizer` | `SecCodeAuthorizer` — peer `audit_token` → `SecCode` DR check + config/MDM allow-list + C7 rate-limit |
  | `Operations::PrompterClientBase` | `MacPrompterClient` — forwards to the agent-owned credential window |
  | `Operations::OperationChannel` | `SocketOperationChannel` — per-op progress/result over the socket (inline results, no memfd) |
  | `log::LogSink` | `OsLogSink` — `os_log` sink injected via `log::init` |
- **`prompter/`** — the agent-owned secure credential window (PIN / CAN / MRZ),
  a separate helper the daemon drives.
- **`pkcs11-module/`** — the card-less, secret-less PKCS#11 facade dylib that
  browsers load; forwards to the agent over the socket. *(Skeleton — future work.)*
- **`packaging/launchd/`** — the LaunchAgent plist. The daemon **self-binds** its
  App-Group container socket at runtime; there is no launchd socket activation
  (a per-user socket path can't ride `SMAppService`).

## Wire protocol

The macOS socket wire protocol (CBOR + `SCM_RIGHTS` + `LOCAL_PEERTOKEN`/`SecCode`
peer-auth) mirrors the D-Bus agent surface message-for-message. The contract of
record is [`agent/wire/librescrs-agent.cddl`](agent/wire/librescrs-agent.cddl),
installed alongside the agent so clients can pin against it. The D-Bus surface
stays the canonical semantic source; this schema mirrors it rather than forking
it.

## Status

**The agent backend is implemented.** The framed AF_UNIX socket transport
(`SCM_RIGHTS` fd-passing, GCD dispatch), the `SecCode`-based peer authorizer, the
deterministic-CBOR wire layer, the agent-owned credential prompter, the process
and launchd hardening, and the constructor-DI composition root are all in place
and exercised by ~20 test suites — including a cross-stack wire-contract guard
that pins the CBOR/CDDL literals to the upstream taxonomy value-for-value and a
libFuzzer gate on the untrusted decoder. `LibreMac` can build and link against
this agent today.

Still skeletal and explicitly scoped as future work: the card-less **PKCS#11
facade** (`pkcs11-module/`) is a stub that browsers will load, and the
CryptoTokenKit integration lives on the `LibreMac` client side. Hardened-runtime
signing and notarization are applied at the `LibreMac` packaging stage, not in
this repo.

## Building

Requirements: macOS 15+, Xcode 16+, CMake ≥ 3.28, a C++23 AppleClang.
LibreMiddleware 4.2 installed (`find_package(LibreMiddleware CONFIG)`).

```bash
cmake -B build -S . -DFETCHCONTENT_SOURCE_DIR_LIBREAGENT=../LibreAgent
cmake --build build -j4
```

Apple Clang compiling against LM's C++23 headers needs `-fexperimental-library`
(applied on the LM-linking targets).
