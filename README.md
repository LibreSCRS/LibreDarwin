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
  a separate helper the daemon drives. *(P1b)*
- **`pkcs11-module/`** — the card-less, secret-less PKCS#11 facade dylib that
  browsers load; forwards to the agent over the socket. *(P2)*
- **`packaging/launchd/`** — the LaunchAgent plist, using launchd **socket
  activation** so the daemon inherits the listening fd.

## Wire protocol

The macOS socket wire protocol (CBOR + `SCM_RIGHTS` + `LOCAL_PEERTOKEN`/`SecCode`
peer-auth) mirrors the D-Bus agent surface message-for-message. The contract of
record is [`agent/wire/librescrs-agent.cddl`](agent/wire/librescrs-agent.cddl),
installed alongside the agent so clients can pin against it. The D-Bus surface
stays the canonical semantic source; this schema mirrors it rather than forking
it.

## Status

**Skeleton (scaffold).** Structure + build wiring + backend interface stubs are
in place; the real backend implementation is phase **P1b**
(`implement-macos-backend`). Every stub is marked `TODO(P1b)`.

## Building

Requirements: macOS 15+, Xcode 16+, CMake ≥ 3.24, a C++23 AppleClang.
LibreMiddleware 4.2 installed (`find_package(LibreMiddleware CONFIG)`).

```bash
cmake -B build -S . -DFETCHCONTENT_SOURCE_DIR_LIBREAGENT=../LibreAgent
cmake --build build -j4
```

Apple Clang compiling against LM's C++23 headers needs `-fexperimental-library`
(applied on the LM-linking targets).
