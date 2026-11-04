<!--
SPDX-License-Identifier: LGPL-2.1-or-later
SPDX-FileCopyrightText: 2026 hirashix0
-->

# Changelog

Notable changes to LibreDarwin, newest first. There is no tagged release yet,
so every entry below describes a change to what you get by building from
source.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased] — 5.0.0

### Security

- **Trust changes can no longer flood you with confirmation dialogs.** Each
  request to change a time-stamping or trust-list source, or to forget the
  country signing anchors, now counts against the same per-client budget as
  signing, and a client may have only one such confirmation waiting at a time;
  a second one is refused at once instead of opening another dialog.
- **The socket agent wipes its copies of a decrypted plaintext or a derived
  secret** on the way to the client: the reply message, its encoded body and
  the queued frame, whether the frame is sent or dropped with its connection.
- **The agent and the prompter no longer take configuration from their
  environment.** `launchctl setenv` reaches every job the user's launchd
  starts, so each variable they honoured was a switch any process running as
  the user could flip. Gone: the socket paths (`LIBRESCRS_AGENT_SOCK`,
  `LIBRESCRS_PROMPTER_SOCK`), the container (`LIBRESCRS_AGENT_CONTAINER`), the
  two opt-outs that skipped peer verification
  (`LIBRESCRS_AGENT_ALLOW_UNVERIFIED_PROMPTER`,
  `LIBRESCRS_PROMPTER_ALLOW_UNVERIFIED_PEER`) and the override of the peer the
  prompter expects (`LIBRESCRS_AGENT_SIGNING_ID`). The plugin directory, loaded
  into the process that holds card secrets, is now a `--plugin-dir` argument
  (`LIBRESCRS_PLUGIN_DIR` is gone); `packaging/install-dev.sh` passes it.
- **The agent keeps only `HOME`, `TMPDIR` and `TZ` from its environment**, so
  `launchctl setenv` can no longer name trust anchors, an OpenSC or OpenSSL
  configuration or a provider directory for it.
  LibreMiddleware's debug variables (`LIBRESCRS_SIGN_TRACE`, `PKCS11_DEBUG`,
  `LIBRESCRS_OPENSC_DEBUG`, `LIBRESCRS_PROBE_TRACE`, `LIBRESCRS_PCSC_TRACE`)
  no longer reach the agent either.
- **The agent and the prompter refuse to start, with exit code 4, when their
  own signature does not match the build**: when it lacks the build's App
  Group, or, for a build that names a team, fails that team's designated
  requirement. Until now only the team was checked, and its failure exited 2,
  the same code as a bad argument; a binary signed into the wrong App Group
  started, served a container its clients never look in, and passed a smoke
  test that expected 2 from a bogus argument. The check runs before the
  arguments are read, so an unsigned build-tree agent now exits 4; run it by
  hand with `packaging/install-dev.sh run`, which signs it first.
- **The agent refuses to start, with exit code 5, when its signature lacks
  `com.apple.security.smartcard`.** CryptoTokenKit shows a process without it
  no reader and opens it no card, so such an agent started, served its socket
  and never saw a card. The check runs right after the one that exits 4, in
  development builds too: `packaging/install-dev.sh` now adds the entitlement
  when it signs the agent (never the prompter, which opens no card), and the
  tests that reach a real card session are signed with it after every link.
- Without a Developer ID signature the agent and prompter cannot verify who
  connects to them beyond same-user ownership of the socket; a process running
  as your user can raise the credential window. Developer-ID builds verify the
  peer's designated requirement. `SECURITY.md` says so, and the code comments
  no longer claim that the app-group entitlement binds a peer to a team.

### Added

- **The socket agent answers `Pkcs11.LoginState`** — whether a PKCS#11 client's
  login on the card in a reader still holds, without extending it — and offers
  the `login-state` feature token. The PKCS#11 module asks it so that Firefox
  sees a login the agent has ended as one, and asks for the PIN again.
- `Pkcs11.Derive`: ECDH with the card's EC key (raw secret, no key-derivation
  function), advertised with the `ec-keys` feature token.
- **`librescrs-pkcs11-agent.dylib`, a PKCS#11 module for applications that
  load one** (Firefox, Thunderbird, ssh). It holds no secret: it forwards every
  call to the agent over the App Group socket and, before sending anything,
  checks the signing identity of the process serving that socket, and with a
  team id its designated requirement too.
- A release workflow and a `KEYS` file. Until now this repository had neither,
  so its first tag would also have been the first execution of a pipeline
  nobody had ever run. The workflow verifies the tag's signature against the
  published key, then publishes the section of this file that names the tag's
  version.
- **Every reader the socket agent publishes carries its label**: the short
  model (`OMNIKEY 5422`) and whether the slot is the contact or the
  contactless side of a dual-interface reader, as `reader-state` `model` and
  `interface`. A label that changes because a reader arrived or left beside it
  reaches clients as a `Reader1` property change, so a client shows the label
  and never parses the PC/SC name.
- The change-PIN window now counts down and closes with a timeout, like the
  single-secret prompt. Its request carries the budget as an optional
  `deadlineMs`; a request without it (from an older agent) still shows a
  window with no clock.

### Changed

- **`packaging/install-dev.sh` signs the development agent and prompter with
  the entitlements LibreMac ships them with**, App Sandbox included, instead of
  a narrower set of its own, so a development run reaches what the shipped
  agent reaches. It reads them from a LibreMac checkout next to this one (or
  `LIBREMAC_DIR`).
- **The hardware signing smoke test names no PKCS#11 module.** The agent signs
  through the card's plugin on the session it already holds, so the test no
  longer derives `LIBRESCRS_PKCS11_MODULE` from the plugin directory, and the
  comments that listed that variable among the ones LibreMiddleware reads are
  gone with it: LibreMiddleware no longer reads it.
- The credential prompt (PIN, CAN or MRZ) names a raw card operation as such
  ("Cryptographic token operation", "Key agreement with the card key") instead
  of showing its category token as a document name.
- The socket agent reports each certificate's key ID, key type, key size and
  whether it can derive, serves the EC public key of a certificate on a NIST
  curve, and runs exactly the mechanism a raw signature or decryption names; an
  unknown mechanism, or input that does not fit the key, is refused as
  `InvalidRequest` before any PIN prompt.
- **The agent reports, per certificate, whether the card asks for the PIN
  before every use of its key**, and asks for it again for every raw signature or
  decryption with such a key (batch document signing asks once per batch).
- The credential prompt keeps OK (and Return) disabled while the PIN, CAN or
  MRZ field is empty, and the change-PIN prompt until each of its fields holds
  at least one character. An empty answer used to reach the agent, which reads
  it as a cancellation.
- **The App Group is named after the signing team.** A build configured with
  `LIBRESCRS_TEAM_ID` uses `<team>.org.librescrs.LibreMac`; one without a team
  (CI, tests, the ad-hoc dev harness) keeps `group.org.librescrs.LibreMac`.
  macOS 27 refuses a sandboxed process an unprovisioned `group.` container,
  while a group prefixed with the team that signed it needs no provisioning
  profile. The agent's container, its sockets and the group it requires of
  its peers all follow the one rule.

- The launchd job keeps an agent that exited cleanly stopped
  (`KeepAlive` = `SuccessfulExit: false`, `ThrottleInterval` 10 s): stopping the
  agent on purpose no longer starts it again at once. A crash is still
  restarted.
- **Dual-interface readers: the contact slot is kept powered while a card
  sits in it, where the platform reports both slots as one unit.** A
  dual-interface card in the contact slot of a reader such as the OMNIKEY 5422
  couples weakly to the reader's contactless coupler, and on Linux the
  contactless slot reported it as an endless insert/remove flap (reader LED
  never at rest, a full card probe per flap). The agent now keeps such a
  contact slot's one session open while a card it serves is present. After
  45 s idle the session is emptied of every secret — what the card plugins
  held for it, the cached PACE secrets, the secure channel — and kept only to
  hold the card powered; the next operation reuses it. No second connection
  is opened on a reader, so nothing lives longer in memory than it did. A card
  no plugin serves is not held. The hold engages only for a reader the agent can classify as the contact slot
  of a dual-interface unit, which it does from the reader names the platform
  publishes: two slots that share a serial in their name. macOS publishes the
  bare product string for the readers measured so far, which names no unit
  and is therefore never held; whether it names the OMNIKEY 5422's two slots
  as one unit is not yet measured. Where the hold does engage: a PC/SC client
  that asks for EXCLUSIVE access to that contact slot (GnuPG's scdaemon does
  by default) is refused while the card is present; SHARED clients, including
  OpenSC tools, are unaffected. On such a slot, and for cards whose PIN state
  is not bound to a secure channel, the card's own verified state survives
  the 45 s idle window, so within a PKCS#11 login a signature after a longer
  pause no longer re-prompts before the login's own idle limit; that on-card
  state is visible to any other local shared PC/SC client while the card
  stays powered. The same change as the Linux host's, on the same agent core.
- **A card no plugin serves is opened once on insertion.** The probe that
  resolves a new card now tells a card it could not open from a card no
  plugin serves; only the first is asked about again, so a card that belongs
  to another application is no longer connected to, probed and released four
  times in a row.

- The credential prompt now names the reader holding the card, and its
  contact or contactless slot where the platform names both slots as one
  unit. The dialog and the wire already carried that line; the daemon never
  handed the core the lookup that fills it, so every prompt named no reader.

- Unplugging a reader now stops the worker thread the agent ran for it, as
  the Linux host already did. Before, every unplug left that thread behind for
  the life of the process; with the power hold above, such a leftover would
  also keep trying to hold a same-named reader plugged in later.

- The version this tree is heading for is recorded in `VERSION` and checked
  against this file on every push, rather than first checked on a tag that
  cannot be taken back.

- The agent and the prompter binaries report the version they are part of. Their
  embedded bundle information said 0.1 while everything else in the tree said 5.0.0,
  so Finder, `mdls` and the crash reporter named a version that does not exist.

- The macOS socket host now names a dismissed prompt on the wire instead of
  folding it into a generic communication failure, so a user who cancels a PIN
  prompt is no longer reported as a device error.

- Nine classes of card operation, and their tests, moved out of this host and
  into the agent project, where the Linux host already read them from. The
  behaviour a user sees is unchanged; what changes is that one implementation
  now serves both platforms.

- The floor this host asks of the agent and of the middleware follows the new
  major.

### Fixed

- A prompter reply that arrived together with the prompter closing the
  connection is read instead of being reported as an error. macOS refuses a
  receive timeout on a socket whose peer has already closed, and the agent set
  it only after sending the request, so a prompter that answered at once (a
  refused caller, for one) read as "the reply wait could not be bounded".
  The timeout is now set before the request is sent.
- **An agent out of file descriptors no longer spins at full CPU.** It pauses
  accepting new clients briefly instead of retrying at once, and it raises its
  open-file limit at start-up to what the system allows.
- **A card inserted while macOS or another token driver is still probing it
  is no longer reported as unsupported until it is re-inserted.** The agent
  asks again with growing waits for up to ten seconds, instead of giving up
  after three tries 50 ms apart. Only a card that was refused because
  something else holds it is asked about again; one that cannot be read for
  any other reason is reported at once. A card more than one plugin
  recognises now reports the type of the plugin that takes precedence, where
  it used to report none.
- **The PIN and confirmation dialogs name the application that asks**, by the
  identifier its signature carries (for example `org.mozilla.firefox`), instead
  of a process number. A request that comes through the Keychain names the
  token extension with a `(Keychain)` mark whose wording comes from the host
  application's translation catalogue.
- **The agent honours what a client says in its `Hello`.** A client that
  declines events (`wantsEvents: false`, as the Keychain token extension does)
  no longer receives reader and card presence frames it never reads, which
  used to pile up until the agent closed its connection; and a client of
  another wire protocol version is answered `UnsupportedProtocol`, and its
  connection closed, instead of failing later on a message it cannot decode.
- **LibreMiddleware's own diagnostics reach the unified log.** The agent wired
  its `os_log` sink into the agent core's logging only, so what the middleware
  reported (reader monitor, plugin loading, signing) went to a standard error
  launchd discards. The core and the middleware now share one facade, and the
  agent installs its sink into it once.
- **Every binary now targets macOS 15, the minimum LibreMac states.** The agent
  and the prompter had been built for macOS 27, the build machine's own
  release, so on an earlier macOS they would not have started.
