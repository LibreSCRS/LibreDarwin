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

### Added

- A release workflow and a `KEYS` file. Until now this repository had neither,
  so its first tag would also have been the first execution of a pipeline
  nobody had ever run. The workflow verifies the tag's signature against the
  published key, then publishes the section of this file that names the tag's
  version.

### Changed

- **Dual-interface readers: the contact slot is kept powered while a card
  sits in it, where the platform reports both slots as one unit.** A
  dual-interface card in the contact slot of a reader such as the OMNIKEY 5422
  couples weakly to the reader's contactless coupler, and on Linux the
  contactless slot reported it as an endless insert/remove flap (reader LED
  never at rest, a full card probe per flap). The agent now keeps a bare power
  hold on such a contact slot: a second PC/SC connection that carries no
  secret and sends no traffic. The logical session still closes after 45 s
  idle exactly as before, so nothing lives longer in memory than it did. The
  hold engages only for a reader the agent can classify as the contact slot
  of a dual-interface unit, which it does from the reader names the platform
  publishes: two slots that share a serial in their name. macOS publishes the
  bare product string for the readers measured so far, which names no unit
  and is therefore never held; whether it names the OMNIKEY 5422's two slots
  as one unit is not yet measured. Where the hold does engage: a PC/SC client
  that asks for EXCLUSIVE access to that contact slot (GnuPG's scdaemon does
  by default) is refused while the card is present; SHARED clients, including
  OpenSC tools, are unaffected. On such a slot, and for cards whose PIN state
  is not bound to a secure channel, the card's own verified state survives
  the 45 s idle close, so within a PKCS#11 login a signature after a longer
  pause no longer re-prompts before the login's own idle limit; as inside the
  old 45 s window, that on-card state is visible to any other local shared
  PC/SC client while the card stays powered. The same change as the Linux
  host's, on the same agent core.

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
