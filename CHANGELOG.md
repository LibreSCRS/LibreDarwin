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

- The version this tree is heading for is recorded in `VERSION` and checked
  against this file on every push, rather than first checked on a tag that
  cannot be taken back.

- The macOS socket host now names a dismissed prompt on the wire instead of
  folding it into a generic communication failure, so a user who cancels a PIN
  prompt is no longer reported as a device error.

- Nine classes of card operation, and their tests, moved out of this host and
  into the agent project, where the Linux host already read them from. The
  behaviour a user sees is unchanged; what changes is that one implementation
  now serves both platforms.

- The floor this host asks of the agent and of the middleware follows the new
  major.
