#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Dev harness for the macOS broker-host agent. LibreMac ships the agent inside
# its app and registers it with SMAppService; this runs a build-tree
# librescrs-agent STANDALONE against the same App-Group container, signed with
# the entitlements the shipped one carries. Modes:
#
#   ./install-dev.sh run        # foreground: create the container, exec the agent
#   ./install-dev.sh launchd    # bootstrap a dev LaunchAgent (build-tree agent)
#   ./install-dev.sh unload      # bootout the dev LaunchAgent
#   ./install-dev.sh smoke       # start the agent, connect, expect readiness
#
# The agent self-binds the container socket; no socket-activation. In
# production the sandboxed LibreMac host creates the container (+ primes CTK) and
# registers the bundled plist via SMAppService — this harness stands in for
# the host when the agent is run from a build tree.
#
# The LibreMac Swift clients (and, on the agent<->prompter private socket, the
# two binaries checking each other -- PeerPolicy.h) verify the peer's SecTask
# signing identifier plus the com.apple.security.application-groups
# entitlement before trusting it. A plain `cmake --build` leaves the linker's
# own ad-hoc signature on librescrs-agent/librescrs-prompter (identifier =
# the binary's own name, no entitlements at all), which fails that check --
# see Scripts/bundle-agent.sh (LibreMac) and RealAgentSmokeTests.swift for the
# same recipe applied to the bundled and manually-run cases respectively.
# `run`, `launchd`, and `smoke` re-sign $AGENT_BIN with sign_dev_binary()
# every time, and also re-sign $PROMPTER_BIN the same way when it exists --
# this harness never starts a prompter process itself (there is no dev
# prompter LaunchAgent template here, unlike the bundled
# org.librescrs.prompter.plist), but if a developer points a hand-made
# LaunchAgent at the build-tree prompter, its signature is kept current by
# whichever of these subcommands they run. SecTask reads the signature of
# the already-running process, not the file on disk, so a prompter that is
# already loaded needs restarting after a re-sign -- each subcommand prints
# (never runs) the `launchctl kickstart` line for that.
set -euo pipefail

LABEL="org.librescrs.agent"
PROMPTER_LABEL="org.librescrs.prompter"
BUILD_DIR="${BUILD_DIR:-build}"
AGENT_BIN="${AGENT_BIN:-$BUILD_DIR/agent/librescrs-agent}"
PROMPTER_BIN="${PROMPTER_BIN:-$BUILD_DIR/prompter/librescrs-prompter}"
# This harness only ever signs ad-hoc (no team, no designated requirement --
# that policy belongs to LibreMac's Scripts/bundle-agent.sh, which team-signs
# the bundled agent/prompter when CODESIGN_IDENTITY names a real identity).
# Kept as a variable, not a literal "-", so sign_dev_binary can refuse to act
# outside that one supported case instead of silently ad-hoc-signing a binary
# someone meant to sign with a real identity.
CODESIGN_IDENTITY="${CODESIGN_IDENTITY:--}"

# The entitlements the shipped agent and prompter are signed with -- App
# Sandbox, smart card, network client, the App Group -- live with the app that
# ships them (LibreMac/Packaging/entitlements, the files LibreMac's
# Scripts/sign-bundle.sh signs from). A development agent signed with anything
# else is not the agent that ships: outside the sandbox it reaches files, the
# network and the keychain differently, and a run that passes here would prove
# nothing about the shipped one. LibreMac is expected next to this checkout.
LIBREMAC_DIR="${LIBREMAC_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/LibreMac}"
ENTITLEMENTS_DIR="$LIBREMAC_DIR/Packaging/entitlements"

# Card plugins the agent dlopens. Defaults to the workspace install prefix that
# rebuild-all populates, because the agent's own compiled default points at a
# system prefix a development machine does not have -- and an agent with no
# plugins fails in the one way that leaves no trace: every card comes back
# unusable and nothing says why. Handed to the agent as --plugin-dir: it reads
# no configuration from its environment.
LM_PREFIX="${LM_PREFIX:-$(cd "$(dirname "$0")/../.." && pwd)/lm-prefix}"
PLUGIN_DIR="${PLUGIN_DIR:-$LM_PREFIX/lib/librescrs/plugins}"
LM_LIB="${LM_LIB:-$LM_PREFIX/lib}"

die() { echo "error: $*" >&2; exit 1; }

# Where the agent listens. The rule -- the App Group named after the team, the
# socket's name inside it -- is the agent's wire contract (socket-location in
# LibreAgent's wire/wire-vocabulary.json), the same file the Swift client and
# LibreMac's signing script read; it is not restated here. This harness signs
# ad hoc, for a build that names no team, so the group is the team-less one; a
# build configured with LIBRESCRS_TEAM_ID refuses to start under this
# signature. The agent resolves its container itself and takes no override, so
# this is the one place it can be. LibreAgent's source is the one the build
# directory was configured with (fetched, or a local checkout), or
# LIBREAGENT_SRC for a build that consumes an installed LibreAgent.
load_socket_location() {
    local src="${LIBREAGENT_SRC:-}"
    if [ -z "$src" ] && [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
        src="$(sed -n 's/^LibreAgent_SOURCE_DIR:STATIC=//p' "$BUILD_DIR/CMakeCache.txt")"
    fi
    [ -n "$src" ] || die "cannot find LibreAgent's source (configure $BUILD_DIR first, or set LIBREAGENT_SRC)"
    local contract="$src/wire/wire-vocabulary.json"
    local field value
    for field in noTeamPrefix appGroupSuffix socketName; do
        value="$(plutil -extract "socket-location.$field" raw -o - "$contract" 2>/dev/null)" \
            || die "cannot read socket-location.$field from $contract"
        printf -v "SOCKET_LOCATION_$field" '%s' "$value"
    done
    APP_GROUP="$SOCKET_LOCATION_noTeamPrefix$SOCKET_LOCATION_appGroupSuffix"
    CONTAINER="$HOME/Library/Group Containers/$APP_GROUP"
    SOCK="$CONTAINER/$SOCKET_LOCATION_socketName"
}

# sign_dev_binary <path> <identifier>
#
# Ad-hoc (re-)signs a dev-built binary with the signing identifier its peers
# check and the entitlements the shipped binary of that identifier carries
# (the agent's or the prompter's file from $ENTITLEMENTS_DIR), with the App
# Group replaced by the one this build names -- the same substitution
# sign-bundle.sh makes. `codesign --force` replaces whatever signature is
# already there -- the linker's ad-hoc one after a fresh build, or our own
# from a previous run -- so calling this again on the same binary is a no-op
# in effect: idempotent.
#
# Deliberately NO --options runtime. The hardened runtime strips DYLD_* out
# of a process's environment unless the binary also carries
# com.apple.security.cs.allow-dyld-environment-variables, and the whole point
# of DYLD_LIBRARY_PATH here (see the `launchd` case below) is to let a dev
# build that links LibreMiddleware with bare @rpath entries find it outside
# an install prefix. A hardened dev binary would just fail to start instead
# of failing the identity check it is being signed to pass. LibreMac's
# signing script DOES use --options runtime -- it signs a bundled agent that
# finds its libraries next to itself and needs no DYLD_LIBRARY_PATH.
#
# The entitlements are signed from a copy made with `mktemp -t` (honors
# $TMPDIR, never a literal /tmp path), removed before this function returns,
# on every exit path, via a scoped EXIT trap.
sign_dev_binary() {
    local bin="$1" identifier="$2"
    # Fail closed, not open: continuing past this with the binary unsigned
    # (or signed under some other identity) hands run/launchd/smoke a binary
    # the peer verifier refuses, which fails minutes later and far from here.
    [ "$CODESIGN_IDENTITY" = "-" ] || die "CODESIGN_IDENTITY='$CODESIGN_IDENTITY' is not ad-hoc; this dev harness only signs ad-hoc (unset it, or run LibreMac's team-signed bundle path instead)"
    [ -x "$bin" ] || die "cannot sign, binary not found/executable: $bin"
    local part
    case "$identifier" in
        "$LABEL") part=agent ;;
        "$PROMPTER_LABEL") part=prompter ;;
        *) die "no shipped entitlements for identifier '$identifier' (expected $LABEL or $PROMPTER_LABEL)" ;;
    esac
    local source="$ENTITLEMENTS_DIR/$part.plist"
    [ -f "$source" ] || die "shipped entitlements not found: $source (check out LibreMac next to this repository, or set LIBREMAC_DIR)"

    # `mktemp -t` itself falls back to a literal /tmp when $TMPDIR is unset;
    # state that rule instead of silently taking the fallback.
    : "${TMPDIR:?TMPDIR must be set -- refusing to fall back to a literal /tmp path}"
    local ents
    ents="$(mktemp -t librescrs-dev-entitlements)"
    # No EXIT trap is set by any caller before this point in the current
    # control flow (`smoke` sets its own AFTER both of its sign_dev_binary
    # calls) -- safe to claim EXIT here and hand it back below. If that ever
    # changes, save/restore the incoming trap instead of clearing it.
    trap 'rm -f "$ents"' EXIT
    cat "$source" > "$ents"
    /usr/libexec/PlistBuddy -c "Set :com.apple.security.application-groups:0 $APP_GROUP" "$ents" >/dev/null
    codesign --force -s - --identifier "$identifier" --entitlements "$ents" "$bin"
    rm -f "$ents"
    trap - EXIT
    echo "signed (ad-hoc): $bin identifier=$identifier entitlements=$source group=$APP_GROUP"
}

ensure_container() {
    mkdir -p "$CONTAINER"
    # AF_UNIX sun_path is 104 bytes; fail early if the resolved socket overflows.
    if [ "${#SOCK}" -ge 104 ]; then
        die "container socket path is ${#SOCK} bytes (>= 104, AF_UNIX limit): $SOCK"
    fi
}

case "${1:-run}" in
    run)
        load_socket_location
        [ -x "$AGENT_BIN" ] || die "agent binary not found/executable: $AGENT_BIN (build first)"
        sign_dev_binary "$AGENT_BIN" "$LABEL"
        if [ -x "$PROMPTER_BIN" ]; then
            sign_dev_binary "$PROMPTER_BIN" "$PROMPTER_LABEL"
            echo "note: if $PROMPTER_LABEL is already loaded (a hand-made LaunchAgent), restart it to pick up this signature: launchctl kickstart -k gui/$UID/$PROMPTER_LABEL"
        fi
        ensure_container
        echo "librescrs-agent (dev) -> self-binds $SOCK"
        echo "stop with Ctrl-C (SIGINT); the agent unlinks the socket on clean exit."
        exec "$AGENT_BIN" --plugin-dir "$PLUGIN_DIR"
        ;;
    launchd)
        load_socket_location
        [ -x "$AGENT_BIN" ] || die "agent binary not found/executable: $AGENT_BIN (build first)"
        sign_dev_binary "$AGENT_BIN" "$LABEL"
        if [ -x "$PROMPTER_BIN" ]; then
            sign_dev_binary "$PROMPTER_BIN" "$PROMPTER_LABEL"
            echo "note: if $PROMPTER_LABEL is already loaded (a hand-made LaunchAgent), restart it to pick up this signature: launchctl kickstart -k gui/$UID/$PROMPTER_LABEL"
        fi
        ensure_container
        ABS_BIN="$(cd "$(dirname "$AGENT_BIN")" && pwd)/$(basename "$AGENT_BIN")"
        PLIST_DIR="$HOME/Library/LaunchAgents"
        mkdir -p "$PLIST_DIR"
        DEST="$PLIST_DIR/$LABEL.plist"
        # Warn rather than fail: an agent with no plugins still starts, still
        # serves config, and is a legitimate thing to run -- but silently, so
        # say it here where someone is watching.
        [ -d "$PLUGIN_DIR" ] || echo "WARNING: plugin dir does not exist: $PLUGIN_DIR (the agent will load no plugins)" >&2
        # Fail rather than warn: without the middleware libraries the agent does
        # not start at all, and launchd answers a crash loop with a throttle, so
        # the report arrives ten seconds late and looks like something else.
        [ -d "$LM_LIB" ] || die "middleware lib dir does not exist: $LM_LIB (the agent will not start; build+install LibreMiddleware, or set LM_PREFIX)"
        # The template carries neither the plugin directory nor an environment,
        # because a bundled agent needs neither. The plugin directory is an
        # argument, which `launchctl setenv` cannot reach. DYLD_LIBRARY_PATH is
        # the one variable a development build needs: it is linked with @rpath
        # entries for @executable_path and ../Frameworks only, which find
        # nothing next to an install prefix, and without it the agent dies
        # before main on a missing LibreMiddleware library -- a crash loop
        # launchd then throttles.
        sed -e "s|<string>@LIBRESCRS_AGENT_PROGRAM@</string>|<string>$ABS_BIN</string><string>--plugin-dir</string><string>$PLUGIN_DIR</string>|g" \
            "$(dirname "$0")/launchd/$LABEL.plist" > "$DEST"
        plutil -insert EnvironmentVariables -json "{\"DYLD_LIBRARY_PATH\":\"$LM_LIB\"}" "$DEST"
        plutil -lint "$DEST" >/dev/null || die "generated plist does not parse: $DEST"
        echo "plugins: $PLUGIN_DIR"
        echo "lm libs: $LM_LIB"
        launchctl bootout "gui/$UID/$LABEL" 2>/dev/null || true
        launchctl bootstrap "gui/$UID" "$DEST"
        echo "bootstrapped $LABEL (gui/$UID). Teardown: launchctl bootout gui/$UID/$LABEL"
        ;;
    unload)
        launchctl bootout "gui/$UID/$LABEL" 2>/dev/null || true
        rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
        echo "booted out + removed the dev $LABEL plist."
        ;;
    smoke)
        load_socket_location
        [ -x "$AGENT_BIN" ] || die "agent binary not found/executable: $AGENT_BIN (build first)"
        sign_dev_binary "$AGENT_BIN" "$LABEL"
        if [ -x "$PROMPTER_BIN" ]; then
            sign_dev_binary "$PROMPTER_BIN" "$PROMPTER_LABEL"
            echo "note: if $PROMPTER_LABEL is already loaded (a hand-made LaunchAgent), restart it to pick up this signature: launchctl kickstart -k gui/$UID/$PROMPTER_LABEL"
        fi
        ensure_container
        "$AGENT_BIN" --plugin-dir "$PLUGIN_DIR" &
        AGENT_PID=$!
        trap 'kill "$AGENT_PID" 2>/dev/null || true' EXIT
        for _ in $(seq 1 20); do
            [ -S "$SOCK" ] && break
            sleep 0.2
        done
        [ -S "$SOCK" ] || die "agent did not bind $SOCK within 4s"
        echo "OK: agent bound $SOCK (0600). Connect a client to exchange Hello/HelloAck."
        ;;
    *)
        die "usage: $0 {run|launchd|unload|smoke}"
        ;;
esac
