#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Dev harness for the macOS broker-host agent. There is no LibreMac host
# yet, so this runs librescrs-agent STANDALONE against a dev App-Group container.
# Two modes:
#
#   ./install-dev.sh run        # foreground: create the container, exec the agent
#   ./install-dev.sh launchd    # bootstrap a dev LaunchAgent (libexec path)
#   ./install-dev.sh unload      # bootout the dev LaunchAgent
#   ./install-dev.sh smoke       # start the agent, connect, expect readiness
#
# The agent self-binds the container socket; no socket-activation. In
# production the sandboxed LibreMac host creates the container (+ primes CTK) and
# registers the bundled plist via SMAppService — this harness stands in for
# that until the host exists.
#
# The LibreMac Swift clients (and, on the agent<->prompter private socket, the
# two binaries checking each other -- PeerPolicy.h) verify the peer's SecTask
# signing identifier plus the com.apple.security.application-groups
# entitlement before trusting it. A plain `cmake --build` leaves the linker's
# own ad-hoc signature on librescrs-agent/librescrs-prompter (identifier =
# the binary's own name, no entitlements at all), which fails that check --
# see Scripts/bundle-agent.sh (LibreMac) and RealAgentSmokeTests.swift for the
# same recipe applied to the bundled and manually-run cases respectively. Every
# subcommand here that runs or loads a binary re-signs it first with
# sign_dev_binary(), ad-hoc, with the identifier + App-Group entitlement the
# checking side expects.
set -euo pipefail

APP_GROUP="group.org.librescrs.LibreMac"
# The agent resolves its container itself and takes no override, so this is
# the one place it can be: the canonical App-Group container.
CONTAINER="$HOME/Library/Group Containers/$APP_GROUP"
SOCK="$CONTAINER/agent.sock"
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

# sign_dev_binary <path> <identifier>
#
# Ad-hoc (re-)signs a dev-built binary with the signing identifier + the
# com.apple.security.application-groups entitlement its peer checks
# (PeerPolicy.h on the C++ side; the LibreMac Swift client on the other).
# `codesign --force` replaces whatever signature is already there -- the
# linker's ad-hoc one after a fresh build, or our own from a previous run --
# so calling this again on the same binary is a no-op in effect: idempotent.
#
# Deliberately NO --options runtime. The hardened runtime strips DYLD_* out
# of a process's environment unless the binary also carries
# com.apple.security.cs.allow-dyld-environment-variables, and the whole point
# of DYLD_LIBRARY_PATH here (see the `launchd` case below) is to let a dev
# build that links LibreMiddleware with bare @rpath entries find it outside
# an install prefix. A hardened dev binary would just fail to start instead
# of failing the identity check it is being signed to pass. LibreMac's
# Scripts/bundle-agent.sh DOES use --options runtime -- it signs a bundled,
# installed agent that finds its libraries next to itself and needs no
# DYLD_LIBRARY_PATH, which is a different binary than the one built here.
#
# The entitlements plist is written to a temp file made with `mktemp -t`
# (honors $TMPDIR, never a literal /tmp path) and is removed before this
# function returns, on every exit path, via a scoped EXIT trap.
sign_dev_binary() {
    local bin="$1" identifier="$2"
    if [ "$CODESIGN_IDENTITY" != "-" ]; then
        echo "not signing $bin: CODESIGN_IDENTITY='$CODESIGN_IDENTITY' is not ad-hoc (this dev harness only signs ad-hoc)" >&2
        return 0
    fi
    [ -x "$bin" ] || die "cannot sign, binary not found/executable: $bin"

    local ents
    ents="$(mktemp -t librescrs-dev-entitlements)"
    trap 'rm -f "$ents"' EXIT
    cat > "$ents" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>$APP_GROUP</string>
    </array>
</dict>
</plist>
PLIST
    codesign --force -s - --identifier "$identifier" --entitlements "$ents" "$bin"
    rm -f "$ents"
    trap - EXIT
    echo "signed (ad-hoc): $bin identifier=$identifier group=$APP_GROUP"
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
        [ -x "$AGENT_BIN" ] || die "agent binary not found/executable: $AGENT_BIN (build first)"
        sign_dev_binary "$AGENT_BIN" "$LABEL"
        ensure_container
        echo "librescrs-agent (dev) -> self-binds $SOCK"
        echo "stop with Ctrl-C (SIGINT); the agent unlinks the socket on clean exit."
        exec "$AGENT_BIN" --plugin-dir "$PLUGIN_DIR"
        ;;
    launchd)
        [ -x "$AGENT_BIN" ] || die "agent binary not found/executable: $AGENT_BIN (build first)"
        sign_dev_binary "$AGENT_BIN" "$LABEL"
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
        [ -x "$AGENT_BIN" ] || die "agent binary not found/executable: $AGENT_BIN (build first)"
        sign_dev_binary "$AGENT_BIN" "$LABEL"
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
    --sign-only)
        # Internal, undocumented in the usage line on purpose: signs one
        # binary and exits, touching no container, launchd, or process.
        # Exists so the signing step above can be exercised (and verified
        # with `codesign -dv --entitlements -`) without running `run`,
        # `launchd`, or `smoke` against a real dev App-Group container.
        SIGN_BIN="${2:?usage: $0 --sign-only <path> [identifier]  (e.g. $AGENT_BIN or $PROMPTER_BIN)}"
        SIGN_ID="${3:-}"
        if [ -z "$SIGN_ID" ]; then
            case "$(basename "$SIGN_BIN")" in
                *agent*) SIGN_ID="$LABEL" ;;
                *prompter*) SIGN_ID="$PROMPTER_LABEL" ;;
                *) die "--sign-only: cannot infer the signing identifier from '$SIGN_BIN'; pass it as a third argument" ;;
            esac
        fi
        sign_dev_binary "$SIGN_BIN" "$SIGN_ID"
        ;;
    *)
        die "usage: $0 {run|launchd|unload|smoke}"
        ;;
esac
