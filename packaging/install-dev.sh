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
set -euo pipefail

APP_GROUP="group.org.librescrs.LibreMac"
# The agent resolves its container itself and takes no override, so this is
# the one place it can be: the canonical App-Group container.
CONTAINER="$HOME/Library/Group Containers/$APP_GROUP"
SOCK="$CONTAINER/agent.sock"
LABEL="org.librescrs.agent"
BUILD_DIR="${BUILD_DIR:-build}"
AGENT_BIN="${AGENT_BIN:-$BUILD_DIR/agent/librescrs-agent}"

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
        ensure_container
        echo "librescrs-agent (dev) -> self-binds $SOCK"
        echo "stop with Ctrl-C (SIGINT); the agent unlinks the socket on clean exit."
        exec "$AGENT_BIN" --plugin-dir "$PLUGIN_DIR"
        ;;
    launchd)
        [ -x "$AGENT_BIN" ] || die "agent binary not found/executable: $AGENT_BIN (build first)"
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
