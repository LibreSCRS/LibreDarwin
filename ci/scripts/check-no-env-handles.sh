#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-no-env-handles.sh — the shipped agent and prompter take no
# configuration from a LIBRESCRS_* environment variable.
#
# Every such variable was a handle into a process that holds card secrets:
# `launchctl setenv` reaches every job the user's launchd starts, so a variable
# that moved a socket, skipped a peer check or named another plugin directory
# was a switch any process running as the user could flip. The socket paths,
# the container and the peer identities are compiled in; the plugin directory
# is an argument (`--plugin-dir`), which `launchctl setenv` cannot reach.
#
# The rule is the name, not the call: a string literal that spells
# "LIBRESCRS_… is what every getenv()/envOr() of one of these variables needs,
# whether it is passed inline or through a named constant, so the literal is
# what is matched. Test sources may read the environment (a hardware test takes
# its PIN from it), so tests/ directories are not scanned.
#
# Reads only tracked files (git ls-files).
#
# Usage:
#   ci/scripts/check-no-env-handles.sh
#
# Exit codes — a consumer writes the condition as `rc = 0`, never "not 1":
#   0  no production source names a LIBRESCRS_ variable
#   1  at least one does; each is printed as file:line
#   2  cannot judge: not a git work tree, no production source under the
#      scanned paths, or grep itself failed
set -uo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || { echo "FATAL: not a git work tree — this check reads git ls-files, nothing else" >&2; exit 2; }

mapfile -t files < <(git ls-files -- 'agent/src/*' 'agent/include/*' 'prompter/*' \
    | grep -Ev '(^|/)tests/')

if [ "${#files[@]}" -eq 0 ]; then
    echo "FATAL: no production source under agent/src, agent/include or prompter — nothing scanned is not clean" >&2
    exit 2
fi

hits="$(grep -HnE '"LIBRESCRS_' -- "${files[@]}")"
st=$?
if [ "$st" -gt 1 ]; then
    echo "FATAL: grep failed (exit $st) — cannot judge" >&2
    exit 2
fi

if [ -n "$hits" ]; then
    printf '%s\n' "$hits"
    n="$(printf '%s\n' "$hits" | wc -l)"
    echo "FAIL: $n production line(s) name a LIBRESCRS_ environment variable; compile the value in or take it as an argument" >&2
    exit 1
fi

echo "OK: ${#files[@]} production source(s) scanned, none names a LIBRESCRS_ environment variable"
exit 0
