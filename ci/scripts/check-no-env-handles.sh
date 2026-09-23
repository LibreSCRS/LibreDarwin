#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-no-env-handles.sh — this repository's agent and prompter sources take no
# configuration from the environment, beyond the readers recorded in
# ci/env-readers.txt.
#
# Every LIBRESCRS_* variable these sources used to honour was a handle into a
# process that holds card secrets: `launchctl setenv` reaches every job the
# user's launchd starts, so a variable that moved a socket, skipped a peer check
# or named another plugin directory was a switch any process running as the
# user could flip. The socket paths, the container and the peer identities are
# compiled in; the plugin directory is an argument (`--plugin-dir`), which
# `launchctl setenv` cannot reach.
#
# What this measures, and what it does not. It reads the sources of THIS
# repository under agent/src, agent/include and prompter/, and nothing else. The
# agent process also runs LibreMiddleware code, linked in through the agent
# core, and that code reads variables of its own -- LIBRESCRS_PKCS11_MODULE (the
# module it loads), LIBRESCRS_CERTIFICATES_DIR (the trust anchors),
# LIBRESCRS_DSS_JAR, SSL_CERT_FILE / SSL_CERT_DIR and a few debug switches. None
# of those is judged here, and a green run says nothing about them.
#
# Two rules:
#
#   1  No string literal names a LIBRESCRS_ variable. A literal is what every
#      read of one needs, whether passed inline or through a named constant.
#
#   2  Every environment READ -- getenv, secure_getenv, environ,
#      _NSGetEnviron, NSProcessInfo -- is recorded in ci/env-readers.txt as
#      <path> <call> <reason>. This is the rule a rename cannot pass: a variable
#      spelled "LIBRESCRS" "_X", renamed to LIBREDARWIN_X or read under a name
#      with no prefix at all is still a new reader, and a new reader is red
#      until somebody records why it is legitimate. A row is matched against
#      one file, and a row that matches no reader any more fails too, so the
#      list cannot keep an amnesty for code that is gone.
#
# Known limits, all of them in how a read is spelled rather than in what is
# read. A reader reached through a macro, an alias or a function pointer that
# hides the token (getenv, environ, ...) passes: a compiler, not a pattern,
# would close that. Two more err towards failing rather than passing: a call
# whose name and recorded argument sit on different lines, and a /* block
# comment */ line that starts with neither // nor * and names a reader token.
#
# Test sources may read the environment (a hardware test takes its PIN from
# it), so files under a tests/ directory are not scanned. Only tracked files
# are read (git ls-files).
#
# Usage:
#   ci/scripts/check-no-env-handles.sh
#
# Exit codes — a consumer writes the condition as `rc = 0`, never "not 1":
#   0  no LIBRESCRS_ literal; every reader recorded, every record used
#   1  a LIBRESCRS_ literal, an unrecorded reader, a stale or reasonless row;
#      each is printed
#   2  cannot judge: not a git work tree, no production source under the
#      scanned paths, no ci/env-readers.txt, or grep could not read a file
set -uo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || { echo "FATAL: not a git work tree — this check reads git ls-files, nothing else" >&2; exit 2; }

READERS=ci/env-readers.txt
[ -f "$READERS" ] \
    || { echo "FATAL: no $READERS — without the recorded readers no reader can be judged" >&2; exit 2; }

mapfile -t files < <(git ls-files -- 'agent/src/*' 'agent/include/*' 'prompter/*' \
    | grep -Ev '(^|/)tests/')

if [ "${#files[@]}" -eq 0 ]; then
    echo "FATAL: no production source under agent/src, agent/include or prompter — nothing scanned is not clean" >&2
    exit 2
fi

rc=0

# Rule 1.
hits="$(grep -HnE '"LIBRESCRS_' -- "${files[@]}")"
st=$?
if [ "$st" -gt 1 ]; then
    echo "FATAL: grep failed (exit $st) — cannot judge" >&2
    exit 2
fi
if [ -n "$hits" ]; then
    printf '%s\n' "$hits"
    echo "FAIL: $(printf '%s\n' "$hits" | wc -l) production line(s) name a LIBRESCRS_ environment variable; compile the value in or take it as an argument" >&2
    rc=1
fi

# Rule 2. A full-line comment is not a read; any other line naming a reader
# token is.
readers="$(grep -HnE '(^|[^A-Za-z0-9_])(secure_getenv|getenv|_NSGetEnviron|environ|NSProcessInfo|processInfo)([^A-Za-z0-9_]|$)' \
    -- "${files[@]}")"
st=$?
if [ "$st" -gt 1 ]; then
    echo "FATAL: grep failed (exit $st) — cannot judge" >&2
    exit 2
fi
readers="$(printf '%s\n' "$readers" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*)' || true)"

verdict="$(printf '%s\n' "$readers" | awk '
    FNR == NR { if ($0 != "") { r[++nr] = $0 }; next }
    /^[[:space:]]*(#|$)/ { next }
    {
        rows++
        path = $1; call = $2
        reason = $0
        sub(/^[[:space:]]*[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]*/, "", reason)
        if (reason == "") { print "FAIL: " FILENAME ":" FNR ": " path " " call " gives no reason"; bad = 1 }
        used = 0
        for (i = 1; i <= nr; i++) {
            file = r[i]; sub(/:.*/, "", file)
            if (file == path && index(r[i], call) > 0) { ok[i] = 1; used = 1 }
        }
        if (!used) { print "FAIL: " FILENAME ":" FNR ": " path " " call " is recorded but no such reader exists"; bad = 1 }
    }
    END {
        for (i = 1; i <= nr; i++) if (!ok[i]) { print "FAIL: unrecorded environment reader: " r[i]; bad = 1 }
        printf "%d reader(s), %d recorded\n", nr, rows
        exit bad
    }' - "$READERS")"
st=$?
if [ "$st" != 0 ]; then
    printf '%s\n' "$verdict" | grep '^FAIL' >&2
    rc=1
fi

if [ "$rc" = 0 ]; then
    echo "OK: ${#files[@]} production source(s) scanned, no LIBRESCRS_ literal, $(printf '%s\n' "$verdict" | tail -n 1)"
fi
exit "$rc"
