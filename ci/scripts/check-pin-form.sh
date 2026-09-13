#!/usr/bin/env bash
# check-pin-form.sh -- the pin's form check must be able to accept a real pin.
#
# cmake/FindOrUseLibreAgent.cmake refuses a libreagent.pin that is not exactly
# forty lowercase hex characters. From 2026-09-04 to 2026-09-10 it spelled that
# as `MATCHES "^[0-9a-f]{40}$"`. CMake's regex engine has no {n} repetition --
# the braces are literal characters there -- so the pattern matched no hash at
# all and the FATAL_ERROR beneath it rejected EVERY pin, including the one a
# correct release would write. Nothing noticed for six days: this repository's
# other pin gate reads the pin FILE, and the guard only speaks when someone
# configures the project.
#
# So this gate runs the guard instead of reading it. It cuts the length and
# character-class test out of the tracked CMake file, wraps it in a standalone
# script, and feeds it three values through `cmake -P`:
#
#     the repository's own cmake/libreagent.pin  -> must be ACCEPTED
#     "main"                                     -> must be REFUSED
#     a 39-hex string                            -> must be REFUSED
#
# Both directions are required. A guard that accepts everything and a guard
# that refuses everything are both wrong, and each looks correct if only the
# other direction is measured.
#
# THREAT MODEL. This gate reads source text and then executes the fragment it
# cut out. It guards against an HONEST regression -- someone rewrites the guard
# in a pattern language that cannot match, or drops a direction. It does not
# and cannot guard against concealment: the extraction is anchored on the
# marker comment and on `string(LENGTH`, so a guard moved elsewhere in the file,
# renamed, split across a macro, or made conditional on a variable this gate
# does not set is outside what it sees. Doors it knowingly leaves: a second
# validation elsewhere in the file that this gate never reaches; a pin value
# computed rather than read; a guard whose accept branch has side effects. Code
# review covers those.
#
# Exit: 0 the guard judges all three correctly - 1 it does not - 2 cannot measure.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cmake_file="${1:-$repo/cmake/FindOrUseLibreAgent.cmake}"
pin_file="${2:-$repo/cmake/libreagent.pin}"

command -v cmake >/dev/null 2>&1 || { echo "FATAL: no cmake on PATH -- cannot measure" >&2; exit 2; }
[ -f "$cmake_file" ] || { echo "FATAL: no such file: $cmake_file" >&2; exit 2; }
[ -f "$pin_file" ]   || { echo "FATAL: no such file: $pin_file" >&2; exit 2; }

# The guard is the block from the length test down to the endif() that closes
# it. Anchored on `string(LENGTH`, so a rewrite that keeps the shape keeps
# being measured; an extraction that comes back empty is rc=2, never a pass.
guard="$(awk '
    /string\(LENGTH .*LIBREAGENT_PIN/ { inb = 1 }
    inb { print }
    inb && /^[[:space:]]*endif\(\)/  { exit }
' "$cmake_file")"

case "$guard" in
    *FATAL_ERROR*) ;;
    *) echo "FATAL: could not cut a pin-form guard out of $cmake_file" >&2
       echo "       (expected a string(LENGTH ...) test and a FATAL_ERROR below it)" >&2
       exit 2 ;;
esac

work="$(mktemp -d "${TMPDIR:-/var/tmp}/check-pin-form.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# <verdict> <label> <value>: run the extracted guard over one value.
judge() {                       # judge <value> -> prints "accept" or "refuse"
    { printf 'set(LIBREAGENT_PIN "%s")\n' "$1"
      printf '%s\n' "$guard"
      printf 'message(STATUS "pin accepted")\n'
    } > "$work/guard.cmake"
    if cmake -P "$work/guard.cmake" >"$work/out" 2>&1; then echo accept; else echo refuse; fi
}

pin="$(tr -d '[:space:]' < "$pin_file")"
rc=0
check() {                       # check <label> <value> <want>
    local got; got="$(judge "$2")"
    if [ "$got" = "$3" ]; then
        printf 'ok    %-34s %s\n' "$1" "$got"
    else
        printf 'FAIL  %-34s %s, wanted %s\n' "$1" "$got" "$3"
        sed 's/^/          /' "$work/out"
        rc=1
    fi
}

check "the repository's own pin" "$pin"                                        accept
check "a branch name"            "main"                                        refuse
check "39 hex characters"        "0123456789abcdef0123456789abcdef0123456"     refuse
check "40 chars, one not hex"    "0123456789abcdef0123456789abcdef0123456g"    refuse
check "40 hex, upper case"       "0123456789ABCDEF0123456789ABCDEF01234567"    refuse
check "an empty pin"             ""                                            refuse

exit "$rc"
