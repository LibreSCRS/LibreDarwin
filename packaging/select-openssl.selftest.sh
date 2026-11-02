#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# select-openssl.selftest.sh -- prove the OpenSSL selection writes the one
# static OpenSSL a LibreMiddleware tree carries, and refuses a tree with none
# or with two rather than letting CMake pick whatever the machine has.
#
# Cases:
#   1  one thirdparty/openssl-*/macosx with libcrypto.a  -> 0, cache names it, static
#   2  none                                              -> 1
#   3  two versions side by side                         -> 1
#   4  one, but without libcrypto.a                      -> 1
#   5  one argument                                      -> 2
#   6  a source directory that does not exist            -> 2
set -uo pipefail

SELECT="$(cd "$(dirname "$0")" && pwd)/select-openssl.sh"
WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/select-openssl-selftest.XXXXXX")" \
    || { echo "FATAL: cannot create a scratch directory" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

fail=0
cases=0
red=0

check() {
    local label="$1" expected="$2" actual="$3"
    cases=$((cases + 1))
    if [ "$expected" = "$actual" ]; then
        echo "case $label: OK   -- exit $actual"
        [ "$expected" != 0 ] && red=$((red + 1))
    else
        echo "case $label: FAIL -- expected exit $expected, got $actual"
        fail=$((fail + 1))
    fi
}

tree() { # tree <name> <version>... : a LibreMiddleware tree with those OpenSSLs
    local dir="$WORK/$1"
    shift
    mkdir -p "$dir/thirdparty"
    local v
    for v in "$@"; do
        mkdir -p "$dir/thirdparty/openssl-$v/macosx/lib"
        : > "$dir/thirdparty/openssl-$v/macosx/lib/libcrypto.a"
    done
    echo "$dir"
}

run() { local rc=0; bash "$SELECT" "$@" >/dev/null 2>&1 || rc=$?; echo "$rc"; }

one="$(tree one 3.5.4)"
check 1 0 "$(run "$one" "$WORK/one.cmake")"
if ! grep -qx "set(OPENSSL_ROOT_DIR \"$one/thirdparty/openssl-3.5.4/macosx\" CACHE PATH \"LibreMiddleware's static OpenSSL\")" "$WORK/one.cmake" \
    || ! grep -q '^set(OPENSSL_USE_STATIC_LIBS TRUE ' "$WORK/one.cmake"; then
    echo "case 1: FAIL -- the cache file does not name the tree's OpenSSL as static:"
    sed 's/^/  | /' "$WORK/one.cmake" 2>/dev/null
    fail=$((fail + 1))
fi

check 2 1 "$(run "$(tree none)" "$WORK/none.cmake")"
check 3 1 "$(run "$(tree two 3.5.4 3.6.0)" "$WORK/two.cmake")"
nolib="$(tree nolib 3.5.4)"
rm -f "$nolib/thirdparty/openssl-3.5.4/macosx/lib/libcrypto.a"
check 4 1 "$(run "$nolib" "$WORK/nolib.cmake")"
check 5 2 "$(run "$one")"
check 6 2 "$(run "$WORK/absent" "$WORK/absent.cmake")"

[ "$fail" -eq 0 ] || { echo "select-openssl selftest: $fail failure(s)"; exit 1; }
echo "selftest: $cases cases, $red red-proved"
