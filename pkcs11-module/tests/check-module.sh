#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# check-module.sh -- the built PKCS#11 module is what a loader expects of it,
# on every architecture it carries.
#
# Four claims, each read from the BUILT FILE rather than from the CMake rules
# that produced it, and each judged per slice: `nm -gU` on a universal file
# reads only the host's slice, so a claim that held on arm64 alone would pass
# a broken x86_64 slice unseen.
#
#   1. exactly one C_* symbol is exported, and it is _C_GetFunctionList. The
#      facade is a static archive pulled in whole; linked by bare name the
#      module builds, loads and exports no entry point at all. Zero is as wrong
#      as two.
#   2. no library a loader would have to find besides the system's: no
#      LibreSCRS library, no OpenSSL, no Qt, nothing from /opt/homebrew or
#      /usr/local. The module runs inside Firefox; it cannot bring a card stack
#      along.
#   3. LC_BUILD_VERSION minos equals the deployment target given. A slice built
#      for a newer macOS refuses to load on the older ones the app supports.
#   4. the file does not contain the name of the test-only socket override.
#      The production module reads nothing from the environment of the
#      application that loaded it.
#
# Exit codes -- a consumer writes the condition as `rc = 0`, never "not 1":
#   0  every claim holds on every slice
#   1  a claim is broken; each failure is printed
#   2  nothing was measured: bad arguments, no module file, not a Mach-O file,
#      or a tool is missing
#
#   Usage: check-module.sh --module=<path> --min=<macOS version>
set -uo pipefail
export LC_ALL=C

module=""
min=""
for arg in "$@"; do
    case "$arg" in
    --module=*) module="${arg#--module=}" ;;
    --min=*) min="${arg#--min=}" ;;
    *) echo "FATAL: unknown argument: $arg" >&2; exit 2 ;;
    esac
done
if [[ -z "$module" || -z "$min" ]]; then
    echo "usage: check-module.sh --module=<path> --min=<macOS version>" >&2
    exit 2
fi

for tool in lipo nm otool strings; do
    command -v "$tool" >/dev/null 2>&1 || { echo "FATAL: $tool not found -- nothing measured" >&2; exit 2; }
done
[[ -f "$module" ]] || { echo "FATAL: no module at $module -- nothing measured" >&2; exit 2; }

archs="$(lipo -archs "$module" 2>/dev/null)" || archs=""
if [[ -z "$archs" ]]; then
    echo "FATAL: $module is not a Mach-O file -- nothing measured" >&2
    exit 2
fi

rc=0
fail() { echo "FAIL: $*" >&2; rc=1; }

for a in $archs; do
    # 1. The exported C_* names.
    if ! syms="$(nm -arch "$a" -gU "$module" 2>/dev/null)"; then
        echo "FATAL: nm could not read the $a slice -- nothing measured" >&2
        exit 2
    fi
    cnames="$(printf '%s\n' "$syms" | awk '{ print $NF }' | grep -E '^_C_' || true)"
    count="$(printf '%s' "$cnames" | grep -c . || true)"
    if [[ "$count" != 1 || "$cnames" != "_C_GetFunctionList" ]]; then
        fail "$a: exports $count C_* symbol(s), expected exactly _C_GetFunctionList: ${cnames//$'\n'/ }"
    fi

    # 2. What the loader must find. The first line names the file and slice.
    if ! deps="$(otool -arch "$a" -L "$module" 2>/dev/null)"; then
        echo "FATAL: otool -L could not read the $a slice -- nothing measured" >&2
        exit 2
    fi
    bad="$(printf '%s\n' "$deps" | tail -n +2 \
        | grep -E 'libLibreSCRS_|libcrypto|libssl|Qt|/opt/homebrew|/usr/local' || true)"
    if [[ -n "$bad" ]]; then
        fail "$a: links what a loading application would have to supply:"
        printf '  %s\n' "$bad" >&2
    fi

    # 3. The minimum macOS of the slice.
    if ! loads="$(otool -arch "$a" -l "$module" 2>/dev/null)"; then
        echo "FATAL: otool -l could not read the $a slice -- nothing measured" >&2
        exit 2
    fi
    minos="$(printf '%s\n' "$loads" | awk '
        $1 == "cmd" { inBuild = ($2 == "LC_BUILD_VERSION") }
        inBuild && $1 == "minos" { print $2; exit }')"
    if [[ -z "$minos" ]]; then
        fail "$a: no LC_BUILD_VERSION minos"
    elif [[ "$minos" != "$min" ]]; then
        fail "$a: minos $minos, expected $min"
    fi
done

# 4. Anywhere in the file, any slice.
if strings -a "$module" | grep -q 'LIBRESCRS_AGENT_SOCK'; then
    fail "the module contains LIBRESCRS_AGENT_SOCK, the test-only socket override"
fi

if [[ "$rc" = 0 ]]; then
    echo "OK: $module ($archs): one export, _C_GetFunctionList; no foreign library; minos $min; no socket override"
fi
exit "$rc"
