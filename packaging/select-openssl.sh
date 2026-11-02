#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# select-openssl.sh <LibreMiddleware source dir> <cache file>
#
# The OpenSSL a macOS build of the agent links: LibreMiddleware's static
# universal build under thirdparty/openssl-<version>/macosx, the one the
# middleware's own libraries link and the release ships. Left alone, CMake's
# find_package(OpenSSL) takes whatever the machine has first -- Homebrew's on a
# runner, arm64 only and moving with the image -- so a universal agent fails to
# link its x86_64 slice, and a single-arch one is tested against an OpenSSL
# that never ships.
#
# Writes a CMake initial-cache file for `cmake -C <cache file>`, so every build
# of the agent -- this repository's CI and LibreMac's release -- names the same
# OpenSSL the same way.
#
# Exit codes: 0 written; 1 the source holds no such OpenSSL, or more than one;
# 2 bad usage.
set -euo pipefail

usage="usage: $0 <LibreMiddleware source dir> <cache file>"
[ "$#" -eq 2 ] || { echo "$usage" >&2; exit 2; }
lm="$1"
out="$2"
[ -d "$lm" ] || { echo "select-openssl: not a directory: $lm" >&2; exit 2; }

fail() {
    # A GitHub annotation in a workflow, a plain line anywhere else.
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        echo "::error::select-openssl: $*"
    fi
    echo "select-openssl: $*" >&2
    exit 1
}

shopt -s nullglob
ossl=("$lm"/thirdparty/openssl-*/macosx)
[ "${#ossl[@]}" -eq 1 ] || fail "want one thirdparty/openssl-*/macosx in $lm, found ${#ossl[@]}"
root="${ossl[0]}"
[ -f "$root/lib/libcrypto.a" ] || fail "$root holds no lib/libcrypto.a"
if command -v lipo >/dev/null 2>&1; then
    lipo -info "$root/lib/libcrypto.a"
fi

cat > "$out" <<CMAKE
# Written by select-openssl.sh: LibreMiddleware's static OpenSSL.
set(OPENSSL_ROOT_DIR "$root" CACHE PATH "LibreMiddleware's static OpenSSL")
set(OPENSSL_USE_STATIC_LIBS TRUE CACHE BOOL "Link OpenSSL statically")
CMAKE
echo "select-openssl: $root"
