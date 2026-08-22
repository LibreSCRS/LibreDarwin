#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Proves the gate fails for the reason it exists. A gate that has never been
# seen to fail is not a gate -- it is a line in a workflow file.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="$here/check-experimental-library.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
check() { # name expected_rc actual_rc
    if [ "$2" = "$3" ]; then
        pass=$((pass + 1))
        printf '  ok    %s (rc=%s)\n' "$1" "$3"
    else
        fail=$((fail + 1))
        printf '  FAIL  %s (expected rc=%s, got %s)\n' "$1" "$2" "$3"
    fi
}

mkbuild() { # dir compiler_id compile_commands_json
    mkdir -p "$1"
    printf 'CMAKE_CXX_COMPILER_ID:STRING=%s\n' "$2" > "$1/CMakeCache.txt"
    printf '%s' "$3" > "$1/compile_commands.json"
}

WITH='-fexperimental-library'

# 1. Every C++ unit carries the flag -> pass.
mkbuild "$tmp/ok" AppleClang '[
 {"file":"/s/a.cpp","output":"x/CMakeFiles/Good.dir/a.cpp.o","command":"clang++ '"$WITH"' -c /s/a.cpp"},
 {"file":"/s/b.mm","output":"x/CMakeFiles/Good.dir/b.mm.o","command":"clang++ '"$WITH"' -c /s/b.mm"}]'
python3 "$checker" "$tmp/ok" >/dev/null 2>&1
check "all units carry the flag" 0 $?

# 2. One unit without it -> fail. This is the case that was live in the tree.
mkbuild "$tmp/bad" AppleClang '[
 {"file":"/s/a.cpp","output":"x/CMakeFiles/Good.dir/a.cpp.o","command":"clang++ '"$WITH"' -c /s/a.cpp"},
 {"file":"/s/parity.cpp","output":"x/CMakeFiles/ParityChecks.dir/parity.cpp.o","command":"clang++ -c /s/parity.cpp"}]'
python3 "$checker" "$tmp/bad" >/dev/null 2>&1
check "one unit missing the flag" 1 $?

# 3. The offending target is named in the report, so the message is actionable.
# Captured to a file first: under `pipefail` a pipeline reports the checker's
# own non-zero exit, not grep's verdict, so piping would test nothing.
python3 "$checker" "$tmp/bad" > "$tmp/bad.out" 2>&1
grep -q 'ParityChecks' "$tmp/bad.out"
check "report names the target" 0 $?

# 4. C sources are exempt -- the vendored CBOR codec is C and has no libc++.
mkbuild "$tmp/csrc" AppleClang '[
 {"file":"/s/qcbor.c","output":"x/CMakeFiles/qcbor.dir/qcbor.c.o","command":"clang -c /s/qcbor.c"}]'
python3 "$checker" "$tmp/csrc" >/dev/null 2>&1
check "C sources are exempt" 0 $?

# 5. Non-Apple compilers are not checked; the flag is Apple Clang only.
mkbuild "$tmp/gcc" GNU '[
 {"file":"/s/a.cpp","output":"x/CMakeFiles/Good.dir/a.cpp.o","command":"g++ -c /s/a.cpp"}]'
python3 "$checker" "$tmp/gcc" >/dev/null 2>&1
check "GCC build is skipped" 0 $?

# 6. The arguments[] form is understood as well as command.
mkbuild "$tmp/args" AppleClang '[
 {"file":"/s/a.cpp","output":"x/CMakeFiles/Good.dir/a.cpp.o","arguments":["clang++","'"$WITH"'","-c","/s/a.cpp"]}]'
python3 "$checker" "$tmp/args" >/dev/null 2>&1
check "arguments[] form is read" 0 $?

# 7. A missing compile_commands.json is a setup error, not a silent pass.
mkdir -p "$tmp/empty"
printf 'CMAKE_CXX_COMPILER_ID:STRING=AppleClang\n' > "$tmp/empty/CMakeCache.txt"
python3 "$checker" "$tmp/empty" >/dev/null 2>&1
check "missing compile_commands is an error" 2 $?

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
