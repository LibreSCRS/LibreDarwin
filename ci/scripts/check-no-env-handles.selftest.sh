#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-no-env-handles.selftest.sh — prove the environment-handle check can
# fail, that it reads the name rather than one spelling of the call, and that
# it does not read an empty scan as a clean repository.
#
# Cases:
#   1  getenv("LIBRESCRS_…") in agent/src                    -> 1 (names file:line)
#   2  envOr("LIBRESCRS_…", …) in prompter/*.mm              -> 1
#   3  the name in a constant, getenv(kName) at the call     -> 1
#   4  an Objective-C @"LIBRESCRS_…" literal                 -> 1
#   5  a public header under agent/include                   -> 1
#   6  only getenv("HOME") / getenv("TMPDIR")                -> 0
#   7  the same read under agent/tests/                      -> 0 (tests may)
#   8  an untracked source with a handle                     -> 0 (only git ls-files counts)
#   9  a comment naming the variable, no string literal      -> 0
#  10  no production source under the scanned paths          -> 2
#  11  not a git work tree                                   -> 2
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-no-env-handles.sh"
[ -f "$CHECK" ] || { echo "missing subject: $CHECK" >&2; exit 2; }
WORK="$(mktemp -d /var/tmp/noenvhandles-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
cases=0
red=0

# make_repo <name> <relative path> <body>: a tracked tree with one source file.
make_repo() {
    local name="$1" rel="$2" body="$3"
    local root="$WORK/$name"
    mkdir -p "$root/ci/scripts" "$root/$(dirname "$rel")"
    cp "$CHECK" "$root/ci/scripts/check-no-env-handles.sh"
    printf '%s\n' "$body" > "$root/$rel"
    git -C "$root" init -q
    git -C "$root" config user.email t@t
    git -C "$root" config user.name t
    git -C "$root" add -A
    git -C "$root" -c commit.gpgsign=false commit -qm x
    echo "$root"
}

check() {
    local label="$1" expected="$2" actual="$3"
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [ "$expected" != 0 ]; then red=$((red + 1)); fi
    if [ "$expected" = "$actual" ]; then
        echo "case $label: OK   — exit $actual"; pass=$((pass + 1))
    else
        echo "case $label: FAIL — expected exit $expected, got $actual"; fail=$((fail + 1))
    fi
}

run() { bash "$1/ci/scripts/check-no-env-handles.sh" 2>&1; }

r="$(make_repo c1 agent/src/backend/Paths.cpp \
    'const char* over = std::getenv("LIBRESCRS_AGENT_CONTAINER");')"
out="$(run "$r")"; rc=$?; check 1 1 $rc
case "$out" in
*"agent/src/backend/Paths.cpp:1"*) ;;
*) echo "  case 1: FAIL — did not name file:line"; fail=$((fail + 1)) ;;
esac

r="$(make_repo c2 prompter/Main.mm \
    'const std::string sock = envOr("LIBRESCRS_PROMPTER_SOCK", fallback);')"
out="$(run "$r")"; rc=$?; check 2 1 $rc

r="$(make_repo c3 agent/src/main.cpp \
    "$(printf 'constexpr const char* kSock = "LIBRESCRS_AGENT_SOCK";\nconst char* v = std::getenv(kSock);\n')")"
out="$(run "$r")"; rc=$?; check 3 1 $rc

r="$(make_repo c4 prompter/Window.mm \
    'NSString* v = NSProcessInfo.processInfo.environment[@"LIBRESCRS_AGENT_SIGNING_ID"];')"
out="$(run "$r")"; rc=$?; check 4 1 $rc

r="$(make_repo c5 agent/include/LibreSCRS/Darwin/backend/Policy.h \
    'inline const char* allowUnverified() { return std::getenv("LIBRESCRS_AGENT_ALLOW_UNVERIFIED_PROMPTER"); }')"
out="$(run "$r")"; rc=$?; check 5 1 $rc

r="$(make_repo c6 agent/src/backend/Home.cpp \
    "$(printf 'const char* home = std::getenv("HOME");\nconst char* tmp = std::getenv("TMPDIR");\n')")"
out="$(run "$r")"; rc=$?; check 6 0 $rc

r="$(make_repo c7 agent/src/backend/Home.cpp 'const char* home = std::getenv("HOME");')"
mkdir -p "$r/agent/tests"
printf 'const char* pin = std::getenv("LIBRESCRS_TEST_PIN");\n' > "$r/agent/tests/HwTest.cpp"
git -C "$r" add -A; git -C "$r" -c commit.gpgsign=false commit -qm tests
out="$(run "$r")"; rc=$?; check 7 0 $rc

r="$(make_repo c8 agent/src/backend/Home.cpp 'const char* home = std::getenv("HOME");')"
printf 'const char* s = std::getenv("LIBRESCRS_AGENT_SOCK");\n' > "$r/agent/src/Untracked.cpp"
out="$(run "$r")"; rc=$?; check 8 0 $rc

r="$(make_repo c9 agent/src/main.cpp \
    "$(printf '// LIBRESCRS_AGENT_SOCK used to move the socket; it is gone.\nint main() { return 0; }\n')")"
out="$(run "$r")"; rc=$?; check 9 0 $rc

# case 10: a tree with nothing under the scanned paths. A pathspec that matches
# nothing must read as "cannot judge", not as "clean".
r="$(make_repo c10 docs/README.md 'getenv("LIBRESCRS_AGENT_SOCK") is gone')"
out="$(run "$r")"; rc=$?; check 10 2 $rc

# case 11: not a git work tree at all.
r="$WORK/c11"; mkdir -p "$r/ci/scripts" "$r/agent/src"
cp "$CHECK" "$r/ci/scripts/check-no-env-handles.sh"
printf 'const char* s = std::getenv("LIBRESCRS_AGENT_SOCK");\n' > "$r/agent/src/main.cpp"
out="$(GIT_CEILING_DIRECTORIES="$WORK" run "$r")"; rc=$?; check 11 2 $rc

echo "selftest: $pass passed, $fail failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
