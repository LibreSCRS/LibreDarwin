#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-no-env-handles.selftest.sh — prove the environment-handle check can
# fail, that a renamed variable does not get past it, and that it does not read
# an empty scan, a missing reader list or an unreadable file as a clean
# repository.
#
# Every fixture carries ci/env-readers.txt; unless a case says otherwise it
# records one reader, std::getenv("HOME") in agent/src/backend/Home.cpp, and
# that file exists.
#
# Cases:
#   1  getenv("LIBRESCRS_…") in agent/src                    -> 1 (names file:line)
#   2  envOr("LIBRESCRS_…", …) in prompter/*.mm              -> 1
#   3  the name in a constant, getenv(kName) at the call     -> 1
#   4  an Objective-C @"LIBRESCRS_…" literal                 -> 1
#   5  a public header under agent/include                   -> 1
#   6  only the recorded getenv("HOME")                      -> 0
#   7  a handle under prompter/tests/                        -> 0 (tests may)
#   8  the same handle in prompter/testsX.mm                 -> 1 (only a tests/ DIRECTORY is exempt)
#   9  an untracked source with a handle                     -> 0 (only git ls-files counts)
#  10  a comment naming the variable, no string literal      -> 0
#  11  "LIBRESCRS" "_AGENT_CONTAINER" (split literal)        -> 1 (rename)
#  12  getenv("LIBREDARWIN_AGENT_CONTAINER")                 -> 1 (rename)
#  13  secure_getenv("AGENT_SOCK")                           -> 1 (rename)
#  14  NSProcessInfo.processInfo.environment[@"X"]           -> 1
#  15  extern char** environ read                            -> 1
#  16  a recorded reader that no longer exists               -> 1 (stale row)
#  17  a recorded row with no reason                         -> 1
#  18  the recorded call spelled in another file             -> 1 (rows are per file)
#  19  a full-line comment naming getenv                     -> 0
#  20  no production source under the scanned paths          -> 2
#  21  not a git work tree                                   -> 2
#  22  no ci/env-readers.txt                                 -> 2
#  23  a tracked source missing from the work tree           -> 2 (grep cannot read it)
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-no-env-handles.sh"
[ -f "$CHECK" ] || { echo "missing subject: $CHECK" >&2; exit 2; }
WORK="$(mktemp -d /var/tmp/noenvhandles-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
cases=0
red=0

HOME_ROW='agent/src/backend/Home.cpp  std::getenv("HOME")  the real home when the passwd lookup fails'
HOME_SRC='const char* home = std::getenv("HOME");'

# make_repo <name> <relative path> <body> [<readers-file body>]: a tracked tree
# with Home.cpp (the one recorded reader), one more source file and the list.
make_repo() {
    local name="$1" rel="$2" body="$3" rows="${4-$HOME_ROW}"
    local root="$WORK/$name"
    mkdir -p "$root/ci/scripts" "$root/agent/src/backend" "$root/$(dirname "$rel")"
    cp "$CHECK" "$root/ci/scripts/check-no-env-handles.sh"
    printf '%s\n' "$HOME_SRC" > "$root/agent/src/backend/Home.cpp"
    printf '%s\n' "$body" > "$root/$rel"
    printf '# readers\n%s\n' "$rows" > "$root/ci/env-readers.txt"
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
    'NSString* v = @"LIBRESCRS_AGENT_SIGNING_ID";')"
out="$(run "$r")"; rc=$?; check 4 1 $rc

r="$(make_repo c5 agent/include/LibreSCRS/Darwin/backend/Policy.h \
    'inline const char* allowUnverified() { return "LIBRESCRS_AGENT_ALLOW_UNVERIFIED_PROMPTER"; }')"
out="$(run "$r")"; rc=$?; check 5 1 $rc

r="$(make_repo c6 agent/src/backend/Other.cpp 'int x = 0;')"
out="$(run "$r")"; rc=$?; check 6 0 $rc

# case 7/8: the tests/ exemption is a DIRECTORY rule. prompter/tests/ is the
# one tests/ directory the pathspec reaches (agent/tests/ is outside it), so
# that is where the exempt file has to be for the filter to be what decides.
r="$(make_repo c7 prompter/tests/HwTest.cpp 'const char* s = std::getenv("LIBRESCRS_AGENT_SOCK");')"
out="$(run "$r")"; rc=$?; check 7 0 $rc

r="$(make_repo c8 prompter/testsX.mm 'const char* s = std::getenv("LIBRESCRS_AGENT_SOCK");')"
out="$(run "$r")"; rc=$?; check 8 1 $rc

r="$(make_repo c9 agent/src/backend/Other.cpp 'int x = 0;')"
printf 'const char* s = std::getenv("LIBRESCRS_AGENT_SOCK");\n' > "$r/agent/src/Untracked.cpp"
out="$(run "$r")"; rc=$?; check 9 0 $rc

r="$(make_repo c10 agent/src/main.cpp \
    "$(printf '// LIBRESCRS_AGENT_SOCK used to move the socket; it is gone.\nint main() { return 0; }\n')")"
out="$(run "$r")"; rc=$?; check 10 0 $rc

# 11-13: the three renames that pass a rule keyed on the name.
r="$(make_repo c11 agent/src/backend/Paths.cpp 'const char* v = std::getenv("LIBRESCRS" "_AGENT_CONTAINER");')"
out="$(run "$r")"; rc=$?; check 11 1 $rc

r="$(make_repo c12 agent/src/backend/Paths.cpp 'const char* v = std::getenv("LIBREDARWIN_AGENT_CONTAINER");')"
out="$(run "$r")"; rc=$?; check 12 1 $rc

r="$(make_repo c13 agent/src/backend/Paths.cpp 'const char* v = ::secure_getenv("AGENT_SOCK");')"
out="$(run "$r")"; rc=$?; check 13 1 $rc

r="$(make_repo c14 prompter/Window.mm 'NSString* v = NSProcessInfo.processInfo.environment[@"PEER"];')"
out="$(run "$r")"; rc=$?; check 14 1 $rc

r="$(make_repo c15 agent/src/backend/Env.cpp "$(printf 'extern char** environ;\nconst char* first = environ[0];\n')")"
out="$(run "$r")"; rc=$?; check 15 1 $rc

r="$(make_repo c16 agent/src/backend/Other.cpp 'int x = 0;' \
    "$(printf '%s\n%s\n' "$HOME_ROW" 'agent/src/backend/Gone.cpp  std::getenv("TMPDIR")  a reader that was deleted')")"
out="$(run "$r")"; rc=$?; check 16 1 $rc

r="$(make_repo c17 agent/src/backend/Other.cpp 'int x = 0;' 'agent/src/backend/Home.cpp  std::getenv("HOME")')"
out="$(run "$r")"; rc=$?; check 17 1 $rc

r="$(make_repo c18 agent/src/backend/Other.cpp 'const char* h = std::getenv("HOME");')"
out="$(run "$r")"; rc=$?; check 18 1 $rc

r="$(make_repo c19 agent/src/backend/Other.cpp \
    "$(printf '// getenv() is not called here: the path is compiled in.\n * and environ is not read either\nint x = 0;\n')")"
out="$(run "$r")"; rc=$?; check 19 0 $rc

# case 20: a tree with nothing under the scanned paths. A pathspec that matches
# nothing must read as "cannot judge", not as "clean".
r="$WORK/c20"; mkdir -p "$r/ci/scripts" "$r/docs"
cp "$CHECK" "$r/ci/scripts/check-no-env-handles.sh"
printf '# readers\n' > "$r/ci/env-readers.txt"
printf 'getenv("LIBRESCRS_AGENT_SOCK") is gone\n' > "$r/docs/README.md"
git -C "$r" init -q; git -C "$r" config user.email t@t; git -C "$r" config user.name t
git -C "$r" add -A; git -C "$r" -c commit.gpgsign=false commit -qm x
out="$(run "$r")"; rc=$?; check 20 2 $rc

# case 21: not a git work tree at all.
r="$WORK/c21"; mkdir -p "$r/ci/scripts" "$r/agent/src"
cp "$CHECK" "$r/ci/scripts/check-no-env-handles.sh"
printf '# readers\n' > "$r/ci/env-readers.txt"
printf 'const char* s = std::getenv("LIBRESCRS_AGENT_SOCK");\n' > "$r/agent/src/main.cpp"
out="$(GIT_CEILING_DIRECTORIES="$WORK" run "$r")"; rc=$?; check 21 2 $rc

# case 22: the reader list is missing -- every reader is then unjudgeable.
r="$(make_repo c22 agent/src/backend/Other.cpp 'int x = 0;')"
git -C "$r" rm -q ci/env-readers.txt; git -C "$r" -c commit.gpgsign=false commit -qm rm
out="$(run "$r")"; rc=$?; check 22 2 $rc

# case 23: a tracked source deleted from the work tree. grep cannot read it and
# exits 2; that is "could not look", never "looked and found nothing".
r="$(make_repo c23 agent/src/backend/Paths.cpp 'const char* v = std::getenv("LIBRESCRS_AGENT_SOCK");')"
rm "$r/agent/src/backend/Paths.cpp"
out="$(run "$r")"; rc=$?; check 23 2 $rc

echo "selftest: $pass passed, $fail failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
