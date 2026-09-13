#!/usr/bin/env bash
# Selftest for check-pin-form.sh. Every case is a way the guard, or the gate
# that measures it, could be wrong rather than merely absent.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -uo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-pin-form.sh"
[ -f "$subject" ] || { echo "missing subject: $subject" >&2; exit 2; }
command -v cmake >/dev/null 2>&1 || { echo "no cmake on PATH -- cannot self-test" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/var/tmp}/check-pin-form-selftest.XXXXXX")
trap 'rm -rf "$work"' EXIT
fails=0
printf '%s\n' "ca4f355f893822f8b875fd81cbd04e8422b26b93" > "$work/pin"

run() {  # run <name> <expected-rc> <cmake-file> [pin-file]
    local name=$1 want=$2 f=$3 p=${4:-$work/pin}
    bash "$subject" "$f" "$p" > "$work/out" 2>&1
    local got=$?
    if [ "$got" -eq "$want" ]; then
        printf '  ok    %-56s rc=%s\n' "$name" "$got"
    else
        printf '  FAIL  %-56s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

# A guard fixture in the shape the real file carries: the length test, the
# character class, and the FATAL_ERROR the gate anchors its sanity check on.
fixture() {  # fixture <path> <condition>
    cat > "$1" <<CMAKE
    file(STRINGS "\${CMAKE_CURRENT_LIST_DIR}/libreagent.pin" LIBREAGENT_PIN LIMIT_COUNT 1)
    string(LENGTH "\${LIBREAGENT_PIN}" LIBREAGENT_PIN_LENGTH)
    if($2)
        message(FATAL_ERROR
            "cmake/libreagent.pin does not hold a 40-character commit hash: '\${LIBREAGENT_PIN}'.")
    endif()
    FetchContent_Declare(LibreAgent GIT_TAG \${LIBREAGENT_PIN})
CMAKE
}

# case_1 -- the correct spelling: length plus character class. Accepts the real
# pin, refuses every malformed one.
fixture "$work/good.cmake" 'NOT LIBREAGENT_PIN_LENGTH EQUAL 40 OR NOT LIBREAGENT_PIN MATCHES "^[0-9a-f]+$"'
run "case_1 length + character class is correct" 0 "$work/good.cmake"

# case_2 -- the 2026-09-04 defect, exactly: CMake has no {n} repetition, so
# this pattern matches the literal brace form and no hash. The guard then
# refuses EVERY pin. A gate that only tries malformed values reads this green.
fixture "$work/brace.cmake" 'NOT LIBREAGENT_PIN MATCHES "^[0-9a-f]{40}$"'
run "case_2 the brace form refuses even a correct pin" 1 "$work/brace.cmake"

# case_3 -- the opposite failure: a guard that accepts anything. Measuring only
# the accept direction reads this green too, which is why both are required.
fixture "$work/lax.cmake" 'FALSE'
run "case_3 a guard that accepts everything" 1 "$work/lax.cmake"

# case_4 -- length only. Accepts a 40-character string that is not hex, which
# FetchContent would then hand to git as a revision.
fixture "$work/len.cmake" 'NOT LIBREAGENT_PIN_LENGTH EQUAL 40'
run "case_4 length without a character class" 1 "$work/len.cmake"

# case_5 -- character class only. Accepts an abbreviated hash, and an
# abbreviated hash in a pin file is the moving target the pin exists to remove.
fixture "$work/cls.cmake" 'NOT LIBREAGENT_PIN MATCHES "^[0-9a-f]+$"'
run "case_5 character class without a length" 1 "$work/cls.cmake"

# case_6 -- no guard at all is "cannot measure", never a pass. A gate whose
# extraction comes back empty and reports success is the vacuous kind.
printf 'FetchContent_Declare(LibreAgent GIT_TAG ${LIBREAGENT_PIN})\n' > "$work/none.cmake"
run "case_6 no guard in the file is rc=2, not a pass" 2 "$work/none.cmake"

# case_7 -- a length test with no FATAL_ERROR under it does not refuse
# anything; the gate must say it cannot measure rather than cut a fragment
# whose accept branch is the only branch.
cat > "$work/nofatal.cmake" <<'CMAKE'
    string(LENGTH "${LIBREAGENT_PIN}" LIBREAGENT_PIN_LENGTH)
    if(NOT LIBREAGENT_PIN_LENGTH EQUAL 40)
        message(STATUS "odd pin")
    endif()
CMAKE
run "case_7 a guard that cannot fail is rc=2" 2 "$work/nofatal.cmake"

# case_8 -- a missing pin file is an error, not a pass.
run "case_8 missing pin file is rc=2" 2 "$work/good.cmake" "$work/no-such-pin"

# case_9 -- the file this repository actually ships must pass, judged against
# the pin it actually holds. This is the case that goes red if someone
# rewrites the guard back into a form that cannot match.
run "case_9 the shipped guard and the shipped pin" 0 \
    "$here/../../cmake/FindOrUseLibreAgent.cmake" "$here/../../cmake/libreagent.pin"

if [ "$fails" -eq 0 ]; then
    echo "check-pin-form selftest: all cases passed (9)"
    exit 0
fi
echo "check-pin-form selftest: $fails case(s) failed"
exit 1
