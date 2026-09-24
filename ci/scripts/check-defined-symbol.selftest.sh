#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-defined-symbol.selftest.sh -- prove the defined-symbol check fails when
# the routine is missing, when only a longer name contains it, and when the
# binary merely refers to it; and that it cannot be talked into a pass by a
# file nm cannot read.
#
# It builds its own inputs with the host C++ compiler, so it judges the same
# way on the Linux format job and on a Mac.
#
# Cases:
#   1  an executable that defines the routine                -> 0
#   2  an executable without it                              -> 1
#   3  an executable defining only a longer name holding it  -> 1  (whole-name match)
#   4  an object that calls it but does not define it        -> 1  (undefined is not defined)
#   5  a file that is not an object                          -> 2
#   6  no such file                                          -> 2
#   7  one argument                                          -> 2
#   8  an empty name                                         -> 2
#   9  case 1 with a listing longer than a pipe buffer       -> 0  (no SIGPIPE false red)
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-defined-symbol.sh"
CXX="${CXX:-c++}"
SYM='LibreSCRS::Darwin::hardenSecretProcess()'
command -v "$CXX" >/dev/null || { echo "FATAL: no C++ compiler ($CXX) -- cannot judge" >&2; exit 2; }
command -v nm >/dev/null || { echo "FATAL: nm not found -- cannot judge" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/defined-symbol-selftest.XXXXXX")" \
    || { echo "FATAL: cannot create a scratch directory" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
cases=0
red=0

check() {
    local label="$1" expected="$2" actual="$3"
    cases=$((cases + 1))
    if [ "$expected" = "$actual" ]; then
        echo "case $label: OK   -- exit $actual"
        pass=$((pass + 1))
        [ "$expected" != 0 ] && red=$((red + 1))
    else
        echo "case $label: FAIL -- expected exit $expected, got $actual"
        fail=$((fail + 1))
    fi
}

build() {
    local out="$1" src="$2"
    shift 2
    printf '%s\n' "$src" > "$out.cpp"
    "$CXX" "$@" -o "$out" "$out.cpp" || { echo "FATAL: cannot compile $out.cpp -- cannot judge" >&2; exit 2; }
}

run() { bash "$CHECK" "$@" 2>&1; }

build "$WORK/defines" '
namespace LibreSCRS::Darwin { bool hardenSecretProcess() noexcept { return true; } }
int main() { return LibreSCRS::Darwin::hardenSecretProcess() ? 0 : 1; }' -std=c++17
build "$WORK/lacks" '
int main() { return 0; }' -std=c++17
build "$WORK/longer" '
namespace LibreSCRS::Darwin { bool hardenSecretProcessStub() noexcept { return true; } }
int main() { return LibreSCRS::Darwin::hardenSecretProcessStub() ? 0 : 1; }' -std=c++17
build "$WORK/refers.o" '
namespace LibreSCRS::Darwin { bool hardenSecretProcess() noexcept; }
int main() { return LibreSCRS::Darwin::hardenSecretProcess() ? 0 : 1; }' -std=c++17 -c
# The object really does refer to it: otherwise case 4 would pass for the
# reason case 2 does, and prove nothing about undefined symbols.
nm -C "$WORK/refers.o" | grep -F -- "$SYM" >/dev/null \
    || { echo "FATAL: the referring object does not name $SYM -- cannot judge" >&2; exit 2; }

out="$(run "$WORK/defines" "$SYM")"; rc=$?; check 1 0 $rc
out="$(run "$WORK/lacks" "$SYM")"; rc=$?; check 2 1 $rc
out="$(run "$WORK/longer" "$SYM")"; rc=$?; check 3 1 $rc
out="$(run "$WORK/refers.o" "$SYM")"; rc=$?; check 4 1 $rc
echo 'not an object' > "$WORK/text"
out="$(run "$WORK/text" "$SYM")"; rc=$?; check 5 2 $rc
out="$(run "$WORK/does-not-exist" "$SYM")"; rc=$?; check 6 2 $rc
out="$(run "$WORK/defines")"; rc=$?; check 7 2 $rc
out="$(run "$WORK/defines" '')"; rc=$?; check 8 2 $rc

# Enough further symbols that the listing outgrows a pipe buffer, so a search
# that stops reading at the first match leaves the writers to die of SIGPIPE.
# They sort AFTER the routine whichever name nm sorts by -- mangled, the length
# prefix 40 against 19; demangled, `z` against `h` -- so the match comes early
# and most of the listing is still unwritten when it does.
fill="$(i=0; while [ $i -lt 3000 ]; do printf 'int zz_fill_symbol_long_enough_to_sort_%05d() { return %d; }\n' $i $i; i=$((i + 1)); done)"
build "$WORK/big" "
namespace LibreSCRS::Darwin { bool hardenSecretProcess() noexcept { return true; }
$fill
}
int main() { return LibreSCRS::Darwin::hardenSecretProcess() ? 0 : 1; }" -std=c++17
[ "$(nm -C --defined-only "$WORK/big" | wc -c)" -gt 131072 ] \
    || { echo "FATAL: the large listing is not larger than a pipe buffer -- cannot judge" >&2; exit 2; }
out="$(run "$WORK/big" "$SYM")"; rc=$?; check 9 0 $rc

echo "selftest: $pass passed, $fail failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
