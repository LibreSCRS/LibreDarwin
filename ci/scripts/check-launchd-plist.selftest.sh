#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-launchd-plist.selftest.sh -- prove the LaunchAgent plist check fails on
# the plist this repository actually shipped, and on each rule on its own.
#
# The restored defect is ci/fixtures/check-launchd-plist/agent-env-block-template.plist,
# the template as it stood before the environment block was dropped, byte for
# byte. It fails twice over: a `--` inside an XML comment that plutil accepts
# and a conforming parser does not, and -- once that is repaired and the file
# is configured the way configure_file() configured it -- an EnvironmentVariables
# block whose two values came out empty.
#
# Cases:
#   1  the tracked template                                   -> 0
#   2  the restored template, verbatim                        -> 1  (does not parse)
#   3  the restored template, comment repaired, configured    -> 1  (block + 2 empty values)
#   4  the tracked template, Label emptied                    -> 1
#   5  the tracked template, ProgramArguments[0] emptied      -> 1
#   6  the tracked template, a block with non-empty values    -> 1  (the block alone)
#   7  the tracked template, an empty key                     -> 1
#   8  a top-level array                                      -> 1
#   9  no such file                                           -> 2
#  10  no argument                                            -> 2
#  11  a good file and a missing one                          -> 2
#  12  a bad file and a missing one                           -> 1  (a finding is a verdict)
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
CHECK="$here/check-launchd-plist.py"
TEMPLATE="$repo/packaging/launchd/org.librescrs.agent.plist"
RESTORED="$repo/ci/fixtures/check-launchd-plist/agent-env-block-template.plist"
command -v python3 >/dev/null || { echo "FATAL: python3 not found -- cannot judge" >&2; exit 2; }
for f in "$CHECK" "$TEMPLATE" "$RESTORED"; do
    [ -f "$f" ] || { echo "FATAL: $f missing -- cannot judge" >&2; exit 2; }
done

WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/launchd-plist-selftest.XXXXXX")" \
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

says() {
    local label="$1" text="$2" out="$3"
    case "$out" in
        *"$text"*) ;;
        *) echo "  case $label: FAIL -- output does not say '$text'"; fail=$((fail + 1)) ;;
    esac
}

# A perturbation that changed nothing proves nothing: every derived file is
# compared against the file it came from before it is judged.
derive() {
    local label="$1" src="$2" dst="$3" program="$4"
    python3 -c "$program" "$src" "$dst" || { echo "FATAL: case $label: derive failed" >&2; exit 2; }
    if cmp -s "$src" "$dst"; then
        echo "FATAL: case $label: the perturbation changed nothing" >&2
        exit 2
    fi
}

run() { python3 "$CHECK" "$@" 2>&1; }

out="$(run "$TEMPLATE")"; rc=$?; check 1 0 $rc

out="$(run "$RESTORED")"; rc=$?; check 2 1 $rc
says 2 "does not parse" "$out"

derive 3 "$RESTORED" "$WORK/c3.plist" '
import re, sys
s = open(sys.argv[1]).read()
s = re.sub(r"<!--.*?-->", "", s, flags=re.S)  # the defect of case 2, repaired
s = s.replace("@LIBRESCRS_AGENT_PROGRAM@", "/usr/local/libexec/librescrs-agent")
s = re.sub(r"@[A-Z_]+@", "", s)                # what configure_file makes of an unset variable
open(sys.argv[2], "w").write(s)'
out="$(run "$WORK/c3.plist")"; rc=$?; check 3 1 $rc
says 3 "carries an EnvironmentVariables block" "$out"
says 3 "empty string at /EnvironmentVariables/LIBRESCRS_PLUGIN_DIR" "$out"
says 3 "empty string at /EnvironmentVariables/DYLD_LIBRARY_PATH" "$out"

derive 4 "$TEMPLATE" "$WORK/c4.plist" '
import sys
s = open(sys.argv[1]).read()
s = s.replace("<string>org.librescrs.agent</string>", "<string></string>", 1)
open(sys.argv[2], "w").write(s)'
out="$(run "$WORK/c4.plist")"; rc=$?; check 4 1 $rc
says 4 "empty string at /Label" "$out"

derive 5 "$TEMPLATE" "$WORK/c5.plist" '
import sys
s = open(sys.argv[1]).read()
s = s.replace("<string>@LIBRESCRS_AGENT_PROGRAM@</string>", "<string></string>", 1)
open(sys.argv[2], "w").write(s)'
out="$(run "$WORK/c5.plist")"; rc=$?; check 5 1 $rc
says 5 "empty string at /ProgramArguments[0]" "$out"

derive 6 "$TEMPLATE" "$WORK/c6.plist" '
import sys
s = open(sys.argv[1]).read()
block = "<key>EnvironmentVariables</key><dict><key>A</key><string>b</string></dict>\n</dict>\n</plist>"
s = s.replace("</dict>\n</plist>", block, 1)
open(sys.argv[2], "w").write(s)'
out="$(run "$WORK/c6.plist")"; rc=$?; check 6 1 $rc
says 6 "carries an EnvironmentVariables block" "$out"
case "$out" in *"empty string"*) echo "  case 6: FAIL -- reported an empty string that is not there"; fail=$((fail + 1)) ;; esac

derive 7 "$TEMPLATE" "$WORK/c7.plist" '
import sys
s = open(sys.argv[1]).read()
s = s.replace("<key>ProcessType</key>", "<key></key>", 1)
open(sys.argv[2], "w").write(s)'
out="$(run "$WORK/c7.plist")"; rc=$?; check 7 1 $rc
says 7 "<empty key>" "$out"

cat > "$WORK/c8.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><array><string>x</string></array></plist>
EOF
out="$(run "$WORK/c8.plist")"; rc=$?; check 8 1 $rc
says 8 "wants a dictionary" "$out"

out="$(run "$WORK/does-not-exist.plist")"; rc=$?; check 9 2 $rc

out="$(run)"; rc=$?; check 10 2 $rc

out="$(run "$TEMPLATE" "$WORK/does-not-exist.plist")"; rc=$?; check 11 2 $rc

out="$(run "$WORK/c4.plist" "$WORK/does-not-exist.plist")"; rc=$?; check 12 1 $rc

echo "selftest: $pass passed, $fail failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
