#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-agent-interface-probe.selftest.sh -- prove R6 of check-agent-interface.sh,
# the compile of ci/interface-probe.cpp, over copies of the REAL headers.
#
# R6 exists because R1 compiles one Darwin implementation and the agent
# interface has four. Its own proof cannot be synthetic: what it has to show is
# that the real SocketTransport.h, SocketOperationChannel.h, MacPrompterClient.h
# and SecCodeAuthorizer.h stop compiling when the real agent base moves under
# them. So the cases below copy this repository's agent/include and the agent
# headers it is handed, move ONE thing in the copy, and run the gate over it:
#
#   D1  CONTROL: nothing moved                          -> R6 ok, rc=0
#   D2  ProbeFailsWhenABaseSignatureMoves:
#       authorize(std::string_view, const CallerToken&) becomes authorize(int)
#                                                       -> rc=1, and the compiler
#                                                          diagnostic under R6
#                                                          stands in
#                                                          SecCodeAuthorizer.h and
#                                                          names authorize
#   D3-D6  a pure virtual ADDED to each of the four bases -> rc=1, and the
#                                                          static_assert for THAT
#                                                          class fired: an added
#                                                          virtual leaves every
#                                                          header well formed, and
#                                                          only is_abstract sees it
#   D7  the D2 verdict applied to D3's output           -> rejected: rc=1 and an
#                                                          R6 failure that does not
#                                                          name the moved method
#                                                          is not D2's proof. A D2
#                                                          that checked the exit
#                                                          code alone would accept it.
#
# The real SocketTransport.h includes <dispatch/dispatch.h>, which only the Apple
# SDK provides, so D1-D7 are judged only where that header exists. The cases
# that follow run everywhere:
#
#   N1  a tree carrying SocketTransport.h that has lost ci/interface-probe.cpp
#                                                       -> rc=2, naming it
#   N2  a compiler that cannot reach <dispatch/dispatch.h>
#                                                       -> rc=2, "cannot judge:
#                                                          <dispatch/dispatch.h>
#                                                          unavailable"
#   W1  every row of ci/selftest-platform-exceptions.txt names a job, on that
#       platform's runner, with a step that runs the self-test  -> 0
#   W2  the same workflow with that step removed        -> 1
#   W3  the same workflow with the job moved to ubuntu  -> 1
#   W4  the same step marked continue-on-error          -> 1
#   W5  a row naming a self-test that is not tracked    -> 1
#
# On a host without the Apple SDK -- the ubuntu job that runs every self-test --
# D1-D7 are NOT JUDGED, and that is said, not skipped: the host must be the
# other platform (a Mac without the header is exit 2), this self-test must carry
# a row in ci/selftest-platform-exceptions.txt, and W1 must have just proved
# that the job the row names runs it on macOS. The trailer then counts what ran
# here and nothing else. Removing the macOS step turns W1 red on every host.
#
# Usage:
#   check-agent-interface-probe.selftest.sh [<LibreAgent include dir>]
# The agent headers default to $LIBREAGENT_INCLUDE, then ../LibreAgent/include;
# LibreMiddleware's headers come in as the gate takes them, through
# LIBRESCRS_EXTRA_INCLUDE or a sibling ../LibreMiddleware checkout.
#
# Exit: 0 every case that could run here passed - 1 one failed - 2 cannot judge.
#
# Runs under the bash macOS ships (3.2): no mapfile, no associative arrays.
set -uo pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
GATE="$HERE/check-agent-interface.sh"
SELF="ci/scripts/check-agent-interface-probe.selftest.sh"
ROWS="ci/selftest-platform-exceptions.txt"
PROBE="ci/interface-probe.cpp"
LA_REAL="${1:-${LIBREAGENT_INCLUDE:-$REPO/../LibreAgent/include}}"
BASE_CXX="${CXX:-c++}"

[ -f "$GATE" ] || { echo "FATAL: no gate at $GATE" >&2; exit 2; }
command -v "$BASE_CXX" >/dev/null 2>&1 || { echo "FATAL: no C++ compiler ($BASE_CXX) -- cannot judge" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 is not on PATH -- the wiring cases cannot be judged" >&2; exit 2; }
python3 -c 'import yaml' 2>/dev/null \
    || { echo "FATAL: PyYAML is not importable -- the wiring cases read the workflow as data and cannot judge without it" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/check-agent-interface-probe-selftest.XXXXXX")" \
    || { echo "FATAL: cannot create a temporary directory" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0; cases=0; red=0; unjudged=""

ok()  { echo "  ok    $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $1"; [ -f "${2:-}" ] && sed 's/^/        /' "$2"; fail=$((fail + 1)); }

run_gate() {  # run_gate <root> <la-include> <out> [CXX] -> the gate's exit code
    if [ -n "${4:-}" ]; then
        REPO_ROOT="$1" CXX="$4" bash "$GATE" "$2" > "$3" 2>&1
    else
        REPO_ROOT="$1" bash "$GATE" "$2" > "$3" 2>&1
    fi
}

# ------------------------------------------------------------------ wiring
# Read as data: the job, its runner, its condition and the step's own condition,
# never a grep over the workflow text -- a name in a comment or in a job that
# never runs on push would satisfy a grep.
cat > "$WORK/wired.py" <<'PY'
import re
import subprocess
import sys

import yaml

rows_path, repo, wfdir = sys.argv[1:4]
RUNNER_PREFIX = {"Darwin": "macos-"}
ALWAYS = ("always()", "success()", "true", "!cancelled()")


def runs(cond):
    return cond is None or str(cond).strip() in ALWAYS


problems = []
rows = 0
try:
    lines = open(rows_path, encoding="utf-8").read().splitlines()
except OSError as err:
    print(f"FATAL: {rows_path}: {err}")
    sys.exit(2)
for n, raw in enumerate(lines, 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split(None, 3)
    if len(parts) < 4 or not parts[3].strip():
        problems.append(f"{rows_path}:{n}: want '<self-test>  <platform>  <workflow>:<job>  <reason>', "
                        "and a row without a reason is not an exemption")
        continue
    rows += 1
    path, plat, where, _reason = parts
    if subprocess.run(["git", "-C", repo, "ls-files", "--error-unmatch", "--", path],
                      capture_output=True).returncode != 0:
        problems.append(f"{rows_path}:{n}: {path} is not a tracked file (stale row)")
        continue
    if "selftest-platform-exceptions.txt" not in open(f"{repo}/{path}", encoding="utf-8").read():
        problems.append(f"{rows_path}:{n}: {path} never reads this file, so the row excuses nothing")
    if plat not in RUNNER_PREFIX:
        problems.append(f"{rows_path}:{n}: '{plat}' is not a platform this check knows a runner for")
        continue
    wf, _, job = where.partition(":")
    try:
        doc = yaml.safe_load(open(f"{wfdir}/{wf}", encoding="utf-8"))
    except (OSError, yaml.YAMLError) as err:
        print(f"FATAL: cannot read {wfdir}/{wf}: {err}")
        sys.exit(2)
    j = ((doc or {}).get("jobs") or {}).get(job)
    if not isinstance(j, dict):
        problems.append(f"{rows_path}:{n}: {wf} has no job '{job}'")
        continue
    runs_on = j.get("runs-on")
    if not (isinstance(runs_on, str) and runs_on.startswith(RUNNER_PREFIX[plat])):
        problems.append(f"{wf}:{job} runs on {runs_on!r}, not on a {plat} runner")
    if not runs(j.get("if")) or j.get("continue-on-error"):
        problems.append(f"{wf}:{job} is conditional or may fail without failing the run")
    pat = re.compile(r"(^|[\s/\"'])" + re.escape(path) + r"($|[\s\"';|&])")
    hits = 0
    for step in j.get("steps") or []:
        body = step.get("run") if isinstance(step, dict) else None
        if not isinstance(body, str):
            continue
        if not any(pat.search(l) for l in body.splitlines() if not l.lstrip().startswith("#")):
            continue
        if not runs(step.get("if")) or step.get("continue-on-error"):
            problems.append(f"{wf}:{job}: the step running {path} is conditional or may fail without failing the job")
            continue
        hits += 1
    if hits == 0:
        problems.append(f"{wf}:{job} has no step that runs {path}; the cases this row stands down on "
                        "other hosts are then judged nowhere")
if rows == 0:
    print(f"FATAL: {rows_path} has no rows -- nothing to judge")
    sys.exit(2)
for p in problems:
    print(f"FAIL: {p}")
sys.exit(1 if problems else 0)
PY

wired() {  # wired <rows> <workflow dir> <out> -> 0 wired, 1 not, 2 cannot judge
    python3 "$WORK/wired.py" "$1" "$REPO" "$2" > "$3" 2>&1
}
wcase() {  # wcase <label> <want> <rows> <workflow dir>
    local rc
    cases=$((cases + 1))
    [ "$2" != 0 ] && red=$((red + 1))
    wired "$3" "$4" "$WORK/w.out"; rc=$?
    if [ "$rc" = "$2" ]; then ok "$1 (rc=$rc)"; else bad "$1: want rc=$2, got rc=$rc" "$WORK/w.out"; fi
}
# A perturbed copy of the workflow. The edit has to have changed something, or
# a red here would be a red over the untouched file.
perturb() {  # perturb <mode> <out dir>
    mkdir -p "$2"
    python3 - "$REPO/.github/workflows/ci.yml" "$2/ci.yml" "$SELF" "$1" <<'PY'
import sys
import yaml
src, dst, path, mode = sys.argv[1:5]
doc = yaml.safe_load(open(src, encoding="utf-8"))
job = doc["jobs"]["agent-interface"]
steps = job.get("steps") or []
mine = [s for s in steps if path in str(s.get("run", ""))]
if not mine:
    print(f"perturb: no step runs {path} -- nothing to perturb")
    sys.exit(3)
if mode == "drop-step":
    job["steps"] = [s for s in steps if s not in mine]
elif mode == "ubuntu":
    job["runs-on"] = "ubuntu-latest"
elif mode == "continue-on-error":
    for s in mine:
        s["continue-on-error"] = True
yaml.safe_dump(doc, open(dst, "w", encoding="utf-8"), sort_keys=False)
PY
}

echo "wiring (every host):"
wcase "W1 every exemption row is backed by a step on that platform's runner" 0 "$REPO/$ROWS" "$REPO/.github/workflows"
for m in drop-step ubuntu continue-on-error; do
    if perturb "$m" "$WORK/wf-$m" > "$WORK/p.out" 2>&1; then
        case "$m" in
            drop-step) l="W2 the step that runs the self-test removed" ;;
            ubuntu)    l="W3 the job moved to an ubuntu runner" ;;
            *)         l="W4 the step marked continue-on-error" ;;
        esac
        wcase "$l" 1 "$REPO/$ROWS" "$WORK/wf-$m"
    else
        cases=$((cases + 1)); bad "perturbation '$m' changed nothing" "$WORK/p.out"
    fi
done
sed "s|^$SELF |ci/scripts/no-such.selftest.sh |" "$REPO/$ROWS" > "$WORK/rows-stale"
if cmp -s "$REPO/$ROWS" "$WORK/rows-stale"; then
    cases=$((cases + 1)); bad "W5 perturbation: $ROWS carries no row for $SELF to rename"
else
    wcase "W5 a row naming a self-test that is not tracked" 1 "$WORK/rows-stale" "$REPO/.github/workflows"
fi

# ------------------------------------------------------------------ N1, N2
# A synthetic pair the gate passes on, so these two exits are R6's and nobody
# else's. <bsm/libbsm.h> is supplied by the gate's own stand-in off Darwin.
mksynthetic() {  # mksynthetic <root>
    mkdir -p "$1/la/LibreSCRS/Agent/backend" "$1/tree/agent/include/LibreSCRS/Darwin/backend"
    cat > "$1/la/LibreSCRS/Agent/backend/Authorizer.h" <<'EOF'
#pragma once
#include <string_view>
namespace LibreSCRS::Agent {
struct CallerToken { int id; };
enum class AuthorizationOutcome { Granted, Denied, Undecided };
class Authorizer {
public:
    virtual ~Authorizer() = default;
    virtual AuthorizationOutcome authorize(std::string_view, const CallerToken&) = 0;
};
}
EOF
    cat > "$1/tree/agent/include/LibreSCRS/Darwin/backend/SecCodeAuthorizer.h" <<'EOF'
#pragma once
#include <bsm/libbsm.h>
#include <LibreSCRS/Agent/backend/Authorizer.h>
namespace LibreSCRS::Darwin {
class SecCodeAuthorizer final : public Agent::Authorizer {
public:
    Agent::AuthorizationOutcome authorize(std::string_view, const Agent::CallerToken&) override;
    audit_token_t tok{};
};
}
EOF
}

echo "R6 refusals (every host):"
mksynthetic "$WORK/n1"
: > "$WORK/n1/tree/agent/include/LibreSCRS/Darwin/backend/SocketTransport.h"
cases=$((cases + 1)); red=$((red + 1))
run_gate "$WORK/n1/tree" "$WORK/n1/la" "$WORK/n1.out"; rc=$?
if [ "$rc" = 2 ] && grep -q "$PROBE is named by this gate but is not in the tree" "$WORK/n1.out"; then
    ok "N1 a tree with SocketTransport.h and no $PROBE refuses to judge, naming it (rc=$rc)"
else
    bad "N1 a tree with SocketTransport.h and no $PROBE: want rc=2 naming it, got rc=$rc" "$WORK/n1.out"
fi

# A compiler whose Apple SDK is taken away for the gate's dispatch probe only:
# the real compiler then reports the header missing in its own words. Off Darwin
# the header is missing anyway, and this case measures the same exit.
mksynthetic "$WORK/n2"
mkdir -p "$WORK/n2/tree/ci"
cp "$REPO/$PROBE" "$WORK/n2/tree/ci/" 2>/dev/null || true
{ echo '#!/usr/bin/env bash'
  echo 'for a in "$@"; do'
  echo "    case \"\$a\" in *dispatchprobe.cpp) exec \"$BASE_CXX\" -isysroot /var/empty \"\$@\" ;; esac"
  echo 'done'
  echo "exec \"$BASE_CXX\" \"\$@\""
} > "$WORK/cxx-without-dispatch"
chmod +x "$WORK/cxx-without-dispatch"
cases=$((cases + 1)); red=$((red + 1))
run_gate "$WORK/n2/tree" "$WORK/n2/la" "$WORK/n2.out" "$WORK/cxx-without-dispatch"; rc=$?
if [ "$rc" = 2 ] && grep -q "R6 cannot judge: <dispatch/dispatch.h> unavailable" "$WORK/n2.out"; then
    ok "N2 no <dispatch/dispatch.h>: R6 cannot judge (rc=$rc)"
else
    bad "N2 no <dispatch/dispatch.h>: want rc=2 and R6 'cannot judge', got rc=$rc" "$WORK/n2.out"
fi

# ------------------------------------------------------------------ D1-D7
printf '#include <dispatch/dispatch.h>\n' > "$WORK/dispatch-reach.cpp"
if ! "$BASE_CXX" -fsyntax-only -x c++ "$WORK/dispatch-reach.cpp" > /dev/null 2>&1; then
    host="$(uname -s)"
    row="$(grep -E "^$SELF[[:space:]]" "$REPO/$ROWS" 2>/dev/null | head -n 1)"
    plat="$(printf '%s' "$row" | awk '{print $2}')"
    job="$(printf '%s' "$row" | awk '{print $3}')"
    reason="$(printf '%s' "$row" | awk '{ $1 = ""; $2 = ""; $3 = ""; sub(/^ +/, ""); print }')"
    if [ -z "$row" ] || [ "$host" = "$plat" ]; then
        echo "check-agent-interface-probe.selftest: $pass passed, $fail failed"
        if [ -n "$row" ]; then why="the row in $ROWS excuses only hosts other than $plat"; else why="$ROWS has no row for $SELF"; fi
        echo "FATAL: cannot judge: <dispatch/dispatch.h> unavailable on this $host host, and $why -- run this where the Apple SDK is" >&2
        exit 2
    fi
    unjudged="D1-D7 NOT JUDGED on this $host host: <dispatch/dispatch.h> is unavailable, and $ROWS says so ($reason). They run in $job on a $plat runner, which W1 above has just proved."
else
    BASE_H="LibreSCRS/Agent/backend"
    [ -f "$LA_REAL/$BASE_H/Authorizer.h" ] \
        || { echo "FATAL: no agent headers under $LA_REAL -- pass the LibreAgent include dir, or set LIBREAGENT_INCLUDE" >&2; exit 2; }
    [ -f "$REPO/$PROBE" ] || { bad "D1-D7: there is no $PROBE to prove"; echo "check-agent-interface-probe.selftest: $pass passed, $fail failed"; printf 'selftest: %s cases, %s red-proved\n' "$((cases + 1))" "$red"; exit 1; }

    mkreal() {  # mkreal <case> -> $WORK/<case>/{tree,la}
        mkdir -p "$WORK/$1/tree/agent" "$WORK/$1/tree/ci"
        cp -R "$REPO/agent/include" "$WORK/$1/tree/agent/include"
        cp "$REPO/$PROBE" "$WORK/$1/tree/ci/"
        cp -R "$LA_REAL" "$WORK/$1/la"
    }
    # D2's verdict, a function because D7 turns it on another case's output.
    names_moved_method() {  # names_moved_method <rc> <out>
        [ "$1" = 1 ] \
            && grep -q '^  R6 FAILED' "$2" \
            && grep -qE '^  R6 \| .*SecCodeAuthorizer\.h:[0-9]+:[0-9]+: error:' "$2" \
            && grep -qE "^  R6 \| .*(error|note):.*[^A-Za-z_]authorize[^A-Za-z_]" "$2"
    }

    echo "R6 over the real headers (this host has the Apple SDK):"
    mkreal d1
    cases=$((cases + 1))
    run_gate "$WORK/d1/tree" "$WORK/d1/la" "$WORK/d1.out"; rc=$?
    if [ "$rc" = 0 ] && grep -q '^  R6 ok' "$WORK/d1.out"; then
        ok "D1 CONTROL: the unmoved headers compile, R6 ok (rc=$rc)"
    elif grep -qE '^  R6 (FAILED|cannot judge)' "$WORK/d1.out"; then
        # The real interface is already broken, or out of reach, before anything
        # was moved: every red below would then prove nothing.
        sed 's/^/        /' "$WORK/d1.out"
        echo "FATAL: cannot judge: the UNMOVED headers under $LA_REAL do not pass R6 (rc=$rc), so a red over a moved copy proves nothing -- the gate itself names why" >&2
        exit 2
    else
        bad "D1 CONTROL: want rc=0 and 'R6 ok', got rc=$rc" "$WORK/d1.out"
    fi

    mkreal d2
    f="$WORK/d2/la/$BASE_H/Authorizer.h"
    sed 's/virtual AuthorizationOutcome authorize(std::string_view actionId, const CallerToken& caller) = 0;/virtual AuthorizationOutcome authorize(int) = 0;/' \
        "$f" > "$f.moved" && mv "$f.moved" "$f"
    cases=$((cases + 1)); red=$((red + 1))
    if [ "$(grep -c 'virtual AuthorizationOutcome authorize(int) = 0;' "$f")" != 1 ]; then
        bad "D2 perturbation: the base declaration of authorize() was not found to move"
    else
        run_gate "$WORK/d2/tree" "$WORK/d2/la" "$WORK/d2.out"; rc=$?
        if names_moved_method "$rc" "$WORK/d2.out"; then
            ok "D2 ProbeFailsWhenABaseSignatureMoves: rc=1, the diagnostic stands in SecCodeAuthorizer.h and names authorize"
        else
            bad "D2 ProbeFailsWhenABaseSignatureMoves: want rc=1 and an R6 diagnostic in SecCodeAuthorizer.h naming authorize, got rc=$rc" "$WORK/d2.out"
        fi
    fi

    n=3
    for pair in Authorizer:SecCodeAuthorizer AgentTransport:SocketTransport \
                OperationChannel:SocketOperationChannel PrompterClientBase:MacPrompterClient; do
        base="${pair%%:*}"; impl="${pair#*:}"; c="d$n"
        mkreal "$c"
        f="$WORK/$c/la/$BASE_H/$base.h"
        awk -v b="$base" '{ print } $0 ~ "virtual ~" b "\\(\\) = default;" { print "    virtual void addedByProbeSelftest() = 0;" }' \
            "$f" > "$f.added" && mv "$f.added" "$f"
        cases=$((cases + 1)); red=$((red + 1))
        if [ "$(grep -c 'addedByProbeSelftest' "$f")" != 1 ]; then
            bad "D$n perturbation: no pure virtual could be added to $base"
        else
            run_gate "$WORK/$c/tree" "$WORK/$c/la" "$WORK/$c.out"; rc=$?
            if [ "$rc" = 1 ] && grep -qE "^  R6 \| .*static assertion failed.*is_abstract_v<LibreSCRS::Darwin::$impl>" "$WORK/$c.out"; then
                ok "D$n a pure virtual added to $base: rc=1, the static_assert for $impl fired"
            else
                bad "D$n a pure virtual added to $base: want rc=1 and the static_assert for $impl under R6, got rc=$rc" "$WORK/$c.out"
            fi
        fi
        n=$((n + 1))
    done

    cases=$((cases + 1))
    if [ ! -f "$WORK/d3.out" ]; then
        bad "D7 there is no D3 output to turn D2's verdict on"
    elif names_moved_method 1 "$WORK/d3.out"; then
        bad "D7 D2's verdict accepted an R6 failure that does not name the moved method" "$WORK/d3.out"
    else
        ok "D7 D2's verdict rejects an R6 failure that names no moved method"
    fi
fi

echo "check-agent-interface-probe.selftest: $pass passed, $fail failed"
[ -n "$unjudged" ] && echo "  NOTE  $unjudged"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" -eq 0 ]
