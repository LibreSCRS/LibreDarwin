#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Selftest for check-agent-pin-wiring.sh. Each case is a way the check could be
# WRONG rather than merely absent -- including the vacuum shapes: an empty
# workflow directory, a repository that stopped checking the agent out at all,
# a workflow that names the pin file without ever reading it, one that reads it
# and then checks the agent out from somewhere else, and -- for the rule that an
# exempt job builds nothing -- a job that builds through a script instead of
# naming a builder, and one that names no builder but carries the inputs of a
# build.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# The subject is overridable so a case can be run against an OLDER copy of the
# gate: a case that does not fail against the version it was written for is a
# case that measures nothing.
subject=${1:-$here/check-agent-pin-wiring.sh}
[ -f "$subject" ] || { echo "missing subject: $subject" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
red=0
# Counted, not hand-written: a figure quoted from a note is a figure that has
# stopped being measured.
cases=0
GOOD=ca4f355f893822f8b875fd81cbd04e8422b26b93

run() {  # run <name> <expected-rc> <dir> [pinfile-arg] [exceptions-arg]
    local name=$1 want=$2 dir=$3 pinarg=${4:-cmake/libreagent.pin} excarg=${5:-ci/agent-ref-exceptions.txt}
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [ "$want" != 0 ]; then red=$((red + 1)); fi
    ( cd "$dir" && bash "$subject" .github/workflows "$pinarg" "$excarg" ) > "$work/out" 2>&1
    local got=$?
    if [ "$got" -eq "$want" ]; then
        printf '  ok    %-56s rc=%s  %s\n' "$name" "$got" "$(grep -m1 '^workflows=' "$work/out" || true)"
    else
        printf '  FAIL  %-56s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

mkcase() {  # mkcase <name> -> echoes dir with .github/workflows and cmake
    local d=$work/$1
    mkdir -p "$d/.github/workflows" "$d/cmake"
    printf '%s\n' "$GOOD" > "$d/cmake/libreagent.pin"
    echo "$d"
}

clean_wf() {  # a workflow that does it right
    cat <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
Y
}

drift_wf() {  # a job that checks the agent out at a ref the pin does not name
    cat <<'Y'
name: ci
on: [push]
jobs:
  drift:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
Y
}

# A fixture built by editing another one is a fixture that can stop being
# edited. For the cases that expect rc=0 a failed edit is silent -- the case
# they were derived from is rc=0 too -- so the edit is asserted, not assumed.
must_contain() {  # must_contain <name> <file> <text>
    cases=$((cases + 1))
    if grep -qF -- "$3" "$2"; then
        printf '  ok    %-56s\n' "$1"
    else
        printf '  FAIL  %-56s\n' "$1"
        sed 's/^/          /' "$2"
        fails=$((fails + 1))
    fi
}

# A case whose verdict is more than the exit code: these turn on WHICH file and
# line the gate names, and a gate that reds for the wrong reason has the same rc
# as one that reds for the right one. Every pattern must appear in the output;
# one written `!<pattern>` must not. Counted as ONE case, because naming the
# wrong line and returning the wrong code are the same defect here.
run_expect() {  # run_expect <name> <expected-rc> <dir> [pattern|!pattern]...
    local name=$1 want=$2 dir=$3; shift 3
    local got pat ok=1
    cases=$((cases + 1))
    ( cd "$dir" && bash "$subject" .github/workflows ) > "$work/out" 2>&1
    got=$?
    [ "$got" -eq "$want" ] || ok=0
    for pat in "$@"; do
        case "$pat" in
            '!'*) ! grep -qE -- "${pat#!}" "$work/out" || ok=0 ;;
            *)    grep -qE -- "$pat" "$work/out" || ok=0 ;;
        esac
    done
    if [ "$ok" -eq 1 ]; then
        printf '  ok    %-56s rc=%s  %s\n' "$name" "$got" "$(grep -m1 '^workflows=' "$work/out" || true)"
    else
        printf '  FAIL  %-56s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

mkexc() {  # mkexc <dir> <line>...
    local d=$1; shift
    mkdir -p "$d/ci"
    printf '%s\n' "$@" > "$d/ci/agent-ref-exceptions.txt"
}

# case_1 -- the regression this gate exists for: a line that mines a SHA out of
# a GIT_TAG occurrence. This is the exact `sed` LibreDarwin's ci.yml carried.
d=$(mkcase case_1); clean_wf > "$d/.github/workflows/ci.yml"
cat >> "$d/.github/workflows/ci.yml" <<'Y'
      - name: Mine it back out
        run: |
          pin=$(sed -n 's/.*GIT_TAG \([0-9a-f]\{40\}\).*/\1/p' cmake/FindOrUseLibreAgent.cmake)
Y
run "case_1 sed mines GIT_TAG" 1 "$d"

# case_2 -- the other spelling of the same mistake (grep -Eo), which is what
# LibreMac's contract-freshness.yml carried. A gate that only knows `sed` is
# a gate that catches one repository.
d=$(mkcase case_2); clean_wf > "$d/.github/workflows/ci.yml"
cat >> "$d/.github/workflows/ci.yml" <<'Y'
      - run: grep -Eo 'GIT_TAG[[:space:]]+[0-9a-f]{40}' f.cmake | awk '{print $2}'
Y
run "case_2 grep -Eo mines GIT_TAG" 1 "$d"

# case_3 -- checks the agent out but never reads the pin file. This is the
# vacuum R2 alone would pass: delete the resolve step and the checkout silently
# takes the agent's default branch.
d=$(mkcase case_3)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
Y
run "case_3 agent checkout without the pin file" 1 "$d"

# case_4 -- the pin file is gone.
d=$(mkcase case_4); clean_wf > "$d/.github/workflows/ci.yml"; rm "$d/cmake/libreagent.pin"
run "case_4 pin file missing" 1 "$d"

# case_5 -- 39 hex. An off-by-one pin is a ref that resolves to nothing.
d=$(mkcase case_5); clean_wf > "$d/.github/workflows/ci.yml"
printf '%s\n' "${GOOD%?}" > "$d/cmake/libreagent.pin"
run "case_5 pin is 39 hex" 1 "$d"

# case_6 -- a tag name where a SHA belongs: the moving target the pin removes.
d=$(mkcase case_6); clean_wf > "$d/.github/workflows/ci.yml"
printf 'v5.0.0\n' > "$d/cmake/libreagent.pin"
run "case_6 pin is a tag name, not hex" 1 "$d"

# case_7 -- uppercase hex. git resolves it, the sibling gates do not, and a pin
# that reads differently in two places is the defect one level up.
d=$(mkcase case_7); clean_wf > "$d/.github/workflows/ci.yml"
printf '%s\n' "$(echo "$GOOD" | tr 'a-f' 'A-F')" > "$d/cmake/libreagent.pin"
run "case_7 pin is uppercase hex" 1 "$d"

# case_8 -- everything right.
d=$(mkcase case_8); clean_wf > "$d/.github/workflows/ci.yml"
run "case_8 wired correctly" 0 "$d"

# case_9 -- no workflow files at all is "cannot measure", not a pass.
d=$(mkcase case_9); rm -rf "$d/.github/workflows"; mkdir -p "$d/.github/workflows"
run "case_9 empty workflow dir is rc=2, not a pass" 2 "$d"

# case_10 -- `-` mode (a repository that owns no pin file and reads a sibling's
# over the API): R1 is skipped, R2 still fires.
d=$(mkcase case_10); rm "$d/cmake/libreagent.pin"
cat > "$d/.github/workflows/f.yml" <<'Y'
name: freshness
on: [push]
jobs:
  freshness:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - run: grep -Eo 'GIT_TAG[[:space:]]+[0-9a-f]{40}' /tmp/x.cmake | awk '{print $2}'
Y
run "case_10 pinless repo still catches the miner" 1 "$d" -

# case_11 -- `-` mode, clean.
d=$(mkcase case_11); rm "$d/cmake/libreagent.pin"
cat > "$d/.github/workflows/f.yml" <<'Y'
name: freshness
on: [push]
jobs:
  freshness:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - run: pinned=$(gh api repos/LibreSCRS/LibreDarwin/contents/cmake/libreagent.pin --jq .content | base64 -d | tr -d '[:space:]')
Y
run "case_11 pinless repo, reads the sibling pin file" 0 "$d" -

# case_12 -- the pin file is NAMED but never READ: the resolve step hard-codes
# the hash, and the only mentions left are a comment and an error message.
# A name-only match stayed green on exactly this shape.
#
# The resolve step carries its `id:`, and that is the whole case. Without it
# nothing in this workflow reads the pin AND owns an id, so the checkout's
# `ref: ${{ steps.p.outputs.ref }}` points at a step that does not exist and R4
# rejects the workflow on its own. The case then reads rc=1 whatever R3 does --
# measured: a copy of the gate with R3 regressed to a name-only match
# (`readre="$pinbase"`) still passed every case in this file. With the id, R3 is
# the only rule left to fail, so a name-only R3 makes this case go green and the
# regression is caught here rather than in a workflow.
d=$(mkcase case_12)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        # the revision lives in cmake/libreagent.pin
        run: |
          pin=ca4f355f893822f8b875fd81cbd04e8422b26b93
          [ -n "$pin" ] || { echo "::error::cmake/libreagent.pin is empty"; exit 1; }
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
Y
run "case_12 pin file named in prose, never read" 1 "$d"

# case_13 -- the pin is read, and the checkout ignores it: `ref: main`. R3 sees
# its read and is satisfied; only a rule that follows the ref back to the
# reading step notices that the checkout never used it.
d=$(mkcase case_13); clean_wf | sed 's|ref: ${{ steps.p.outputs.ref }}|ref: main|' > "$d/.github/workflows/ci.yml"
grep -q 'ref: main' "$d/.github/workflows/ci.yml" || { echo "case_13 setup: sed matched nothing" >&2; exit 2; }
run "case_13 pin read, checkout ref is a branch name" 1 "$d"

# case_14 -- the pin is read, and the checkout has no `ref:` at all:
# actions/checkout then takes the agent's default branch.
d=$(mkcase case_14); clean_wf | grep -v 'ref: ${{ steps.p.outputs.ref }}' > "$d/.github/workflows/ci.yml"
grep -q 'ref:' "$d/.github/workflows/ci.yml" && { echo "case_14 setup: ref line survived" >&2; exit 2; }
run "case_14 pin read, checkout has no ref line" 1 "$d"

# case_15 -- the pin is read by step p, and the checkout takes its ref from
# step q, which hard-codes a hash. Every mention and every read is present;
# the wire between them is what is wrong.
d=$(mkcase case_15)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - name: Something else entirely
        id: q
        run: echo "ref=ca4f355f893822f8b875fd81cbd04e8422b26b93" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.q.outputs.ref }}
Y
run "case_15 checkout ref taken from a step that does not read" 1 "$d"

# case_16 -- the reading step and the checkout live in different jobs. Step
# outputs do not cross jobs, so `steps.p.outputs.ref` is empty where the
# checkout runs, and actions/checkout takes the default branch.
d=$(mkcase case_16)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  resolve:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
Y
run "case_16 reader and checkout in different jobs" 1 "$d"

# case_17 -- the miner spelled with a POSIX class instead of [0-9a-f]. A gate
# that knows one spelling of the character class is a gate that catches one
# author. `-` mode, since that is where R2 has no other rule behind it.
d=$(mkcase case_17); rm "$d/cmake/libreagent.pin"
cat > "$d/.github/workflows/f.yml" <<'Y'
name: freshness
on: [push]
jobs:
  freshness:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - run: pinned=$(grep -Eo 'GIT_TAG +[[:xdigit:]]{40}' /tmp/x.cmake | awk '{print $2}')
Y
run "case_17 miner spelled with [[:xdigit:]], pinless repo" 1 "$d" -

# case_18 -- GIT_TAG mentioned only in a comment explaining where the revision
# used to live, next to a real read of the sibling pin file. This is the shape
# a repaired workflow has; it must stay green or R2 punishes the explanation.
d=$(mkcase case_18); rm "$d/cmake/libreagent.pin"
cat > "$d/.github/workflows/f.yml" <<'Y'
name: freshness
on: [push]
jobs:
  freshness:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - run: |
          # It used to sit inline as `GIT_TAG <40 hex>` and was mined back out.
          pinned=$(gh api repos/LibreSCRS/LibreDarwin/contents/cmake/libreagent.pin --jq .content | base64 -d | tr -d '[:space:]')  # GIT_TAG is gone
Y
run "case_18 GIT_TAG only in comments, pinless repo" 0 "$d" -

# case_19 -- the read survives only inside a trailing comment: the hash is
# hard-coded and the old command line is kept after a `#`. Dropping whole-line
# comments alone lets the `<` in the comment satisfy the read rule.
d=$(mkcase case_19)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=ca4f355f893822f8b875fd81cbd04e8422b26b93  # was: $(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
Y
run "case_19 read kept only in a trailing comment" 1 "$d"

# case_20 -- a repository declared pinless (`-`) that checks the agent out
# anyway. There is no pin to read, so there is nothing a ref could be wired
# to; the declaration is what is wrong.
d=$(mkcase case_20); rm "$d/cmake/libreagent.pin"; clean_wf > "$d/.github/workflows/ci.yml"
run "case_20 pinless repo checks the agent out" 1 "$d" -

# case_21 -- the checkout value quoted: `repository: "LibreSCRS/LibreAgent"`.
# YAML hands GitHub the same string as the bare spelling. A match on the bare
# text saw no checkout here, so R3 and R4 had nothing to apply to, and a
# workflow with the read deleted and `ref: main` passed as agent-checkouts=0.
d=$(mkcase case_21)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          repository: "LibreSCRS/LibreAgent"
          ref: main
Y
run "case_21 checkout value quoted, no read, ref: main" 1 "$d"

# case_22 -- the checkout value lower-cased. GitHub resolves owner/repo
# case-insensitively, so `librescrs/libreagent` fetches the same repository;
# an exact-case match saw no checkout, same vacuum as case_21.
d=$(mkcase case_22)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          repository: librescrs/libreagent
          ref: main
Y
run "case_22 checkout value lower-cased, no read, ref: main" 1 "$d"

# case_23 -- CONTROL: single-quoted and odd-cased, wired correctly. The
# tolerance is for recognising the checkout, not for rejecting a spelling.
d=$(mkcase case_23)
clean_wf | sed "s|repository: LibreSCRS/LibreAgent|repository: 'librescrs/LibreAgent'|" > "$d/.github/workflows/ci.yml"
grep -q "repository: 'librescrs/LibreAgent'" "$d/.github/workflows/ci.yml" || { echo "case_23 setup: sed matched nothing" >&2; exit 2; }
run "case_23 quoted, odd-cased checkout, wired correctly" 0 "$d"

# case_24 -- CONTROL: the ref expression quoted. Same value to GitHub; a rule
# that compares the raw text rejected it as "not the output of the step".
d=$(mkcase case_24)
clean_wf | sed 's|ref: ${{ steps.p.outputs.ref }}|ref: "${{ steps.p.outputs.ref }}"|' > "$d/.github/workflows/ci.yml"
grep -q 'ref: "${{ steps.p.outputs.ref }}"' "$d/.github/workflows/ci.yml" || { echo "case_24 setup: sed matched nothing" >&2; exit 2; }
run "case_24 ref expression quoted, wired correctly" 0 "$d"

# case_25 -- the repository named by an expression. It may resolve to the
# agent or to anything else; a checkout the gate cannot classify is an error,
# not a pass -- otherwise this is the cheapest way to hide one.
d=$(mkcase case_25)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
env:
  AGENT_REPO: LibreSCRS/LibreAgent
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ env.AGENT_REPO }}
          ref: main
Y
run "case_25 repository named by an expression" 1 "$d"

# case_26 -- the checkout folded into a flow-style mapping on one line. The
# scanner reads one key per line; a checkout it cannot follow must say so
# rather than fall through as no checkout at all.
d=$(mkcase case_26)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with: { repository: LibreSCRS/LibreAgent, ref: main }
Y
run "case_26 agent checkout in a flow-style mapping" 1 "$d"

# case_27 -- the read is there, and the next line overwrites the variable
# from the CMake file the revision used to live in, with a regex that never
# says GIT_TAG. R3 sees its read and R4 sees its wire; a textual gate cannot
# follow the variable, so naming the CMake file is what it must object to.
d=$(mkcase case_27)
clean_wf | sed "s|^\(          pin=\$(tr -d '\[:space:\]' < cmake/libreagent.pin)\)\$|\1\n          pin=\$(grep -Eo '[0-9a-f]{40}' cmake/FindOrUseLibreAgent.cmake \| head -1)|" > "$d/.github/workflows/ci.yml"
grep -q 'FindOrUseLibreAgent.cmake' "$d/.github/workflows/ci.yml" || { echo "case_27 setup: sed matched nothing" >&2; exit 2; }
run "case_27 read kept, then overwritten from the CMake file" 1 "$d"

# case_28 -- CONTROL: the CMake file and GIT_TAG named only in a comment
# saying where the revision used to live. Every repaired workflow carries
# one, and a rule that punishes the explanation would be removed with it.
d=$(mkcase case_28)
clean_wf | sed 's|^        id: p$|        # It used to sit in cmake/FindOrUseLibreAgent.cmake as `GIT_TAG <hex>`.\n        id: p|' > "$d/.github/workflows/ci.yml"
grep -q '# It used to sit in cmake/FindOrUseLibreAgent.cmake' "$d/.github/workflows/ci.yml" || { echo "case_28 setup: sed matched nothing" >&2; exit 2; }
run "case_28 CMake file named only in a comment" 0 "$d"

# case_29 -- a step id is not an exemption by itself. The drift job exists and
# says `ref: main`, and nothing lists it: this is case_13 with an id, and it
# must still fail, or writing `id:` would be the way to opt out of the pin.
d=$(mkcase case_29); drift_wf > "$d/.github/workflows/ci.yml"
run "case_29 trunk checkout with an id nobody listed" 1 "$d"

# case_30 -- the same workflow with the step listed, and a reason, NEXT TO a
# workflow that builds off the pin. R3 and R4 do not apply to the listed step:
# it reads no pin file at all, on purpose, because a pinned build is green on
# precisely the drift it is there to report. This is the shape of the real
# repository, and the only shape in this block that passes.
d=$(mkcase case_30); drift_wf > "$d/.github/workflows/drift.yml"; clean_wf > "$d/.github/workflows/ci.yml"
mkexc "$d" '# the interface drift job' 'drift.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_30 trunk checkout listed, beside a pinned build" 0 "$d"

# case_31 -- the listed id names no checkout any more: the job was renamed or
# deleted and the amnesty stayed. A pardon that outlives its job reads like a
# rule somebody still needs, and the next checkout can borrow the id.
d=$(mkcase case_31); clean_wf > "$d/.github/workflows/ci.yml"
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_31 listed address names no checkout (stale)" 1 "$d"

# case_32 -- listed, with no reason. An exemption whose ground is not written
# down is a pardon, and the next reader has nothing to weigh it against.
d=$(mkcase case_32); drift_wf > "$d/.github/workflows/ci.yml"
mkexc "$d" 'ci.yml:drift:agent_trunk'
run "case_32 listed with no reason" 1 "$d"

# case_33 -- listed, and the checkout names no ref at all. The exemption is for
# a ref written down out loud; the default branch is the one nobody chose.
d=$(mkcase case_33); drift_wf | grep -v 'ref: main' > "$d/.github/workflows/ci.yml"
grep -q 'ref:' "$d/.github/workflows/ci.yml" && { echo "case_33 setup: ref line survived" >&2; exit 2; }
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_33 listed, but the checkout names no ref" 1 "$d"

# case_34 -- one address, two checkouts. Copy the exempt step inside its own
# job and the address itself is carried twice, which pardons a checkout nobody
# weighed. One entry, one step.
d=$(mkcase case_34)
clean_wf > "$d/.github/workflows/ci.yml"
drift_wf > "$d/.github/workflows/drift.yml"
cat >> "$d/.github/workflows/drift.yml" <<'Y'
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
          path: second
Y
mkexc "$d" 'drift.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_34 two checkouts carry the listed address" 1 "$d"

# case_35 -- the exemption consumed the last pinned checkout: every agent
# checkout in the repository is listed, so nothing reads the pin into a ref any
# more. The counters said pinned-refs=0 and the exit code said nothing.
d=$(mkcase case_35); drift_wf > "$d/.github/workflows/ci.yml"
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_35 every agent checkout exempt, none pinned" 1 "$d"

# case_36 -- a bare step id in the exemption file. It was the format, and it is
# not an address: an id is unique only inside its job, so the pardon belongs to
# whatever step wears the name. Rejected on sight, before anything is skipped.
d=$(mkcase case_36)
clean_wf > "$d/.github/workflows/ci.yml"
drift_wf > "$d/.github/workflows/drift.yml"
mkexc "$d" 'agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_36 a bare step id is not an address" 1 "$d"

# case_37 -- the migration the bare id allowed: the drift job is gone and the
# job that BUILDS has taken its step id and a branch ref. Under a name-keyed
# exemption every rule went quiet and the shipping build came off the pin with
# the gate green; measured on this repository's real workflow, that read rc=0.
# The address names the job too, so the pardon does not follow the name.
d=$(mkcase case_37)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
Y
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_37 the exempt id worn by another job" 1 "$d"

# case_38 -- the escape a repository-wide count leaves open. Every checkout may
# not be exempt (case_35), but "every" is counted across the repository, so a
# job that only reads headers keeps the count above zero while the job that
# SHIPS is given a freshly written exemption of its own. Measured on this
# repository's real workflow, that read rc=0 with the release build on
# `ref: main`. The exemption file describes a job that builds nothing, and this
# is that sentence enforced.
d=$(mkcase case_38)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  headers:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - name: Build
        run: cmake --build build -j4
Y
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run "case_38 the job that builds writes itself an exemption" 1 "$d"

# case_39 -- and the control the rule above needs: the drift job as it really
# is, fetching headers and running a check. A rule that reddened this would
# forbid the one job the exemption exists for, and would be worked around
# rather than read.
d=$(mkcase case_39)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  drift:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - name: Install gtest headers
        run: sudo apt-get update && sudo apt-get install -y libgtest-dev
      - name: Interface check
        run: ci/scripts/check-agent-interface.sh "$GITHUB_WORKSPACE/LibreAgent/include"
Y
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_39 CONTROL: the exempt job installs headers and checks" 0 "$d"

# case_40 -- the same escape one script deep. BUILDRE is a list of builders, so
# a job that moves its builders into a script of its own names none of them:
# measured on this repository's real workflow, the release job with every build
# line replaced by one call to a tracked script read rc=0 with the agent on
# `main`. A run: line naming a script this repository ships is followed one
# level.
d=$(mkcase case_40)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  headers:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - name: Build
        run: ./Scripts/ci-build.sh
Y
mkdir -p "$d/Scripts"
printf '#!/usr/bin/env bash\ncmake --build build -j4\n' > "$d/Scripts/ci-build.sh"
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run "case_40 the builders moved into a script of this repository" 1 "$d"

# case_41 -- and the third way, for a job that names no builder at all. A job
# can be written without a builder; it cannot be written without its INPUTS. The
# prefix this repository's dependency installs to is one of them, and a job that
# measures drift needs none.
d=$(mkcase case_41)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  headers:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    env:
      LM_PREFIX: ${{ github.workspace }}/lm-prefix
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - name: Assemble
        run: ./Scripts/release.sh
Y
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run "case_41 an exempt job carrying this repository's build inputs" 1 "$d"

# case_42 -- the control the two rules above need. The drift job really does run
# a script of this repository, and that script really does talk about builders
# in its own header. A rule that read prose would redden the one job the
# exemption exists for.
d=$(mkcase case_42)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  drift:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - name: Install gtest headers
        run: sudo apt-get update && sudo apt-get install -y libgtest-dev
      - name: Interface check
        run: ci/scripts/check-agent-interface.sh "$GITHUB_WORKSPACE/LibreAgent/include"
Y
mkdir -p "$d/ci/scripts"
{ printf '#!/usr/bin/env bash\n'
  printf '# Compiles with -fsyntax-only; it never runs cmake --build and never calls ctest.\n'
  printf 'c++ -std=c++23 -fsyntax-only "$1"\n'
} > "$d/ci/scripts/check-agent-interface.sh"
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_42 CONTROL: the exempt job runs a gate script that only names builders" 0 "$d"

# case_83 -- the same escape written without a file extension. The rule that
# follows a `run:` line into a script of this repository matched
# `.sh|.bash|.py`, so a tracked runner called `Scripts/assemble-release` was
# opened by nothing: the job named no builder on its own lines, used no local
# action, and ran a script the gate declined to recognise as one. It was covered
# by accident until the dependency checkout stopped counting as a build input --
# an exempt job of exactly this shape was reddened by the checkout beside it, not
# by what it ran. An extensionless candidate now counts when it is executable
# and starts with a shebang.
d=$(mkcase case_83)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  headers:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - name: Assemble
        run: ./Scripts/assemble-release
Y
mkdir -p "$d/Scripts"
printf '#!/usr/bin/env bash
cmake --build build -j4
' > "$d/Scripts/assemble-release"
chmod +x "$d/Scripts/assemble-release"
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run_expect "case_83 the builders in a tracked runner with no extension" 1 "$d" \
    'runs a script of this repository that builds' \
    'Scripts/assemble-release'

# case_84 -- the green that case must not cost. The same extensionless token,
# resolving to a tracked file that is NOT a script: no executable bit, no
# shebang. Judged as a script it would be judged by a grep over whatever bytes
# it holds, and a data file that happens to spell `ninja` would redden the one
# job the exemption exists for.
d=$(mkcase case_84)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  headers:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  drift:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - name: Report what the release notes will say
        run: cat docs/release-recipe
Y
mkdir -p "$d/docs"
printf 'the release is assembled with ninja and ctest, by hand, on a Mac
' > "$d/docs/release-recipe"
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run_expect "case_84 CONTROL: an extensionless data file is not a script" 0 "$d" \
    '!::error'

# case_43 -- the same escape one composite action deep. `run:` was followed one
# level; `uses: ./<path>` was not, and moving steps into a local action is the
# cheaper refactor of the two. Measured on the real workflow: the release job's
# checkout, its cmake calls and its ctest behind `uses: ./.github/actions/assemble`
# read rc=0 with the agent on `main`.
d=$(mkcase case_43)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./.github/actions/assemble
Y
mkdir -p "$d/.github/actions/assemble"
cat > "$d/.github/actions/assemble/action.yml" <<'Y'
name: assemble
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
        cmake --build build -j4
Y
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run "case_43 the builders moved into a local composite action" 1 "$d"

# case_44 -- the same shape one level further: the action names no builder but
# carries the prefix this repository's dependency build installs to. INPUTRE
# asks that of a job; it has to ask it of the action too, or the inputs move
# with the builders. The action used to carry the LibreMiddleware CHECKOUT
# instead, which is no longer an input at all -- see case_80, and INPUTRE's own
# comment for why a copy of somebody's headers is not a build.
d=$(mkcase case_44)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./.github/actions/deps
Y
mkdir -p "$d/.github/actions/deps"
cat > "$d/.github/actions/deps/action.yml" <<'Y'
name: deps
runs:
  using: composite
  steps:
    - shell: bash
      env:
        LM_PREFIX: ${{ github.workspace }}/lm-prefix
      run: ./Scripts/assemble-release
Y
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run "case_44 a local composite action carrying this repository's build inputs" 1 "$d"

# case_45 -- a local action the gate cannot open. Skipping it would be the same
# escape written as a path, so it is refused in place.
d=$(mkcase case_45)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./tools/elsewhere
Y
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run "case_45 a local action whose path does not resolve" 1 "$d"

# case_46 -- and the control the three above need. The exempt drift job really
# may use a local action, as long as that action measures rather than builds:
# a rule that reddened on `uses: ./` at all would push the one job the exemption
# exists for into inlining its steps.
d=$(mkcase case_46)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  drift:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./.github/actions/interface-check
Y
mkdir -p "$d/.github/actions/interface-check"
cat > "$d/.github/actions/interface-check/action.yml" <<'Y'
name: interface-check
# Compiles with -fsyntax-only; it never runs cmake --build and never calls ctest.
runs:
  using: composite
  steps:
    - shell: bash
      run: sudo apt-get update && sudo apt-get install -y libgtest-dev
    - shell: bash
      run: ci/scripts/check-agent-interface.sh "$GITHUB_WORKSPACE/LibreAgent/include"
Y
mkdir -p "$d/ci/scripts"
{ printf '#!/usr/bin/env bash\n'
  printf 'c++ -std=c++23 -fsyntax-only "$1"\n'
} > "$d/ci/scripts/check-agent-interface.sh"
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_46 CONTROL: the exempt job uses a local action that only measures" 0 "$d"

# case_47/48 -- the same action, quoted. A YAML scalar may be written bare,
# double-quoted or single-quoted and GitHub runs all three identically; the rule
# read only the bare one, so `uses: "./.github/actions/assemble"` was neither
# followed nor refused and the shipping job built against an agent branch at
# rc=0. The fixture is case_43 with one quote character changed.
quoted_builder_case() {  # quoted_builder_case <case name> <uses value>
    local d
    d=$(mkcase "$1")
    { cat <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
Y
      printf '      - uses: %s\n' "$2"
    } > "$d/.github/workflows/ci.yml"
    mkdir -p "$d/.github/actions/assemble"
    cat > "$d/.github/actions/assemble/action.yml" <<'Y'
name: assemble
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
        cmake --build build -j4
Y
    mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
    printf '%s\n' "$d"
}
d=$(quoted_builder_case case_47 '"./.github/actions/assemble"')
run "case_47 the local action named as a double-quoted scalar" 1 "$d"
d=$(quoted_builder_case case_48 "'./.github/actions/assemble'")
run "case_48 the local action named as a single-quoted scalar" 1 "$d"

# case_49 -- the script indirection moved INSIDE the action. The job is judged
# four ways and the action was judged by two of them, so the same builders
# escaped by moving one step sideways: measured, this fixture read rc=0 while
# the identical script named on a job `run:` line read rc=1.
d=$(mkcase case_49)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./.github/actions/assemble
Y
mkdir -p "$d/.github/actions/assemble" "$d/ci/scripts"
cat > "$d/.github/actions/assemble/action.yml" <<'Y'
name: assemble
runs:
  using: composite
  steps:
    - shell: bash
      run: ci/scripts/ci-assemble.sh
Y
{ printf '#!/usr/bin/env bash\n'
  printf 'cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release\n'
  printf 'cmake --build build -j4\n'
  printf 'ctest --test-dir build\n'
} > "$d/ci/scripts/ci-assemble.sh"
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run "case_49 a script that builds, run from inside the local action" 1 "$d"

# case_50 -- and one action deeper. "The same one level" was a bound the gate
# stated and did not enforce: an action whose only step is `uses: ./<another>`
# put the builders one hop past everything.
d=$(mkcase case_50)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./.github/actions/assemble
Y
mkdir -p "$d/.github/actions/assemble" "$d/.github/actions/inner"
cat > "$d/.github/actions/assemble/action.yml" <<'Y'
name: assemble
runs:
  using: composite
  steps:
    - uses: ./.github/actions/inner
Y
cat > "$d/.github/actions/inner/action.yml" <<'Y'
name: inner
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
        cmake --build build -j4
Y
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run "case_50 the builders one local action further in" 1 "$d"

# case_51 -- an action that reaches an action this checkout does not carry.
# Refused, for the reason case_45 is refused: a step the gate cannot read is a
# step the exemption cannot cover, at whatever depth it is written.
d=$(mkcase case_51)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./.github/actions/assemble
Y
mkdir -p "$d/.github/actions/assemble"
cat > "$d/.github/actions/assemble/action.yml" <<'Y'
name: assemble
runs:
  using: composite
  steps:
    - uses: ./.github/actions/gone
Y
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run "case_51 a nested local action whose path does not resolve" 1 "$d"

# case_52 -- a `uses:` path that resolves to nothing is refused rather than
# stripped down to whatever does exist. `./LibreDarwin/.github/actions/probe`
# used to be judged by reading `.github/actions/probe`, a file the workflow
# never named, and the error printed that file's path. Here the action that
# exists at the shorter path BUILDS and the exempt job must still be refused for
# naming a path this checkout does not carry -- not reddened for the wrong
# reason, and not passed either.
d=$(mkcase case_52)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  drift:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./Elsewhere/.github/actions/probe
Y
mkdir -p "$d/.github/actions/probe"
cat > "$d/.github/actions/probe/action.yml" <<'Y'
name: probe
runs:
  using: composite
  steps:
    - shell: bash
      run: cmake --build build -j4
Y
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_52 a local path that resolves to nothing is refused, not stripped" 1 "$d"
( cd "$d" && bash "$subject" .github/workflows > "$work/out52" 2>&1 )
cases=$((cases + 1))
if grep -q 'does not resolve to an action file here' "$work/out52" \
   && ! grep -q '\.github/actions/probe/action\.yml' "$work/out52"; then
    printf '  ok    %-56s\n' "case_52b the refusal names the path that was written"
else
    printf '  FAIL  %-56s\n' "case_52b the refusal names a file the workflow never named"
    sed 's/^/          /' "$work/out52"
    fails=$((fails + 1))
fi

# case_53 -- the control for case_52's stripping. A job that checks this
# repository out under a path of its own really does name its own actions
# through that path, and the prefix it DECLARED is the one that comes off.
# The action only measures, so the job stays green: what is being shown is that
# the action was found and read, not that it was refused.
d=$(mkcase case_53)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  drift:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          path: LibreDarwin
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./LibreDarwin/.github/actions/probe
Y
mkdir -p "$d/.github/actions/probe"
cat > "$d/.github/actions/probe/action.yml" <<'Y'
name: probe
runs:
  using: composite
  steps:
    - shell: bash
      run: ci/scripts/check-agent-interface.sh
Y
mkdir -p "$d/ci/scripts"
{ printf '#!/usr/bin/env bash\n'
  printf 'c++ -std=c++23 -fsyntax-only "$1"\n'
} > "$d/ci/scripts/check-agent-interface.sh"
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_53 CONTROL: a prefix the job declares with path: is stripped" 0 "$d"

# case_54 and case_55 -- what KIND of local action it is. Everything this gate
# reads inside an action is `steps:`, which only a composite action has. A node
# or a docker action resolves to an action file and is then judged by nothing:
# measured on the real workflow with every builder behind
# `uses: ./.github/actions/assemble` and that action rewritten to
# `runs: {using: node20, main: index.js}`, the gate read rc=0 with no ::error at
# all -- past a bound the header announced ("judged by ALL three rules") and did
# not enforce. A kind whose steps cannot be read is refused where an unreadable
# path already is; the control is the same topology with a composite action that
# only measures, which stays green.
d=$(mkcase case_54)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  ship:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        id: agent_ship
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./.github/actions/assemble
Y
mkdir -p "$d/.github/actions/assemble"
cat > "$d/.github/actions/assemble/action.yml" <<'Y'
name: assemble
runs:
  using: node20
  main: index.js
Y
mkexc "$d" 'ci.yml:ship:agent_ship  the release build tracks the agent trunk on purpose'
run "case_54 a local node action, whose steps this gate cannot read" 1 "$d"

d=$(mkcase case_55)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  drift:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./.github/actions/probe
Y
mkdir -p "$d/.github/actions/probe"
cat > "$d/.github/actions/probe/action.yml" <<'Y'
name: probe
runs:
  using: composite
  steps:
    - shell: bash
      run: diff -u a b
Y
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run "case_55 CONTROL: a local composite action that only measures" 0 "$d"

# case_56 -- the agent fetched by the shell instead of by actions/checkout, at
# a branch. This is the live shape in a sibling consumer -- `git clone` of the
# agent followed by `git -C LibreAgent checkout <ref>` inside one run block --
# and with the ref written as a branch name the build takes the moving target
# the pin exists to remove. R3 and R4 read `repository:` keys and saw no
# checkout here at all: measured on this repository's own workflow with
# build-macos rewritten this way, the gate read agent-checkouts=2 pinned-refs=1
# rc=0 while the shipping job built against the agent trunk.
d=$(mkcase case_56)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          path: LibreDarwin
      - name: Build & install LibreAgent at the recorded pin
        run: |
          git clone https://github.com/LibreSCRS/LibreAgent.git LibreAgent
          git -C LibreAgent checkout main
          cmake -S LibreAgent -B la-build
Y
run "case_56 agent cloned in a run block, checked out at a branch" 1 "$d"

# case_57 -- CONTROL: the same shape done right, byte for byte the sibling's
# own lines -- the clone, then a checkout whose ref IS the read of the pin
# file, in the same step. There is no `ref:` key for a rule to follow here, so
# the read in that step is the whole of the evidence and it has to be enough:
# a rule that failed this would be a rule nobody could satisfy without
# rewriting a working workflow.
d=$(mkcase case_57)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          path: LibreDarwin
      - name: Build & install LibreAgent at the recorded pin
        run: |
          git clone https://github.com/LibreSCRS/LibreAgent.git LibreAgent
          git -C LibreAgent checkout "$(tr -d '[:space:]' < LibreDarwin/cmake/libreagent.pin)"
          cmake -S LibreAgent -B la-build
Y
run "case_57 CONTROL: agent cloned, checked out at the pin it reads" 0 "$d"

# case_58 -- the same clone as case_56 with the command WRAPPED. A long shell
# command continued with a trailing backslash is one command; matched one
# physical line at a time, the verb sits on the first line and the repository on
# the second and neither line carries both. The wrap is ordinary style in these
# files -- adding `--depth 1` to the sibling clone is what puts it there -- so
# without folding this spelling restored exactly the vacuum R6 was added to
# close: measured against the gate before the fold, agent-checkouts=0, rc=0, no
# ::error at all.
d=$(mkcase case_58)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          path: LibreDarwin
      - name: Build & install LibreAgent at the recorded pin
        run: |
          git clone --depth 1 --no-single-branch \
            https://github.com/LibreSCRS/LibreAgent.git LibreAgent
          git -C LibreAgent checkout main
          cmake -S LibreAgent -B la-build
Y
run "case_58 the clone wrapped across a backslash continuation" 1 "$d"

# case_59 -- CONTROL for the fold: the same wrapped clone with the checkout
# taking the read of the pin. Folding must not make a wired workflow red.
d=$(mkcase case_59)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          path: LibreDarwin
      - name: Build & install LibreAgent at the recorded pin
        run: |
          git clone --depth 1 --no-single-branch \
            https://github.com/LibreSCRS/LibreAgent.git LibreAgent
          git -C LibreAgent checkout "$(tr -d '[:space:]' < LibreDarwin/cmake/libreagent.pin)"
          cmake -S LibreAgent -B la-build
Y
run "case_59 CONTROL: the wrapped clone that reads the pin" 0 "$d"

# case_60 -- CONTROL: a fetch INSIDE a checkout that is already pinned. `git -C
# LibreAgent fetch --tags --unshallow` deepens the working copy actions/checkout
# left behind; it cannot move HEAD off the pinned revision, and the checkout
# beside it satisfies R3 and R4 in full. Matched on the directory argument alone
# this read rc=1 and printed a remedy the workflow already followed -- and the
# shape is one line away here, since the agent is checked out without
# fetch-depth while its own jobs ask for full history.
d=$(mkcase case_60)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          path: LibreAgent
          ref: ${{ steps.p.outputs.ref }}
      - name: Deepen for tags
        run: git -C LibreAgent fetch --tags --unshallow
Y
run "case_60 CONTROL: a fetch inside the pinned checkout" 0 "$d"

# case_61 -- and the fetch that names the agent as a SOURCE stays counted: same
# `-C` directory as case_60, but the URL fetched from is the agent. The checkout
# after it would count on its own too (case_65 and case_67 are that shape
# without a source), so this case pins the source half of the split.
d=$(mkcase case_61)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          path: LibreDarwin
      - name: Build & install LibreAgent at the recorded pin
        run: |
          mkdir LibreAgent && git -C LibreAgent init
          git -C LibreAgent fetch https://github.com/LibreSCRS/LibreAgent.git
          git -C LibreAgent checkout main
Y
run "case_61 a fetch of the agent remote, checked out at a branch" 1 "$d"

# case_62 -- a shell fetch wired the way a checkout is: the resolve step reads
# the pin and publishes it, and the fetch step consumes
# ${{ steps.<id>.outputs.* }}. That workflow is pinned and says so in text this
# gate already resolves for `ref:`; refusing it made the gate ask for a worse
# workflow than the one in front of it.
d=$(mkcase case_62)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          path: LibreDarwin
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < LibreDarwin/cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - name: Build & install LibreAgent at the recorded pin
        run: |
          git clone https://github.com/LibreSCRS/LibreAgent.git LibreAgent
          git -C LibreAgent checkout ${{ steps.p.outputs.ref }}
          cmake -S LibreAgent -B la-build
Y
run "case_62 CONTROL: the fetch takes the output of the reading step" 0 "$d"

# case_63 -- and that acceptance is not a blanket pass for any step output: the
# step this fetch takes its ref from publishes a branch name and never reads the
# pin, which is R4 read through R6.
d=$(mkcase case_63)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          path: LibreDarwin
      - name: Resolve
        id: q
        run: echo "ref=main" >> "$GITHUB_OUTPUT"
      - name: Build & install LibreAgent at the recorded pin
        run: |
          git clone https://github.com/LibreSCRS/LibreAgent.git LibreAgent
          git -C LibreAgent checkout ${{ steps.q.outputs.ref }}
          cmake -S LibreAgent -B la-build
Y
run "case_63 the fetch takes the output of a step that reads nothing" 1 "$d"

# case_64 -- the pinless (-) branch of R6, the analogue of case_20 for a shell
# fetch. A repository that owns no pin file may not fetch the agent from its own
# shell either; the mode matters because a sibling without a pin file is exactly
# where this gate gets borrowed to.
d=$(mkcase case_64)
cp "$work/case_56/.github/workflows/ci.yml" "$d/.github/workflows/ci.yml"
run "case_64 pinless repo fetches the agent in a run block" 1 "$d" -
# and it is refused AS pinless: the generic refusal has the same exit code, so
# the rc above alone would stay green with this branch deleted.
( cd "$d" && bash "$subject" .github/workflows - > "$work/out64" 2>&1 )
cases=$((cases + 1))
if grep -q 'declared pinless' "$work/out64"; then
    printf '  ok    %-56s\n' "case_64b the refusal says the repository has no pin file"
else
    printf '  FAIL  %-56s\n' "case_64b the refusal blames the read instead of the missing pin"
    sed 's/^/          /' "$work/out64"
    fails=$((fails + 1))
fi

# case_65 -- what the `-C` narrowing cost when it was written as "the agent must
# be named somewhere other than the working directory" and nothing else: after a
# checkout actions/checkout pinned, `git -C LibreAgent fetch origin main` names
# no source this gate can read -- `origin` is a remote NAME -- and the checkout
# on the next line then lands the build on the trunk. Measured against the gate
# before the move rule: rc=0, no ::error at all, while the job builds the agent
# trunk. The fetch is not the tell; the checkout run inside the agent tree is.
d=$(mkcase case_65)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          path: LibreAgent
          ref: ${{ steps.p.outputs.ref }}
      - name: Take the trunk
        run: |
          git -C LibreAgent fetch origin main
          git -C LibreAgent checkout FETCH_HEAD
          cmake -S LibreAgent -B la-build
Y
run "case_65 the pinned checkout moved onto the trunk by FETCH_HEAD" 1 "$d"

# case_66 -- the same move spelled with `reset --hard`, which leaves no
# `checkout` on any line.
d=$(mkcase case_66)
sed -e 's|git -C LibreAgent fetch origin main|git -C LibreAgent fetch origin|' \
    -e 's|git -C LibreAgent checkout FETCH_HEAD|git -C LibreAgent reset --hard origin/main|' \
    "$work/case_65/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"
run "case_66 the pinned checkout reset onto the trunk" 1 "$d"

# case_67 -- and the same move one line under the deepening fetch case_60
# blesses: `--tags --unshallow` brings the trunk into the working copy, and
# `git -C LibreAgent checkout main` then takes it. case_60 stays green because
# it stops before that line; this case is case_60 plus that one line, so the two
# together say exactly where the boundary is.
d=$(mkcase case_67)
sed -e 's|run: git -C LibreAgent fetch --tags --unshallow|run: \|\n          git -C LibreAgent fetch --tags --unshallow\n          git -C LibreAgent checkout main\n          cmake -S LibreAgent -B la-build|' \
    "$work/case_60/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"
run "case_67 CONTROL case_60 plus one checkout of a branch" 1 "$d"

# case_68 -- CONTROL: the deepening fetch written the way this house writes a
# command that needs a working directory -- `cd <dir> &&` rather than `-C`.
# Matched on `-C` alone it was red with a remedy the workflow already followed,
# which is the same false red case_60 exists to keep out.
d=$(mkcase case_68)
sed 's|run: git -C LibreAgent fetch --tags --unshallow|run: cd LibreAgent \&\& git fetch --tags --unshallow|' \
    "$work/case_60/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"
must_contain "case_68a the fixture really says cd, not -C" \
    "$d/.github/workflows/ci.yml" 'run: cd LibreAgent && git fetch --tags --unshallow'
run "case_68 CONTROL: the deepening fetch after cd, not -C" 0 "$d"

# case_69 -- CONTROL: and with the `cd` on a line of its own, which is how every
# live instance of it is written here. The directory carries to the next line;
# it must not make the deepening fetch a fetch OF the agent.
d=$(mkcase case_69)
sed 's|run: git -C LibreAgent fetch --tags --unshallow|run: \|\n          cd LibreAgent\n          git fetch --tags --unshallow|' \
    "$work/case_60/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"
must_contain "case_69a the fixture really puts cd on its own line" \
    "$d/.github/workflows/ci.yml" '          cd LibreAgent'
run "case_69 CONTROL: cd on its own line, then the deepening fetch" 0 "$d"

# case_70 -- and the escape written in that same style: `cd LibreAgent` on one
# line, then a fetch and a checkout that never repeat the directory. A rule that
# only reads `-C` and the command it stands in sees nothing here.
d=$(mkcase case_70)
sed 's|run: git -C LibreAgent fetch --tags --unshallow|run: \|\n          cd LibreAgent\n          git fetch origin main\n          git checkout FETCH_HEAD\n          cmake -S . -B la-build|' \
    "$work/case_60/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"
run "case_70 the same move after a cd on its own line" 1 "$d"

# case_71 -- CONTROL: an unrelated repository cloned in the folded style, with a
# destination path held in a variable whose NAME contains the agent. Folding
# joins the continuation lines into one command, and a bare substring test over
# the result blamed this clone as an agent fetch. A computed value is not
# something written down, so the tokens carrying one are not read.
d=$(mkcase case_71)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          path: LibreAgent
          ref: ${{ steps.p.outputs.ref }}
      - name: Vendor the card library
        run: |
          git clone --depth 1 \
            https://github.com/OpenSC/OpenSC.git \
            "$LIBREAGENT_ROOT/../opensc"
Y
run "case_71 CONTROL: a folded clone of something else entirely" 0 "$d"

# case_72 -- `switch` is the third spelling of the move and the one a modern
# script reaches for; a verb list that stops at checkout and reset is a verb
# list with a hole in it.
d=$(mkcase case_72)
sed 's|git -C LibreAgent checkout FETCH_HEAD|git -C LibreAgent switch main|' \
    "$work/case_65/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"
run "case_72 the pinned checkout switched onto a branch" 1 "$d"

# case_73 -- lower-casing the line makes `git -C <dir>` and `git -c key=value`
# the same word, and a move that carries a config setting must still be judged
# by the directory it is in. `-c advice.detachedHead=false` is what a script
# adds the day the detached-HEAD notice becomes noise.
d=$(mkcase case_73)
sed 's|run: git -C LibreAgent fetch --tags --unshallow|run: \|\n          cd LibreAgent\n          git fetch origin main\n          git -c advice.detachedHead=false checkout main\n          cmake -S . -B la-build|' \
    "$work/case_60/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"
run "case_73 the move carries a git config setting" 1 "$d"

# case_74 -- the checkout itself moved into a local composite action, in a job
# that is NOT exempt. Everything above follows `uses: ./<path>` only for a job
# an exemption names; the count R3 and R4 judge read a job's literal `steps:`,
# so a `repository: LibreSCRS/LibreAgent` written inside
# .github/actions/<x>/action.yml belonged to nobody. Measured on this
# repository's own workflow with build-macos's agent checkout moved that way:
# agent-checkouts silently dropped from 3 to 2, rc=0, no ::error at all, while
# the job that ships built against `main`. GitHub runs that checkout in the
# using job's workspace, so it is that job's checkout and its ref is R4's
# business.
# Both directions are in one fixture, because a rule that reddened on any local
# action would pass the rc alone: build-macos hides a checkout on `main` and
# must be reported, build-linux hides one wired to the pin through a resolve
# step of the action's own and must not be. Hence the counters and the error
# count, not just the exit code.
d=$(mkcase case_74)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  build-macos:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - uses: ./.github/actions/fetch-agent
      - run: cmake --build build -j4
  build-linux:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: ./.github/actions/fetch-agent-pinned
      - run: cmake --build build -j4
Y
mkdir -p "$d/.github/actions/fetch-agent" "$d/.github/actions/fetch-agent-pinned"
cat > "$d/.github/actions/fetch-agent/action.yml" <<'Y'
name: fetch-agent
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      with:
        repository: LibreSCRS/LibreAgent
        ref: main
Y
cat > "$d/.github/actions/fetch-agent-pinned/action.yml" <<'Y'
name: fetch-agent-pinned
runs:
  using: composite
  steps:
    - name: Resolve
      id: p
      shell: bash
      run: |
        pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
        echo "ref=$pin" >> "$GITHUB_OUTPUT"
    - uses: actions/checkout@v4
      with:
        repository: LibreSCRS/LibreAgent
        ref: ${{ steps.p.outputs.ref }}
Y
run_expect "case_74 a checkout hidden in a local composite action" 1 "$d" \
    '::error file=\.github/actions/fetch-agent/action\.yml,line=[0-9]+::ref is .main.' \
    'agent-checkouts=3 pinned-refs=2' \
    '!::error file=\.github/actions/fetch-agent-pinned'

# case_81 -- case_74's mirror, and the shape the fix for it left open: ONE job
# using ONE parameterised action TWICE. That is how a workflow checks the agent
# out at the pin for one purpose and at the trunk for another without writing
# the checkout twice, and the two uses are two checkouts with two different
# refs. The queue of actions a job reaches was deduplicated on the action PATH,
# so the second use contributed no steps at all: measured on this shape,
# `agent-checkouts=1 pinned-refs=1`, rc=0, over a checkout on `main` -- the same
# silent drop case_74 exists for, one level of parameterisation further in. The
# assertion names the line of the SECOND `with:`, because that is the value R4
# judged and the line a maintainer edits.
d=$(mkcase case_81)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: ./.github/actions/fetch-agent
        with:
          ref: ${{ steps.p.outputs.ref }}
      - uses: ./.github/actions/fetch-agent
        with:
          ref: main
Y
mkdir -p "$d/.github/actions/fetch-agent"
cat > "$d/.github/actions/fetch-agent/action.yml" <<'Y'
name: fetch-agent
inputs:
  ref:
    description: the agent revision to check out
    default: main
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      with:
        repository: LibreSCRS/LibreAgent
        ref: ${{ inputs.ref }}
Y
# The line is looked up rather than written down: a fixture edit must not turn
# this assertion into one that passes for the wrong reason.
second_with=$(grep -n 'ref: main' "$d/.github/workflows/ci.yml" | tail -1 | cut -d: -f1)
run_expect "case_81 one job using one parameterised action twice" 1 "$d" \
    "::error file=\.github/workflows/ci\.yml,line=$second_with::ref is .main." \
    'agent-checkouts=2 pinned-refs=1'

# case_82 -- the empty ref, and WHERE it is reported. `with: ref:` with nothing
# after it is a real spelling -- a variable that expanded to nothing, an input
# left blank -- and actions/checkout then takes the agent's default branch, the
# moving target the pin exists to remove. The rule caught it, and pointed at the
# `ref: ${{ inputs.ref }}` line INSIDE the action, which is not the line anyone
# can fix: the value is written in the workflow's `with:`. Every other verdict
# on that value already reports the workflow line; this one did not.
d=$(mkcase case_82)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: ./.github/actions/fetch-agent
        with:
          ref:
Y
mkdir -p "$d/.github/actions/fetch-agent"
cat > "$d/.github/actions/fetch-agent/action.yml" <<'Y'
name: fetch-agent
inputs:
  ref:
    description: the agent revision to check out
    default: main
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      with:
        repository: LibreSCRS/LibreAgent
        ref: ${{ inputs.ref }}
Y
empty_with=$(grep -n 'ref:$' "$d/.github/workflows/ci.yml" | tail -1 | cut -d: -f1)
run_expect "case_82 an empty ref is reported where it is written" 1 "$d" \
    "::error file=\.github/workflows/ci\.yml,line=$empty_with::checks out LibreSCRS/LibreAgent with no ref:" \
    '!::error file=\.github/actions/fetch-agent/action\.yml'

# case_75 -- the id space a `${{ steps.<id>.outputs.* }}` is resolved in is the
# FILE it is written in, not the job the steps were counted onto. Inside a
# composite action the `steps` context holds that action's own steps only, so a
# checkout there naming a resolve step of the CALLING job resolves to nothing at
# runtime and actions/checkout takes the agent's default branch. Keyed by job
# alone this read agent-checkouts=1 pinned-refs=1 rc=0 -- a green over a
# workflow that builds the trunk. The mirror is here too, in build-linux: a job
# step consuming an id that exists only inside an action it uses.
d=$(mkcase case_75)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build-macos:
    runs-on: macos-15
    timeout-minutes: 60
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: ./.github/actions/fetch-agent
  build-linux:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: ./.github/actions/resolve-agent
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.q.outputs.ref }}
Y
mkdir -p "$d/.github/actions/fetch-agent" "$d/.github/actions/resolve-agent"
cat > "$d/.github/actions/fetch-agent/action.yml" <<'Y'
name: fetch-agent
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      with:
        repository: LibreSCRS/LibreAgent
        ref: ${{ steps.p.outputs.ref }}
Y
cat > "$d/.github/actions/resolve-agent/action.yml" <<'Y'
name: resolve-agent
runs:
  using: composite
  steps:
    - name: Resolve
      id: q
      shell: bash
      run: |
        pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
        echo "ref=$pin" >> "$GITHUB_OUTPUT"
Y
run_expect "case_75 a ref naming a resolve step of another file" 1 "$d" \
    '::error file=\.github/actions/fetch-agent/action\.yml,line=[0-9]+::ref comes from step .p.' \
    '::error file=\.github/workflows/ci\.yml,line=[0-9]+::ref comes from step .q.' \
    'agent-checkouts=2 pinned-refs=0'

# case_76 -- CONTROL: the way a composite action that checks the agent out is
# actually written. The action takes the ref as an INPUT and the step using it
# passes the resolve step's output; the action file says only which input
# carries the value. Judged where it stands, every such action was red with a
# message naming a line nobody could fix -- `ref is '${{ inputs.ref }}', not the
# output of the step that reads cmake/libreagent.pin`. The input is followed one
# level, to the `with:` of the step that uses the action, and the value found
# there is what R4 judges.
d=$(mkcase case_76)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: ./.github/actions/fetch-agent
        with:
          ref: ${{ steps.p.outputs.ref }}
Y
mkdir -p "$d/.github/actions/fetch-agent"
cat > "$d/.github/actions/fetch-agent/action.yml" <<'Y'
name: fetch-agent
inputs:
  ref:
    description: the agent revision to check out
    default: main
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      with:
        repository: LibreSCRS/LibreAgent
        ref: ${{ inputs.ref }}
Y
run_expect "case_76 CONTROL: the action takes the ref as an input" 0 "$d" \
    'agent-checkouts=1 pinned-refs=1' '!::error'

# case_77 -- and the same shape with the value that is wrong. The input is
# followed to the `with:` of the using step, so the ref judged is `main` and the
# line named is the one somebody has to edit -- in the workflow, not in the
# action that merely passes the input on.
d=$(mkcase case_77)
sed 's|          ref: ${{ steps.p.outputs.ref }}|          ref: main|' \
    "$work/case_76/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"
mkdir -p "$d/.github/actions/fetch-agent"
cp "$work/case_76/.github/actions/fetch-agent/action.yml" "$d/.github/actions/fetch-agent/action.yml"
must_contain "case_77a the fixture really passes a branch" \
    "$d/.github/workflows/ci.yml" '          ref: main'
run_expect "case_77 the action input passed a branch" 1 "$d" \
    '::error file=\.github/workflows/ci\.yml,line=[0-9]+::ref is .main.' \
    '!::error file=\.github/actions'

# case_78 -- and the input the gate cannot follow: the using step passes nothing,
# so the value is the action's own default, or -- one action further in -- an
# input handed on by a nested `with:`. Judging the expression as if it were the
# ref names a line that cannot be fixed as the message asks, so it is refused
# where an unreadable checkout already is and counted with them.
d=$(mkcase case_78)
sed '/^        with:$/,/^          ref: /d' \
    "$work/case_76/.github/workflows/ci.yml" > "$d/.github/workflows/ci.yml"
mkdir -p "$d/.github/actions/fetch-agent"
cp "$work/case_76/.github/actions/fetch-agent/action.yml" "$d/.github/actions/fetch-agent/action.yml"
must_contain "case_78a the fixture really passes no input" \
    "$d/.github/workflows/ci.yml" '      - uses: ./.github/actions/fetch-agent'
run_expect "case_78 an action input the using step does not set" 1 "$d" \
    '::error file=\.github/actions/fetch-agent/action\.yml,line=[0-9]+::ref is .\$\{\{ inputs\.ref \}\}., an action input' \
    'unreadable-checkouts=1'

# case_79 -- an exemption addresses a step written in the WORKFLOW file. A step
# id inside a composite action lives in that action's id space, and the amnesty
# `ci.yml:drift:agent_trunk` pardoned any step called agent_trunk the job could
# reach: measured, a SKIP line for a checkout in .github/actions/probe nobody
# listed, on `ref: main`, in a job whose own exempt checkout kept the entry from
# reading stale. The listed step is still pardoned; the one in the action is
# judged like any other.
d=$(mkcase case_79)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  drift:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: ./.github/actions/probe
Y
mkdir -p "$d/.github/actions/probe"
cat > "$d/.github/actions/probe/action.yml" <<'Y'
name: probe
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      id: agent_trunk
      with:
        repository: LibreSCRS/LibreAgent
        ref: main
    - shell: bash
      run: diff -u a b
Y
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; builds nothing'
run_expect "case_79 an exempt step id borrowed inside a local action" 1 "$d" \
    'SKIP: \.github/workflows/ci\.yml' \
    '::error file=\.github/actions/probe/action\.yml,line=[0-9]+::ref is .main.' \
    '!is carried by' \
    'agent-checkouts=3 pinned-refs=1 named-trunk-refs=1'

# case_80 -- the green case_44 gave up, and the one the interface gate needs. A
# job that checks LibreMiddleware out for its HEADERS and compiles them with
# -fsyntax-only builds nothing: nothing is linked, nothing is installed, no
# artefact leaves the job. Counting the checkout as a build input reddened that
# job for doing exactly the measuring its exemption is written for -- measured,
# `carries this repository's build inputs: MIDDLEWARE_REF: main` over a job
# whose only compiler call links nothing. The builders are still asked four
# ways; this case is the one shape that has none of them.
d=$(mkcase case_80)
cat > "$d/.github/workflows/ci.yml" <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Resolve
        id: p
        run: |
          pin=$(tr -d '[:space:]' < cmake/libreagent.pin)
          echo "ref=$pin" >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreAgent
          ref: ${{ steps.p.outputs.ref }}
  drift:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    env:
      MIDDLEWARE_REF: main
    steps:
      - uses: actions/checkout@v4
        id: agent_trunk
        with:
          repository: LibreSCRS/LibreAgent
          ref: main
      - uses: actions/checkout@v4
        with:
          repository: LibreSCRS/LibreMiddleware
          ref: ${{ env.MIDDLEWARE_REF }}
          path: LibreMiddleware
      - name: Compile the headers and judge nothing else
        run: c++ -std=c++23 -fsyntax-only -I LibreMiddleware/include probe.cpp
Y
mkexc "$d" 'ci.yml:drift:agent_trunk  measures the agent trunk on purpose; compiles headers and builds nothing'
# rc alone would pass on a run that printed a build-input error and then found
# a pinned checkout elsewhere: this is the control for a rule that must print
# NOTHING about this job, so it asserts the absence and the counters too.
run_expect "case_80 CONTROL: an exempt job that only compiles headers" 0 "$d" \
    '!::error' \
    'SKIP: \.github/workflows/ci\.yml' \
    'agent-checkouts=2 pinned-refs=1 named-trunk-refs=1'

if [ "$fails" -eq 0 ]; then
    echo "check-agent-pin-wiring selftest: all cases passed ($cases)"
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 0
fi
echo "check-agent-pin-wiring selftest: $fails of $cases case(s) failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit 1
