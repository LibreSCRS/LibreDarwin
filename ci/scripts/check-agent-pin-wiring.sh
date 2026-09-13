#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-agent-pin-wiring.sh
#
# The LibreAgent revision this repository builds against lives in ONE place --
# cmake/libreagent.pin -- and every workflow that fetches the agent must read it
# from there.
#
# It did not always. The revision used to sit inline in
# cmake/FindOrUseLibreAgent.cmake as `GIT_TAG <40 hex>`, and two workflows mined
# it back out with a regex. When the revision moved into the pin file, the CMake
# file stopped carrying any hex -- so the regex started resolving to the empty
# string. One workflow died on `[ -z "$pin" ] && exit 1` naming a file that was
# correct; another kept going and compared a recorded revision against nothing.
# Neither failure names its cause, and nothing in this repository could see it:
# the two scripts that read a workflow look at timeout-minutes
# (check-job-timeouts.sh) and at which gate scripts are named
# (check-gates-wired.sh), not at where the agent ref comes from.
#
# Six rules, each a different way this can be wrong:
#   R1  cmake/libreagent.pin exists and holds exactly 40 lowercase hex.
#   R2  no workflow line outside a comment mentions GIT_TAG at all, or names
#       cmake/FindOrUseLibreAgent.cmake, the file the revision used to live
#       in. The miner was spelled two ways here (sed with [0-9a-f], grep -Eo
#       with {40}) and can be spelled a dozen more ([[:xdigit:]], \w{40}, an
#       awk column), or spelled without GIT_TAG at all (`grep -Eo
#       '[0-9a-f]{40}' cmake/FindOrUseLibreAgent.cmake`); once the revision
#       lives in the pin file a workflow has no reason to look at either, so
#       the mention is the defect whatever follows it.
#   R3  a workflow that checks out LibreSCRS/LibreAgent with actions/checkout
#       reads the pin file (a fetch written in the shell instead is R6) --
#       an actual read (a `<` redirect or `cat`) on a line that is not a
#       comment, with any trailing comment cut off first. The checkout counts
#       in every spelling GitHub accepts: owner/repo resolve case-insensitively
#       and YAML strips the quotes, so `"LibreSCRS/LibreAgent"` and
#       `librescrs/libreagent` are the same checkout as the bare one. A
#       `repository:` whose value is a `${{ }}` expression, or one folded into
#       a flow-style `{ ... }` mapping, is a checkout this gate cannot
#       classify, and fails for that reason rather than being skipped.
#   R4  that checkout USES the read: its `ref:` is `${{ steps.<id>.outputs.* }}`
#       (quoted or bare) and <id> is a step in the same job that performs the
#       read. One shape is exempt, and only by name: a job that checks the
#       agent out on purpose at a ref the pin does not name, because measuring
#       drift is its whole point. Such a step is listed in
#       ci/agent-ref-exceptions.txt WITH a reason, by ADDRESS -- <workflow
#       file>:<job>:<step id> -- and R3 and R4 then do not apply to it. The
#       address is the rule. A step id alone is unique only inside its job, so
#       an exemption keyed on the id travels: rename the building job's checkout
#       step to the exempt id, drop its `ref:` back to a branch, and every rule
#       here goes quiet without the exemption file being touched. Measured, it
#       did: the drift checkout removed and `build-macos` given `id:
#       agent_trunk` + `ref: main` read rc=0. With an address it cannot, because
#       the pardon now names the job as well.
#       A listed address that no agent checkout carries any more fails, so the
#       amnesty cannot outlive the job it was written for; an address TWO
#       checkouts carry fails as well; and a listed step with no `ref:` fails
#       too -- an exemption is for a ref named out loud, never for the default
#       branch nobody wrote down. Last, at least one agent checkout must still
#       be pinned: a repository whose every checkout is exempt has the pin wired
#       to nothing, and the counters would say so while the exit code did not.
#   R5  and the exempt job must be the shape the exemption file describes: it
#       measures drift and BUILDS NOTHING. Without this, R4's last clause is
#       satisfied by any pinned checkout anywhere -- so the shipping job can be
#       given a freshly written exemption of its own while a gate job that
#       compiles headers keeps the pinned count above zero. Measured, that read
#       rc=0 with the release build on `ref: main`. A job carrying an exempt
#       checkout may therefore not invoke a build system or publish an artefact.
#       "Builds nothing" is asked four ways, because each of the first three is
#       one step from being talked past. BUILDRE below is what building looks like
#       here -- a list of builders rather than of spellings, and a repository
#       that adds one adds it there. But a job can move its builders into a
#       script of its own and name none of them: measured, the release job with
#       every build line replaced by a single call to a tracked script read rc=0
#       with the agent on `main`. So a `run:` line naming a script this
#       repository ships is followed one level, and what that script does counts
#       as what the job does. And a job can be written without a builder but not
#       without its INPUTS, so INPUTRE asks the third way: an exempt job may not
#       check this repository's dependencies out, name the prefix they install
#       to or the ref they track, or take an artefact from another job.
#       Fourth: a job can move its steps into a LOCAL COMPOSITE ACTION and name
#       none of it, which is cheaper than the script above and was not followed
#       -- measured, the release job with its checkout, its cmake calls and its
#       ctest behind `uses: ./.github/actions/assemble` read rc=0 with the agent
#       on `main`. A local `uses:` in an exempt job is opened and judged by ALL
#       THREE of the rules above -- what it builds, what it consumes, and the
#       script it runs -- and every local action it reaches in turn, each opened
#       once. Two escapes were measured on the real workflow before it read that
#       way: the builders in a script named on a `run:` line INSIDE the action
#       (rc=0, while the identical script on a job `run:` line was rc=1), and an
#       action whose only step is `uses: ./<another>` with the builders in the
#       second one (rc=0, past a bound the file announced as "one level" and did
#       not enforce). A path that resolves to no action file here is refused;
#       it is resolved literally, against this checkout, and the only prefix
#       stripped is one a checkout in the same job declares with `path:`.
#       And a THIRD escape, which is what "judged by all three rules" cost when
#       it was written before it was true: everything above reads `steps:`, and
#       only a composite action has them. The same topology with the action
#       rewritten to `runs: {using: node20, main: index.js}` resolved to a real
#       action file and was then judged by nothing -- rc=0, no ::error at all.
#       So the kind is asked, and an action whose steps this gate cannot read is
#       refused where an unreadable path already is.
#       The `uses:` value is read with its YAML quoting removed, because
#       `uses: "./.github/actions/assemble"` is the same action written another
#       way and was, measured, neither followed nor refused: the shipping macOS
#       job built the release against an agent branch at rc=0 on one quote
#       character. An exemption is a statement about a job, so the gate reads
#       the job -- and everything the job reaches.
#   R6  and the agent can be fetched without actions/checkout at all: a
#       `git clone` (or `gh repo clone`, or a `git fetch`) naming LibreAgent in
#       a `run:` block, followed by a `git -C LibreAgent checkout <ref>`. That is
#       the live shape in a sibling consumer of this pin, and R3/R4 read
#       `repository:` keys, so they saw no checkout in it whatsoever. Measured
#       on this repository's own workflow with build-macos rewritten that way
#       and its resolve step deleted: agent-checkouts=2 pinned-refs=1, rc=0, no
#       ::error at all, while the job that ships the release built against the
#       agent trunk. Such a fetch counts as an agent checkout, and it must be
#       wired to the pin one of the two ways a shell fetch can be: the step
#       reads the pin itself, or it consumes `${{ steps.<id>.outputs.* }}` from
#       a step in the same job that does -- the same lookup R4 makes on a
#       `ref:`, applied to the body of the step instead of to a key, because a
#       resolve step feeding a shell fetch is as pinned as one feeding a
#       checkout and asking it to read the pin a second time buys nothing. A
#       fetch wired to neither is refused with the three ways out.
#       And the same rule takes the OTHER half of the shape: a `git checkout`,
#       `git switch` or `git reset` run inside the agent working tree. A fetch
#       is not the choke point it looked like -- after a checkout this gate
#       already blessed, `git -C LibreAgent fetch origin main` names no source
#       (`origin` is a remote NAME) and `git -C LibreAgent fetch --tags
#       --unshallow` names none either, and the line UNDER each of them takes
#       the trunk. Measured on a workflow satisfying R3 and R4 in full: rc=0, no
#       ::error, agent build on the trunk, three spellings of it. So a move run
#       in the agent tree is an agent checkout on the same terms as a fetch, and
#       wants the pin wired the same two ways.
#       What counts is narrower than "the line says LibreAgent", and wider than
#       one physical line:
#         - the LINES ARE FOLDED first. A command continued with a trailing
#           backslash is one command, and wrapping a long one is ordinary style
#           in these files -- `git clone --depth 1 \` with the URL underneath
#           puts the verb on one line and the repository on the next. Matched a
#           physical line at a time, that spelling restored the whole vacuum
#           above: measured, agent-checkouts=0, rc=0, no ::error.
#         - a FETCH must name the agent as a SOURCE -- anywhere except as the
#           directory the command runs in. `git -C LibreAgent fetch --tags
#           --unshallow` deepens a working copy and fetches from wherever that
#           copy already points; counted as a fetch OF the agent it turned a
#           fully wired workflow red and printed a remedy that workflow already
#           followed. `git -C LibreAgent fetch https://.../LibreAgent.git` names
#           a source and counts.
#         - a MOVE is judged the other way round: it counts when the directory
#           it runs IN is the agent, because that is what it acts on. The
#           directory is `-C <dir>`, or a `cd <dir>` / `pushd <dir>` in the same
#           command, or the last such `cd` earlier in the SAME step -- every
#           live `cd` in these workflows sits on a line of its own, so reading
#           only the command it stands in would miss the ordinary spelling.
#         - a token carrying a shell or workflow expansion is dropped before
#           either question. A computed value is not something written down (see
#           the doors below), and reading one as if it were made an unrelated
#           folded clone whose destination path merely contains the agent name
#           -- `"$LIBREAGENT_ROOT/../opensc"` under `git clone ... OpenSC.git`,
#           both halves live in these repositories -- into an agent fetch.
#
# Each rule exists because the one before it passed vacuously:
#   - delete the resolve step altogether and R2 is silent, while the checkout
#     takes the agent's default branch -- the moving target the pin exists to
#     remove. R3 catches that.
#   - replace the read with a hard-coded hash and the workflow still NAMES the
#     pin file four times, in comments and in its own error messages; a
#     name-only R3 stayed green. R3 therefore looks for a read, not a mention,
#     and not a read that survives only inside a trailing comment
#     (`pin=<hash>  # was: $(tr -d '[:space:]' < cmake/libreagent.pin)`).
#   - keep the read and change the checkout's `ref:` to `main`, or delete the
#     `ref:` line, or point it at some other step's output: R3 still sees its
#     read and stays green while the checkout ignores it. R4 catches that.
#   - and the exemption is that same rule read the other way: the one job that
#     must NOT be pinned says so in a tracked file, with a reason and with its
#     address, instead of being invisible. A pinned build cannot report that the base class has
#     moved -- a pin is the interface as it WAS, so it stays green on a
#     combination no release ships -- which is why such a job exists, and why
#     it may not simply be pinned to keep this gate quiet.
#   - keep the read and, on the next line, overwrite the variable from the
#     CMake file with a regex that never says GIT_TAG: R3 sees its read, R4
#     sees its wire, and the miner is back. This gate is textual; it cannot
#     follow a variable. Naming the CMake file at all is what it can see,
#     and no repaired workflow has a reason to.
#   - drop actions/checkout entirely and clone the agent in the job's own
#     shell: R3 and R4 look for a `repository:` key and there is none, so every
#     rule above is silent about a fetch that is really there. R6 counts it, in
#     the spellings named there -- and wraps the line, which is how that same
#     silence came back once the rule existed.
#   - keep the pinned actions/checkout, satisfy R3 and R4 in full, and move the
#     working tree it left behind with one more line: `git -C LibreAgent
#     checkout main`, or `reset --hard origin/main`, or the same after a `cd`.
#     A rule that counted only FETCHES saw a fetch that names no source and
#     stayed silent while the build took the trunk. R6 counts the move too.
#   - spell the checkout `"LibreSCRS/LibreAgent"` or `librescrs/libreagent`
#     and a match on the bare, exact-case spelling saw no checkout at all:
#     R3 and R4 had nothing to apply to, and the workflow passed with the read
#     deleted and `ref: main`. The match now normalises case and quotes, and
#     the two spellings it cannot normalise (an expression, a flow mapping)
#     are errors instead of blind spots.
#
# Scans the workflow files under one directory, relative to the current
# directory, so a sibling repository without its own copy can borrow one. The
# exemption file is the third argument and defaults to
# ci/agent-ref-exceptions.txt; a repository that ships none has no exemptions. A
# composite action (.github/actions/*/action.yml) has the same `steps:` shape
# and is NOT scanned unless its directory is passed as the first argument;
# this repository ships none. Pass `-` as the pin path for a repository that
# owns no pin file and reads a sibling's over the API: R1 is skipped, R2 still
# runs, and R3/R4 fail outright if such a repository checks the agent out --
# give it a real pin file rather than leaving it on `-`.
#
# Threat model. This gate catches an honest regression: a checkout, a shell
# fetch or move, or a build step written directly in a job's own `steps:`, in the
# ordinary shapes this repository's workflows and its siblings' are written in
# today, that stops reading the pin or stops using what it read. It reads YAML
# as text, one `steps:` block at a time, so it cannot see what a job assembles
# out of other files and does not try to, except for the one case R5 opens on
# purpose: a LOCAL composite
# action a job EXEMPTED in ci/agent-ref-exceptions.txt reaches through
# `uses: ./...`, which is followed and judged recursively because that is
# exactly the shape the exempt job is trusted not to abuse. Known door,
# measured on this repository's own workflow: that following is done only for
# an exempt job. R3/R4's own checkout count (`agent-checkouts` in the summary
# line below) reads a job's literal `steps:` and nothing a `uses: ./...` in it
# points at. Moving a NON-exempt job's OWN LibreSCRS/LibreAgent checkout --
# `build-macos`'s, the one this gate exists to keep pinned -- behind a local
# composite action makes that checkout invisible to the count: measured,
# `agent-checkouts` silently drops from 3 to 2, rc=0, no `::error` at all. The
# checkout is still real and still unpinned from this gate's point of view; it
# is simply not counted, because the recursive action-reading this gate has
# only extends to jobs already named as exempt. `agent-checkouts` counts the
# `repository:` checkouts of a job's literal `steps:` PLUS R6's shell fetches
# and moves, and nothing else.
# Four more doors, all R6's, all named rather than closed. First, a step that
# reads the pin and then takes a branch anyway -- `pin=$(< ...libreagent.pin)`
# on one line and `git -C LibreAgent checkout main` on the next -- is counted
# as pinned: the read is the only evidence a shell fetch offers, and following
# the variable from the read to the checkout argument is past what a textual
# rule can do. It leaves a variable nothing uses, which is not a shape this
# project writes -- and being counted as pinned, such a step also satisfies
# R4's last clause, the one that wants at least one agent checkout still wired
# to the pin. The same holds one remove: a step that CONSUMES
# `${{ steps.<id>.outputs.* }}` from a reading step ANYWHERE in its body counts
# as pinned even if the fetch beside it uses something else, on exactly the
# terms the read itself does and for the same reason.
# Second, a fetch has to NAME the agent: a URL held in a variable
# (`url=https://.../LibreAgent.git` on one line, `git clone "$url" agent-src` on
# the next) is a computed value, and a textual rule reads what is written. The
# converse holds for a move, which is judged by the directory it runs IN: a
# move whose directory is computed (`cd "$AGENT_DIR"`) is not seen either. Such
# a `cd` leaves the directory UNKNOWN rather than inherited from an earlier one
# -- the safe way round for false reds, the leaky way round for this door.
# Third, a `cd` is followed only inside ONE step: the runner gives each step its
# own shell and its own working directory, so a `cd` in an earlier step does not
# carry, and neither does one inside a script this gate does not open.
# And a shell fetch cannot be EXEMPTED: an exemption addresses
# <workflow>:<job>:<step id> and is matched against `repository:` checkouts, so
# a listed address that only a fetch carries is a stale entry and fails. A job
# that must take the agent trunk on purpose writes it as actions/checkout, gives
# the step an id and lists that address -- which is the readable shape anyway.
set -u

wfdir=${1:-.github/workflows}
pinfile=${2:-cmake/libreagent.pin}
exceptions=${3:-ci/agent-ref-exceptions.txt}
rc=0

shopt -s nullglob
files=("$wfdir"/*.yml "$wfdir"/*.yaml)
shopt -u nullglob

if [ "${#files[@]}" -eq 0 ]; then
    echo "no workflow files under $wfdir — nothing to check, and that is not a pass" >&2
    exit 2
fi

# Whole-line comments dropped, trailing comments cut off. Lines keep their
# numbers (grep -n) so an error can point at one.
numbered_code_lines() {  # numbered_code_lines <file> -> "<lineno>:<line>"
    grep -n '' "$1" | grep -v '^[0-9]*:[[:space:]]*#' | sed 's/[[:space:]]#.*$//'
}

# The code lines of ONE job, numbered. Jobs are the keys directly under the
# top-level `jobs:`; a line belongs to the job whose key most recently opened at
# that depth. Used by R5, which judges what an exempt job does rather than how
# its checkout is spelled.
job_lines() {  # job_lines <file> <job name> -> "<lineno>:<line>"
    awk -v want="$2" '
    BEGIN { injobs = 0; jobind = -1; cur = "" }
    {
        line = $0
        if (line ~ /^[[:space:]]*(#|$)/) next
        sub(/[[:space:]]#.*$/, "", line)
        match(line, /^[[:space:]]*/); ind = RLENGTH
        if (line ~ /^jobs:[[:space:]]*$/) { injobs = 1; jobind = -1; cur = ""; next }
        if (!injobs) next
        if (ind == 0) { injobs = 0; next }
        if (jobind < 0) jobind = ind
        if (ind == jobind && line ~ /^[[:space:]]*[A-Za-z0-9_.-]+:[[:space:]]*$/) {
            cur = line; sub(/^[[:space:]]*/, "", cur); sub(/:[[:space:]]*$/, "", cur); next
        }
        if (cur == want) print NR ":" line
    }' "$1"
}

# What building or publishing looks like in this project. A job that does any of
# it is not the drift job the exemption file describes, whatever its reason
# says. It is a list of builders, not of spellings, and a repository that adds
# one adds it here.
BUILDRE='(cmake[[:space:]]+(--build|--install|-B)|(^|[^A-Za-z0-9_-])(ctest|xcodebuild|ninja|make|msbuild|gradle)([^A-Za-z0-9_-]|$)|swift[[:space:]]+build|upload-artifact|action-gh-release|FETCHCONTENT_SOURCE_DIR)'
# Fetching a build tool is not building with it: `brew install ninja` names a
# builder and runs none, and a rule that reported it would name the wrong line
# in a job that really does build ten lines further down.
INSTALLRE='(brew|apt|apt-get|yum|dnf|apk|pip|pip3|npm|gem|choco)[[:space:]]+(-[^[:space:]]+[[:space:]]+)*install'
# What a building job CONSUMES. A job can be written to build without naming a
# builder -- put the builders in a script -- but not without its inputs: this
# repository's own dependency checkout, the prefix that build installs to, the
# ref it tracks, or an artefact another job produced. A drift job needs none of
# them.
INPUTRE='(LM_PREFIX|MIDDLEWARE_REF|[Ll]ibre[Ss][Cc][Rr][Ss]/[Ll]ibre[Mm]iddleware|download-artifact)'

# One level of indirection, for the same reason: a `run:` line naming a script
# this repository ships is followed, and what the script does counts as what the
# job does. Comments are cut off first -- a gate script that explains a builder
# in prose is not one. One level, not a graph: a script that calls a script is
# past what a textual rule can follow, and the two rules above are what remains.
# Numbered code lines on stdin, so the same rule can be pointed at a job's lines
# or at a composite action's. It read a job only, and the indirection then moved
# one step sideways: the builders in a script named on a `run:` line INSIDE a
# local action were reached by nothing, while the identical script named on a
# job `run:` line was caught.
script_builders_lines() {  # numbered lines on stdin -> "<lineno>: <script> runs <line>"
    local ln text cand rest hit
    while IFS=: read -r ln text; do
        [ -n "$ln" ] || continue
        for cand in $(printf '%s\n' "$text" | grep -oE '[A-Za-z0-9_./-]+\.(sh|bash|py)' || true); do
            rest=${cand#./}
            # The run: line names the script as the JOB sees it, which may carry
            # the path this repository is checked out under. Leading components
            # are dropped until one resolves here, or none does.
            while [ -n "$rest" ] && [ ! -f "$rest" ]; do
                case "$rest" in */*) rest=${rest#*/} ;; *) rest="" ;; esac
            done
            [ -n "$rest" ] || continue
            hit=$(numbered_code_lines "$rest" | grep -vE "$INSTALLRE" | grep -Em1 "$BUILDRE" || true)
            if [ -n "$hit" ]; then
                printf '%s: %s runs %s\n' "$ln" "$rest" "${hit#*:}"
                return 0
            fi
        done
    done
    return 0
}
script_builders() {  # script_builders <file> <job> -> "<lineno>: <script> runs <line>"
    job_lines "$1" "$2" | script_builders_lines
}

# And the same one level for a LOCAL COMPOSITE ACTION. `uses: ./<path>` is the
# standard way to move steps out of a workflow -- cheaper than the script
# indirection above, and the rule that followed `run:` did not follow it:
# measured, the release job with its LibreMiddleware checkout, its `cmake -B`,
# its `cmake --build` and its `ctest` moved into .github/actions/assemble and
# invoked as `uses: ./.github/actions/assemble` read rc=0 with the agent on
# `main`. So the action file is opened and judged by the same two rules, what it
# builds and what it consumes. A local `uses:` whose path does not resolve here
# is refused rather than skipped: an exempt job may not reach code this gate
# cannot read. Actions from the marketplace are not followed -- `actions/`
# and every other `owner/repo@ref` form is somebody else's tree -- and
# BUILDRE already names the two of them that publish.
# What a `uses:` line names, with YAML quoting removed. The path used to be cut
# out with a regex that wanted `./` to follow the whitespace directly, and
# `uses: "./.github/actions/assemble"` -- standard YAML, resolving to the same
# action, run by GitHub identically -- was then neither followed nor refused:
# the release job built against an agent branch at rc=0 on one quote character.
# A rule keyed on a spelling admits whoever picks another spelling, and this
# file has now paid that four times.
uses_value() {  # uses_value <line> -> the value, or ""
    local v="$1"
    case "$v" in *uses:*) ;; *) return 0 ;; esac
    v=${v#*uses:}
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    case "$v" in
        \"*\") v=${v#\"}; v=${v%\"} ;;
        \'*\') v=${v#\'}; v=${v%\'} ;;
    esac
    printf '%s\n' "$v"
}
action_file() {  # action_file <path> -> the action file, rc 0 when there is one
    if   [ -f "$1" ];              then printf '%s\n' "$1"
    elif [ -f "$1/action.yml" ];   then printf '%s\n' "$1/action.yml"
    elif [ -f "$1/action.yaml" ];  then printf '%s\n' "$1/action.yaml"
    else return 1
    fi
    return 0
}
# `uses: ./<path>` is resolved LITERALLY, against this checkout's root, which is
# what GitHub does with it. Leading components were dropped until something
# existed, and a path that named no action here was then judged by whatever file
# the stripping happened to land on -- a different file from the one written,
# and the error named it. The one prefix that is stripped is one a checkout in
# THIS job actually declares with `path:`, because a workflow that checks this
# repository out under a directory names its own actions through it.
resolve_local() {  # resolve_local <file> <job> <path> -> action file, rc 1 when none
    local f="$1" job="$2" cand="$3" rest pv p
    rest=${cand#./}
    rest=${rest%/}
    [ -n "$rest" ] || return 1
    action_file "$rest" && return 0
    while IFS=: read -r _ pl; do
        pv=$(printf '%s\n' "$pl" | sed -n 's|^[[:space:]]*path:[[:space:]]*\(.*\)$|\1|p')
        [ -n "$pv" ] || continue
        pv=${pv#\"}; pv=${pv%\"}; pv=${pv#\'}; pv=${pv%\'}; pv=${pv%/}
        [ -n "$pv" ] || continue
        case "$rest" in
            "$pv"/*) p=${rest#"$pv"/}; action_file "$p" && return 0 ;;
        esac
    done < <(job_lines "$f" "$job")
    return 1
}
# One local action, and every local action it reaches. The three rules a JOB is
# judged by are all applied to it -- what it builds, what it consumes, and the
# script it runs -- because an escape that moves one step is an escape that
# moves two: measured, the builders in a script named on a `run:` line inside
# the action read rc=0 while the same script named on a job line read rc=1.
# Nesting is followed rather than granted: `uses: ./a` whose action is
# `uses: ./b` was "one level" and therefore invisible, which is a bound the gate
# announced and did not enforce. Each action is opened once, so a cycle ends.
# What kind of action a local action file declares. Everything below reads
# `steps:`, which only a composite action has: a node or a docker action's work
# is in an index.js or an image, and both resolve to an action file and are then
# judged by nothing at all. Measured on the real workflow with every builder
# moved behind `uses: ./.github/actions/assemble` and that action rewritten to
# `runs: {using: node20, main: index.js}`, the gate read rc=0 with no ::error at
# all. So the kind is asked, and a kind whose steps this gate cannot read is
# refused where the unreadable local `uses:` already is.
action_using() {  # action_using <action file> -> the `using:` value, or ""
    numbered_code_lines "$1" \
        | sed -n 's|^[0-9]*:[[:space:]]*using:[[:space:]]*\(.*\)$|\1|p' \
        | head -1 | tr -d '"'\''' | tr -d '[:space:]'
}
judge_action() {  # judge_action <file> <job> <action file> -> "<why>" or ""
    local f="$1" job="$2" af hit text cand next using seen=" $3 "
    local -a queue=("$3")
    while [ "${#queue[@]}" -gt 0 ]; do
        af=${queue[0]}
        queue=("${queue[@]:1}")
        using=$(action_using "$af")
        if [ "$using" != composite ]; then
            printf 'the local action %s is a %s action, whose steps this gate cannot read -- an exempt job may not reach work this gate cannot judge\n' \
                "$af" "${using:-kindless}"
            return 0
        fi
        hit=$(numbered_code_lines "$af" | grep -vE "$INSTALLRE" | grep -Em1 "$BUILDRE" || true)
        if [ -n "$hit" ]; then
            printf 'the local action %s builds: %s\n' "$af" "${hit#*:}"; return 0
        fi
        hit=$(numbered_code_lines "$af" | grep -Em1 "$INPUTRE" || true)
        if [ -n "$hit" ]; then
            printf 'the local action %s carries this repository build inputs: %s\n' "$af" "${hit#*:}"; return 0
        fi
        hit=$(numbered_code_lines "$af" | script_builders_lines)
        if [ -n "$hit" ]; then
            printf 'the local action %s runs a script of this repository that builds: %s\n' "$af" "${hit#*: }"; return 0
        fi
        while IFS=: read -r _ text; do
            cand=$(uses_value "$text")
            case "$cand" in ./*) ;; *) continue ;; esac
            if ! next=$(resolve_local "$f" "$job" "$cand"); then
                printf 'the local action %s uses %s, which does not resolve to an action file here -- an exempt job may not reach steps this gate cannot read\n' "$af" "$cand"
                return 0
            fi
            case "$seen" in *" $next "*) continue ;; esac
            seen="$seen$next "
            queue+=("$next")
        done < <(numbered_code_lines "$af")
    done
    return 0
}
action_builders() {  # action_builders <file> <job> -> "<lineno>: <why>"
    local ln text cand af hit
    while IFS=: read -r ln text; do
        [ -n "$ln" ] || continue
        cand=$(uses_value "$text")
        case "$cand" in ./*) ;; *) continue ;; esac
        if ! af=$(resolve_local "$1" "$2" "$cand"); then
            printf '%s: uses the local action %s, which does not resolve to an action file here -- an exempt job may not reach steps this gate cannot read\n' "$ln" "$cand"
            return 0
        fi
        hit=$(judge_action "$1" "$2" "$af")
        if [ -n "$hit" ]; then
            printf '%s: %s\n' "$ln" "$hit"
            return 0
        fi
    done < <(job_lines "$1" "$2")
    return 0
}

# R1 -- the pin file itself. `-` means this repository owns no pin file (it
# reads a sibling's over the API); the other rules still apply.
if [ "$pinfile" = "-" ]; then
    :
elif [ ! -f "$pinfile" ]; then
    echo "::error file=$pinfile::the pin file does not exist; there is no revision for a workflow to read"
    rc=1
else
    pin=$(tr -d '[:space:]' < "$pinfile")
    case "$pin" in
        *[!0-9a-f]* | "")
            echo "::error file=$pinfile::pin is not lowercase hex: '$pin'"
            rc=1 ;;
        *)
            if [ "${#pin}" -ne 40 ]; then
                echo "::error file=$pinfile::pin is ${#pin} chars, want 40: '$pin'"
                rc=1
            fi ;;
    esac
fi

# R2 -- nobody looks at a GIT_TAG occurrence, or at the CMake file the
# revision used to live in. The three repositories that own a pin file all
# call that file FindOrUseLibreAgent.cmake.
cmakefile=FindOrUseLibreAgent.cmake
mined=0
cmakelines=0
for f in "${files[@]}"; do
    while IFS=: read -r lineno text; do
        [ -n "$lineno" ] || continue
        case "$text" in
            *GIT_TAG*)
                echo "::error file=$f,line=$lineno::this line looks at a GIT_TAG occurrence;" \
                     "the revision lives in a pin file — read that instead"
                mined=$((mined + 1)) ;;
            *)
                echo "::error file=$f,line=$lineno::this line names $cmakefile, which no longer carries" \
                     "the revision; it lives in a pin file — read that instead"
                cmakelines=$((cmakelines + 1)) ;;
        esac
        rc=1
    done < <(numbered_code_lines "$f" | grep -E "GIT_TAG|${cmakefile//./\\.}")
done

# The read this gate looks for: a `<` redirect or a `cat` naming the pin file.
pinbase=$(basename "$pinfile" | sed 's/[.[\*^$]/\\&/g')
readre="(<|cat)[[:space:]]*[^[:space:]]*$pinbase"

# One record per step, fields separated by \037 (a tab would collapse the
# empty ones): job number, step id, 1 if the step reads the pin, the line of
# a `repository:` naming LibreSCRS/LibreAgent in it (0 if none), its `ref:`,
# the line of a `repository:` whose value is an expression (0 if none), the
# line of a flow-style mapping the scanner cannot read (0 if none), the line of
# a `git clone` / `gh repo clone` / `git fetch` naming the agent in the step's
# own shell (0 if none) -- R6's shape, which is not a `uses:` at all -- and the
# step outputs (`${{ steps.<id>.outputs.* }}`) that step's body consumes, so a
# shell fetch can be wired through a resolve step the way a checkout is.
# Steps are the list items directly under a `steps:` key -- the list's own
# indentation delimits them, so a `- name:` deeper inside a run block or a
# matrix include is not mistaken for one. A `steps:` key starts a new job.
# Key values are compared with their YAML quotes stripped and, for the
# repository, in lower case: GitHub resolves owner/repo case-insensitively.
# The regex goes in through the environment: `awk -v` rewrites backslash
# escapes, and the pin's dot is escaped. \047 is the single quote, which
# cannot appear literally inside this single-quoted program.
scan_steps() {  # scan_steps <file>
    READRE=$readre awk '
    function value(kv,    v) {
        v = kv
        sub(/^[^:]*:[[:space:]]*/, "", v); sub(/[[:space:]]*,?[[:space:]]*$/, "", v)
        return v
    }
    function unquote(v) {
        if (v ~ /^"[^"]*"$/ || v ~ /^\047[^\047]*\047$/) v = substr(v, 2, length(v) - 2)
        return v
    }
    function flush() {
        if (instep) printf "%d\037%s\037%d\037%d\037%s\037%d\037%d\037%d\037%s\037%s\037%s\n", job, id, reads, agentline, ref, exprline, flowline, cloneline, outrefs, jobname, clonekind
        instep = 0; id = ""; reads = 0; agentline = 0; ref = ""; exprline = 0; flowline = 0; cloneline = 0; outrefs = ""; cont = ""; clonekind = ""; curdir = ""
    }
    BEGIN { insteps = 0; stepind = -1; instep = 0; job = 0; jobname = ""; cloneline = 0; outrefs = ""; cont = ""; clonekind = ""; curdir = "" }
    {
        line = $0
        if (line ~ /^[[:space:]]*(#|$)/) next
        sub(/[[:space:]]#.*$/, "", line)
        match(line, /^[[:space:]]*/); ind = RLENGTH
        if (line ~ /^[[:space:]]*steps:[[:space:]]*$/) {
            flush(); insteps = 1; stepind = -1; job++
            # The job this steps: belongs to is the nearest enclosing block key:
            # the deepest remembered key still shallower than this line.
            jobname = ""; best = -1
            for (i in keyname) if (i + 0 < ind && i + 0 > best) { best = i + 0; jobname = keyname[i] }
            next
        }
        # Remember block keys by indentation, so the lookup above has something
        # to find. A key resets everything at or below its own depth.
        if (line ~ /^[[:space:]]*[A-Za-z0-9_.-]+:[[:space:]]*$/) {
            kn = line; sub(/^[[:space:]]*/, "", kn); sub(/:[[:space:]]*$/, "", kn)
            for (i in keyname) if (i + 0 >= ind) delete keyname[i]
            keyname[ind] = kn
        }
        if (!insteps) next
        if (stepind < 0) {
            if (line ~ /^[[:space:]]*-[[:space:]]/) stepind = ind
            else { insteps = 0; next }
        }
        if (ind < stepind) { flush(); insteps = 0; next }
        if (ind == stepind) {
            flush()
            if (line ~ /^[[:space:]]*-[[:space:]]/) instep = 1
            else { insteps = 0; next }
        }
        if (!instep) next
        body = line
        sub(/^[[:space:]]*(-[[:space:]]+)?/, "", body)
        if (body ~ /^id:/) id = unquote(value(body))
        else if (body ~ /^repository:/) {
            v = value(body)
            if (v ~ /\$\{\{/) exprline = NR
            else if (tolower(unquote(v)) == "librescrs/libreagent") agentline = NR
        }
        else if (body ~ /^ref:/) ref = unquote(value(body))
        else if (tolower(line) ~ /[{,][[:space:]]*repository:[[:space:]]*(["\047]?librescrs\/libreagent|\$\{\{)/) flowline = NR
        # The step outputs consumed in the body of this step, for the same
        # lookup R4 performs on a `ref:`: a shell fetch can be wired to the pin
        # through the output of a resolve step exactly as a checkout is.
        rest = line
        while (match(rest, /\$\{\{[[:space:]]*steps\.[A-Za-z_][A-Za-z0-9_-]*\.outputs\./)) {
            t = substr(rest, RSTART, RLENGTH)
            rest = substr(rest, RSTART + RLENGTH)
            sub(/^\$\{\{[[:space:]]*steps\./, "", t); sub(/\.outputs\.$/, "", t)
            if (index(" " outrefs " ", " " t " ") == 0) outrefs = (outrefs == "" ? t : outrefs " " t)
        }
        # The agent taken by the shell of the step itself rather than by a
        # checkout action. Physical lines are FOLDED first: a command continued
        # with a trailing backslash is one command, and wrapping a long one is
        # ordinary style in these files, so `git clone --depth 1 \` with the URL
        # on the next line has its verb and its repository on two lines and one
        # physical line is not the unit to match. The whole line is lower-cased
        # before the comparison, which is why -C is spelled -c here and no
        # character class is needed.
        # Two shapes count, told apart by WHERE the agent is named:
        #   fetch -- `git clone` / `git fetch` / `gh repo clone` naming the agent
        #     as a SOURCE, that is: anywhere except as the directory the command
        #     runs in. `git -C LibreAgent fetch --tags --unshallow` deepens a
        #     working copy and names no source, so it is not one.
        #   move  -- `git checkout` / `git switch` / `git reset` run IN the agent
        #     working tree. That is how a checkout actions/checkout pinned is
        #     taken off its pin one line later, and the deepening fetch above is
        #     harmless only until such a line stands next to it.
        # The directory a command runs in is `-C <dir>`, or a `cd <dir>` /
        # `pushd <dir>` in the same command, or the last such `cd` earlier in the
        # SAME step -- shell house style here puts `cd` on a line of its own. A
        # `cd` whose argument is a computed value leaves the directory unknown
        # rather than inherited.
        # Tokens carrying a shell or workflow expansion are dropped before either
        # question: a computed value is not something written down, and reading
        # one as if it were turned an unrelated clone whose destination path
        # merely contains the agent name into an agent fetch.
        low = tolower(line)
        if (cont != "") logical = cont " " low
        else { logical = low; lstart = NR }
        if (line ~ /\\[[:space:]]*$/) cont = logical
        else {
            cont = ""
            probe = logical
            gsub(/[^[:space:]]*\$[^[:space:]]*/, " ", probe)
            nf = split(probe, tok, /[[:space:]]+/)
            wdir = ""; named = ""; sawcd = 0
            for (i = 1; i <= nf; i++) {
                if (tok[i] == "-c" && i < nf && tok[i + 1] ~ /=/) {
                    # `git -c key=value`, a setting rather than a directory:
                    # lower-casing makes -C and -c the same word, and the `=` is
                    # what tells them apart.
                    i++
                } else if (tok[i] == "-c" || tok[i] == "cd" || tok[i] == "pushd") {
                    if (tok[i] != "-c") sawcd = 1
                    if (i < nf) { wdir = wdir " " tok[i + 1]; i++ }
                } else named = named " " tok[i]
            }
            here = (wdir != "" ? wdir : curdir)
            if (cloneline == 0) {
                if (named ~ /libreagent/ && \
                    logical ~ /(git[[:space:]]+(-c[[:space:]]+[^[:space:]]+[[:space:]]+)*(clone|fetch)|gh[[:space:]]+repo[[:space:]]+clone)/) {
                    cloneline = lstart; clonekind = "fetch"
                } else if (here ~ /libreagent/ && \
                    logical ~ /git[[:space:]]+(-c[[:space:]]+[^[:space:]]+[[:space:]]+)*(checkout|switch|reset)([^0-9A-Za-z_-]|$)/) {
                    cloneline = lstart; clonekind = "move"
                }
            }
            if (sawcd) curdir = wdir
        }
        if (line ~ ENVIRON["READRE"]) reads = 1
    }
    END { flush() }' "$1"
}

# The named exemptions: an ADDRESS -- <workflow file>:<job>:<step id> -- then a
# reason. An entry without a reason is rejected: an exemption whose ground is not
# written down is a pardon. A bare step id is not an address: an id is unique
# only inside its job, so the shipping job could take the exempt step's name and
# be pardoned by a line nobody re-read. Moving the amnesty now means editing this
# file, which is the point of it.
declare -A trunk_reason=()
declare -A trunk_count=()
declare -A trunk_where=()
if [ -f "$exceptions" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue;; esac
        addr=${line%%[[:space:]]*}
        why=${line#"$addr"}; why=${why#"${why%%[![:space:]]*}"}
        case "$addr" in
            *:*:*:*|*:*:*)
                if [ "${addr%%:*}" = "" ] || [ "${addr##*:}" = "" ] || [ "$(printf '%s' "$addr" | tr -cd ':' | wc -c)" -ne 2 ]; then
                    echo "::error file=$exceptions::'$addr' is not an address; write <workflow file>:<job>:<step id>"
                    rc=1
                    continue
                fi ;;
            *)
                echo "::error file=$exceptions::'$addr' is a bare name, not an address; write <workflow file>:<job>:<step id> so the amnesty cannot travel to another job by having its step renamed"
                rc=1
                continue ;;
        esac
        if [ -z "$why" ]; then
            echo "::error file=$exceptions::'$addr' carries no reason"
            rc=1
            continue
        fi
        trunk_reason[$addr]=$why
    done < "$exceptions"
fi

# R3 -- a workflow that checks the agent out must read the pin file.
# R4 -- and the checkout must use that read: `ref:` names the output of the
# step, in the same job, that performed it.
checkouts=0
pinned=0
trunk=0
unreadable=0
for f in "${files[@]}"; do
    mapfile -t steps < <(scan_steps "$f")
    unset readers
    declare -A readers=()
    for s in "${steps[@]}"; do
        IFS=$'\037' read -r job id reads _ _ _ _ _ _ _ _ <<< "$s"
        [ "$reads" = 1 ] && [ -n "$id" ] && readers["$job/$id"]=1
    done
    for s in "${steps[@]}"; do
        IFS=$'\037' read -r job id reads agentline ref exprline flowline cloneline outrefs jobname clonekind <<< "$s"
        if [ "$exprline" != 0 ]; then
            echo "::error file=$f,line=$exprline::checks out a repository named by an expression; this gate" \
                 "cannot tell whether that is LibreSCRS/LibreAgent, so name the repository literally"
            unreadable=$((unreadable + 1))
            rc=1
        fi
        if [ "$flowline" != 0 ]; then
            echo "::error file=$f,line=$flowline::checks out LibreSCRS/LibreAgent (or an expression) inside a" \
                 "flow-style mapping; this gate reads one key per line, so spell the checkout out in block style"
            unreadable=$((unreadable + 1))
            rc=1
        fi
        # R6 -- the agent fetched by the step's own shell. Counted as a
        # checkout, and the pin has to reach it one of the two ways a shell
        # fetch can be wired: the step reads the pin itself, or it consumes the
        # output of a step in the same job that does -- the same lookup R4
        # performs on a `ref:`.
        if [ "$cloneline" != 0 ]; then
            checkouts=$((checkouts + 1))
            if [ "$clonekind" = move ]; then
                what="moves the LibreSCRS/LibreAgent working tree to a revision of its own"
            else
                what="fetches LibreSCRS/LibreAgent"
            fi
            wired=$reads
            if [ "$wired" != 1 ]; then
                # Unquoted on purpose: outrefs is the space-separated list of
                # step outputs this step consumes.
                # shellcheck disable=SC2086
                for src in $outrefs; do
                    if [ -n "${readers["$job/$src"]:-}" ]; then
                        wired=1
                        break
                    fi
                done
            fi
            if [ "$pinfile" = "-" ]; then
                echo "::error file=$f,line=$cloneline::$what, but this repository was" \
                     "declared pinless (-); give it a real pin file"
                rc=1
            elif [ "$wired" = 1 ]; then
                pinned=$((pinned + 1))
            else
                echo "::error file=$f,line=$cloneline::$what in a run: block that neither" \
                     "reads $pinfile nor uses the output of a step that does; the revision it lands on comes" \
                     "from somewhere this gate cannot see. Read the pin in this step, take a" \
                     "\${{ steps.<id>.outputs.* }} from the step that reads it, or write the checkout as" \
                     "actions/checkout with repository: LibreSCRS/LibreAgent and a ref:"
                rc=1
            fi
        fi

        [ "$agentline" != 0 ] || continue
        checkouts=$((checkouts + 1))
        if [ "$pinfile" = "-" ]; then
            echo "::error file=$f,line=$agentline::checks out LibreSCRS/LibreAgent, but this repository was" \
                 "declared pinless (-); give it a real pin file"
            rc=1
            continue
        fi
        if [ -z "$jobname" ]; then
            echo "::error file=$f,line=$agentline::this checkout is not inside a job this gate can name, so no" \
                 "exemption can be addressed to it and none may be assumed"
            unreadable=$((unreadable + 1))
            rc=1
            continue
        fi
        addr="$(basename "$f"):$jobname:$id"
        if [ -n "$id" ] && [ -n "${trunk_reason[$addr]:-}" ]; then
            trunk_count[$addr]=$(( ${trunk_count[$addr]:-0} + 1 ))
            trunk_where[$addr]="${trunk_where[$addr]:+${trunk_where[$addr]}, }$f:$agentline"
            trunk=$((trunk + 1))
            if [ -z "$ref" ]; then
                echo "::error file=$f,line=$agentline::step '$addr' is listed in $exceptions but names no ref:;" \
                     "actions/checkout then takes the agent's default branch, which is not a ref anyone wrote down"
                rc=1
            else
                echo "SKIP: $f:$agentline checks out LibreSCRS/LibreAgent at '$ref' --" \
                     "step '$addr' is listed in $exceptions: ${trunk_reason[$addr]}"
            fi
            # R5 -- and this job builds nothing. An exemption is granted to a
            # job that measures the agent trunk, not to one that ships against
            # it: the pinned count is repository-wide, so a gate job holds it
            # above zero while the release build takes a branch. Asked three
            # ways, because naming the builders is the easiest of the three to
            # stop doing.
            exempt_why=""
            exempt_hit=$(job_lines "$f" "$jobname" | grep -vE "$INSTALLRE" | grep -Em1 "$BUILDRE" || true)
            [ -n "$exempt_hit" ] && exempt_why="builds:${exempt_hit#*:}"
            if [ -z "$exempt_why" ]; then
                exempt_hit=$(job_lines "$f" "$jobname" | grep -Em1 "$INPUTRE" || true)
                [ -n "$exempt_hit" ] && exempt_why="carries this repository's build inputs:${exempt_hit#*:}"
            fi
            if [ -z "$exempt_why" ]; then
                exempt_hit=$(script_builders "$f" "$jobname")
                [ -n "$exempt_hit" ] && exempt_why="runs a script of this repository that builds:${exempt_hit#*:}"
            fi
            if [ -z "$exempt_why" ]; then
                exempt_hit=$(action_builders "$f" "$jobname")
                if [ -n "$exempt_hit" ]; then
                    exempt_why="${exempt_hit#*:}"
                    exempt_why="${exempt_why# }"
                fi
            fi
            if [ -n "$exempt_why" ]; then
                echo "::error file=$f,line=${exempt_hit%%:*}::job '$jobname' carries the exempt agent" \
                     "checkout '$addr' and $exempt_why. An exemption is for a job that measures" \
                     "the agent trunk and builds nothing — a job that builds takes the agent from $pinfile"
                rc=1
            fi
            continue
        fi
        if ! numbered_code_lines "$f" | grep -Eq "$readre"; then
            echo "::error file=$f,line=$agentline::checks out LibreSCRS/LibreAgent but never reads $pinfile;" \
                 "the ref it uses comes from somewhere this gate cannot see"
            rc=1
            continue
        fi
        if [ -z "$ref" ]; then
            echo "::error file=$f,line=$agentline::checks out LibreSCRS/LibreAgent with no ref:" \
                 "actions/checkout then takes the agent's default branch, the moving target the pin exists to remove"
            rc=1
        elif [[ $ref =~ ^\$\{\{[[:space:]]*steps\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.[A-Za-z_][A-Za-z0-9_-]*[[:space:]]*\}\}$ ]]; then
            src=${BASH_REMATCH[1]}
            if [ -n "${readers["$job/$src"]:-}" ]; then
                pinned=$((pinned + 1))
            else
                echo "::error file=$f,line=$agentline::ref comes from step '$src', which does not read $pinfile" \
                     "in this job; the checkout is wired to something other than the pin"
                rc=1
            fi
        else
            echo "::error file=$f,line=$agentline::ref is '$ref', not the output of the step that reads $pinfile"
            rc=1
        fi
    done
done

# An amnesty that outlives its job is worse than none: it reads like a rule
# somebody still needs, and the next agent checkout can quietly borrow the id.
# Both directions are errors -- an entry no checkout carries, and an entry two
# of them do. A step id is unique per JOB, not per workflow, so the second is
# legal YAML: copy the exempt step's `with:` block into the building job, keep
# its id, and every checkout in the repository is pardoned by one line nobody
# re-read.
for addr in "${!trunk_reason[@]}"; do
    n=${trunk_count[$addr]:-0}
    if [ "$n" -eq 0 ]; then
        echo "::error file=$exceptions::'$addr' names no LibreSCRS/LibreAgent checkout under $wfdir (stale entry)"
        rc=1
    elif [ "$n" -gt 1 ]; then
        echo "::error file=$exceptions::'$addr' is carried by $n LibreSCRS/LibreAgent checkouts" \
             "(${trunk_where[$addr]}); an exemption names ONE step, so give each its own id and its own reason" \
             "-- or pin the one that builds"
        rc=1
    fi
done

# And the exemption may not consume the last pinned checkout: a repository that
# fetches the agent somewhere must still fetch it from the pin somewhere, or
# there is no pin left to wire and this gate would be measuring an empty set.
# Only worth saying when an exemption is in play -- an unpinned checkout that
# nobody listed is R3's or R4's to report, in its own words.
if [ "$pinfile" != "-" ] && [ "$trunk" -gt 0 ] && [ "$pinned" -eq 0 ]; then
    echo "::error file=$pinfile::no LibreSCRS/LibreAgent checkout under $wfdir is wired to the pin" \
         "($trunk of $checkouts exempt); the pin then binds no build in this repository"
    rc=1
fi

printf 'workflows=%d agent-checkouts=%d pinned-refs=%d named-trunk-refs=%d unreadable-checkouts=%d mined-git-tag-lines=%d cmake-file-lines=%d\n' \
       "${#files[@]}" "$checkouts" "$pinned" "$trunk" "$unreadable" "$mined" "$cmakelines"
exit "$rc"
