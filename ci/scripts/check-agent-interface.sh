#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-agent-interface.sh — the Darwin authorizer must implement the
# LibreAgent Authorizer interface AS THE RELEASE WILL SEE IT.
#
# This repository's macOS job builds against cmake/libreagent.pin. A pin is by
# construction the interface as it was, so a CI that only builds the pin can
# never report that the base class has moved: it is green on a combination the
# release does not ship. That is how bool authorize() survived here after
# LibreAgent had already changed it to AuthorizationOutcome and the Linux host
# had already followed.
#
# So this gate deliberately does NOT read the pin. It compiles against a
# LibreAgent checkout handed to it -- in CI, the agent's main branch.
#
# Five rules, because the type alone is not the contract and R1 sees exactly
# one declaration:
#   R1  SecCodeAuthorizer's override signature matches the base declaration,
#       and the authorizer's own test compiles against it. Proven by a real
#       -fsyntax-only compile of the real headers and one real source file, not
#       a grep. Everything else is still off its include path -- the out-of-line
#       definition in agent/src, the socket frontend and its test, all of which
#       need Apple frameworks this host does not have. R1 proves the declaration
#       and seventeen assertions; R2 and R3 carry the rest, and until an Apple
#       host builds the tree that is the whole of the evidence.
#   R2  nothing under agent/ declares, defines or consumes authorize() as a
#       bool. A scoped enum has no operator! and no conversion, so
#       `if (!...authorize(...))`, `bool ok = ...authorize(...)`, an
#       out-of-line `bool SecCodeAuthorizer::authorize(...)` and a SECOND
#       Authorizer subclass still declaring `bool authorize(...) override` are
#       all ill-formed. Every one of them is invisible to R1, and fixing only
#       the header would leave eight call sites behind.
#   R3  every remaining mention of authorize() is a shape the scoped enum
#       permits: a statement naming AuthorizationOutcome, a switch scrutinee,
#       an EXPECT_EQ/ASSERT_EQ comparison, or a binding of the result to a
#       deduced name. Anything else is red BY DEFAULT, because a rule that
#       enumerates the bad shapes is always one spelling behind the next one
#       somebody writes -- `if (a.authorize(x, y))` names no bool and negates
#       nothing, and it does not compile either. A legitimate new shape is
#       added to OKPAT deliberately, having read this.
#   R4  and the name a binding introduces is followed. R3 lets a statement bind
#       the result to a name precisely because binding it is correct; what
#       happens to that name AFTERWARDS decides whether the code compiles.
#       `const auto outcome = ...authorize(...); if (!outcome)` is two
#       statements, both green under R2 and R3 -- the first spells the type, the
#       second never mentions authorize() -- and it is ill-formed. R4 records
#       every name bound from a call and judges every later statement in the
#       same file that mentions that name, with R3's polarity: only the shapes a
#       scoped enum stands in are accepted, and anything else is red. It listed
#       the ill-formed spellings once instead, and `outcome == false`,
#       `if ((outcome))`, `assert(outcome)`, `bool ok{outcome}` and a bare
#       `return outcome;` all read green -- five spellings of one defect, which
#       is what listing spellings always costs. The accepted shapes live in
#       permitted() below and a legitimate new one is added there deliberately,
#       having read this. Two more read green after that, for reasons that are
#       not spellings at all: a statement was pardoned by an assignment
#       ANYWHERE in it, so `if (outcome) { outcome = other; }` -- ill-formed --
#       counted as a rebinding; and a functional-style cast to a builtin,
#       `bool(outcome)` or `int(outcome)`, read as the outcome being passed to a
#       call. Those two compile, which is worse: no Apple host will report them
#       either. permitted() now cuts the assignment out and judges what is left,
#       and a builtin type name is a cast rather than a callee.
#
#   R5  and the compiler over every unit that names the call, which is the only
#       one of these that is not a textual rule at all. A scoped enum has no
#       conversion to bool, so a compiler rejects every shape R2, R3 and R4 try
#       to enumerate -- and the ones they accept by mistake too. What stops it
#       being the whole gate is reach: two of the units that name the call need
#       LibreMiddleware's headers and Apple blocks. It judges what it reaches,
#       says how many that was, and leaves the rest to the rules above.
#       A failure is THIS contract's when the FIRST error -- with the notes
#       hanging off it, and not the source line echoed under the caret -- names
#       AuthorizationOutcome, and when that first error stands inside this
#       checkout: the extra include roots are somebody else's tree, and an
#       ill-formed expression in a foreign header, outside this checkout, must
#       not be counted against this repository's translation unit. Reading the
#       whole log instead was wrong both ways: a pinned run
#       named a call site here over a first error about an unrelated stale wire
#       symbol, and clang's wording for an argument conversion (`no matching
#       function for call to ...`, with the type on the note) read "out of
#       reach", rc=0, on a shape the textual rules pardon BY CONSTRUCTION.
#       Out of reach is a claim about the environment and names its reasons; a
#       unit the compiler opened and rejected for none of them is counted apart
#       and the verdict word becomes INCOMPLETE, because the count is the whole
#       signal and nobody keeps it between runs. And when R5 does report a break
#       it says FAILED rather than ok -- it printed "R5 ok" on the same run in
#       which it set rc=1, five verdict lines all reading ok over a red gate,
#       and the lines are what this repository quotes as evidence.
#
# What they read is every tracked source in the repository, by extension, minus
# ci/ -- this gate, its selftest and this paragraph name the interface by
# construction. It read agent/ alone once, and the same ill-formed boolean use
# one directory over left all four rules "ok"; the patch for that was a grep for
# the AGENT header's spelling, and a Darwin-side caller in prompter/ names the
# Darwin subclass instead and read "ok" again. A rule keyed on a spelling admits
# whoever picks another spelling, so the rules now judge the CALL wherever it
# stands. Prose is not source: a release note may name the interface in a
# sentence, and nothing compiles a .md.
#
# R2, R3 and R4 read STATEMENTS, assembled from physical lines with comments
# removed, over the same source-file set the rest of this repository calls
# source. Read line by line they were wrong in both directions: a trailing
# comment naming AuthorizationOutcome made a boolean use acceptable, and a call
# wrapped at the margin was called ill-formed for having its context on the next
# line.
#
# What R4 does NOT do is type inference: it follows a name within one file,
# forgets it when something else is assigned to it, and knows nothing of scope,
# so two functions using the same name are one name to it. That is deliberate --
# the shapes it exists to catch are local, and a rule that guessed at scope
# would go red on code that compiles.
#
# A statement cannot borrow acceptance from another operand, and that took three
# goes to make true. R3 accepted any statement NAMING AuthorizationOutcome and
# permitted() ended in the same pardon, so `if (outcome) { last =
# A::AuthorizationOutcome::Denied; }` -- the commonest boolean use there is --
# read green; and statements were assembled a physical line at a time, so a
# binding and its use written on ONE line merged into a single statement that
# named the type. Statements now end at the ; { or } that ends them, at
# parenthesis depth zero.
#
# The third go is the one worth remembering. The pardon was removed for a value
# standing as the condition of an `if` or a `while` -- which is a list of two
# out of six, and enumerating controlling contexts is the same mistake as
# enumerating spellings, one level up. Measured at this repository's own sign
# call site, at the line the if/while patch was demonstrated on, all of these
# read R1-R5 ok, rc=0, and none of them compiles: the call as the condition of
# a ternary, the call in the condition slot of a `for`, and the bound name in
# either. So the value is LOCATED and its position is read structurally -- the
# whole controlling expression of an if, a while, a do-while or a for, or an
# operand of `!`, `&&`, `||`, `?`. A comparison against an enumerator is still
# the way to write every one of them, and stays green.
#
# Two shapes are accepted whose legality it cannot actually see, and they are
# named here rather than left to be discovered: the name passed as an argument
# to a call (the parameter's type is in another file), and `return <name>;` from
# a function whose header spells AuthorizationOutcome (the header is the only
# return type a textual rule has). Both are the compiler's to catch -- but only
# in a unit R5 actually reaches, which is not guaranteed: see the threat model
# below.
#
# Threat model. This gate catches an honest regression: bool creeping back into
# a signature, a comparison or a rebinding, in the ordinary shapes this codebase
# writes authorize() calls in today. R2, R3 and R4 read source text with
# comments stripped, so they cannot see what a value actually converts to and
# do not try to -- a shape none of the three enumerates is judged only by R5,
# the compiler, and R5 judges only the units it can reach. Known door, measured
# on this repository's own workflow: the job CI actually runs checks the
# interface out WITHOUT a LibreMiddleware sibling, so R5 there compiles 3 of
# the 5 translation units that name authorize() and leaves the other 2 --
# agent/src/backend/SocketFrontend.cpp and its test, together 8 of the 9 real
# call sites -- "out of reach", counted rather than silently dropped, but
# judged by nothing at all. A call in one of those two files that binds the
# outcome to a name and passes that name as an argument to another call (one of
# the two shapes R3/R4 accept above) is therefore unjudged end to end in the
# configuration this repository's own CI runs, not merely pending an Apple
# host: rc=0, R1-R5 all "ok". Reachable only by checking the same job out
# alongside LibreMiddleware, which changes what "the CI configuration" means.
#
# R1 needs one Darwin-only type, audit_token_t from <bsm/libbsm.h>. On a Mac the
# real header is used. Elsewhere a stand-in is generated below, in a temporary
# directory: shipping it as a tracked .h would put a header nobody formats into
# ci/, and check-format-scope.sh would rightly complain.
#
# Exit codes:
#   0  every rule holds
#   1  a rule is broken; the offending declaration or call sites are printed
#   2  refusing to judge -- no compiler, no LibreAgent headers, no gtest
#      headers, a named translation unit missing, a text rule that could not be
#      run, or R1's own compile failing for a reason that is not the authorize()
#      contract. A gate that
#      reports the defect it was built for whenever anything at all goes wrong
#      is a gate that will one day be "fixed" by deleting it.
set -uo pipefail
export LC_ALL=C   # the diagnostic text below is matched; a translated compiler
                  # prints "сукобљен повратни тип" and the match would silently miss.

# REPO_ROOT is overridable so the selftest can drive this over fixture trees.
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
cd "$REPO_ROOT" || exit 2

LA_INCLUDE="${1:-${LIBREAGENT_INCLUDE:-$REPO_ROOT/../LibreAgent/include}}"
# Where that checkout came from. It changes one sentence and only one: when the
# agent turns out to predate the outcome type, what moves depends on which
# revision was handed in. `pin` is a checkout at cmake/libreagent.pin, and
# raising the pin is the answer. `trunk` is the agent's published branch, which
# reads no pin at all -- telling its reader to raise one names a file that had
# no part in the verdict, and the agent has to publish the revision instead.
# Anything else is refused rather than quietly generic.
LA_ORIGIN="${2:-${LIBREAGENT_ORIGIN:-unnamed}}"
case "$LA_ORIGIN" in
    pin|trunk|unnamed) ;;
    *) echo "FATAL: '$LA_ORIGIN' is not a LibreAgent provenance — pass 'pin', 'trunk', or nothing" >&2; exit 2 ;;
esac
CXX_BIN="${CXX:-c++}"

HDR="agent/include/LibreSCRS/Darwin/backend/SecCodeAuthorizer.h"
BASE="$LA_INCLUDE/LibreSCRS/Agent/backend/Authorizer.h"

command -v "$CXX_BIN" >/dev/null 2>&1 || { echo "FATAL: no C++ compiler ($CXX_BIN)" >&2; exit 2; }
[ -f "$HDR" ]  || { echo "FATAL: $HDR not found — wrong working directory?" >&2; exit 2; }
[ -f "$BASE" ] || { echo "FATAL: no Authorizer.h under $LA_INCLUDE — pass the LibreAgent include dir" >&2; exit 2; }

SCRATCH="$(mktemp -d /var/tmp/check-agent-interface.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

# A real checkout, or one of the selftest's fixture trees? The two differ in
# what may be demanded of them: a fixture carries only the files its case needs.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    in_checkout=1
else
    in_checkout=0
fi

# ---------------------------------------------------------------- the file set
# What the rules read, decided before anything reads it. R2, R3 and R4 read
# text, so what they do NOT read is silent, and this has been narrower than it
# printed twice: the extension list was .h/.hpp/.cpp/.mm while the repository's
# own check-format-scope.sh already treats .c/.cc/.cxx/.hh/.m as source, and the
# directory was agent/ while the repository builds prompter/, pkcs11-module/ and
# build-cc/ as well. The second one was then patched with a grep for the AGENT
# header's spelling -- and a Darwin-side caller names the Darwin subclass, not
# that header, so a boolean use of authorize() in prompter/ still read
# "R1 ok / R2 ok / R3 ok / R4 ok", rc=0. A rule keyed on a spelling admits
# whoever picks another spelling.
#
# So the file set is every tracked source in the repository, by extension, and
# the rules judge the CALL wherever it stands. ci/ is the one exclusion: this
# gate, its selftest and the paragraph you are reading name the interface by
# construction. Prose is not source -- CHANGELOG.md and README.md may say
# `LibreSCRS::Agent::Authorizer` in a sentence, and a release note is the first
# place that sentence gets written; nothing compiles a .md.
#
# A file whose kind is in neither list is judged by nothing here, and that is a
# blind spot only when the file has something to say about this contract. The
# rule used to be unconditional, and widening the file set from agent/ to the
# repository widened it with them: measured, a tracked Dockerfile, a tracked
# docs/*.svg and an untracked scratch note at the repository root -- none of
# which mentions authorize() -- took BOTH agent-interface jobs to rc=1 with a
# message about R2, R3 and R4. That is the same false red as the release-note
# sentence this file removed one round earlier, spread over every kind of file
# that is not a C or C++ source.
#
# So an unknown kind is an error when it NAMES THE CALL, and a note otherwise.
# A new source extension carrying a boolean use is still caught -- it names the
# call, by construction -- and a new kind of file that says nothing about the
# contract is what it is.
SRC_RE='\.(c|cc|cpp|cxx|h|hh|hpp|m|mm)$'
NONSRC_RE='(\.(txt|plist|md|json|in|cmake|entitlements|modulemap|xcconfig|yml|yaml|strings|storyboard|xib|pch|pin|sh|py|bash|1)$|(^|/)(KEYS|LICENSE|VERSION|\.clang-format|\.gitignore|\.gitattributes)$|(^|/)LICENSES/)'

# Inside a checkout: tracked files plus the ones written but not added yet -- a
# source nobody has added compiles exactly like one that has been. Over a
# fixture tree that is not a repository: everything on disk.
if [ "$in_checkout" = 1 ]; then
    { git ls-files -- . ':!ci'; git ls-files --others --exclude-standard -- . ':!ci'; } 2>/dev/null
else
    find . -type f -not -path './ci/*' -not -path './.git/*' 2>/dev/null | sed 's|^\./||'
fi | sort -u > "$SCRATCH/files.txt"

grep -E "$SRC_RE" "$SCRATCH/files.txt" > "$SCRATCH/sources.txt"
grep -vE "$SRC_RE" "$SCRATCH/files.txt" | grep -vE "$NONSRC_RE" > "$SCRATCH/unknown-kind.txt"
: > "$SCRATCH/unclassified.txt"
while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    grep -qE 'authorize[[:space:]]*\(' "$f" 2>/dev/null && printf '%s\n' "$f"
done < "$SCRATCH/unknown-kind.txt" >> "$SCRATCH/unclassified.txt"
rc=0
if [ -s "$SCRATCH/unclassified.txt" ]; then
    echo "::error::these files name authorize() and are neither source nor a known non-source kind, so no rule below reads them; classify them in SRC_RE or NONSRC_RE in $0"
    cat "$SCRATCH/unclassified.txt"
    rc=1
elif [ -s "$SCRATCH/unknown-kind.txt" ]; then
    echo "  note    $(wc -l < "$SCRATCH/unknown-kind.txt") file(s) of a kind neither list names; none of them mentions authorize(), so nothing here reads them"
fi

# Extra include roots come from LIBRESCRS_EXTRA_INCLUDE (colon-separated), or
# from a sibling LibreMiddleware checkout when there is one. They are named in
# the output, so what was on the path is part of the verdict rather than
# something the reader has to guess.
EXTRA_INC="${LIBRESCRS_EXTRA_INCLUDE:-}"
if [ -z "$EXTRA_INC" ] && [ -d "$REPO_ROOT/../LibreMiddleware/include" ]; then
    EXTRA_INC="$REPO_ROOT/../LibreMiddleware/include"
fi
extra_inc=()
extra_named=""
oldifs=$IFS; IFS=:
for d in $EXTRA_INC; do
    [ -d "$d" ] || continue
    extra_inc+=(-isystem "$d")
    extra_named="${extra_named:+$extra_named }$d"
done
IFS=$oldifs

# NOTE: these roots are built HERE, above R1, because R1 compiles too. They
# used to be assembled just before R5, so R1 ran without them: on a machine
# where gtest is not in a default system path -- every macOS box -- R1 could
# not compile the authorizer's test at all, and LIBRESCRS_EXTRA_INCLUDE, the
# documented way to say where the headers are, could not reach it.

# ---------------------------------------------------------------- R1
mkdir -p "$SCRATCH/shim/bsm"
cat > "$SCRATCH/shim/bsm/libbsm.h" <<'EOF'
#pragma once
// Stand-in for the Darwin header, supplying only what PeerIdentity.h names.
// Used ONLY where the real header is unreachable -- see the probe below, which
// asks the compiler rather than guessing a path. Where the real one is
// reachable this file stays off the include path, so drift shows up as a
// compile error against the real declarations.
typedef struct { unsigned int val[8]; } audit_token_t;
extern "C" int audit_token_to_pid(audit_token_t);
extern "C" int audit_token_to_pidversion(audit_token_t);
EOF
echo '#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>' > "$SCRATCH/tu.cpp"

# Is the REAL <bsm/libbsm.h> reachable? Ask the compiler, not the filesystem.
# This used to test `-e /usr/include/bsm/libbsm.h`, which is a Linux path: on
# macOS /usr/include does not exist at all (the header lives in the SDK), so the
# probe always missed and the shim was ALWAYS injected -- on the one platform
# that ships the real header. The shim's audit_token_t then collided with the
# SDK's own typedef in <mach/message.h> (reached via <dispatch/dispatch.h> under
# -fblocks), and because that first error stands outside the checkout, R5
# declined to judge two translation units and reported 3 of 5 instead of 5 of 5.
# The compiler knows about SDK roots, framework paths and sysroots; a literal
# path knows about one distribution's layout.
echo '#include <bsm/libbsm.h>' > "$SCRATCH/bsmprobe.cpp"
shim_inc=()
if ! "$CXX_BIN" -fsyntax-only -x c++ "$SCRATCH/bsmprobe.cpp" >/dev/null 2>&1; then
    shim_inc=(-isystem "$SCRATCH/shim")
fi

# The translation units R1 compiles. The first is the header on its own. The
# second is a real source file from this repository -- the authorizer's test,
# which names the outcome seventeen times and pulls in nothing Apple beyond the
# header itself, so it compiles here. It is worth a great deal: of the five
# files the outcome change touched, four are compiled by nothing on this
# platform, and this is the one that can be. It needs gtest's headers (not its
# library: -fsyntax-only links nothing).
#
# The list is a promise, not a search. In a checkout, a named unit that is not
# there is a stale list and this refuses to judge rather than quietly measuring
# less; over a fixture tree, which carries only what its case needs, it is
# simply absent.
tus=("$SCRATCH/tu.cpp")
for t in agent/tests/SecCodeAuthorizerTest.cpp; do
    if [ -f "$t" ]; then
        tus+=("$t")
    elif [ "$in_checkout" = 1 ]; then
        echo "FATAL: $t is named by this gate but is not in the tree — the list in $0 is stale" >&2
        exit 2
    fi
done

# LibreAgent's headers (and the shim) come in with -isystem: they are not this
# repository's to keep warning-clean, and a diagnostic raised inside them must
# not be read as a defect here. Errors still surface -- the conflicting return
# type is reported against OUR header, which is the one on -I.
: > "$SCRATCH/r1.log"
r1=0
for t in "${tus[@]}"; do
    "$CXX_BIN" -std=c++23 -fsyntax-only "${shim_inc[@]}" \
        -I agent/include -isystem "$LA_INCLUDE" "${extra_inc[@]}" "$t" >> "$SCRATCH/r1.log" 2>&1 || r1=1
done
# Both spellings: GCC says `gtest/gtest.h: No such file or directory`, clang says
# `'gtest/gtest.h' file not found`. Matching only GCC's meant that on macOS this
# precise diagnosis never fired and the run fell through to the generic "failed
# to compile for a reason that is not the authorize() contract", which sends the
# reader looking at the contract for a missing package.
if grep -qE "gtest/gtest\.h: No such file|'gtest/gtest\.h' file not found" "$SCRATCH/r1.log"; then
    echo "FATAL: gtest's headers are not on the include path, so the authorizer's test cannot be compiled — install them (Debian/Ubuntu: libgtest-dev; macOS: point LIBRESCRS_EXTRA_INCLUDE at a prefix that has gtest/, e.g. the LibreMiddleware install prefix's include/) rather than letting this rule measure one header" >&2
    exit 2
fi

# --------------------------------------------- classifying a failed compile
# Whose failure is it? R1 and R5 both turn on that question, and both got it
# wrong, in opposite directions.
#
# The FIRST error decides, together with the notes hanging off it. Two
# measurements say why. A pinned run over a LibreAgent that predates the
# outcome type printed `::error file=agent/src/backend/SocketFrontend.cpp::this
# translation unit does not compile against the authorize() contract` over a
# first error reading `'Cancelled' is not a member of Wire::SyncError` -- the
# type was named hundreds of lines further down and "somewhere in the log"
# accepted it as the cause. The other way: clang words an argument conversion
# as `error: no matching function for call to 'sinkBool'` and puts the type on
# the `note:` underneath, so a real boolean use -- one of the two shapes this
# file's header says the textual rules cannot judge AT ALL -- read "out of
# reach" and rc=0 under the compiler this repository ships to, while gcc
# reported it. So the type is looked for in the first error and its notes, and
# nowhere else.
#
# And "out of reach" is a claim about the ENVIRONMENT, not a shrug. It names
# the reasons it accepts: a header this checkout does not own, a missing
# include, an Apple extension the compiler has not got, an agent revision that
# predates the type. A compile that failed inside this checkout for any other
# reason is measured by nothing here, and a rule that prints ok about a unit it
# could not judge is the false green this file exists to remove. That is exit
# 2, refusing to judge -- which is also what stops R5's coverage shrinking in
# silence: an unrelated broken symbol in one of these units used to move it
# from judged to out of reach at rc=0, with a count nobody compares.
STALERE='(AuthorizationOutcome. in namespace|no type named .AuthorizationOutcome|AuthorizationOutcome. is not a member)'
BLOCKSRE="(expected primary-expression before .\\^. token|blocks support disabled|blocks are not enabled)"
ENVRE="(No such file or directory|file not found|$BLOCKSRE)"

# The first error the compiler reported, with the notes attached to it -- its
# own message lines and nothing else. Both compilers echo the offending SOURCE
# LINE under the caret, and a source line that reads
# `EXPECT_EQ(a.authorize(x, y), Agent::AuthorizationOutcome::Denied)` names the
# type without saying anything at all about what went wrong: measured, three
# CONTROL fixtures went red on their own echoed text.
first_diag() {  # first_diag <log>
    awk '/: (fatal )?error:/ { n++ } n > 1 { exit } n == 1 && /: (fatal error|error|warning|note):/ { print }' "$1" 2>/dev/null
}
# 0 when that first diagnostic is about THIS contract, i.e. names the type.
contract_diag() {  # contract_diag <log>
    first_diag "$1" | grep -q AuthorizationOutcome
}
# The file the first error stands in, as the compiler printed it. Our own units
# are on relative paths; an -isystem root is absolute, so an absolute path that
# is not under this checkout belongs to somebody else.
first_error_file() {  # first_error_file <log> -> path, or ""
    grep -m1 -E '^[^[:space:]].*:[0-9]+:[0-9]+: (fatal )?error:' "$1" 2>/dev/null \
        | sed 's/:[0-9]*:[0-9]*: .*$//'
}
foreign_error() {  # foreign_error <path> -> 0 when it is outside this checkout
    [ -n "$1" ] || return 1
    case "$1" in
        /*) [ "${1#"$REPO_ROOT"/}" = "$1" ] ;;
        *)  return 1 ;;
    esac
}
first_error_text() {  # first_error_text <log> -> one line, for a verdict
    grep -m1 -E '(fatal error|error):' "$1" \
        | sed 's/^.*\(fatal error\|error\): /\1: /' | cut -c1-110
}

# The compiler's own lines, not the include chain that leads to them: a real
# source file drags in dozens of "In file included from" lines, and the first
# twenty of those would be the whole of what a reader is shown.
r1_diagnostics() {
    if grep -qE '(error|warning|note):' "$SCRATCH/r1.log"; then
        grep -E '(error|warning|note):' "$SCRATCH/r1.log" | head -20
    else
        head -20 "$SCRATCH/r1.log"
    fi
}

agent_stale=0
if [ "$r1" -eq 0 ]; then
    echo "  R1 ok   — SecCodeAuthorizer implements Authorizer as declared in $LA_INCLUDE"
elif grep -qE "$STALERE" "$SCRATCH/r1.log"; then
    # One direction: this repository already carries the three-way outcome and
    # the LibreAgent it was pointed at predates it. That is a stale agent
    # revision, not a stale override, and saying so here saves the next reader
    # from "fixing" the authorizer back to bool. Which revision has to move is
    # the one thing this rule cannot infer from the compile, so the caller says
    # where the headers came from. It is asked FIRST, because a header that has
    # no AuthorizationOutcome at all also produces diagnostics that name the
    # type, and the answer to those is not "the override is wrong".
    agent_stale=1
    case "$LA_ORIGIN" in
        pin)   stale_next="Raise cmake/libreagent.pin to a published revision that carries it." ;;
        trunk) stale_next="This is the agent's own branch and reads no pin: publish the LibreAgent revision that introduces the outcome type. Moving a pin cannot answer this one." ;;
        *)     stale_next="Point this check at a LibreAgent revision that carries it." ;;
    esac
    echo "::error file=$HDR::the LibreAgent under $LA_INCLUDE predates AuthorizationOutcome — this is a stale agent revision, not a stale override. $stale_next"
    r1_diagnostics
    rc=1
elif contract_diag "$SCRATCH/r1.log"; then
    # The other direction, and it is decided by the first diagnostic naming the
    # type rather than by a list of phrases. The list was gcc's: measured, the
    # same boolean use in the authorizer's own test read rc=1 under `c++` and
    # rc=2 -- "failed to compile for a reason that is not the authorize()
    # contract" -- under clang, whose wording puts the type on the note and
    # says `no known conversion from`. clang is the compiler of the platform
    # this repository ships to, and "the gate is broken" is what that message
    # gets read as.
    echo "::error file=$HDR::the authorize() contract does not hold against the Authorizer declared in $LA_INCLUDE"
    r1_diagnostics
    rc=1
else
    echo "FATAL: $HDR failed to compile for a reason that is not the authorize() contract — refusing to judge" >&2
    r1_diagnostics >&2
    exit 2
fi

# Statements, not lines. A line-based rule reads a trailing comment as part of
# the code it is judging, so `if (a.authorize(x, y)) // AuthorizationOutcome`
# was accepted for naming the type -- in a comment, on a line that does not
# compile. And a call wrapped at the margin has its context on the NEXT line, so
# the same rule called correct code broken. This assembles each statement from
# its physical lines with comments removed, and reports the line where
# authorize() was first mentioned.
#
# The result bound to a name and misused in a LATER statement is R4's, below:
# this assembler stops at the statement it is given, and the statement that
# misuses the name never mentions authorize() at all.
cat > "$SCRATCH/stmt.awk" <<'AWK'
function flush(   s) {
    s = buf
    gsub(/[[:space:]]+/, " ", s)
    sub(/^ /, "", s); sub(/ $/, "", s)
    if (s != "") printf "%s\t%d\t%d\t%s\n", F, start, mention, s
    buf = ""; mention = 0; start = 0; pd = 0
}
BEGIN { inblock = 0; buf = ""; mention = 0; start = 0; pd = 0 }
{
    line = $0
    if (inblock) {
        if (line ~ /\*\//) { sub(/^.*\*\//, "", line); inblock = 0 } else { next }
    }
    while (match(line, /\/\*/)) {
        pre = substr(line, 1, RSTART - 1)
        rest = substr(line, RSTART + 2)
        if (match(rest, /\*\//)) {
            line = pre " " substr(rest, RSTART + 2)
        } else {
            line = pre; inblock = 1; break
        }
    }
    sub(/\/\/.*/, "", line)
    # A statement ends at the ; { or } that ends it, not at the end of the
    # physical line that happens to carry it. Flushing per LINE merged a binding
    # and its use when both were written on one line, and the merged statement
    # then named AuthorizationOutcome (from the binding) and was pardoned for it:
    #   `const auto o = ...authorize(...); if (o) { m_last = A::AuthorizationOutcome::Denied; }`
    # read rc=0 with every rule ok, and does not compile. Split here and it is
    # two statements again, judged as it is when it is written over two lines.
    nn = length(line)
    for (ii = 1; ii <= nn; ii++) {
        ch = substr(line, ii, 1)
        buf = buf ch
        if (ch == "(") pd++
        else if (ch == ")") pd--
        if (start == 0 && ch ~ /[^[:space:]]/) start = FNR
        if (mention == 0 && buf ~ /authorize[[:space:]]*\(/) mention = FNR
        # Only at depth zero: the `;` in `if (auto o = f(); o == X)` separates an
        # init-statement from its condition and does not end a statement, and a
        # brace inside parentheses belongs to a lambda or a braced initialiser.
        if (pd <= 0 && (ch == ";" || ch == "{" || ch == "}")) flush()
    }
    buf = buf " "
}
END { flush() }
AWK

: > "$SCRATCH/stmts.txt"
while IFS= read -r f; do
    [ -f "$f" ] || continue
    awk -v F="$f" -f "$SCRATCH/stmt.awk" "$f" >> "$SCRATCH/stmts.txt"
done < "$SCRATCH/sources.txt"

# R2 and R3 judge the statements that mention authorize(), in the format they
# have always reported: <file>:<line authorize() was first mentioned>:<statement>.
awk -F'\t' '$3 > 0 { print $1 ":" $3 ":" $4 }' "$SCRATCH/stmts.txt" > "$SCRATCH/uses.txt"

# R2's shapes: a bool-typed declaration, definition or variable in the same
# statement, a negation, or a truth assertion.
BOOLPAT='((^|[^A-Za-z0-9_])bool[[:space:]][^;]*authorize[[:space:]]*\(|![[:alnum:]_.>()[:space:]-]*authorize[[:space:]]*\(|(EXPECT|ASSERT)_(TRUE|FALSE)[[:space:]]*\([^;]*authorize[[:space:]]*\()'
# R3's accepted shapes, and nothing else. The last one is a statement that binds
# the result to a deduced name and does nothing else with it: it is anchored to
# the start of the statement AND to the closing parenthesis of the call, so that
# `if (auto ok = ...; ok)` (a condition) and `const auto r = ...authorize(...) ?
# 1 : 0` (a ternary) -- both ill-formed against a scoped enum -- are not let in
# with it. What happens to the bound name afterwards is beyond a textual gate;
# the header says so.
OKPAT='(AuthorizationOutcome|switch[[:space:]]*\(|(EXPECT|ASSERT)_EQ[[:space:]]*\(|^[^:]*:[0-9]+:(const[[:space:]]+)?auto[[:space:]&]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[^;]*authorize[[:space:]]*\([^;]*\)[[:space:]]*;$)'

grep -E "$BOOLPAT" "$SCRATCH/uses.txt" > "$SCRATCH/r2.txt"
grep -vE "$BOOLPAT" "$SCRATCH/uses.txt" > "$SCRATCH/r3cand.txt"

# ---------------------------------------------------------------- position
# Where the value STANDS, shared by R3 and R4.
#
# Both rules had the same defect and it was patched the same wrong way twice:
# they asked whether the value was the condition of an `if` or a `while`.
# Measured, the identical ill-formed call one keyword over read every rule
# "ok", rc=0 -- in the condition slot of a `for`, and as the condition of a
# ternary:
#   `for (A::AuthorizationOutcome g = ...; ...authorize(...); ) { }`
#   `A::AuthorizationOutcome o = ...authorize(...) ? ...::Denied : ...::Granted;`
# Neither compiles. Enumerating controlling contexts is the same mistake as
# enumerating spellings, one level up: `if` and `while` were two of six.
#
# So the value is located and its POSITION is read. mark_call() replaces the
# whole call expression with a marker, ctl_segment() walks out to the
# controlling expression the marker stands in -- the condition of an if or a
# while (the part after the last init-statement), or the middle slot of a for
# -- and adj_bool() reads the operators immediately around it, which is what
# `!`, `&&`, `||` and `?` are. A comparison against an enumerator is still the
# way to write all of this, and stays green.
cat > "$SCRATCH/pos.awk" <<'AWK'
BEGIN { MARK = "\001"; UNSET = "\002" }
function trim(x) { sub(/^[[:space:]]+/, "", x); sub(/[[:space:]]+$/, "", x); return x }
function balanced(x,   i, d, c) {
    d = 0
    for (i = 1; i <= length(x); i++) {
        c = substr(x, i, 1)
        if (c == "(") d++
        else if (c == ")") { d--; if (d < 0) return 0 }
    }
    return d == 0
}
function strip_outer(x,   y) {
    x = trim(x)
    while (x ~ /^\(.*\)$/) {
        y = substr(x, 2, length(x) - 2)
        if (!balanced(y)) break
        x = trim(y)
    }
    return x
}
# The `;`-separated slots of a parenthesised group, at depth zero: an `if` may
# carry an init-statement and a `for` carries three.
function split_d0(s, arr,   i, d, cur, n, c) {
    n = 0; d = 0; cur = ""
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "(") d++
        else if (c == ")") d--
        if (c == ";" && d == 0) { arr[++n] = cur; cur = "" } else cur = cur c
    }
    arr[++n] = cur
    return n
}
# The controlling expression TOK stands in, or UNSET when it stands in none.
# What precedes the slot -- the init-statement of an `if`, the first slot of a
# `for` -- is left in CTL_INIT, because a condition that is merely the name a
# binding introduced has to be read together with the binding.
function ctl_segment(t, tok,   p, i, j, d, c, op, cl, kw, q, inner, n, parts) {
    p = index(t, tok)
    if (p == 0) return UNSET
    d = 0; op = 0
    for (i = p - 1; i >= 1; i--) {
        c = substr(t, i, 1)
        if (c == ")") d++
        else if (c == "(") { if (d == 0) { op = i; break } d-- }
    }
    if (op == 0) return UNSET
    d = 0; cl = 0
    for (j = op; j <= length(t); j++) {
        c = substr(t, j, 1)
        if (c == "(") d++
        else if (c == ")") { d--; if (d == 0) { cl = j; break } }
    }
    if (cl == 0) return UNSET
    q = op - 1
    while (q >= 1 && substr(t, q, 1) == " ") q--
    kw = ""
    while (q >= 1 && substr(t, q, 1) ~ /[A-Za-z0-9_]/) { kw = substr(t, q, 1) kw; q-- }
    inner = substr(t, op + 1, cl - op - 1)
    n = split_d0(inner, parts)
    CTL_INIT = ""
    if (kw == "if" || kw == "while") {
        for (i = 1; i < n; i++) CTL_INIT = CTL_INIT parts[i] ";"
        return parts[n]
    }
    if (kw == "for") {
        if (n != 3) return UNSET   # a range-for has no condition slot
        CTL_INIT = parts[1]
        return parts[2]
    }
    return UNSET
}
# The call expression `<postfix>.authorize(<args>)`, replaced by MARK. The
# postfix expression in front of it is taken with it -- names, `.`, `->`, `::`
# and a balanced `()` for `authorizer()` -- so what is left on either side of
# the marker is the context the call stands in and nothing else.
function mark_call(t,   a, o, i, j, d, c, ch, cl) {
    if (match(t, /authorize[[:space:]]*\(/) == 0) return ""
    a = RSTART
    o = RSTART + RLENGTH - 1
    d = 0; cl = 0
    for (j = o; j <= length(t); j++) {
        ch = substr(t, j, 1)
        if (ch == "(") d++
        else if (ch == ")") { d--; if (d == 0) { cl = j; break } }
    }
    if (cl == 0) return ""
    i = a - 1
    while (i >= 1) {
        c = substr(t, i, 1)
        if (c ~ /[A-Za-z0-9_:.]/) { i--; continue }
        if (c == ">" && i > 1 && substr(t, i - 1, 1) == "-") { i -= 2; continue }
        if (c == ")") {
            d = 0
            for (j = i; j >= 1; j--) {
                ch = substr(t, j, 1)
                if (ch == ")") d++
                else if (ch == "(") { d--; if (d == 0) break }
            }
            if (j < 1) break
            i = j - 1; continue
        }
        break
    }
    return substr(t, 1, i) MARK substr(t, cl + 1)
}
# The operators immediately around the marker, which is what a boolean operand
# looks like wherever it stands: `!x`, `x && y`, `y || x`, `x ? a : b`.
function adj_bool(t,   p, i, c, c2) {
    p = index(t, MARK)
    if (p == 0) return 0
    i = p + length(MARK)
    while (substr(t, i, 1) == " ") i++
    c = substr(t, i, 1); c2 = substr(t, i, 2)
    if (c == "?") return 1
    if (c2 == "&&" || c2 == "||") return 1
    i = p - 1
    while (i >= 1 && substr(t, i, 1) == " ") i--
    c = substr(t, i, 1)
    if (c == "!" && substr(t, i + 1, 1) != "=") return 1
    if (substr(t, i - 1, 2) == "&&" || substr(t, i - 1, 2) == "||") return 1
    return 0
}
# The name an init-statement binds: the identifier before the declaration's `=`.
# Compound and comparison operators are stepped over, so `auto o = f(a == b)`
# still binds `o`.
function bound_name(str,   i, n, ch, prev, nxt, t) {
    n = length(str)
    for (i = 1; i <= n; i++) {
        ch = substr(str, i, 1)
        if (ch != "=") continue
        nxt = (i < n) ? substr(str, i + 1, 1) : " "
        if (nxt == "=") { i++; continue }
        prev = (i > 1) ? substr(str, i - 1, 1) : " "
        if (prev ~ /[=!<>+\-*\/%&|^]/) continue
        t = substr(str, 1, i - 1)
        sub(/[[:space:]]+$/, "", t)
        if (match(t, /[A-Za-z_][A-Za-z0-9_]*$/)) return substr(t, RSTART, RLENGTH)
        return ""
    }
    return ""
}
# The controlling expression is the value itself: bare, in parentheses, or
# negated. Anything more than that is a shape a textual rule should not guess
# at, and R4 reads it in the statements that follow.
function is_the_value(x, nm,   y) {
    y = strip_outer(x)
    while (y ~ /^!/) { sub(/^![[:space:]]*/, "", y); y = strip_outer(y) }
    return (y == nm)
}
AWK

# OKPAT's first alternative accepts a statement for NAMING AuthorizationOutcome,
# anywhere on it -- which is a statement borrowing acceptance from another
# operand. Measured at the sign call site:
#   `if (m_core.authorizer().authorize(A::kActionSign, in.caller)) { m_lastOutcome = A::AuthorizationOutcome::Denied; return; }`
# read rc=0 with all four rules ok, and it does not compile. So the CALL is
# located and the pardon is removed wherever the call stands in a boolean
# position -- whatever else the statement names.
#
# Which positions those are is not a list this rule keeps. It kept one twice --
# "the condition of an if or a while" -- and both times the identical call one
# keyword over read every rule ok, rc=0:
#   `for (A::AuthorizationOutcome g = ...; ...authorize(...); ) { }`
#   `A::AuthorizationOutcome o = ...authorize(...) ? ...::Denied : ...::Granted;`
# So position is read structurally instead, by the functions above: the call is
# replaced by a marker, and the marker is red when it is the whole controlling
# expression of an if, a while, a do-while or a for, or when the operator
# beside it is one that takes a bool -- `!`, `&&`, `||`, `?`.
#
# The condition after an init-statement is judged as a NAME as well as a call,
# which took one more measurement. That expression is usually the bound name
# and mentions authorize() nowhere, so requiring the call to appear in it
# dropped the statement -- and OKPAT then pardoned the whole thing for spelling
# the type in the declaration:
#   `if (A::AuthorizationOutcome o = ...authorize(...); o) { ... }`   rc=0
#   `if (A::AuthorizationOutcome o = ...authorize(...); !o) { ... }`  rc=0
# while the same two written with `auto` were rc=1. Both are ill-formed, and a
# verdict that turns on whether the declaration spells the type out is exactly
# the pardon this paragraph exists to remove. So when the slot before the
# condition binds a name from the call, and the controlling expression is that
# name -- bare, parenthesised, or negated -- the statement is red. A comparison
# against an enumerator is still the way to write every one of these.
cat > "$SCRATCH/cond.awk" <<'AWK'
{
    p1 = index($0, ":")
    rest = substr($0, p1 + 1)
    p2 = index(rest, ":")
    txt = substr(rest, p2 + 1)
    t = mark_call(txt)
    if (t == "") next
    if (adj_bool(t)) { print $0; next }
    seg = ctl_segment(t, MARK)
    if (seg == UNSET) next
    if (index(seg, MARK) > 0) {
        c = strip_outer(seg)
        while (c ~ /^!/) { sub(/^![[:space:]]*/, "", c); c = strip_outer(c) }
        if (c ~ /(==|!=)/) next
        print $0
        next
    }
    # The condition is not the call but the name a binding in the slot before
    # it introduced.
    if (index(CTL_INIT, MARK) > 0) {
        nm = bound_name(CTL_INIT)
        if (nm != "" && is_the_value(seg, nm)) print $0
    }
}
AWK
# awk's own failure is not a verdict: a parse error in the programs above goes
# to stderr, produces no matches, and leaves R3 and R4 reading "ok".
awk -f "$SCRATCH/pos.awk" -f "$SCRATCH/cond.awk" "$SCRATCH/r3cand.txt" > "$SCRATCH/r3cond.txt" \
    || { echo "FATAL: the statement-position program failed to run — refusing to judge" >&2; exit 2; }
{ grep -vE "$OKPAT" "$SCRATCH/r3cand.txt"; cat "$SCRATCH/r3cond.txt"; } \
    | awk '!seen[$0]++' > "$SCRATCH/r3.txt"

if [ -s "$SCRATCH/r2.txt" ]; then
    echo "::error::authorize() returns a scoped enum; these declare, define or consume it as a bool"
    cat "$SCRATCH/r2.txt"
    echo "  $(wc -l < "$SCRATCH/r2.txt") boolean statement(s) mentioning authorize()"
    rc=1
else
    echo "  R2 ok   — no tracked source treats authorize() as a bool"
fi

if [ -s "$SCRATCH/r3.txt" ]; then
    echo "::error::these use authorize() in a shape a scoped enum does not permit — a switch, an AuthorizationOutcome comparison, EXPECT_EQ/ASSERT_EQ or a deduced binding, and nothing else. If the shape is legitimate, add it to OKPAT in $0."
    cat "$SCRATCH/r3.txt"
    echo "  $(wc -l < "$SCRATCH/r3.txt") unrecognised statement(s) mentioning authorize()"
    rc=1
else
    echo "  R3 ok   — every use of authorize() is a switch, a comparison, a declaration or a deduced binding"
fi

# ---------------------------------------------------------------- R4
# R3 accepts a binding because binding the outcome is the correct thing to do.
# What the binding is used for afterwards is a different statement, and no rule
# above reads it: the second statement never mentions authorize() at all. So
# follow the name. Every statement that assigns the result of a call to a name
# starts a window on that name, and every later statement that MENTIONS the name
# must be a shape a scoped enum stands in. Anything else is red.
#
# The polarity is R3's, and it is the whole of the rule. Listing the ill-formed
# spellings instead was measured: `if (!outcome)` was caught and
# `if (outcome == false)`, `if ((outcome))`, `assert(outcome)`,
# `bool ok{outcome}` and `return outcome;` from a void function were not -- one
# defect, five spellings, and the sixth is whatever the next person types.
#
# The window ends when something else is assigned to the name, and never crosses
# a file. It does not respect scope -- two functions with an `outcome` local are
# one name here -- which can only over-report, and over-reporting is loud and
# has a rename for a cure.
cat > "$SCRATCH/bind.awk" <<'AWK'
# The name a statement binds the call to: the identifier before the last plain
# assignment that precedes the call. Compound and comparison operators are not
# assignments, and `==` is not one either.
function binder(t,   ia, pre, i, c, prv, nxt, best, nm, j) {
    ia = index(t, "authorize")
    if (ia == 0) return ""
    pre = substr(t, 1, ia - 1)
    best = 0
    for (i = 1; i <= length(pre); i++) {
        c = substr(pre, i, 1)
        if (c != "=") continue
        nxt = substr(pre, i + 1, 1)
        if (nxt == "=") { i++; continue }
        prv = (i > 1) ? substr(pre, i - 1, 1) : " "
        if (prv ~ /[=!<>+*\/%&|^-]/) continue
        best = i
    }
    if (best == 0) return ""
    nm = substr(pre, 1, best - 1)
    sub(/[[:space:]]+$/, "", nm)
    if (nm !~ /[A-Za-z0-9_]$/) return ""
    j = length(nm)
    while (j > 0 && substr(nm, j, 1) ~ /[A-Za-z0-9_]/) j--
    nm = substr(nm, j + 1)
    if (nm ~ /^[0-9]/) return ""
    return nm
}
# Where the bare name occurs, or 0. Bare: not part of a longer identifier and
# not the tail of a qualified one, so `holder.outcome` and `p->outcome` are
# other things with the same last word.
function nameat(t, n,   s, off, p, pre, post) {
    off = 0; s = t
    while (match(s, n)) {
        p = RSTART
        pre = (p > 1) ? substr(s, p - 1, 1) : " "
        post = substr(s, p + length(n), 1)
        if (pre !~ /[A-Za-z0-9_.>]/ && post !~ /[A-Za-z0-9_]/) return off + p
        s = substr(s, p + length(n))
        off += p + length(n) - 1
    }
    return 0
}
# The callee whose argument list the name sits in: the identifier before the
# innermost parenthesis still open where the name stands. Empty when the name is
# not an argument at all, and empty for `static_cast<bool>(n)`, whose `(` is
# preceded by `>` rather than by a name.
function callee(t, n,   pos, i, depth, ch, j, q) {
    pos = nameat(t, n)
    if (pos == 0) return ""
    depth = 0
    for (i = pos - 1; i >= 1; i--) {
        ch = substr(t, i, 1)
        if (ch == ")") depth++
        else if (ch == "(") { if (depth == 0) break; depth-- }
    }
    if (i < 1) return ""
    j = i - 1
    while (j >= 1 && substr(t, j, 1) == " ") j--
    q = j
    while (q >= 1 && substr(t, q, 1) ~ /[A-Za-z0-9_]/) q--
    return substr(t, q + 1, j - q)
}
# Redundant parentheses around the name, collapsed: `if ((outcome))` is
# `if (outcome)` and has to be read as one, or the rule is evaded with a
# bracket.
function unparen(t, n,   re, prev) {
    re = "\\([[:space:]]*\\([[:space:]]*" n "[[:space:]]*\\)[[:space:]]*\\)"
    do { prev = t; gsub(re, "(" n ")", t) } while (t != prev)
    return t
}
# A new value for the name: the window ends here, and the statement is not a
# misuse of what the name held before.
function rebinds(t, n) {
    return (t ~ ("(^|[^A-Za-z0-9_.>])" n "[[:space:]]*=[^=]"))
}
# The same statement with every assignment TO the name cut out, from the name to
# the semicolon that ends it. `outcome = x;` leaves nothing, which is a pure
# rebinding; `if (outcome) { outcome = x; }` leaves `if (outcome) { }`, which is
# the statement that has to be judged. Accepting a statement outright because it
# assigns somewhere was measured: that condition is ill-formed against a scoped
# enum -- g++ says "could not convert from AuthorizationOutcome to bool" -- and
# read green.
function stripassign(t, n,   out, s, p, rest, semi) {
    out = ""; s = t
    while (1) {
        p = nameat(s, n)
        if (p == 0) break
        rest = substr(s, p + length(n))
        if (rest ~ /^[[:space:]]*=([^=]|$)/) {
            semi = index(rest, ";")
            out = out substr(s, 1, p - 1)
            if (semi == 0) { s = ""; break }
            s = substr(s, p + length(n) + semi)
        } else {
            out = out substr(s, 1, p + length(n) - 1)
            s = substr(s, p + length(n))
        }
    }
    return out s
}
# The name standing alone as the controlling expression -- the commonest
# boolean use of all, and the one the "it names the type somewhere" pardon
# below let through. Measured:
#   `if (outcome) { m_lastOutcome = A::AuthorizationOutcome::Denied; return; }`
#   `while (outcome) { m_lastOutcome = A::AuthorizationOutcome::Denied; }`
# both read R4 ok, rc=0, and neither compiles. It asked whether the name was
# the condition of an `if` or a `while`, which is a list of two out of six --
# the condition slot of a `for` was open by the same reasoning. So the name is
# marked and its position is read by ctl_segment() above, the way R3 reads the
# call's.
function sole_condition(t, n,   p, t2, seg, c) {
    p = nameat(t, n)
    if (p == 0) return 0
    t2 = substr(t, 1, p - 1) MARK substr(t, p + length(n))
    seg = ctl_segment(t2, MARK)
    if (seg == UNSET) return 0
    c = strip_outer(seg)
    while (c ~ /^!/) { sub(/^![[:space:]]*/, "", c); c = strip_outer(c) }
    return (c == MARK)
}
# Shapes no statement may borrow acceptance from: a statement that names
# AuthorizationOutcome somewhere else is still ill-formed if it negates the
# outcome (`if (!o && p == AuthorizationOutcome::Granted)`).
function never(t, n) {
    if (t ~ ("(^|[^A-Za-z0-9_])![[:space:]]*" n "([^A-Za-z0-9_]|$)")) return 1
    if (t ~ ("[^A-Za-z0-9_]" n "[[:space:]]*(&&|\\|\\||\\?)")) return 1
    if (t ~ ("(&&|\\|\\|)[[:space:]]*" n "([^A-Za-z0-9_]|$)")) return 1
    if (t ~ ("[^A-Za-z0-9_]" n "[[:space:]]*(==|!=)[[:space:]]*(true|false|0|1)([^A-Za-z0-9_]|$)")) return 1
    if (t ~ ("(true|false|0|1)[[:space:]]*(==|!=)[[:space:]]*" n "([^A-Za-z0-9_]|$)")) return 1
    return 0
}
# The shapes a scoped enum stands in, and nothing else. An upper-case callee is
# a macro, and the assertion macros are exactly the ones that impose a bool, so
# it is accepted only when the statement also names the type -- EXPECT_EQ
# against an enumerator does, EXPECT_TRUE cannot. `assert` is that same macro
# spelled in lower case. A legitimate new shape is added here deliberately,
# having read the header.
function permitted(t, n, fnhdr,   cal, rest) {
    t = unparen(t, n)
    # The assignment first, and only the assignment: what is left of the
    # statement is judged like any other. Nothing left means a pure rebinding.
    if (rebinds(t, n)) {
        rest = stripassign(t, n)
        if (nameat(rest, n) == 0) return 1
        t = rest
    }
    if (never(t, n)) return 0
    if (sole_condition(t, n)) return 0
    if (t ~ ("switch[[:space:]]*\\([[:space:]]*" n "[[:space:]]*\\)")) return 1
    if (t ~ ("\\(void\\)[[:space:]]*" n "([^A-Za-z0-9_]|$)")) return 1
    if (t ~ ("(^|[^A-Za-z0-9_])return[[:space:]]+" n "[[:space:]]*;")) return (fnhdr ~ /AuthorizationOutcome/)
    cal = callee(t, n)
    if (cal != "" && cal != "assert" &&
        cal !~ /^(if|while|for|switch|return|catch|sizeof|do|else)$/ &&
        cal !~ /^(bool|char|short|int|long|float|double|signed|unsigned|void|wchar_t|char8_t|char16_t|char32_t|size_t|ssize_t|ptrdiff_t|intptr_t|uintptr_t|int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t)$/ &&
        (cal !~ /^[A-Z][A-Z0-9_]*$/ || t ~ /AuthorizationOutcome/)) return 1
    if (t ~ /AuthorizationOutcome/) return 1
    return 0
}
BEGIN { FS = "\t" }
{
    file = $1; start = $2 + 0; mention = $3 + 0; txt = $4
    if (file != prevfile) { delete bound; prevfile = file; fnhdr = "" }
    ndrop = 0
    for (n in bound) {
        if (nameat(txt, n) == 0) continue
        if (permitted(txt, n, fnhdr)) {
            if (mention == 0 && rebinds(txt, n)) drop[++ndrop] = n
            continue
        }
        printf "%s:%d:%s\n", file, start, txt
        printf "        (%s holds the outcome, bound at %s:%d)\n", n, file, bound[n]
        drop[++ndrop] = n
    }
    for (i = 1; i <= ndrop; i++) delete bound[drop[i]]
    if (mention > 0) {
        nm = binder(txt)
        if (nm != "") bound[nm] = mention
    }
    # The enclosing function, for `return <name>;`: the last statement that ends
    # in an opening brace and is not a control-flow block. A lambda takes that
    # place too, which is honest -- its return type is the one in force.
    if (txt ~ /\{$/ && txt ~ /\)/ &&
        txt !~ /^(if|for|while|switch|else|do|try|catch|namespace|struct|class|union|enum)[^A-Za-z0-9_]/)
        fnhdr = txt
}
AWK
awk -f "$SCRATCH/pos.awk" -f "$SCRATCH/bind.awk" "$SCRATCH/stmts.txt" > "$SCRATCH/r4.txt" \
    || { echo "FATAL: the bound-name program failed to run — refusing to judge" >&2; exit 2; }

if [ -s "$SCRATCH/r4.txt" ]; then
    echo "::error::the outcome is bound to a name here and then used in a shape a scoped enum does not stand in — a switch, a statement naming AuthorizationOutcome, an argument to a call, a rebinding, a discard or a return from a function declared to return it, and nothing else. If the shape is legitimate, add it to permitted() in $0."
    cat "$SCRATCH/r4.txt"
    echo "  $(grep -c "^[^ ]" "$SCRATCH/r4.txt") later use(s) of a bound outcome in an unrecognised shape"
    rc=1
else
    echo "  R4 ok   — every later use of a name bound from authorize() is a shape a scoped enum stands in"
fi


# ---------------------------------------------------------------- R5
# The compiler over every unit that names the call.
#
# R2, R3 and R4 read text, and text has been narrower than it printed three
# rounds running: an extension list one kind short, a directory list one
# directory short, a scope patched with a grep for the AGENT header's spelling
# while a Darwin-side caller names the Darwin subclass. Each patch was correct
# and each left the next spelling open, because a rule that enumerates is a rule
# that can be out-spelled.
#
# The property is not textual at all. authorize() returns a scoped enum, a
# scoped enum has no conversion to bool, and the COMPILER rejects every shape
# those rules try to enumerate -- including the ones they accept by mistake.
# What stops it being the whole of this gate is reach, not power: of the units
# that name the call, the socket frontend and its test include LibreMiddleware's
# headers and Apple blocks, so they compile here only when those headers are on
# the path and the compiler understands `^{ }`. Measured on a Linux host with
# clang and a sibling LibreMiddleware checkout: every one of them passes
# -fsyntax-only, with the bsm stand-in above as the only stub. With a compiler
# that has no blocks, or with no LibreMiddleware headers to hand: three of five.
#
# So this rule judges what it can reach and PRINTS how many that was. A unit it
# cannot reach is not a refusal: R2-R4 still read it, and a rule that went
# yellow whenever a sibling checkout was absent is a rule somebody switches off.
# A unit it CAN reach and that fails on the contract is rc=1 -- the strongest
# verdict in this file, and the only one no spelling can answer.
#

# Apple blocks: the socket frontend dispatches with `^{ }`, which is a clang
# extension. Probed rather than assumed, because a compiler without it reports
# a syntax error that has nothing to do with this contract.
blocks=()
printf 'void f(void){ void (^b)(void) = ^{ }; (void)b; }\n' > "$SCRATCH/blocks.cpp"
if "$CXX_BIN" -std=c++23 -fblocks -fsyntax-only "$SCRATCH/blocks.cpp" >/dev/null 2>&1; then
    blocks=(-fblocks)
fi

: > "$SCRATCH/r5-tus.txt"
while IFS= read -r f; do
    [ -f "$f" ] || continue
    grep -qE 'authorize[[:space:]]*\(' "$f" && printf '%s\n' "$f"
done < "$SCRATCH/sources.txt" > "$SCRATCH/r5-tus.txt"

# When the chosen compiler has no blocks, one that HAS them is looked for on
# PATH before a unit is written off. Measured on this workspace: the default
# `c++` is gcc and judged three of five, while a clang++ installed beside it
# judges all five -- and the durable record blamed a missing sibling checkout
# that was in fact found. Which compiler produced the verdict is printed.
BLOCKS_CXX=""
if [ "${#blocks[@]}" -gt 0 ]; then
    BLOCKS_CXX="$CXX_BIN"
else
    for cand in clang++ clang++-21 clang++-20 clang++-19 clang++-18; do
        command -v "$cand" >/dev/null 2>&1 || continue
        if "$cand" -std=c++23 -fblocks -fsyntax-only "$SCRATCH/blocks.cpp" >/dev/null 2>&1; then
            BLOCKS_CXX="$cand"
            break
        fi
    done
fi

r5_try() {  # r5_try <compiler> [flags...] — compiles $t, log in $SCRATCH/r5.log
    local cc="$1"; shift
    "$cc" -std=c++23 "$@" -fsyntax-only "${shim_inc[@]}" "${defs[@]}" \
        -I agent/include -I agent/src -I agent/tests -isystem "$LA_INCLUDE" "${extra_inc[@]}" \
        "$t" > "$SCRATCH/r5.log" 2>&1
}

r5_total=0; r5_compiled=0; r5_unreached=0; r5_broken=0; r5_alt=0; r5_unclear=0
: > "$SCRATCH/r5-unreached.txt"
while IFS= read -r t; do
    [ -n "$t" ] || continue
    r5_total=$((r5_total + 1))
    defs=()
    case "$t" in agent/tests/*) defs=(-DLIBRESCRS_INTERNAL_BUILD) ;; esac

    r5_ok=0
    if r5_try "$CXX_BIN" "${blocks[@]}"; then
        r5_ok=1
    elif [ -n "$BLOCKS_CXX" ] && [ "$BLOCKS_CXX" != "$CXX_BIN" ] \
         && grep -qE "$BLOCKSRE" "$SCRATCH/r5.log"; then
        r5_alt=1
        r5_try "$BLOCKS_CXX" -fblocks && r5_ok=1
    fi
    if [ "$r5_ok" = 1 ]; then
        r5_compiled=$((r5_compiled + 1))
        continue
    fi

    if [ "$agent_stale" = 1 ] || grep -qE "$STALERE" "$SCRATCH/r5.log"; then
        # R1 has already reported which revision has to move. Every unit that
        # fails after that fails for the same reason, and naming a call site
        # here would send the reader to fix code that is correct.
        r5_unreached=$((r5_unreached + 1))
        printf '        %s -- the LibreAgent revision under test predates the outcome type; R1 above says so\n' "$t" \
            >> "$SCRATCH/r5-unreached.txt"
    elif errfile=$(first_error_file "$SCRATCH/r5.log"); foreign_error "$errfile"; then
        # The first error is in a header this repository does not own. Whatever
        # it says, it is not a verdict about a call site here.
        r5_unreached=$((r5_unreached + 1))
        printf '        %s -- the first error stands in %s, outside this checkout\n' "$t" "$errfile" \
            >> "$SCRATCH/r5-unreached.txt"
    elif contract_diag "$SCRATCH/r5.log"; then
        r5_broken=$((r5_broken + 1))
        echo "::error file=$t::this translation unit does not compile against the authorize() contract — a scoped enum has no conversion to bool, and no spelling makes one"
        grep -E '(error|note):' "$SCRATCH/r5.log" | head -10
        rc=1
    elif grep -qE "$ENVRE" "$SCRATCH/r5.log"; then
        r5_unreached=$((r5_unreached + 1))
        printf '        %s -- out of reach: %s\n' "$t" "$(first_error_text "$SCRATCH/r5.log")" \
            >> "$SCRATCH/r5-unreached.txt"
    else
        # The compiler opened this unit and rejected it, and the rejection is
        # neither this contract's nor the environment's. That is a hole in the
        # measurement, and it used to be spelled "out of reach" underneath the
        # word "ok": an unrelated broken symbol moved a unit from judged to
        # unjudged at rc=0, and the count is the only signal there is. It is
        # counted apart and the verdict word changes, so a coverage drop is
        # read rather than deduced from a number nobody kept.
        r5_unclear=$((r5_unclear + 1))
        r5_unreached=$((r5_unreached + 1))
        printf '        %s -- NOT JUDGED, and not for a reason this rule recognises: %s\n' \
            "$t" "$(first_error_text "$SCRATCH/r5.log")" >> "$SCRATCH/r5-unreached.txt"
    fi
done < "$SCRATCH/r5-tus.txt"

# The verdict line says what the rule found, not merely how far it reached. A
# rule that prints "R5 ok" on the same run in which it reports a contract
# failure and sets rc=1 leaves a log whose verdict lines all read ok over a red
# gate. Every other rule here prints no ok line when it has an ::error to
# report, and these lines are the only record of what was judged.
r5_reach_note=""
[ "$r5_unreached" -gt 0 ] && r5_reach_note="; $r5_unreached out of reach and left to R2-R4"
r5_with="${extra_named:+ with $extra_named}"
[ "$r5_alt" = 1 ] && r5_with="${r5_with:+$r5_with,} $BLOCKS_CXX where $CXX_BIN has no blocks"
r5_with="${r5_with:+ ($(echo "$r5_with" | sed 's/^ //'))}"
if [ "$r5_broken" -gt 0 ]; then
    echo "  R5 FAILED — $r5_broken of $((r5_broken + r5_compiled)) translation unit(s) judged here do not compile against the authorize() contract$r5_with$r5_reach_note"
    [ "$r5_unreached" -gt 0 ] && cat "$SCRATCH/r5-unreached.txt"
elif [ "$r5_total" -eq 0 ]; then
    echo "  R5 ok   — no source in this tree names authorize(), so there is nothing for a compiler to judge"
elif [ "$r5_unreached" -eq 0 ]; then
    echo "  R5 ok   — all $r5_total translation unit(s) naming authorize() compile against $LA_INCLUDE$r5_with"
elif [ "$r5_unclear" -gt 0 ]; then
    echo "  R5 INCOMPLETE — $r5_compiled of $r5_total translation unit(s) naming authorize() were compiled here$r5_with; $r5_unreached left to R2-R4, of which $r5_unclear failed for a reason this rule cannot attribute:"
    cat "$SCRATCH/r5-unreached.txt"
else
    echo "  R5 ok   — $r5_compiled of $r5_total translation unit(s) naming authorize() were compiled here$r5_with; $r5_unreached out of reach and left to R2-R4:"
    cat "$SCRATCH/r5-unreached.txt"
fi

exit "$rc"
