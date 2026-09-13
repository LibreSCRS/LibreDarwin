#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-agent-interface.selftest.sh — drive check-agent-interface.sh over
# synthetic pairs, so the suite does not depend on what this repository happens
# to declare today (it would then pass or fail with the very defect it guards).
#
# Pairs chosen so each rule can be shown to flip on its own:
#   1  base enum   + derived enum  + switch caller    -> 0
#   2  base enum   + derived bool                     -> 1  (R1: the release break)
#   3  base enum   + derived enum  + `if (!...)`      -> 1  (R2: the half-fix)
#   4  base bool   + derived enum                     -> 1  (stale agent, named as such)
# one that must REFUSE to judge rather than report the defect:
#   5  a derived header with an unrelated syntax error -> 2
# and five for what R1 cannot see, because its translation unit is ONE header:
#   6  `if (a.authorize(x, y))`                        -> 1  (R3: no bool named,
#                                                             nothing negated,
#                                                             and it does not
#                                                             compile either)
#   7  `bool ok = a.authorize(x, y);`                  -> 1  (R2)
#   8  EXPECT_FALSE( with the call on the NEXT line    -> 1  (R3: a line-based
#                                                             rule that looks
#                                                             for the macro and
#                                                             the call together
#                                                             misses this)
#   9  a bool OUT-OF-LINE definition in agent/src      -> 1  (R2)
#  10  a SECOND Authorizer subclass declaring bool     -> 1  (R2: the test
#                                                             double is off R1's
#                                                             include path)
#  11  CONTROL: switch + EXPECT_EQ + an enum definition + a comment naming
#      authorize()                                     -> 0  (a rule that is red
#                                                             by default must
#                                                             still be green on
#                                                             the shapes in use)
# and six for reading text as text rather than as code:
#  12  a boolean use with `// AuthorizationOutcome` at the end of the SAME line
#                                                      -> 1  (a rule matched
#                                                             against the raw
#                                                             line takes the
#                                                             comment for the
#                                                             code)
#  13  CONTROL: a call wrapped at the margin, bound and switched on
#                                                      -> 0  (correct code the
#                                                             line-based rule
#                                                             called broken)
#  14  `if (auto ok = ...authorize(...); ok)`           -> 1  (a condition, not
#                                                             a binding)
#  15  `const auto r = ...authorize(...) ? 1 : 0;`      -> 1  (a ternary, not a
#                                                             binding)
#  16  a boolean use in a .cc file                      -> 1  (the extension list
#                                                             was narrower than
#                                                             the one this
#                                                             repository calls
#                                                             source)
#  17  a file under agent/ whose extension is in neither list
#                                                      -> 1  (what the rules do
#                                                             not read must be
#                                                             said out loud)
# and one for the half a compiler reaches and no text rule does:
#  18  the outcome bound in one statement, negated in the next, in the one file
#      R1 compiles                                     -> 1  (R1)
# four for the same shape where no compiler reaches, which is where it was found:
#  19  bound, then negated, in a file nothing on this host compiles
#                                                      -> 1  (R4)
#  20  bound, then EXPECT_TRUE'd two statements later  -> 1  (R4)
#  21  CONTROL: bound, then switched on and compared    -> 0  (binding the
#                                                             outcome is the
#                                                             correct shape; R4
#                                                             must not punish it)
#  22  CONTROL: the name reassigned from something else, then used as a bool
#                                                      -> 0  (the window ends
#                                                             where the outcome
#                                                             does)
# seven for R4's polarity, which was an allowlist of the ILL-FORMED spellings
# until every one of these read green:
#  24  `if (outcome == false)`                            -> 1  (R4)
#  25  `if ((outcome))`                                   -> 1  (R4: a bracket
#                                                                is not a cure)
#  26  `assert(outcome)`                                  -> 1  (R4: the
#                                                                assertion macro
#                                                                spelled in
#                                                                lower case)
#  27  `bool ok{outcome};`                                -> 1  (R4)
#  28  `return outcome;` from a function returning void   -> 1  (R4)
#  29  CONTROL: `return outcome;` where the function is
#      declared to return the outcome                     -> 0  (the only return
#                                                                type a textual
#                                                                rule can see is
#                                                                the header)
#  30  CONTROL: the outcome passed to a call              -> 0  (the parameter's
#                                                                type is in
#                                                                another file;
#                                                                a rule that
#                                                                reddened this
#                                                                would forbid
#                                                                passing the
#                                                                outcome at all)
# three more for the two shapes that survived that polarity change, neither of
# them a spelling:
#  31  `if (outcome) { outcome = ...; }` on ONE line       -> 1  (R4: a statement
#                                                                was pardoned by
#                                                                an assignment
#                                                                anywhere in it,
#                                                                and this one is
#                                                                ill-formed. One
#                                                                line, because
#                                                                statements are
#                                                                assembled a
#                                                                physical line at
#                                                                a time: written
#                                                                over three lines
#                                                                the condition is
#                                                                a statement of
#                                                                its own and was
#                                                                already red)
#  32  `if (bool(outcome))`                                -> 1  (R4: a
#                                                                functional-style
#                                                                cast to a
#                                                                builtin read as
#                                                                a call taking
#                                                                the outcome --
#                                                                and it compiles,
#                                                                so no host
#                                                                reports it)
#  33  CONTROL: `if (ready) { outcome = ...; }`            -> 0  (cutting the
#                                                                assignment out
#                                                                must not cost
#                                                                a real
#                                                                rebinding its
#                                                                pardon; what is
#                                                                left names the
#                                                                outcome nowhere)
# and two for the file list itself:
#  23  a boolean use in a source that is written but not `git add`ed
#                                                      -> 1  (a source nobody
#                                                             added compiles
#                                                             exactly like one
#                                                             that has been; the
#                                                             branch that reads
#                                                             them had no
#                                                             fixture, so it
#                                                             could be deleted
#                                                             with the suite
#                                                             still green)
# three for which revision the reader is sent to move:
#  35  a stale agent reached through the pin                -> 1  (and the
#                                                                verdict names
#                                                                the pin)
#  36  a stale agent trunk                                  -> 1  (and it names
#                                                                publishing, not
#                                                                the pin: the
#                                                                trunk job reads
#                                                                no pin)
#  37  a provenance that is neither                         -> 2  (a closed set,
#                                                                not free text)
#  34  a boolean use of authorize() in prompter/          -> 1  (the rules read
#                                                             agent/, and this
#                                                             repository builds
#                                                             three other source
#                                                             trees; measured,
#                                                             all four rules read
#                                                             "ok" one directory
#                                                             over)
set -uo pipefail
export LC_ALL=C

GATE="${1:-$(cd "$(dirname "$0")" && pwd)/check-agent-interface.sh}"
[ -f "$GATE" ] || { echo "FATAL: no gate at $GATE" >&2; exit 2; }

WORK="$(mktemp -d /var/tmp/check-agent-interface-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

mkbase() { # <dir> <bool|enum>
    mkdir -p "$1/LibreSCRS/Agent/backend"
    { echo '#pragma once'
      echo '#include <string_view>'
      echo 'namespace LibreSCRS::Agent {'
      echo 'struct CallerToken { int id; };'
      [ "$2" = enum ] && echo 'enum class AuthorizationOutcome { Granted, Denied, Undecided };'
      echo 'class Authorizer {'
      echo 'public:'
      echo '    virtual ~Authorizer() = default;'
      if [ "$2" = enum ]; then
        echo '    virtual AuthorizationOutcome authorize(std::string_view, const CallerToken&) = 0;'
      else
        echo '    virtual bool authorize(std::string_view, const CallerToken&) = 0;'
      fi
      echo '};'
      echo '}'
    } > "$1/LibreSCRS/Agent/backend/Authorizer.h"
}
mkderived() { # <root> <bool|enum|broken> <switch|bang|if|boolvar|expectfalse2|eq|none>
    local h="$1/agent/include/LibreSCRS/Darwin/backend"
    mkdir -p "$h" "$1/agent/src" "$1/agent/tests"
    { echo '#pragma once'
      echo '#include <bsm/libbsm.h>'
      echo '#include <LibreSCRS/Agent/backend/Authorizer.h>'
      echo 'namespace LibreSCRS::Darwin {'
      echo 'class SecCodeAuthorizer final : public Agent::Authorizer {'
      echo 'public:'
      case "$2" in
        bool)   echo '    bool authorize(std::string_view, const Agent::CallerToken&) override;' ;;
        enum)   echo '    Agent::AuthorizationOutcome authorize(std::string_view, const Agent::CallerToken&) override;' ;;
        broken) echo '    this is not c++ at all;' ;;
      esac
      echo '    audit_token_t tok{};'
      echo '};'
      echo '}'
    } > "$h/SecCodeAuthorizer.h"
    case "$3" in
      switch)       echo 'void f() { switch (a.authorize(x, y)) { default: break; } }'   > "$1/agent/src/caller.cpp" ;;
      bang)         echo 'void f() { if (!a.authorize(x, y)) { return; } }'              > "$1/agent/src/caller.cpp" ;;
      if)           echo 'void f() { if (a.authorize(x, y)) { return; } }'               > "$1/agent/src/caller.cpp" ;;
      boolvar)      echo 'void f() { const bool ok = a.authorize(x, y); (void)ok; }'     > "$1/agent/src/caller.cpp" ;;
      expectfalse2) { echo 'void f() { EXPECT_FALSE('
                      echo '        a.authorize(x, y)); }'
                    }                                                                    > "$1/agent/src/caller.cpp" ;;
      eq)           echo 'void f() { EXPECT_EQ(a.authorize(x, y), Agent::AuthorizationOutcome::Denied); }' > "$1/agent/src/caller.cpp" ;;
      trailcomment) echo 'void f() { if (a.authorize(x, y)) { return; } }  // AuthorizationOutcome' > "$1/agent/src/caller.cpp" ;;
      wrapped)      { echo 'void f() {'
                      echo '    const auto outcome = a.authorize(x,'
                      echo '                                     y);'
                      echo '    switch (outcome) { default: break; }'
                      echo '}'
                    }                                                                    > "$1/agent/src/caller.cpp" ;;
      ifauto)       echo 'void f() { if (auto ok = a.authorize(x, y); ok) { return; } }' > "$1/agent/src/caller.cpp" ;;
      ternary)      echo 'void f() { const auto r = a.authorize(x, y) ? 1 : 0; (void)r; }' > "$1/agent/src/caller.cpp" ;;
      none)         : > "$1/agent/src/caller.cpp" ;;
    esac
}
# The out-of-line definition: a .cpp is never on R1's include path, and on this
# host the Darwin one cannot be compiled at all.
mkdefinition() { # <root> <bool|enum>
    mkdir -p "$1/agent/src"
    if [ "$2" = bool ]; then
        echo 'bool SecCodeAuthorizer::authorize(std::string_view a, const Agent::CallerToken& c) { return false; }' > "$1/agent/src/def.cpp"
    else
        echo 'Agent::AuthorizationOutcome SecCodeAuthorizer::authorize(std::string_view a, const Agent::CallerToken& c) { return Agent::AuthorizationOutcome::Denied; }' > "$1/agent/src/def.cpp"
    fi
}
# The second subclass: this repository has one, a test double under agent/tests.
# R1 compiles the production header and never learns it exists.
mkdouble() { # <root> <bool|enum>
    mkdir -p "$1/agent/tests"
    { echo 'struct DenyAllAuthorizer final : Agent::Authorizer {'
      if [ "$2" = bool ]; then
        echo '    [[nodiscard]] bool authorize(std::string_view, const Agent::CallerToken&) override { return false; }'
      else
        echo '    [[nodiscard]] Agent::AuthorizationOutcome authorize(std::string_view, const Agent::CallerToken&) override { return Agent::AuthorizationOutcome::Denied; }'
      fi
      echo '};'
    } > "$1/agent/tests/double.cpp"
}
check() { # <label> <want-rc> <root> <la-include>
    local label="$1" want="$2" rc
    REPO_ROOT="$3" bash "$GATE" "$4" > "$WORK/out.txt" 2>&1; rc=$?
    if [ "$rc" = "$want" ]; then
        echo "  ok    $label (rc=$rc)"; pass=$((pass+1))
    else
        echo "  FAIL  $label: want rc=$want, got rc=$rc"; sed 's/^/        /' "$WORK/out.txt"; fail=$((fail+1))
    fi
}

mkbase "$WORK/la-enum" enum
mkbase "$WORK/la-bool" bool
mkderived "$WORK/c1" enum   switch ; check "enum base + enum override + switch" 0 "$WORK/c1" "$WORK/la-enum"
mkderived "$WORK/c2" bool   bang   ; check "enum base + bool override (R1)"     1 "$WORK/c2" "$WORK/la-enum"
mkderived "$WORK/c3" enum   bang   ; check "enum base + enum override + if(!) (R2)" 1 "$WORK/c3" "$WORK/la-enum"
mkderived "$WORK/c4" enum   switch ; check "bool base + enum override (stale agent)" 1 "$WORK/c4" "$WORK/la-bool"
mkderived "$WORK/c5" broken switch ; check "unrelated syntax error refuses to judge" 2 "$WORK/c5" "$WORK/la-enum"

# Six through ten are the half of the contract R1 cannot reach. Each is
# ill-formed against a scoped enum and each was green before R2 was widened and
# R3 added; the tree they describe compiles nowhere, but on this host nothing
# compiles it, so the text rules are the whole of the evidence.
mkderived "$WORK/c6" enum if           ; check "plain if (...authorize(...)) (R3)"        1 "$WORK/c6" "$WORK/la-enum"
mkderived "$WORK/c7" enum boolvar      ; check "bool variable from authorize() (R2)"      1 "$WORK/c7" "$WORK/la-enum"
mkderived "$WORK/c8" enum expectfalse2 ; check "EXPECT_FALSE with the call a line down (R3)" 1 "$WORK/c8" "$WORK/la-enum"
mkderived "$WORK/c9" enum switch ; mkdefinition "$WORK/c9" bool ; check "bool out-of-line definition (R2)" 1 "$WORK/c9" "$WORK/la-enum"
mkderived "$WORK/c10" enum switch ; mkdouble "$WORK/c10" bool ; check "second subclass declares bool (R2)" 1 "$WORK/c10" "$WORK/la-enum"

# Eleven is the control a red-by-default rule needs: the shapes actually in use,
# plus a comment that names authorize() in prose. A gate that fails on the
# explanation of the rule is a gate that gets deleted with it.
mkderived "$WORK/c11" enum eq ; mkdefinition "$WORK/c11" enum ; mkdouble "$WORK/c11" enum
printf '%s\n' '// authorize() returns AuthorizationOutcome; do not call it in a bool context.' \
               '/* not even inside EXPECT_TRUE(authorize(x, y)) */' >> "$WORK/c11/agent/src/caller.cpp"
cat >> "$WORK/c11/agent/src/def.cpp" <<'EOF'
void g() { switch (a.authorize(x, y)) { default: break; } }
EOF
check "accepted shapes and a comment naming authorize()" 0 "$WORK/c11" "$WORK/la-enum"

# Twelve through fifteen: the rules read statements, not lines. Two of them are
# ill-formed code a line-based rule accepted (a trailing comment supplying the
# token it looks for; a ternary that borrows the binding shape), one is a
# condition that borrows it too, and one is correct code the line-based rule
# rejected -- a gate that goes red on a call wrapped at the margin gets worked
# around, not read.
mkderived "$WORK/c12" enum trailcomment ; check "boolean use, type named in a trailing comment (R3)" 1 "$WORK/c12" "$WORK/la-enum"
mkderived "$WORK/c13" enum wrapped      ; check "CONTROL: call wrapped at the margin, bound and switched" 0 "$WORK/c13" "$WORK/la-enum"
mkderived "$WORK/c14" enum ifauto       ; check "if (auto ok = ...; ok) is a condition (R3)"  1 "$WORK/c14" "$WORK/la-enum"
mkderived "$WORK/c15" enum ternary      ; check "ternary on the outcome (R3)"                 1 "$WORK/c15" "$WORK/la-enum"

# Sixteen and seventeen are about scope rather than shape: a rule that reads
# text is only as wide as its file list, and the list was narrower than the one
# check-format-scope.sh already commits to. Seventeen is the same defect made
# loud: an extension in neither list is an error, not a silence.
mkderived "$WORK/c16" enum switch ; echo 'void g() { if (!a.authorize(x, y)) { return; } }' > "$WORK/c16/agent/src/other.cc"
check "boolean use in a .cc source (R2)" 1 "$WORK/c16" "$WORK/la-enum"
mkderived "$WORK/c17" enum switch ; echo 'if (!a.authorize(x, y)) { return; }' > "$WORK/c17/agent/src/other.zz"
check "a file in neither extension list that names the call" 1 "$WORK/c17" "$WORK/la-enum"

# Eighteen is what a compiler buys that no text rule can. R1 now compiles a real
# source file from this repository, and the fixture below writes one at the same
# path: it binds the outcome to a name in one statement and negates the name in
# the NEXT. R2 and R3 are green on it BY DESIGN -- the first statement spells
# AuthorizationOutcome, the second never mentions authorize() -- and the header
# says as much. The compiler is not fooled: `no match for operator!`.
mkderived "$WORK/c18" enum switch
cat > "$WORK/c18/agent/tests/SecCodeAuthorizerTest.cpp" <<'EOF'
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
namespace {
LibreSCRS::Darwin::SecCodeAuthorizer* a = nullptr;
}
void f()
{
    const LibreSCRS::Agent::AuthorizationOutcome o = a->authorize("x", {});
    if (!o) {
        return;
    }
}
EOF
check "outcome bound, then negated in the next statement (R1)" 1 "$WORK/c18" "$WORK/la-enum"

# Nineteen through twenty-two are that same shape where no compiler follows it:
# agent/src, four of whose five outcome-carrying files this host cannot compile
# at all, and one of which holds every call site. R2 and R3 are green on it by
# construction -- the binding names the type, the use names nothing -- so R4
# follows the name instead. The two controls matter as much as the reds: a rule
# that went off on a bound outcome would forbid the shape the repaired code
# uses.
mkderived "$WORK/c19" enum switch
cat > "$WORK/c19/agent/src/caller.cpp" <<'EOF'
void f()
{
    const auto outcome = a.authorize(x, y);
    if (!outcome) {
        return;
    }
}
EOF
check "outcome bound, negated in a file no compiler reads (R4)" 1 "$WORK/c19" "$WORK/la-enum"

mkderived "$WORK/c20" enum switch
cat > "$WORK/c20/agent/src/caller.cpp" <<'EOF'
void f()
{
    const auto outcome = a.authorize(x, y);
    record(outcome);
    EXPECT_TRUE(outcome);
}
EOF
check "outcome bound, EXPECT_TRUE'd two statements later (R4)" 1 "$WORK/c20" "$WORK/la-enum"

mkderived "$WORK/c21" enum switch
cat > "$WORK/c21/agent/src/caller.cpp" <<'EOF'
void f()
{
    const auto outcome = a.authorize(x, y);
    switch (outcome) {
    default:
        break;
    }
    EXPECT_EQ(outcome, Agent::AuthorizationOutcome::Denied);
}
EOF
check "CONTROL: outcome bound, switched on and compared" 0 "$WORK/c21" "$WORK/la-enum"

mkderived "$WORK/c22" enum switch
cat > "$WORK/c22/agent/src/caller.cpp" <<'EOF'
void f()
{
    auto outcome = a.authorize(x, y);
    log(outcome);
    bool outcome = readyToSign();
    if (!outcome) {
        return;
    }
}
EOF
check "CONTROL: the name reassigned away from the outcome" 0 "$WORK/c22" "$WORK/la-enum"

# Twenty-four through thirty are R4's polarity. Each of the five reds below was
# measured green while R4 listed the ill-formed spellings instead of the
# well-formed ones -- one defect in five spellings, in the file that carries
# every call site and that no compiler on this host reads. The two controls are
# the other half: a rule that is red by default has to be green on the shapes
# correct code uses, or it gets worked around rather than read.
r4_fixture() {  # r4_fixture <root> <body>
    mkderived "$1" enum switch
    { echo 'void f()'
      echo '{'
      printf '%s\n' "$2"
      echo '}'
    } > "$1/agent/src/caller.cpp"
}
r4_fixture "$WORK/c24" '    const auto outcome = a.authorize(x, y);
    if (outcome == false) {
        return;
    }'
check "outcome bound, compared against false (R4)" 1 "$WORK/c24" "$WORK/la-enum"

r4_fixture "$WORK/c25" '    const auto outcome = a.authorize(x, y);
    if ((outcome)) {
        return;
    }'
check "outcome bound, wrapped in one more paren (R4)" 1 "$WORK/c25" "$WORK/la-enum"

r4_fixture "$WORK/c26" '    const auto outcome = a.authorize(x, y);
    assert(outcome);'
check "outcome bound, then asserted (R4)" 1 "$WORK/c26" "$WORK/la-enum"

r4_fixture "$WORK/c27" '    const auto outcome = a.authorize(x, y);
    bool ok{outcome};
    (void)ok;'
check "outcome bound, brace-initialising a bool (R4)" 1 "$WORK/c27" "$WORK/la-enum"

r4_fixture "$WORK/c28" '    const auto outcome = a.authorize(x, y);
    return outcome;'
check "outcome bound, returned from a void function (R4)" 1 "$WORK/c28" "$WORK/la-enum"

mkderived "$WORK/c29" enum switch
cat > "$WORK/c29/agent/src/caller.cpp" <<'EOF'
Agent::AuthorizationOutcome forwardTo(Backend& a)
{
    const auto outcome = a.authorize(x, y);
    return outcome;
}
EOF
check "CONTROL: the outcome returned by a function declared to return it" 0 "$WORK/c29" "$WORK/la-enum"

mkderived "$WORK/c30" enum switch
cat > "$WORK/c30/agent/src/caller.cpp" <<'EOF'
void f()
{
    const auto outcome = a.authorize(x, y);
    recordDecision(connId, outcome);
    (void)outcome;
}
EOF
check "CONTROL: the outcome passed to a call and discarded" 0 "$WORK/c30" "$WORK/la-enum"

# Thirty-one through thirty-three are the two shapes that outlived the polarity
# change, and they are not spellings. The first is ill-formed and was accepted
# because the statement assigns to the name somewhere; the second compiles,
# which is worse -- it is the outcome consumed as a bool, and no compiler on any
# host will report it. The control is the other half: cutting the assignment out
# before judging must not cost a real rebinding its pardon.
r4_fixture "$WORK/c31" '    const auto outcome = a.authorize(x, y);
    if (outcome) { outcome = Agent::AuthorizationOutcome::Denied; }'
check "outcome bound, tested and then assigned in one statement (R4)" 1 "$WORK/c31" "$WORK/la-enum"

r4_fixture "$WORK/c32" '    const auto outcome = a.authorize(x, y);
    if (bool(outcome)) {
        return;
    }'
check "outcome bound, cast to bool by a functional cast (R4)" 1 "$WORK/c32" "$WORK/la-enum"

r4_fixture "$WORK/c33" '    auto outcome = a.authorize(x, y);
    if (ready) { outcome = Agent::AuthorizationOutcome::Denied; }
    (void)outcome;'
check "CONTROL: the outcome rebound inside one statement, and nothing else" 0 "$WORK/c33" "$WORK/la-enum"

# Twenty-three is about the file list rather than a rule. Inside a checkout the
# gate reads tracked files AND the ones written but not added, because a source
# nobody added compiles exactly like one that has been -- and that branch had no
# fixture at all: every case above is a plain directory, so the branch could be
# deleted with all of them still green. This one is a real repository.
if command -v git >/dev/null 2>&1; then
    mkderived "$WORK/c23" enum switch
    # This fixture is a checkout, so the translation unit the gate names by hand
    # has to be there: inside a repository a missing one is a stale list and the
    # gate refuses to judge, which is not what this case is about.
    cat > "$WORK/c23/agent/tests/SecCodeAuthorizerTest.cpp" <<'EOF'
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
namespace {
LibreSCRS::Darwin::SecCodeAuthorizer* a = nullptr;
}
void t()
{
    switch (a->authorize("x", {})) {
    default:
        break;
    }
}
EOF
    git -C "$WORK/c23" init -q 2>/dev/null
    git -C "$WORK/c23" add agent >/dev/null 2>&1
    echo 'void g() { if (!a.authorize(x, y)) { return; } }' > "$WORK/c23/agent/src/unadded.cpp"
    if git -C "$WORK/c23" rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
       [ -n "$(git -C "$WORK/c23" ls-files -- agent)" ]; then
        check "boolean use in a source that was never git added (R2)" 1 "$WORK/c23" "$WORK/la-enum"
    else
        echo "  FAIL  the untracked-source fixture is not a repository with a tracked agent/ -- it would pass for the wrong reason"
        fail=$((fail+1))
    fi
else
    echo "  FAIL  git is not available, so the tracked/untracked branch cannot be measured -- do not read this as a pass"
    fail=$((fail+1))
fi

# Thirty-four is about the directory rather than the file. The rules read
# agent/; this repository also builds prompter/, pkcs11-module/ and build-cc/,
# and the same ill-formed boolean use one directory over left all four rules
# "ok". A checkout, because the scope rule asks git which files are tracked.
if command -v git >/dev/null 2>&1; then
    mkderived "$WORK/c34" enum switch
    cat > "$WORK/c34/agent/tests/SecCodeAuthorizerTest.cpp" <<'EOF'
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
namespace {
LibreSCRS::Darwin::SecCodeAuthorizer* a = nullptr;
}
void t()
{
    switch (a->authorize("x", {})) {
    default:
        break;
    }
}
EOF
    mkdir -p "$WORK/c34/prompter"
    { echo '#include <LibreSCRS/Agent/backend/Authorizer.h>'
      echo 'bool gate(LibreSCRS::Agent::Authorizer& a) { return !a.authorize("x", {}); }'
    } > "$WORK/c34/prompter/NewCaller.cpp"
    git -C "$WORK/c34" init -q 2>/dev/null
    git -C "$WORK/c34" add agent prompter >/dev/null 2>&1
    if [ -n "$(git -C "$WORK/c34" ls-files -- prompter)" ]; then
        check "a caller of the agent interface outside agent/" 1 "$WORK/c34" "$WORK/la-enum"
    else
        echo "  FAIL  the out-of-scope fixture has no tracked prompter/ -- it would pass for the wrong reason"
        fail=$((fail+1))
    fi
else
    echo "  FAIL  git is not available, so the scope rule cannot be measured -- do not read this as a pass"
    fail=$((fail+1))
fi

# Thirty-five through thirty-seven: which revision has to move. CI runs this
# check against BOTH the agent's published branch and cmake/libreagent.pin, and
# the stale-agent verdict used to end "Raise cmake/libreagent.pin." whatever it
# had been handed. On the trunk side that names a file the job never reads --
# and while both are red for the same missing type, it sends the reader to move
# a pin that cannot answer. The provenance is a closed set: an unrecognised one
# refuses to judge rather than falling back to a sentence that fits neither.
check_origin() {  # check_origin <label> <origin> <want-rc> <root> <la-include> <want> <banned>
    local label="$1" origin="$2" want="$3" rc out
    REPO_ROOT="$4" bash "$GATE" "$5" "$origin" > "$WORK/out.txt" 2>&1; rc=$?
    out="$(cat "$WORK/out.txt")"
    if [ "$rc" = "$want" ] && [ -z "$6" -o "${out#*"$6"}" != "$out" ] && [ -z "$7" -o "${out#*"$7"}" = "$out" ]; then
        echo "  ok    $label (rc=$rc)"; pass=$((pass+1))
    else
        echo "  FAIL  $label: want rc=$want naming '$6' and not '$7', got rc=$rc"
        sed 's/^/        /' "$WORK/out.txt"; fail=$((fail+1))
    fi
}
mkderived "$WORK/c35" enum switch
check_origin "a stale agent reached through the pin says to raise the pin" \
    pin 1 "$WORK/c35" "$WORK/la-bool" "Raise cmake/libreagent.pin" "publish the LibreAgent revision"
mkderived "$WORK/c36" enum switch
check_origin "a stale agent trunk says to publish it, not to raise a pin" \
    trunk 1 "$WORK/c36" "$WORK/la-bool" "publish the LibreAgent revision" "Raise cmake/libreagent.pin"
mkderived "$WORK/c37" enum switch
check_origin "an unrecognised provenance refuses to judge" \
    somewhere 2 "$WORK/c37" "$WORK/la-enum" "is not a LibreAgent provenance" ""


# Thirty-eight through forty-three: the two shapes the last round left, and the
# green the fix for one of them must not cost.
#
# The scope rule that closed case 34 was written as a grep for the AGENT
# header's spelling -- `Agent/backend/Authorizer.h` or `Agent::Authorizer`. A
# Darwin-side caller in prompter/ names neither: it names the Darwin subclass.
# Measured, that read R1/R2/R3/R4 ok, rc=0. The file set is now every tracked
# source by extension, and the rules judge the call wherever it stands.
if command -v git >/dev/null 2>&1; then
    mkderived "$WORK/c38" enum switch
    cat > "$WORK/c38/agent/tests/SecCodeAuthorizerTest.cpp" <<'EOF'
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
namespace {
LibreSCRS::Darwin::SecCodeAuthorizer* a = nullptr;
}
void t()
{
    switch (a->authorize("x", {})) {
    default:
        break;
    }
}
EOF
    mkdir -p "$WORK/c38/prompter/src"
    { echo '#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>'
      echo 'namespace LibreSCRS::Darwin {'
      echo 'void check(SecCodeAuthorizer& a, std::string_view id, const Agent::CallerToken& c)'
      echo '{'
      echo '    if (!a.authorize(id, c)) { return; }'
      echo '}'
      echo '}'
    } > "$WORK/c38/prompter/src/ConfirmCaller.cpp"
    git -C "$WORK/c38" init -q 2>/dev/null
    git -C "$WORK/c38" add agent prompter >/dev/null 2>&1
    if [ -n "$(git -C "$WORK/c38" ls-files -- prompter)" ]; then
        check "a Darwin-side boolean caller in prompter/, naming no agent header" 1 "$WORK/c38" "$WORK/la-enum"
    else
        echo "  FAIL  the Darwin-caller fixture has no tracked prompter/ -- it would pass for the wrong reason"
        fail=$((fail+1))
    fi

    # And the green that rule must not cost: prose. A release note's natural
    # sentence about this change names the interface, and the previous rule --
    # which read every tracked file, markdown included -- went red on it, with a
    # remedy ("widen the file set, or keep the caller under agent/") that is
    # nonsense advice for a changelog line. Nothing compiles a .md.
    mkderived "$WORK/c39" enum switch
    cat > "$WORK/c39/agent/tests/SecCodeAuthorizerTest.cpp" <<'EOF'
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
namespace {
LibreSCRS::Darwin::SecCodeAuthorizer* a = nullptr;
}
void t()
{
    switch (a->authorize("x", {})) {
    default:
        break;
    }
}
EOF
    { echo '# Changelog'
      echo '- The Darwin authorizer now implements `LibreSCRS::Agent::Authorizer` with a three-way outcome.'
    } > "$WORK/c39/CHANGELOG.md"
    { echo '# LibreDarwin'
      echo 'SecCodeAuthorizer implements `Agent/backend/Authorizer.h`; every call site switches on the result.'
    } > "$WORK/c39/README.md"
    git -C "$WORK/c39" init -q 2>/dev/null
    git -C "$WORK/c39" add agent CHANGELOG.md README.md >/dev/null 2>&1
    if [ -n "$(git -C "$WORK/c39" ls-files -- CHANGELOG.md)" ]; then
        check "CONTROL: the interface named in prose in CHANGELOG.md and README.md" 0 "$WORK/c39" "$WORK/la-enum"
    else
        echo "  FAIL  the prose fixture has no tracked CHANGELOG.md -- it would pass for the wrong reason"
        fail=$((fail+1))
    fi
else
    echo "  FAIL  git is not available, so the scope rule cannot be measured -- do not read this as a pass"
    fail=$((fail+1))
    echo "  FAIL  git is not available, so the prose control cannot be measured -- do not read this as a pass"
    fail=$((fail+1))
fi

# Forty through forty-two: a statement borrowing acceptance from another operand.
# R3 accepted any statement NAMING AuthorizationOutcome, and R4's permitted()
# ended in the same pardon, so the commonest boolean use of all -- the value as
# the whole controlling expression -- was green as long as the statement said
# the type somewhere else. Written on one line, because statements were
# assembled a physical line at a time and the binding then merged with its use
# into one statement that named the type. All three are ill-formed.
mkderived "$WORK/c40" enum none
echo 'void f() { if (a.authorize(x, y)) { last = Agent::AuthorizationOutcome::Denied; return; } }' > "$WORK/c40/agent/src/caller.cpp"
check "the call as the whole condition, with the type named beside it" 1 "$WORK/c40" "$WORK/la-enum"

mkderived "$WORK/c41" enum none
echo 'void f() { const auto outcome = a.authorize(x, y); if (outcome) { last = Agent::AuthorizationOutcome::Denied; return; } }' > "$WORK/c41/agent/src/caller.cpp"
check "the bound name as the whole condition, on one line with the type" 1 "$WORK/c41" "$WORK/la-enum"

mkderived "$WORK/c42" enum none
echo 'void f() { const auto outcome = a.authorize(x, y); while (outcome) { last = Agent::AuthorizationOutcome::Denied; } }' > "$WORK/c42/agent/src/caller.cpp"
check "the bound name as a while condition, on one line with the type" 1 "$WORK/c42" "$WORK/la-enum"

# Forty-three: the green the three above must not cost. A comparison against an
# enumerator IS the correct shape, in the condition of an if and in a binding
# used two statements later; a rule that reddened these would forbid the only
# spelling that compiles.
mkderived "$WORK/c43" enum none
{ echo 'void f() { if (a.authorize(x, y) == Agent::AuthorizationOutcome::Granted) { return; } }'
  echo 'void g() { const auto outcome = a.authorize(x, y); if (outcome != Agent::AuthorizationOutcome::Granted) { return; } }'
  echo 'void h() { if (auto outcome = a.authorize(x, y); outcome == Agent::AuthorizationOutcome::Denied) { return; } }'
} > "$WORK/c43/agent/src/caller.cpp"
check "CONTROL: comparisons against an enumerator, in a condition and after a binding" 0 "$WORK/c43" "$WORK/la-enum"

# Forty-four: the compiler rule's reach. A unit that names authorize() and
# cannot be compiled here -- a missing header, an extension this compiler has
# not got -- is NOT a refusal: the textual rules still read it, and a rule that
# went yellow whenever a sibling checkout was absent is a rule somebody switches
# off. It has to SAY so, though, or "N of K" is the only honest verdict left
# unprinted.
mkderived "$WORK/c44" enum switch
{ echo '#include <this/header/does/not/exist.h>'
  echo 'void f() { switch (a.authorize(x, y)) { default: break; } }'
} > "$WORK/c44/agent/src/unreachable.cpp"
REPO_ROOT="$WORK/c44" bash "$GATE" "$WORK/la-enum" > "$WORK/out.txt" 2>&1; rc=$?
if [ "$rc" = 0 ] && grep -q 'out of reach' "$WORK/out.txt" && grep -q 'agent/src/unreachable.cpp' "$WORK/out.txt"; then
    echo "  ok    a unit the compiler cannot reach is counted and named, not refused (rc=$rc)"; pass=$((pass+1))
else
    echo "  FAIL  a unit the compiler cannot reach: want rc=0 naming it out of reach, got rc=$rc"
    sed 's/^/        /' "$WORK/out.txt"; fail=$((fail+1))
fi

# Forty-five: the compiler rule going red WHERE NOTHING ELSE CAN. The fixture is
# one of the two shapes the gate's own header says the textual rules cannot
# judge -- the outcome passed as an argument to a call, whose parameter type is
# in another file -- so R2, R3 and R4 pardon it by construction and only a
# compiler can see it. This case owned that branch with a fixture that R3 also
# reddens, and a comment describing a third thing again (a static_cast, which is
# well-formed on a scoped enum and which no compiler reds on), so nothing in the
# suite showed the rule catching anything the text misses.
mk_argpardon() {  # <root>
    mkderived "$1" enum none
    { echo '#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>'
      echo 'namespace LibreSCRS::Darwin {'
      echo 'void sink(bool);'
      echo 'void f(SecCodeAuthorizer& a) { const auto outcome = a.authorize("x", {}); sink(outcome); }'
      echo '}'
    } > "$1/agent/src/caller.cpp"
}
mk_argpardon "$WORK/c45"
REPO_ROOT="$WORK/c45" bash "$GATE" "$WORK/la-enum" > "$WORK/out.txt" 2>&1; rc=$?
# The verdict LINE is asserted as well as the exit code. It printed "R5 ok" on
# exactly this run -- five verdict lines reading ok over a red gate -- and the
# case that owns the branch looked only at rc, so the suite could not see it.
if [ "$rc" = 1 ] && grep -q 'does not compile against the authorize() contract' "$WORK/out.txt" \
   && grep -q 'R5 FAILED' "$WORK/out.txt" && ! grep -q 'R5 ok' "$WORK/out.txt" \
   && grep -q 'R2 ok' "$WORK/out.txt" && grep -q 'R3 ok' "$WORK/out.txt" \
   && grep -q 'R4 ok' "$WORK/out.txt"; then
    echo "  ok    the compiler alone reds on the outcome passed as an argument, and R5 says so (rc=$rc)"; pass=$((pass+1))
else
    echo "  FAIL  the compiler rule did not name the contract alone, or still printed 'R5 ok': want rc=1, got rc=$rc"
    sed 's/^/        /' "$WORK/out.txt"; fail=$((fail+1))
fi

# Forty-six through forty-eight: the condition after an INIT-STATEMENT. The
# controlling expression there mentions authorize() nowhere -- it is the bound
# name -- so requiring the call to appear in it dropped the statement, and the
# declaration spelling the type out then pardoned the whole thing. Measured:
# the first two read rc=0 with all four textual rules ok while the same two
# written with `auto` read rc=1, and both are ill-formed. A verdict that turns
# on how the declaration is spelled is not a verdict about the code.
mkderived "$WORK/c46" enum none
echo 'void f() { if (Agent::AuthorizationOutcome o = a.authorize(x, y); o) { return; } }' > "$WORK/c46/agent/src/caller.cpp"
check "an init-statement condition, the type spelled out" 1 "$WORK/c46" "$WORK/la-enum"

mkderived "$WORK/c47" enum none
echo 'void f() { if (Agent::AuthorizationOutcome o = a.authorize(x, y); !o) { return; } }' > "$WORK/c47/agent/src/caller.cpp"
check "an init-statement condition, negated, the type spelled out" 1 "$WORK/c47" "$WORK/la-enum"

mkderived "$WORK/c48" enum none
{ echo 'void f() { if (Agent::AuthorizationOutcome o = a.authorize(x, y); o == Agent::AuthorizationOutcome::Granted) { return; } }'
  echo 'void g() { if (auto o = a.authorize(x, y); o != Agent::AuthorizationOutcome::Granted) { return; } }'
} > "$WORK/c48/agent/src/caller.cpp"
check "CONTROL: an init-statement compared against an enumerator, both spellings" 0 "$WORK/c48" "$WORK/la-enum"

# Forty-nine and fifty: the file-kind rule, which the widening from agent/ to
# the repository turned into a repository-wide allowlist of file kinds. Measured
# on this repository: a tracked Dockerfile, a tracked docs/*.svg and an
# untracked scratch note -- none of them mentioning authorize() -- took BOTH
# agent-interface jobs to rc=1 with a message about R2, R3 and R4. What the rule
# is for is a file the rules do not read AND that has something to say about the
# contract, so that is what it asks.
if command -v git > /dev/null 2>&1; then
    mkderived "$WORK/c49" enum switch
    cat > "$WORK/c49/agent/tests/SecCodeAuthorizerTest.cpp" <<'EOF'
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
namespace LibreSCRS::Darwin {
void probe(SecCodeAuthorizer& a) {
    switch (a.authorize("x", {})) {
    default:
        break;
    }
}
}
EOF
    mkdir -p "$WORK/c49/docs"
    printf 'FROM debian:bookworm\nRUN apt-get update\n' > "$WORK/c49/Dockerfile"
    printf '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n' > "$WORK/c49/docs/arch.svg"
    git -C "$WORK/c49" init -q 2>/dev/null
    git -C "$WORK/c49" add agent Dockerfile docs/arch.svg > /dev/null 2>&1
    printf 'scratch\n' > "$WORK/c49/NOTES.org"
    if [ -n "$(git -C "$WORK/c49" ls-files -- Dockerfile)" ]; then
        check "CONTROL: file kinds no rule reads, none of them naming the call" 0 "$WORK/c49" "$WORK/la-enum"
    else
        echo "  FAIL  the file-kind fixture has no tracked Dockerfile -- it would pass for the wrong reason"
        fail=$((fail+1))
    fi

    mkderived "$WORK/c50" enum switch
    cat > "$WORK/c50/agent/tests/SecCodeAuthorizerTest.cpp" <<'EOF'
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
namespace LibreSCRS::Darwin {
void probe(SecCodeAuthorizer& a) {
    switch (a.authorize("x", {})) {
    default:
        break;
    }
}
}
EOF
    git -C "$WORK/c50" init -q 2>/dev/null
    printf 'FROM debian:bookworm\nRUN check "if (!a.authorize(x, y)) exit 1"\n' > "$WORK/c50/Dockerfile"
    git -C "$WORK/c50" add agent Dockerfile > /dev/null 2>&1
    check "a file kind no rule reads that DOES name the call" 1 "$WORK/c50" "$WORK/la-enum"
else
    echo "  FAIL  git is not available, so the file-kind rule cannot be measured -- do not read this as a pass"
    fail=$((fail+1))
    echo "  FAIL  git is not available, so the file-kind control cannot be measured -- do not read this as a pass"
    fail=$((fail+1))
fi

# Fifty-one: whose error it is. The compiler rule takes extra include roots, and
# those roots are somebody else's tree. It used to accept a list of generic
# diagnostic phrases whoever raised them: measured, one unrelated ill-formed
# expression in a sibling repository's header printed
# `::error file=<a source of THIS repository>::this translation unit does not
# compile against the authorize() contract` for two innocent files and took the
# gate from rc=0 to rc=1. A first error standing outside this checkout is out of
# reach, and the verdict says which header it was.
mkderived "$WORK/c51" enum switch
mkdir -p "$WORK/c51-extra/Foreign"
{ echo '#pragma once'
  echo 'namespace Foreign { struct Probe { int v; }; inline void probe() { Probe p{0}; if (!p) { } } }'
} > "$WORK/c51-extra/Foreign/Probe.h"
{ echo '#include <Foreign/Probe.h>'
  echo '#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>'
  echo 'namespace LibreSCRS::Darwin {'
  echo 'void f(SecCodeAuthorizer& a) { switch (a.authorize("x", {})) { default: break; } }'
  echo '}'
} > "$WORK/c51/agent/src/caller.cpp"
REPO_ROOT="$WORK/c51" LIBRESCRS_EXTRA_INCLUDE="$WORK/c51-extra" bash "$GATE" "$WORK/la-enum" > "$WORK/out.txt" 2>&1; rc=$?
if [ "$rc" = 0 ] && grep -q 'outside this checkout' "$WORK/out.txt" \
   && grep -q 'Foreign/Probe.h' "$WORK/out.txt" \
   && ! grep -q 'does not compile against the authorize() contract' "$WORK/out.txt"; then
    echo "  ok    an error in a foreign include root is out of reach, and is named as such (rc=$rc)"; pass=$((pass+1))
else
    echo "  FAIL  an error in a foreign include root: want rc=0 naming the foreign header, got rc=$rc"
    sed 's/^/        /' "$WORK/out.txt"; fail=$((fail+1))
fi

# Fifty-two through fifty-seven: WHERE the value stands, which R3 and R4 asked
# as "is it the condition of an if or a while" and which is a list of two out of
# six. Measured on this repository's own sign call site, at the same line the
# if/while patch was demonstrated on, all four of these read R1-R5 ok, rc=0, and
# none of them compiles.
mkderived "$WORK/c52" enum none
echo 'void f() { Agent::AuthorizationOutcome o = a.authorize(x, y) ? Agent::AuthorizationOutcome::Denied : Agent::AuthorizationOutcome::Granted; (void)o; }' \
    > "$WORK/c52/agent/src/caller.cpp"
check "the call as the condition of a ternary, the type named twice beside it" 1 "$WORK/c52" "$WORK/la-enum"

mkderived "$WORK/c53" enum none
echo 'void f() { for (Agent::AuthorizationOutcome g = Agent::AuthorizationOutcome::Granted; a.authorize(x, y); ) { (void)g; break; } }' \
    > "$WORK/c53/agent/src/caller.cpp"
check "the call in the condition slot of a for, the type named in the init" 1 "$WORK/c53" "$WORK/la-enum"

mkderived "$WORK/c54" enum none
echo 'void f() { bool ready = true; if (a.authorize(x, y) && ready) g(Agent::AuthorizationOutcome::Denied); }' \
    > "$WORK/c54/agent/src/caller.cpp"
check "the call as an operand of &&, the type named on the same statement" 1 "$WORK/c54" "$WORK/la-enum"

mkderived "$WORK/c55" enum none
{ echo 'void f() { for (Agent::AuthorizationOutcome o = a.authorize(x, y); o == Agent::AuthorizationOutcome::Undecided; o = a.authorize(x, y)) { break; } }'
  echo 'void g() { int n = (a.authorize(x, y) == Agent::AuthorizationOutcome::Granted) ? 1 : 0; (void)n; }'
} > "$WORK/c55/agent/src/caller.cpp"
check "CONTROL: comparisons against an enumerator in a for and in a ternary" 0 "$WORK/c55" "$WORK/la-enum"

mkderived "$WORK/c56" enum none
{ echo 'void f() { const auto outcome = a.authorize(x, y);'
  echo '    for (Agent::AuthorizationOutcome g = Agent::AuthorizationOutcome::Granted; outcome; ) { (void)g; break; } }'
} > "$WORK/c56/agent/src/caller.cpp"
check "the bound name in the condition slot of a for" 1 "$WORK/c56" "$WORK/la-enum"

mkderived "$WORK/c57" enum none
{ echo 'void f() { const auto outcome = a.authorize(x, y);'
  echo '    Agent::AuthorizationOutcome eff = outcome ? Agent::AuthorizationOutcome::Denied : Agent::AuthorizationOutcome::Granted; (void)eff; }'
} > "$WORK/c57/agent/src/caller.cpp"
check "the bound name as the condition of a ternary" 1 "$WORK/c57" "$WORK/la-enum"

# Fifty-eight and fifty-nine: the same two verdicts under CLANG, which is the
# compiler of the platform this repository ships to and which words both of
# them differently. R1's classifier was a list of gcc phrases, so a real
# boolean use in the authorizer's test read rc=1 under `c++` and rc=2 --
# "failed to compile for a reason that is not the authorize() contract" --
# under clang++; and R5 read the same shape as "out of reach", rc=0, because
# clang puts the type on the `note:` under the error. A verdict that depends on
# whose wording the compiler uses is not a verdict about the code.
if command -v clang++ > /dev/null 2>&1; then
    mk_argpardon "$WORK/c58"
    REPO_ROOT="$WORK/c58" CXX=clang++ bash "$GATE" "$WORK/la-enum" > "$WORK/out.txt" 2>&1; rc=$?
    if [ "$rc" = 1 ] && grep -q 'R5 FAILED' "$WORK/out.txt"; then
        echo "  ok    clang wording: the compiler rule still names the contract (rc=$rc)"; pass=$((pass+1))
    else
        echo "  FAIL  clang wording, compiler rule: want rc=1 with R5 FAILED, got rc=$rc"
        sed 's/^/        /' "$WORK/out.txt"; fail=$((fail+1))
    fi

    mkderived "$WORK/c59" enum none
    { echo '#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>'
      echo 'namespace LibreSCRS::Darwin {'
      echo 'void sink(bool);'
      echo 'void probe(SecCodeAuthorizer& a) { const auto outcome = a.authorize("x", {}); sink(outcome); }'
      echo '}'
    } > "$WORK/c59/agent/tests/SecCodeAuthorizerTest.cpp"
    REPO_ROOT="$WORK/c59" CXX=clang++ bash "$GATE" "$WORK/la-enum" > "$WORK/out.txt" 2>&1; rc=$?
    if [ "$rc" = 1 ] && grep -q 'the authorize() contract does not hold' "$WORK/out.txt"; then
        echo "  ok    clang wording: R1 names the broken contract rather than refusing (rc=$rc)"; pass=$((pass+1))
    else
        echo "  FAIL  clang wording, R1: want rc=1 naming the contract, got rc=$rc"
        sed 's/^/        /' "$WORK/out.txt"; fail=$((fail+1))
    fi
else
    echo "  note  clang++ is not installed here, so the two clang-wording cases were not measured"
fi


# ---------------------------------------------------------------------------
# Portability of the gate itself. All three cases below are RED against the
# revision of check-agent-interface.sh that shipped before 2026-09-13, and that
# revision passed the other 59 -- which is why they exist: the suite was green
# on macOS while the gate could not judge there at all.

# P1 -- LIBRESCRS_EXTRA_INCLUDE must reach R1, not only R5. It is the documented
# way to say where foreign headers are; wired into R5 alone it cannot help R1,
# and R1 is the rule that compiles the authorizer's test. On any host where
# gtest is not in a default system path -- every macOS box -- that made the whole
# gate unreachable.
mkdir -p "$WORK/extra-inc"
echo '#pragma once
inline int librescrs_selftest_marker() { return 1; }' > "$WORK/extra-inc/librescrs_selftest_marker.h"
mkderived "$WORK/p1" enum none
{ echo '#include <librescrs_selftest_marker.h>'
  echo '#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>'
  echo 'namespace LibreSCRS::Darwin {'
  echo 'void probe(SecCodeAuthorizer& a) {'
  echo '    switch (a.authorize("x", {})) { default: break; }'
  echo '    (void)librescrs_selftest_marker();'
  echo '}'
  echo '}'
} > "$WORK/p1/agent/tests/SecCodeAuthorizerTest.cpp"
REPO_ROOT="$WORK/p1" LIBRESCRS_EXTRA_INCLUDE="$WORK/extra-inc" bash "$GATE" "$WORK/la-enum" > "$WORK/out.txt" 2>&1; rc=$?
if [ "$rc" = 0 ]; then
    echo "  ok    LIBRESCRS_EXTRA_INCLUDE reaches R1, not only R5 (rc=$rc)"; pass=$((pass+1))
else
    echo "  FAIL  extra include root did not reach R1: want rc=0, got rc=$rc"
    sed 's/^/        /' "$WORK/out.txt"; fail=$((fail+1))
fi

# P2 -- the shim decision must not be a hard-coded absolute path. `/usr/include`
# does not exist on macOS at all (the real bsm/libbsm.h is in the SDK), so a
# `[ -e /usr/include/... ]` probe always missed there and forced the Linux shim
# onto the one platform that ships the real header; its audit_token_t then
# collided with <mach/message.h> and two translation units were written off as
# out of reach. Ask the compiler instead -- it knows sysroots and frameworks.
if grep -qE '^\s*\[\s*-e\s+/usr/include/' "$GATE"; then
    echo "  FAIL  the shim decision tests a literal /usr/include path; probe the compiler instead"
    grep -nE '^\s*\[\s*-e\s+/usr/include/' "$GATE" | sed 's/^/        /'; fail=$((fail+1))
elif grep -q 'bsmprobe' "$GATE"; then
    echo "  ok    the real bsm/libbsm.h is probed through the compiler, not a literal path"; pass=$((pass+1))
else
    echo "  FAIL  no compiler probe for bsm/libbsm.h found in the gate"; fail=$((fail+1))
fi

# P3 -- the missing-gtest diagnosis must fire under both compilers' wording.
# GCC says `gtest/gtest.h: No such file or directory`; clang says
# `'gtest/gtest.h' file not found`. Matching GCC alone meant that on macOS this
# rule fell through to the generic "not the authorize() contract" FATAL, which
# points the reader at the contract for what is a missing package.
#
# The case must not depend on the host: a Linux box carries gtest in a default
# include root (/usr/include/gtest), so a plain clang++ finds it, compiles the
# test and the gate answers 0 -- the case was red on Linux for exactly the
# reason the other three were red on macOS. The wrapper below takes the
# standard include roots away for the authorizer test's translation unit only
# (every other invocation runs clang++ unchanged), so the real compiler reports
# the header as missing in its own words on any host. The include of gtest is
# the first line of that unit, and a missing include is fatal, so it is the
# one diagnostic the log carries.
if command -v clang++ >/dev/null 2>&1; then
    mkderived "$WORK/p3" enum none
    { echo '#include <gtest/gtest.h>'
      echo '#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>'
      echo 'namespace LibreSCRS::Darwin {'
      echo 'void probe(SecCodeAuthorizer& a) { switch (a.authorize("x", {})) { default: break; } }'
      echo '}'
    } > "$WORK/p3/agent/tests/SecCodeAuthorizerTest.cpp"
    { echo '#!/usr/bin/env bash'
      echo 'for a in "$@"; do'
      echo '    case "$a" in *SecCodeAuthorizerTest.cpp) exec clang++ -nostdinc "$@" ;; esac'
      echo 'done'
      echo 'exec clang++ "$@"'
    } > "$WORK/p3/clang-without-gtest"
    chmod +x "$WORK/p3/clang-without-gtest"
    REPO_ROOT="$WORK/p3" CXX="$WORK/p3/clang-without-gtest" LIBRESCRS_EXTRA_INCLUDE="$WORK/extra-inc" \
        bash "$GATE" "$WORK/la-enum" > "$WORK/out.txt" 2>&1; rc=$?
    if [ "$rc" = 2 ] && grep -q "gtest's headers are not on the include path" "$WORK/out.txt"; then
        echo "  ok    clang wording: missing gtest is named as missing gtest (rc=$rc)"; pass=$((pass+1))
    else
        echo "  FAIL  clang wording, missing gtest: want rc=2 naming gtest, got rc=$rc"
        sed 's/^/        /' "$WORK/out.txt"; fail=$((fail+1))
    fi
else
    echo "  note  clang++ is not installed here, so the gtest-wording case was not measured"
fi

echo "check-agent-interface.selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
