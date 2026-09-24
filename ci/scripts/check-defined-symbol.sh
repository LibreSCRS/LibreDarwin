#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-defined-symbol.sh -- fail when a binary does not DEFINE a function.
#
# The prompter denies debugger attach and core dumps before it reads a secret;
# a link that stopped pulling that routine in would still build, start and
# pass every test that does not look at the binary. This reads the binary.
#
# Property, not proxy: the name is compared WHOLE against the demangled name
# column of the defined symbols only. A bare substring grep would accept a
# symbol that merely contains the name, and one the binary imports from a
# library it may not ship with (nm lists those as undefined).
#
# It proves the routine is linked in, not that it is called; the prompter's own
# test drives the call.
#
# Usage:  check-defined-symbol.sh <binary> '<demangled name>'
#         e.g. check-defined-symbol.sh build/prompter/librescrs-prompter \
#                  'LibreSCRS::Darwin::hardenSecretProcess()'
#
# Exit:   0  defined
#         1  not defined
#         2  cannot judge: wrong arguments, no such file, or nm cannot read it
set -uo pipefail

if [ "$#" -ne 2 ] || [ -z "$2" ]; then
    echo "usage: check-defined-symbol.sh <binary> '<demangled name>'" >&2
    exit 2
fi
bin="$1"
sym="$2"

[ -f "$bin" ] || { echo "FATAL: $bin: no such file -- cannot judge" >&2; exit 2; }

# Captured before searching, so an nm that cannot read the file is exit 2 and
# not an empty listing that reads as "not defined".
if ! listing="$(nm -C --defined-only "$bin" 2>&1)"; then
    echo "FATAL: nm cannot read $bin -- cannot judge" >&2
    printf '%s\n' "$listing" >&2
    exit 2
fi

# Drop the value and type columns; what remains is the name, spaces and all.
# The value is optional so an undefined symbol's line is cut the same way: the
# --defined-only above is what keeps it out, not a column shape it happens to
# have.
# No `grep -q`: it stops reading at the first match, the writers upstream take
# SIGPIPE, and under pipefail a found symbol would read as a missing one.
if printf '%s\n' "$listing" | sed -E 's/^ *[0-9A-Fa-f]* *[A-Za-z] //' | grep -Fx -- "$sym" >/dev/null; then
    echo "$bin defines $sym"
    exit 0
fi
echo "::error::$bin does not define $sym"
exit 1
