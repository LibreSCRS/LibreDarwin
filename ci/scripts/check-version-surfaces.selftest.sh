#!/usr/bin/env sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Selftest for check-version-surfaces.sh.
#
# Each case is a way this check could be wrong about the tree rather than the
# tree being wrong. The rc=2 cases matter most: a check that cannot measure
# must not report a pass, or the gate turns green on exactly the runners where
# it stopped working.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-version-surfaces.sh"
[ -f "$subject" ] || { echo "missing subject: $subject" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fails=0
out="$work/out"

run() {   # run <name> <expected-rc> <dir> [VAR=VAL ...]
    name=$1; want=$2; dir=$3; shift 3
    ( cd "$dir" && env "$@" sh "$subject" ) > "$out" 2>&1
    got=$?
    if [ "$got" -eq "$want" ]; then
        printf '  ok    %-58s rc=%s\n' "$name" "$got"
    else
        printf '  FAIL  %-58s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$out"
        fails=$((fails + 1))
    fi
}

says() {  # says <name> <pattern>  -- about the last run
    if grep -q -- "$2" "$out"; then
        printf '  ok    %-58s\n' "$1"
    else
        printf '  FAIL  %-58s (no match: %s)\n' "$1" "$2"
        sed 's/^/          /' "$out"
        fails=$((fails + 1))
    fi
}

# A fixture repo: VERSION 5.0.0, one CMake project, one Plasma metadata, one
# XML plist and one xcodegen spec -- one of every kind the script knows.
fixture() {   # fixture <dir> <cmake-version> <metadata-version> <plist-version> <yaml-version>
    d=$1
    mkdir -p "$d/ci" "$d/pkg" "$d/app"
    printf '5.0.0\n' > "$d/VERSION"
    cat > "$d/CMakeLists.txt" <<EOF
cmake_minimum_required(VERSION 3.24.0 FATAL_ERROR)
project(Fixture VERSION $2 LANGUAGES NONE)
EOF
    # X-Plasma-API-Minimum-Version is here on purpose: its key ENDS in
    # "Version", so a loose pattern reads 6.0 as the applet's version.
    cat > "$d/pkg/metadata.json" <<EOF
{
    "KPlugin": {
        "Id": "org.librescrs.smartcard",
        "Version": "$3"
    },
    "X-Plasma-API-Minimum-Version": "6.0"
}
EOF
    cat > "$d/app/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>CFBundleShortVersionString</key>
	<string>$4</string>
</dict>
</plist>
EOF
    cat > "$d/project.yml" <<EOF
targets:
  App:
    info:
      properties:
        CFBundleShortVersionString: $5
        CFBundleVersion: 1
EOF
    printf '# <kind> <path>\ncmake-project        .\nplasma-metadata      pkg/metadata.json\nplist-short-version  app/Info.plist\nyaml-short-version   project.yml\n' \
        > "$d/ci/version-surfaces.txt"
}

# case_1 -- everything agrees. Without it a check that fails everything passes
# every other case in this file.
d=$work/case_1; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0
run "case_1 every surface agrees" 0 "$d"
says "case_1 all four surfaces were counted" 'all 4 version surface(s) state 5.0.0'
says "case_1 CFBundleVersion 1 is not read as the version" '  -> app/Info.plist (CFBundleShortVersionString) states 5.0.0'
says "case_1 X-Plasma-API-Minimum-Version is not read as the version" '  -> pkg/metadata.json (KPlugin.Version) states 5.0.0'

# case_2 -- the shipped bug: project() stamps its own literal while VERSION and
# every packaging recipe say 5.0.0.
d=$work/case_2; fixture "$d" 0.1.0 5.0.0 5.0.0 5.0.0
run "case_2 project() stamps something else" 1 "$d"
says "case_2 the message names project()" "project(Fixture) in . states '0.1.0'"

# case_3 -- the applet metadata is installed verbatim, so a stale literal there
# is what Plasma shows even when the build stamp is right.
d=$work/case_3; fixture "$d" 5.0.0 0.1.0 5.0.0 5.0.0
run "case_3 applet metadata states something else" 1 "$d"
says "case_3 the message names metadata.json" "pkg/metadata.json (KPlugin.Version) states '0.1.0'"

# case_4 -- the plist half, which is what Finder, mdls and About windows read.
d=$work/case_4; fixture "$d" 5.0.0 5.0.0 0.1 5.0.0
run "case_4 plist states something else" 1 "$d"
says "case_4 the message names the plist" "app/Info.plist (CFBundleShortVersionString) states '0.1'"

# case_5 -- the xcodegen spec, which is UPSTREAM of the generated plist:
# editing the plist alone is undone by the next `xcodegen generate`.
d=$work/case_5; fixture "$d" 5.0.0 5.0.0 5.0.0 0.1.0
run "case_5 xcodegen spec states something else" 1 "$d"
says "case_5 the message names project.yml" "project.yml (CFBundleShortVersionString) states '0.1.0'"

# case_6 -- a configure_file() that never ran leaves the placeholder in the file
# that gets installed. It is unequal for a different reason, so it says so.
d=$work/case_6; fixture "$d" 5.0.0 '@PROJECT_VERSION@' 5.0.0 5.0.0
run "case_6 unexpanded placeholder in the installed file" 1 "$d"
says "case_6 the message names the placeholder" 'still holds the literal @PROJECT_VERSION@'

# case_7 -- a tree that HAS moved to configure_file must stay green, or this
# check becomes the reason nobody makes that move.
d=$work/case_7; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0
sed 's/"Version": "5.0.0"/"Version": "@PROJECT_VERSION@"/' "$d/pkg/metadata.json" > "$d/pkg/metadata.json.in"
rm "$d/pkg/metadata.json"
run "case_7 template form is accepted" 0 "$d"

# case_8 -- nothing to compare against is not a pass.
d=$work/case_8; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0; rm "$d/VERSION"
run "case_8 no VERSION file is undecidable, not green" 2 "$d"

# case_9 -- an empty surface list is the vacuum case: every surface agreed
# because none was named.
d=$work/case_9; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0
printf '# nothing listed\n' > "$d/ci/version-surfaces.txt"
run "case_9 an empty surface list is undecidable, not green" 2 "$d"

# case_10 -- a missing surface list, likewise.
d=$work/case_10; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0; rm "$d/ci/version-surfaces.txt"
run "case_10 a missing surface list is undecidable" 2 "$d"

# case_11 -- a surface kind nobody implements must stop the run, not be skipped
# silently: a typo in the list would otherwise remove a surface from the gate.
d=$work/case_11; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0
printf 'plist-shortversion  app/Info.plist\n' > "$d/ci/version-surfaces.txt"
run "case_11 an unknown surface kind is undecidable" 2 "$d"

# case_12 -- a listed file that does not exist is undecidable, not green: a
# path typo would otherwise drop the surface.
d=$work/case_12; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0
printf 'plist-short-version  app/Gone.plist\n' > "$d/ci/version-surfaces.txt"
run "case_12 a listed file that is missing is undecidable" 2 "$d"

# case_13 -- no cmake on the runner is not a pass. This is the one that would
# otherwise turn the gate green on exactly the machines where it broke.
d=$work/case_13; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0
run "case_13 no cmake is undecidable, not green" 2 "$d" CMAKE=/nonexistent/cmake

# case_14 -- a configure that dies BEFORE project() reports no version at all.
d=$work/case_14; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0
printf 'cmake_minimum_required(VERSION 3.24.0 FATAL_ERROR)\nmessage(FATAL_ERROR "died early")\n' > "$d/CMakeLists.txt"
run "case_14 configure dies before project() is undecidable" 2 "$d"

# case_15 -- a CMakeLists with no project(VERSION) at all: CMake still fires
# the hook, with an implicit project(Project) carrying no version. Blaming the
# tree for "states ''" would hide this check's own blind spot.
d=$work/case_15; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0
printf 'cmake_minimum_required(VERSION 3.24.0 FATAL_ERROR)\nproject(Fixture LANGUAGES NONE)\n' > "$d/CMakeLists.txt"
run "case_15 project() with no VERSION is undecidable" 2 "$d"

# case_16 -- a leading v in VERSION is the same version, as elsewhere in this
# repo's tooling (check-release-lockstep.sh strips it too).
d=$work/case_16; fixture "$d" 5.0.0 5.0.0 5.0.0 5.0.0; printf 'v5.0.0\n' > "$d/VERSION"
run "case_16 a v-prefixed VERSION is the same version" 0 "$d"

if [ "$fails" -eq 0 ]; then
    echo "check-version-surfaces selftest: all cases passed"
    exit 0
fi
echo "check-version-surfaces selftest: $fails case(s) failed"
exit 1
