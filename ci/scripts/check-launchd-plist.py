#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fail when a LaunchAgent plist is one launchd would read differently from
the way it reads.

Three properties, each of which has already shipped broken here:

  * It parses as XML. plutil is lenient: it accepted a template whose comment
    carried a `--`, which is not well-formed XML, so the check on macOS alone
    said nothing. Python's plistlib uses a conforming XML parser, so the same
    check gives the same answer on the Linux format job and on the macOS job.

  * No string in it is empty. configure_file() turns a placeholder whose
    variable is not set into an empty string without a word; launchd then
    starts the job with an empty argument or an empty environment value.
    Checked everywhere in the tree -- keys, values, array elements.

  * No EnvironmentVariables block. launchd hands that block to the job at
    start, which makes it a place to steer the agent from outside; the agent
    reads no configuration from its environment, and the one thing a
    development build needs is added by the dev harness, not the template.

It reads the file it is given: run it on the template in the source tree and
on the plist `cmake --install` wrote, since the second is the one that ships.

Usage:  check-launchd-plist.py <plist> [<plist> ...]

Exit:   0  every plist passes
        1  at least one does not; each finding is printed with its path
        2  cannot judge: no argument, or a file that cannot be read (and no
           other file failed)
"""
import plistlib
import sys


def empty_strings(node, where):
    if isinstance(node, str):
        if node == "":
            yield where
    elif isinstance(node, dict):
        for key, value in node.items():
            if key == "":
                yield f"{where}/<empty key>"
            yield from empty_strings(value, f"{where}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from empty_strings(value, f"{where}[{index}]")


def judge(path):
    """Return a list of findings, or None when the file cannot be read."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as err:
        print(f"FATAL: {path}: {err.strerror} -- cannot judge", file=sys.stderr)
        return None
    try:
        root = plistlib.loads(raw)
    except Exception as err:  # any refusal to parse is the finding itself
        return [f"does not parse as a property list: {type(err).__name__}: {err}"]
    if not isinstance(root, dict):
        return [f"top level is {type(root).__name__}, launchd wants a dictionary"]
    findings = []
    if "EnvironmentVariables" in root:
        findings.append("carries an EnvironmentVariables block")
    findings.extend(f"empty string at {where}" for where in empty_strings(root, ""))
    return findings


def main(argv):
    if not argv:
        print("usage: check-launchd-plist.py <plist> [<plist> ...]", file=sys.stderr)
        return 2
    unreadable = False
    failed = False
    for path in argv:
        findings = judge(path)
        if findings is None:
            unreadable = True
            continue
        for finding in findings:
            print(f"{path}: {finding}")
        if findings:
            failed = True
        else:
            print(f"{path}: ok")
    # A finding is a verdict even when another file could not be read.
    if failed:
        return 1
    return 2 if unreadable else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
