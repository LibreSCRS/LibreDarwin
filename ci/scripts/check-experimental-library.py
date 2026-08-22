#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
"""Fail the build when a C++ translation unit is compiled without
-fexperimental-library on Apple Clang.

The flag is not a per-target convenience. On Apple Clang it gates std::expected
and std::jthread/std::stop_token AND selects a libc++ ABI, so a single unit
compiled without it sees a different standard library than everything it links
against. That is an ODR violation, and neither the compiler nor the linker
diagnoses it: the build is green and the program is wrong.

The flag used to be applied per target, by hand, in five different files -- and
one target (a compile-only check library) was missing it. This reads what the
compiler was ACTUALLY told, from compile_commands.json, rather than what the
CMake files appear to say.

Usage:  check-experimental-library.py [BUILD_DIR]        (default: build)
"""
import json
import pathlib
import sys

FLAG = "-fexperimental-library"
CXX_SUFFIXES = (".cpp", ".cc", ".cxx", ".mm")


def compiler_id(build_dir: pathlib.Path) -> str:
    """Read CMAKE_CXX_COMPILER_ID out of the cache; '' when unknown."""
    cache = build_dir / "CMakeCache.txt"
    if not cache.is_file():
        return ""
    for line in cache.read_text(errors="replace").splitlines():
        if line.startswith("CMAKE_CXX_COMPILER_ID:"):
            return line.split("=", 1)[1].strip() if "=" in line else ""
    return ""


def target_of(entry: dict) -> str:
    """The CMake target name, recovered from the object path (…/<name>.dir/…)."""
    for part in (entry.get("output") or "").split("/"):
        if part.endswith(".dir"):
            return part[: -len(".dir")]
    return "?"


def main(argv: list[str]) -> int:
    build_dir = pathlib.Path(argv[1] if len(argv) > 1 else "build")
    cc_path = build_dir / "compile_commands.json"
    if not cc_path.is_file():
        print(
            f"check-experimental-library: {cc_path} not found. Configure with "
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON.",
            file=sys.stderr,
        )
        return 2

    cid = compiler_id(build_dir)
    if cid and cid != "AppleClang":
        print(f"check-experimental-library: compiler is {cid}, not AppleClang -- nothing to check.")
        return 0

    entries = json.loads(cc_path.read_text())
    offenders: dict[str, list[str]] = {}
    checked = 0
    for e in entries:
        source = e.get("file", "")
        if not source.endswith(CXX_SUFFIXES):
            continue  # C sources (the vendored CBOR codec) have no libc++
        command = e.get("command") or " ".join(e.get("arguments", []))
        checked += 1
        if FLAG not in command:
            offenders.setdefault(target_of(e), []).append(pathlib.Path(source).name)

    if offenders:
        print(f"check-experimental-library: {FLAG} missing from these translation units:\n", file=sys.stderr)
        for target in sorted(offenders):
            names = ", ".join(sorted(offenders[target]))
            print(f"  {target}: {names}", file=sys.stderr)
        print(
            "\nThe flag belongs to the whole build, not to a list of targets: set it "
            "with add_compile_options()/add_link_options() before the first target, "
            "and export it to consumers as a PUBLIC usage requirement.",
            file=sys.stderr,
        )
        return 1

    print(f"check-experimental-library: OK -- {checked} C++ translation units, all carry {FLAG}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
