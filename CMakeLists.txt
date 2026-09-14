# SPDX-License-Identifier: LGPL-2.1-or-later
# 3.28 tracks LibreAgent's own floor — FetchContent add_subdirectory()s it.
cmake_minimum_required(VERSION 3.28)

# Derives PROJECT_VERSION + GIT_VERSION_* from git tags (committed VERSION file /
# 0.0.1 fallback). Must run before project() — see the module's own note.
include(cmake/GitVersion.cmake)

# Universal (x86_64;arm64) build toggle for the release/packaging gate. CMAKE_OSX_
# ARCHITECTURES MUST be set before the first project()/enable_language call — the
# compiler-id check locks the arch set in. OFF (single-arch, the host's native
# arch) is the dev default; the LibreMac release gate builds ON.
option(LIBREDARWIN_UNIVERSAL "Build a universal x86_64;arm64 binary" OFF)
if(LIBREDARWIN_UNIVERSAL)
    set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64" CACHE STRING "" FORCE)
endif()

project(LibreDarwin
    VERSION ${GIT_VERSION_MAJOR}.${GIT_VERSION_MINOR}.${GIT_VERSION_PATCH}
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# LibreDarwin is the macOS broker-HOST (the twin of LibreLinux): the launchd
# daemon + the macOS backend for the five LibreAgent::Core interfaces + the
# credential prompter + the card-less PKCS#11 facade. The LM-free desktop client
# lives elsewhere (LibreMac). This repo is macOS-only.
if(NOT APPLE)
    message(FATAL_ERROR "LibreDarwin is the macOS broker-host; configure it on macOS (Apple).")
endif()

include(GNUInstallDirs)

# Apple Clang gates std::expected and std::jthread/std::stop_token behind
# -fexperimental-library, and the flag also selects a libc++ ABI. That makes it
# a property of the whole build rather than of individual targets: one
# translation unit compiled without it sees a different libc++ than everything
# it links against, and the mismatch is an ODR violation no compiler diagnoses.
#
# Declared once, here, before the first target exists, so nothing can be left
# out by being forgotten from a list. It sits above the LibreAgent include below
# on purpose, so the FetchContent subproject inherits it too. Per-target copies
# used to be spread across agent/, agent/tests/, prompter/ and the LibreAgent
# glue; they are gone, and ci/scripts/check-experimental-library.py fails the
# build if a translation unit ever appears without the flag again.
if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    add_compile_options(-fexperimental-library)
    add_link_options(-fexperimental-library)
endif()

# The single LibreMiddleware owner: the daemon links LM through LibreAgent::Core.
find_package(LibreMiddleware 5.0 REQUIRED CONFIG)

# The platform-neutral agent core (flows, scheduler, presence model, caches,
# lease/broker policy, LM-backed seams, the 5 backend interfaces). The macOS
# backend under agent/ implements those interfaces and builds the
# librescrs-agent daemon on top of LibreAgent::Core — exactly as LibreLinux does
# with its D-Bus backend.
include(cmake/FindOrUseLibreAgent.cmake)

# Diagnostics for THIS project's own targets. Until now no translation unit
# under agent/, prompter/ or pkcs11-module/ was compiled with any -W flag at
# all, so an unused constant or a sign mismatch in the daemon or its tests
# was seen by nobody; the fetched agent had been building its own sources with
# these three flags the whole time. Placed AFTER the LibreAgent include on
# purpose: add_compile_options reaches only targets defined after it, so the
# fetched subproject keeps the flags it sets for itself and its own -Werror
# switch, and nothing here can turn a foreign diagnostic into this build's
# failure. Not -Werror, for the reason LibreMiddleware gives next to the same
# line: a compiler upgrade must not break this build through a diagnostic
# nobody has seen yet.
add_compile_options(-Wall -Wextra -Wpedantic)
# CI turns this on, as the Linux host and the agent do for theirs, so a new
# diagnostic in this project's own sources fails the job instead of scrolling
# past in a log nobody reads. It sits below the same include for the same
# reason as the line above: the fetched agent is never compiled with this
# project's -Werror.
option(LIBREDARWIN_WERROR "Treat compiler warnings in this project's own targets as errors" OFF)
if(LIBREDARWIN_WERROR)
    add_compile_options(-Werror)
endif()

# Bound every test. ctest's built-in default is 1500 seconds and nothing in this
# tree overrode it, so a single wedged test could hold a hosted runner for
# twenty-five minutes without ever being named; a handful of them consume the
# whole job. That is not hypothetical — one CI job in this project sat for two
# hours and forty-nine minutes on one deadlocked test, and only cancelling it
# released a log that said which.
#
# include(CTest) rather than a bare enable_testing(): DART_TESTING_TIMEOUT is
# read by the CTest MODULE, which is what writes DartConfiguration.tcl, and a
# bare enable_testing() never writes that file. Measured on a twelve-second
# test with a three-second declared timeout, the bare call reports the suite
# passing after twelve seconds and the module form times the test out after
# three — so declaring the value next to a bare call would have had no effect
# at all, silently. include(CTest) calls enable_testing() itself, so the
# placement of the call below is unchanged. Set BEFORE the include, which would
# otherwise cache 1500.
set(DART_TESTING_TIMEOUT 300 CACHE STRING
    "Default per-test ctest timeout, in seconds")
include(CTest)

add_subdirectory(agent)

# Card-less, secret-less PKCS#11 facade dylib (browser-loadable) that forwards to
# the agent over the App-Group socket. Full implementation is pending.
add_subdirectory(pkcs11-module)

# The agent-owned macOS credential window (secure PIN / CAN / MRZ). Optional so a
# headless/CI build can drop the UI target. Full implementation is pending.
option(LIBREDARWIN_BUILD_PROMPTER "Build the macOS credential prompter" ON)
if(LIBREDARWIN_BUILD_PROMPTER)
    add_subdirectory(prompter)
endif()
