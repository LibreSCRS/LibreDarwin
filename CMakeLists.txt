# SPDX-License-Identifier: LGPL-2.1-or-later
# 3.28 tracks LibreAgent's own floor — FetchContent add_subdirectory()s it.
cmake_minimum_required(VERSION 3.28)

# GIT_VERSION_* from this repository's own git tags (the VERSION file as the
# floor). The byte-identical copy every LibreSCRS repository carries; the
# check-version gate compares it with the canonical one. Must run before
# project() -- see the module's own note.
include(cmake/GitVersion.cmake)

# Universal (x86_64;arm64) build toggle for the release/packaging gate. CMAKE_OSX_
# ARCHITECTURES MUST be set before the first project()/enable_language call — the
# compiler-id check locks the arch set in. OFF (single-arch, the host's native
# arch) is the dev default; the LibreMac release gate builds ON.
option(LIBREDARWIN_UNIVERSAL "Build a universal x86_64;arm64 binary" OFF)
if(LIBREDARWIN_UNIVERSAL)
    set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64" CACHE STRING "" FORCE)
endif()

# The oldest macOS this build runs on. Set before project(), so every target in
# the build -- the fetched agent core and its static archives included -- is
# compiled for it; unset, clang targets the SDK's own version and the binaries
# refuse to start on anything older, whatever the app's Info.plist claims.
set(CMAKE_OSX_DEPLOYMENT_TARGET "15.0" CACHE STRING "Minimum macOS version")

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

# The agent core links OpenSSL itself; found here, so the check below reads
# the library this build links rather than whatever a dependency left set.
find_package(OpenSSL 3 REQUIRED)

# A universal build needs an OpenSSL with both slices. Left alone, the one found
# above is whatever the machine has first (Homebrew's, arm64 only, on a runner),
# and the x86_64 slice then fails to link. Refuse in configure instead.
if(LIBREDARWIN_UNIVERSAL)
    execute_process(COMMAND lipo -archs "${OPENSSL_CRYPTO_LIBRARY}"
        OUTPUT_VARIABLE librescrsOpenSslArchs OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    separate_arguments(librescrsOpenSslArchs)
    foreach(arch IN LISTS CMAKE_OSX_ARCHITECTURES)
        if(NOT arch IN_LIST librescrsOpenSslArchs)
            message(FATAL_ERROR "${OPENSSL_CRYPTO_LIBRARY} has no ${arch} slice. Point OPENSSL_ROOT_DIR at a "
                "universal OpenSSL (LibreMiddleware's thirdparty/openssl-<version>/macosx) with "
                "OPENSSL_USE_STATIC_LIBS=TRUE.")
        endif()
    endforeach()
endif()

# The platform-neutral agent core (flows, scheduler, presence model, caches,
# lease/broker policy, LM-backed seams, the 5 backend interfaces). The macOS
# backend under agent/ implements those interfaces and builds the
# librescrs-agent daemon on top of LibreAgent::Core — exactly as LibreLinux does
# with its D-Bus backend. Built from the deps.lock revision by default
# (LIBRESCRS_AGENT_FROM_SOURCE=OFF takes an installed one); the module is the
# byte-identical copy every consumer of the agent carries.
#
# Five components: the neutral core and the wire vocabulary the daemon links,
# the Cryptoki facade and its socket transport the PKCS#11 module is built
# from, and the agent's signed master-list fixture the anchor-import test
# links. An installed agent package must have been built with all five.
set(LIBRESCRS_AGENT_FROM_SOURCE_DEFAULT ON)
include(cmake/FindOrUseLibreAgent.cmake)
librescrs_use_libreagent(COMPONENTS Core Wire Pkcs11Facade Pkcs11SocketClient TestSupport)

# Diagnostics for THIS project's own targets. Until now no translation unit
# under agent/, prompter/ or pkcs11-module/ was compiled with any -W flag at
# all, so an unused constant or a sign mismatch in the daemon or its tests
# was seen by nobody. Placed AFTER the LibreAgent include on purpose:
# add_compile_options reaches only targets defined after it, so the fetched
# subproject keeps the warning set it gives its own libraries. Not -Werror by
# default, for the reason LibreMiddleware gives next to the same line: a
# compiler upgrade must not break this build through a diagnostic nobody has
# seen yet.
add_compile_options(-Wall -Wextra -Wpedantic)
# CI turns this on, so a new diagnostic in this project's own sources fails
# the job instead of scrolling past in a log nobody reads. The name every
# LibreSCRS repository uses: a fetched agent declares the same option, so one
# -DLIBRESCRS_WERROR=ON also makes the agent's own libraries -Werror, as its
# CI builds them.
option(LIBRESCRS_WERROR "Treat compiler warnings as errors" OFF)
if(LIBRESCRS_WERROR)
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

# librescrs-pkcs11-agent.dylib: the card-less, secret-less PKCS#11 module other
# applications load. It forwards every call to the agent over the App-Group
# socket, after checking the serving process's signing identity (and, when the
# build names a team, its designated requirement).
add_subdirectory(pkcs11-module)

# librescrs-prompter: the agent-owned macOS credential window (secure PIN / CAN /
# MRZ), served over its own socket to the agent alone. Optional so a headless
# build can drop the UI target.
option(LIBREDARWIN_BUILD_PROMPTER "Build the macOS credential prompter" ON)
if(LIBREDARWIN_BUILD_PROMPTER)
    add_subdirectory(prompter)
endif()
