# SPDX-License-Identifier: LGPL-2.1-or-later
cmake_minimum_required(VERSION 3.24)

# Derives PROJECT_VERSION + GIT_VERSION_* from git tags (committed VERSION file /
# 0.0.1 fallback). Must run before project() — see the module's own note.
include(cmake/GitVersion.cmake)

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

# The single LibreMiddleware owner: the daemon links LM through LibreAgent::Core.
find_package(LibreMiddleware 4.2 REQUIRED CONFIG)

# The platform-neutral agent core (flows, scheduler, presence model, caches,
# lease/broker policy, LM-backed seams, the 5 backend interfaces). The macOS
# backend under agent/ implements those interfaces and builds the
# librescrs-agent daemon on top of LibreAgent::Core — exactly as LibreLinux does
# with its D-Bus backend.
include(cmake/FindOrUseLibreAgent.cmake)

enable_testing()

add_subdirectory(agent)

# Card-less, secret-less PKCS#11 facade dylib (browser-loadable) that forwards to
# the agent over the App-Group socket. Full implementation is P2.
add_subdirectory(pkcs11-module)

# The agent-owned macOS credential window (secure PIN / CAN / MRZ). Optional so a
# headless/CI build can drop the UI target. Full implementation is P1b.
option(LIBREDARWIN_BUILD_PROMPTER "Build the macOS credential prompter" ON)
if(LIBREDARWIN_BUILD_PROMPTER)
    add_subdirectory(prompter)
endif()
