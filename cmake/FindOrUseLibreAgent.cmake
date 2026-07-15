# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Hybrid LibreAgent core consumption (mirrors LibreLinux's file of the same
# name): prefer find_package(CONFIG) when LIBREDARWIN_USE_INSTALLED_AGENT_CORE=ON,
# otherwise build the neutral core from source via FetchContent. Either path
# provides the namespaced LibreAgent::Core imported/alias target the macOS
# backend links.
#
# Dev builds re-point FetchContent at a local sibling checkout with
#   -DFETCHCONTENT_SOURCE_DIR_LIBREAGENT=/path/to/LibreAgent
# (the source tree is consumed in place; its tests + install/export stay behind
# PROJECT_IS_TOP_LEVEL, so only the library builds here).

option(LIBREDARWIN_USE_INSTALLED_AGENT_CORE
       "Consume LibreAgent via find_package(CONFIG) instead of FetchContent" OFF)

if(LIBREDARWIN_USE_INSTALLED_AGENT_CORE)
    # LibreAgent is on the 4.x train (VERSION 4.2.0 today); bump in lockstep.
    find_package(LibreAgent 4.2 REQUIRED CONFIG)
    message(STATUS "LibreAgent: using installed package (CONFIG)")
else()
    message(STATUS "LibreAgent: building from source (FetchContent)")
    include(FetchContent)
    FetchContent_Declare(LibreAgent
        GIT_REPOSITORY https://github.com/LibreSCRS/LibreAgent.git
        GIT_TAG main)
    FetchContent_MakeAvailable(LibreAgent) # provides LibreAgent::Core

    # The neutral core uses std::jthread/std::stop_token, which AppleClang 16/17
    # (Xcode 16, the macos-15 CI image) still gates behind -fexperimental-library
    # (harmless on newer AppleClang where the types are stable). The core's own
    # build is GCC-based and needs no flag, so the consumer adds it to the
    # fetched target from its side.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" AND TARGET LibreAgentCore)
        target_compile_options(LibreAgentCore PRIVATE -fexperimental-library)
        target_link_options(LibreAgentCore PRIVATE -fexperimental-library)
    endif()
endif()
