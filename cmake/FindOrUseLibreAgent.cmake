# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Hybrid LibreAgent consumption (mirrors LibreLinux's file of the same name):
# prefer find_package(CONFIG) when LIBREDARWIN_USE_INSTALLED_AGENT_CORE=ON,
# otherwise build from source via FetchContent. Either path provides the
# namespaced LibreAgent::Core (the neutral agent core) AND LibreAgent::Wire
# (the shared socket-wire codec/framing/message model) imported/alias targets
# the macOS backend links; LibreAgent::ClientQt (a Qt client library) stays
# off — LibreDarwin is the daemon side, not a client.
#
# Dev builds re-point FetchContent at a local sibling checkout with
#   -DFETCHCONTENT_SOURCE_DIR_LIBREAGENT=/path/to/LibreAgent
# (the source tree is consumed in place; its tests + install/export stay behind
# PROJECT_IS_TOP_LEVEL, so only the enabled component libraries build here).

option(LIBREDARWIN_USE_INSTALLED_AGENT_CORE
       "Consume LibreAgent via find_package(CONFIG) instead of FetchContent" OFF)

if(LIBREDARWIN_USE_INSTALLED_AGENT_CORE)
    # LibreAgent is on the 4.x train (VERSION 4.2.0 today); bump in lockstep.
    find_package(LibreAgent 4.2 REQUIRED CONFIG)
    message(STATUS "LibreAgent: using installed package (CONFIG)")
else()
    message(STATUS "LibreAgent: building from source (FetchContent)")
    include(FetchContent)

    # Pre-seed LibreAgent's own component switches (option() only sets a cache
    # variable that does not already exist, so this wins over LibreAgent's
    # defaults): Core + Wire ON (the daemon links both), ClientQt OFF (no Qt
    # here). Core and Wire already default this way upstream too — this is a
    # defensive pin against a future default flip, not a behavior change today.
    set(LIBREAGENT_BUILD_CORE ON CACHE BOOL "" FORCE)
    set(LIBREAGENT_BUILD_WIRE ON CACHE BOOL "" FORCE)
    set(LIBREAGENT_BUILD_CLIENT_QT OFF CACHE BOOL "" FORCE)

    # A fixed revision, not a branch: the client's contract conformance is
    # proven against exactly this revision, and a moving branch would let the
    # built agent run ahead of what was proven. Raising it is a deliberate act
    # that moves this line and the client's recorded revision together.
    FetchContent_Declare(LibreAgent
        GIT_REPOSITORY https://github.com/LibreSCRS/LibreAgent.git
        GIT_TAG 8fbc9e348a287acaf3d80daf85232e13b125767e)
    FetchContent_MakeAvailable(LibreAgent) # provides LibreAgent::Core + LibreAgent::Wire

    # The neutral core uses std::jthread/std::stop_token, which AppleClang 16/17
    # (Xcode 16, the macos-15 CI image) still gates behind -fexperimental-library
    # (harmless on newer AppleClang where the types are stable). The core's own
    # build is GCC-based and needs no flag, so the consumer adds it to the
    # fetched target from its side.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" AND TARGET LibreAgentCore)
        target_compile_options(LibreAgentCore PRIVATE -fexperimental-library)
        target_link_options(LibreAgentCore PRIVATE -fexperimental-library)
    endif()

    # NOTE: no equivalent patch is added for LibreAgentWire here. Unlike Core,
    # Wire's own CMakeLists.txt already applies -fexperimental-library PUBLIC
    # for AppleClang (LibreAgent's top-level CMakeLists.txt, LIBREAGENT_BUILD_WIRE
    # block) specifically so every Darwin consumer inherits it for free — adding
    # a second copy here would be redundant, not defensive.
endif()
