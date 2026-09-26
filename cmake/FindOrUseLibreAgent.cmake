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

# The agent's synthetic master-list fixture archive, LibreAgent::TestSupport:
# the anchor-import test under agent/tests drives ImportCscaMasterList with a
# signed list and links it. That fixture is the agent's, asked for by name
# rather than carried here as a copy -- the Linux host does the same in its
# file of this name. Set BEFORE either branch below, both of which read it.
#
# Deliberately not gated on BUILD_TESTING: this file is included before the
# root include(CTest) defines that variable, so the condition would simply be
# false, the component would never be requested, and the fixture would go
# missing at link time. A gate that is always closed is worse than no gate.
set(LIBREAGENT_BUILD_TEST_SUPPORT ON CACHE BOOL "" FORCE)

if(LIBREDARWIN_USE_INSTALLED_AGENT_CORE)
    # LibreAgent is on the 5.x train (VERSION 5.0.0 today); bump in lockstep.
    #
    # Name the components. Without them the lookup probes EVERY known component,
    # which on a machine that also has the Qt client installed runs that
    # component's find_dependency(Qt6) and fails hard for a dependency this
    # backend never asked for. Naming them also makes an agent package built
    # without one of them fail configuration BY NAME here, instead of the
    # fixture test quietly disappearing at link time. Three are needed: the
    # neutral core and the wire vocabulary the daemon links, and the
    # master-list fixture the anchor-import test links.
    find_package(LibreAgent 5.0 REQUIRED CONFIG COMPONENTS Core Wire TestSupport)
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
    # built agent run ahead of what was proven. Raising it is a deliberate act:
    # `bump-deps to-head` moves the row in a commit of its own.
    #
    # The revision -- and the URL -- are the LibreAgent row of deps.lock
    # (`<name> <url> <commit> <main|version>`), which `bump-deps` writes and
    # `bump-deps check` holds (form, reachable from upstream main, same revision
    # as every other consumer, and in CI: the tree actually built == the row).
    # This file only reads the row. CMAKE_CONFIGURE_DEPENDS makes a bumped lock
    # re-run configure, so the fetched tree follows the lock instead of staying
    # at the revision the build directory first fetched.
    set(_libredarwin_deps_lock "${CMAKE_CURRENT_LIST_DIR}/../deps.lock")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_libredarwin_deps_lock}")
    file(STRINGS "${_libredarwin_deps_lock}" _libredarwin_agent_row REGEX "^LibreAgent[ \t]")
    list(LENGTH _libredarwin_agent_row _libredarwin_agent_rows)
    if(NOT _libredarwin_agent_rows EQUAL 1)
        message(FATAL_ERROR "deps.lock must hold exactly one LibreAgent row")
    endif()
    string(REGEX REPLACE "[ \t]+" ";" _libredarwin_agent_row "${_libredarwin_agent_row}")
    list(GET _libredarwin_agent_row 1 LIBREAGENT_URL)
    list(GET _libredarwin_agent_row 2 LIBREAGENT_PIN)
    FetchContent_Declare(LibreAgent
        GIT_REPOSITORY ${LIBREAGENT_URL}
        GIT_TAG ${LIBREAGENT_PIN})
    FetchContent_MakeAvailable(LibreAgent) # provides LibreAgent::Core + LibreAgent::Wire

    # No -fexperimental-library patching happens here any more. Both fetched
    # targets carry it as a PUBLIC usage requirement from LibreAgent's own
    # CMakeLists, and this project sets it for its whole build before this file
    # is included, so the fetched subproject inherits it as well.
    #
    # Patching it in from the consumer side was guarded on `TARGET LibreAgentCore`,
    # which is the shape of a check that silently does nothing if the target is
    # ever renamed — the flag would simply stop being applied, with no error and
    # no failing build, and the resulting libc++ mismatch is an ODR violation the
    # compiler cannot diagnose. ci/scripts/check-experimental-library.py now
    # fails the build if any translation unit lacks the flag.
endif()
