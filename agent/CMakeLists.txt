# SPDX-License-Identifier: LGPL-2.1-or-later
#
# macOS backend for LibreAgent::Core + the librescrs-agent launchd daemon.
# The backend is the App-Group socket (CBOR wire via LibreAgent::Wire) + SecCode.

find_library(SECURITY_FRAMEWORK Security REQUIRED)
find_library(CORE_FOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
find_library(APPKIT_FRAMEWORK AppKit REQUIRED)   # NSWorkspace / DistributedNotificationCenter (SystemLifecycle)
find_library(IOKIT_FRAMEWORK IOKit REQUIRED)     # IORegisterForSystemPower (SystemLifecycle)

# Darwin-only wire-adjacent pieces that sit alongside, but are NOT themselves,
# the shared LibreAgent::Wire codec/framing/message model: anonymous-fd
# creation (the memfd_create analog), the private agent<->prompter CBOR
# protocol, the App-Group paths, and the process hardening both secret-holding
# binaries call first. The peer check (BSM peer identity, SecTask/SecCode) is
# LibreAgent::Wire's, the same one every client of the socket runs. Links NO
# LibreMiddleware/LibreAgent::Core, so the agent-owned prompter and the PKCS#11
# module can reuse it without pulling the card stack. Its headers do include
# two std-only headers from the agent's Core tree (the prompter vocabulary);
# tests/WireCoreHeaderPurity.cpp keeps them, and every header here, free of the
# middleware. The libc++ std::expected/std::format this layer uses on
# AppleClang need -fexperimental-library, which the root CMakeLists sets for
# the whole build.
add_library(LibreDarwinWireCore STATIC
    src/backend/wire/AnonFd.cpp
    src/backend/wire/PrompterProtocol.cpp
    src/backend/AppGroupPaths.cpp
    src/backend/ProcessHardening.cpp
    src/backend/SingleInstanceLock.cpp)
target_include_directories(LibreDarwinWireCore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
# The team id the agent and the prompter hold each other (and themselves, at
# start-up) to, and the App Group they meet in, are LibreAgent::Wire's: its
# LIBRESCRS_TEAM_ID cache variable is the one setting, compiled into the peer
# check every end of the socket shares. Never read from the environment.
target_compile_features(LibreDarwinWireCore PUBLIC cxx_std_23)
set_target_properties(LibreDarwinWireCore PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(LibreDarwinWireCore
    PUBLIC
        # AnonFd.h/PrompterProtocol.h expose UniqueFd/CborValue in their public
        # API, and every user of this library checks its peer through Wire.
        LibreAgent::Wire)

add_library(LibreDarwinAgentBackend STATIC
    src/backend/SocketTransport.cpp
    src/backend/SecCodeAuthorizer.cpp
    src/backend/MacPrompterClient.cpp
    src/backend/SocketOperationChannel.cpp
    src/backend/SocketFrontend.cpp
    src/backend/SystemLifecycle.mm
    src/backend/OsLogSink.cpp
    src/backend/PluginDirectory.cpp
    src/backend/PeerPolicy.cpp)
target_include_directories(LibreDarwinAgentBackend PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(LibreDarwinAgentBackend PUBLIC cxx_std_23)
set_target_properties(LibreDarwinAgentBackend PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(LibreDarwinAgentBackend
    PUBLIC
        LibreAgent::Core # re-exports LM SmartCard/Plugin PUBLIC
        LibreAgent::Wire # SocketTransport.h/SocketFrontend.h expose the wire message model in their public API
        LibreDarwinWireCore
    PRIVATE
        ${SECURITY_FRAMEWORK}
        ${CORE_FOUNDATION_FRAMEWORK}
        ${FOUNDATION_FRAMEWORK}
        ${APPKIT_FRAMEWORK}
        ${IOKIT_FRAMEWORK})


# The daemon: wires the macOS backend into an AgentCore and runs the run loop.
add_executable(librescrs-agent src/main.cpp)
target_link_libraries(librescrs-agent PRIVATE LibreDarwinAgentBackend ${CORE_FOUNDATION_FRAMEWORK})
target_compile_definitions(librescrs-agent PRIVATE
    LIBREDARWIN_VERSION_STR="${PROJECT_VERSION}")

# Bundle-ready: the LibreMac host stages this binary at
# Contents/MacOS/librescrs-agent with LM dylibs at Contents/Frameworks/.
# @executable_path/../Frameworks covers that layout; the bare @executable_path entry covers co-located dylibs
# (none today, kept for symmetry with the prompter).
set_target_properties(librescrs-agent PROPERTIES
    INSTALL_RPATH "@executable_path;@executable_path/../Frameworks"
    BUILD_WITH_INSTALL_RPATH ON)
# Embedded __info_plist: a bare sandboxed main executable needs its own
# CFBundleIdentifier for secinitd container keying, or App Sandbox init SIGTRAPs
# in libsystem_secinit — see agent/librescrs-agent-info.plist.in. The short
# version comes from the same PROJECT_VERSION that LIBREDARWIN_VERSION_STR above
# carries, so the number the linker embeds cannot drift from the number the
# binary reports; the link reads the generated file, not the template.
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/librescrs-agent-info.plist.in
               ${CMAKE_CURRENT_BINARY_DIR}/librescrs-agent-info.plist @ONLY)
target_link_options(librescrs-agent PRIVATE
    "-Wl,-sectcreate,__TEXT,__info_plist,${CMAKE_CURRENT_BINARY_DIR}/librescrs-agent-info.plist")
set_property(TARGET librescrs-agent APPEND PROPERTY LINK_DEPENDS
    ${CMAKE_CURRENT_BINARY_DIR}/librescrs-agent-info.plist)

# Nothing is installed: LibreMac stages the agent from this build tree into its
# bundle with a LaunchAgent plist of its own, and the dev harness
# (packaging/install-dev.sh) runs it from here.

if(PROJECT_IS_TOP_LEVEL AND BUILD_TESTING)
    add_subdirectory(tests)
endif()
