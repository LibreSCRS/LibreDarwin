# SPDX-License-Identifier: LGPL-2.1-or-later
#
# macOS backend for LibreAgent::Core + the librescrs-agent launchd daemon.
# Mirrors LibreLinux/agent (which builds LibreLinuxAgentCore + the daemon on the
# D-Bus backend); here the backend is the App-Group socket + CBOR + SecCode.
# TODO(P1b): every .cpp body is a stub — see implement-macos-backend.

find_library(SECURITY_FRAMEWORK Security REQUIRED)
find_library(CORE_FOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
find_library(APPKIT_FRAMEWORK AppKit REQUIRED)   # NSWorkspace / DistributedNotificationCenter (SystemLifecycle)
find_library(IOKIT_FRAMEWORK IOKit REQUIRED)     # IORegisterForSystemPower (SystemLifecycle)
find_library(BSM_LIB bsm REQUIRED) # audit_token_to_pid / _pidversion (PeerIdentity)

# LM-free wire core: the CBOR codec, framing, streaming reassembler, peer
# identity, and the prompter protocol. Links NO LibreMiddleware/LibreAgent, so
# the agent-owned prompter (and, later, the P2 PKCS#11 facade) can reuse it
# without pulling the card stack. -fexperimental-library is still needed for the
# libc++ std::expected/std::format the wire layer uses on AppleClang.
add_library(LibreDarwinWireCore STATIC
    src/backend/wire/Cbor.cpp
    src/backend/wire/Framing.cpp
    src/backend/wire/FrameReassembler.cpp
    src/backend/wire/AnonFd.cpp
    src/backend/wire/PrompterProtocol.cpp
    src/backend/PeerIdentity.cpp)
target_include_directories(LibreDarwinWireCore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(LibreDarwinWireCore PUBLIC cxx_std_23)
set_target_properties(LibreDarwinWireCore PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_options(LibreDarwinWireCore PUBLIC -fexperimental-library)
target_link_options(LibreDarwinWireCore PUBLIC -fexperimental-library)
target_link_libraries(LibreDarwinWireCore
    PRIVATE
        qcbor::qcbor # deterministic CBOR codec (D1); not exposed in headers
        ${BSM_LIB})  # PeerIdentity audit_token_to_pid

add_library(LibreDarwinAgentBackend STATIC
    src/backend/SocketTransport.cpp
    src/backend/SecCodeAuthorizer.cpp
    src/backend/MacPrompterClient.cpp
    src/backend/SocketOperationChannel.cpp
    src/backend/SocketFrontend.cpp
    src/backend/SystemLifecycle.mm
    src/backend/OsLogSink.cpp
    src/backend/ProcessHardening.cpp
    src/backend/wire/Messages.cpp # Messages reuses the LibreAgent value enums
    # Operation subclasses: platform-neutral twins copied verbatim from
    # LibreLinux/agent/src/operations (they depend only on core flows +
    # OperationBase + the OperationChannel interface, never on the transport).
    # No ODR clash — LibreDarwin is a separate binary. Cross-track:
    # promote-operation-subclasses-to-core would let both hosts share one copy.
    src/operations/ReadIdentityOperation.cpp
    src/operations/GetPhotoOperation.cpp
    src/operations/ReadCertificatesOperation.cpp
    src/operations/SignOperation.cpp)
target_include_directories(LibreDarwinAgentBackend PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src) # operations/*.cpp use "operations/X.h"
target_compile_features(LibreDarwinAgentBackend PUBLIC cxx_std_23)
set_target_properties(LibreDarwinAgentBackend PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(LibreDarwinAgentBackend
    PUBLIC
        LibreAgent::Core # re-exports LM SmartCard/Plugin PUBLIC
        LibreDarwinWireCore
    PRIVATE
        qcbor::qcbor # Messages.cpp encodes via the Cbor seam
        ${SECURITY_FRAMEWORK}
        ${CORE_FOUNDATION_FRAMEWORK}
        ${FOUNDATION_FRAMEWORK}
        ${APPKIT_FRAMEWORK}
        ${IOKIT_FRAMEWORK})

# AppleClang needs the experimental C++23 library flag when compiling against
# LM's <expected>/<stop_token> (feedback_apple_clang_experimental). Do NOT swap
# for a backport/polyfill — the flag is the documented upstream mechanism.
target_compile_options(LibreDarwinAgentBackend PRIVATE -fexperimental-library)
target_link_options(LibreDarwinAgentBackend PRIVATE -fexperimental-library)

# The wire contract (CBOR/CDDL) is a project artifact installed alongside the
# agent — the macOS mirror of LibreLinux/agent/dbus/*.xml (design §8.3). The
# canonical semantic source stays the Linux D-Bus XML; this schema mirrors it.
install(FILES wire/librescrs-agent.cddl
    DESTINATION ${CMAKE_INSTALL_DATADIR}/librescrs)

# The daemon: wires the macOS backend into an AgentCore and runs the run loop.
add_executable(librescrs-agent src/main.cpp)
target_link_libraries(librescrs-agent PRIVATE LibreDarwinAgentBackend ${CORE_FOUNDATION_FRAMEWORK})
target_compile_definitions(librescrs-agent PRIVATE
    LIBREDARWIN_VERSION_STR="${PROJECT_VERSION}"
    LIBREDARWIN_APP_GROUP="group.org.librescrs.LibreMac")
target_compile_options(librescrs-agent PRIVATE -fexperimental-library)
target_link_options(librescrs-agent PRIVATE -fexperimental-library)

# Install the daemon to libexec (the dev harness path; in production it is the
# librescrs-agent inside the LibreMac host's Contents/MacOS, P4) and the bundled
# SMAppService-ready LaunchAgent plist, configured with the installed path.
install(TARGETS librescrs-agent RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})
set(LIBRESCRS_AGENT_PROGRAM "${CMAKE_INSTALL_FULL_LIBEXECDIR}/librescrs-agent")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../packaging/launchd/org.librescrs.agent.plist
               ${CMAKE_CURRENT_BINARY_DIR}/org.librescrs.agent.plist @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.librescrs.agent.plist
        DESTINATION ${CMAKE_INSTALL_DATADIR}/librescrs/launchd)

if(PROJECT_IS_TOP_LEVEL)
    add_subdirectory(tests)
endif()
