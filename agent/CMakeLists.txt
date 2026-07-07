# SPDX-License-Identifier: LGPL-2.1-or-later
#
# macOS backend for LibreAgent::Core + the librescrs-agent launchd daemon.
# Mirrors LibreLinux/agent (which builds LibreLinuxAgentCore + the daemon on the
# D-Bus backend); here the backend is the App-Group socket + CBOR + SecCode.
# TODO(P1b): every .cpp body is a stub — see implement-macos-backend.

find_library(SECURITY_FRAMEWORK Security REQUIRED)
find_library(CORE_FOUNDATION_FRAMEWORK CoreFoundation REQUIRED)

add_library(LibreDarwinAgentBackend STATIC
    src/backend/SocketTransport.cpp
    src/backend/SecCodeAuthorizer.cpp
    src/backend/MacPrompterClient.cpp
    src/backend/SocketOperationChannel.cpp
    src/backend/OsLogSink.cpp
    src/backend/wire/Framing.cpp)
target_include_directories(LibreDarwinAgentBackend PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(LibreDarwinAgentBackend PUBLIC cxx_std_23)
set_target_properties(LibreDarwinAgentBackend PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(LibreDarwinAgentBackend
    PUBLIC
        LibreAgent::Core # re-exports LM SmartCard/Plugin PUBLIC
    PRIVATE
        ${SECURITY_FRAMEWORK}
        ${CORE_FOUNDATION_FRAMEWORK})

# AppleClang needs the experimental C++23 library flag when compiling against
# LM's <expected>/<stop_token> (feedback_apple_clang_experimental). Do NOT swap
# for a backport/polyfill — the flag is the documented upstream mechanism.
target_compile_options(LibreDarwinAgentBackend PRIVATE -fexperimental-library)
target_link_options(LibreDarwinAgentBackend PRIVATE -fexperimental-library)

# The daemon: wires the macOS backend into an AgentCore and runs the run loop.
add_executable(librescrs-agent src/main.cpp)
target_link_libraries(librescrs-agent PRIVATE LibreDarwinAgentBackend)
target_compile_options(librescrs-agent PRIVATE -fexperimental-library)
target_link_options(librescrs-agent PRIVATE -fexperimental-library)

if(PROJECT_IS_TOP_LEVEL)
    add_subdirectory(tests)
endif()
