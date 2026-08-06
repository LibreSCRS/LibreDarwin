# SPDX-License-Identifier: LGPL-2.1-or-later
#
# LibreDarwin agent-backend tests. The codec/framing/message-model wire tests
# and the CDDL wire-contract guard moved to LibreAgent alongside the shared
# LibreAgent::Wire library; the suites here cover backend/transport/frontend/
# config/credential behavior against a fake socket peer (LibreAgent::Wire is
# just a consumed, already-tested dependency from this repo's point of view).
find_package(GTest REQUIRED)

# OsLogSink smoke: the sink is constructible + emits each severity (os_log has no
# public readback, so this is a crash/throw smoke only).
add_executable(OsLogSinkTest OsLogSinkTest.cpp)
target_link_libraries(OsLogSinkTest
    PRIVATE
        LibreDarwinAgentBackend
        GTest::gtest
        GTest::gtest_main)
target_compile_options(OsLogSinkTest PRIVATE -fexperimental-library)
target_link_options(OsLogSinkTest PRIVATE -fexperimental-library)
add_test(NAME OsLogSinkTest COMMAND OsLogSinkTest)

# Backend: peer identity + the socket transport (real bound socket + GCD loop).
foreach(backend_test PeerIdentityTest PeerCodeSigningTest SocketTransportTest SecCodeAuthorizerTest PrompterProtocolTest MacPrompterClientTest SocketOperationChannelTest SocketFrontendTest SystemLifecycleTest ProcessHardeningTest SignHwSmokeTest ReadCertificatesOperationTest ManagePinOperationTest PluginDirectoryTest)
    add_executable(${backend_test} ${backend_test}.cpp)
    target_link_libraries(${backend_test}
        PRIVATE
            LibreDarwinAgentBackend
            GTest::gtest
            GTest::gtest_main)
    target_compile_options(${backend_test} PRIVATE -fexperimental-library)
    target_link_options(${backend_test} PRIVATE -fexperimental-library)
    add_test(NAME ${backend_test} COMMAND ${backend_test})
endforeach()

# White-box unit test of a backend-private operation: the ops headers live under
# src/ (PRIVATE on the backend target, so they stay off the public surface), so
# this test reaches them directly the way the backend's own .cpp files do.
target_include_directories(ReadCertificatesOperationTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
# It also builds a session via the LM-internal detached-session factory
# LibreSCRS::SmartCard::detail::makeDetachedCardSession, whose prototype in
# <LibreSCRS/SmartCard/CardSession.h> is guarded behind LIBRESCRS_INTERNAL_BUILD.
# Only this TEST TU opts in; production agent targets never define it, so the
# internal surface stays out of the shipped binaries.
target_compile_definitions(ReadCertificatesOperationTest PRIVATE LIBRESCRS_INTERNAL_BUILD)

# ManagePinOperationTest reaches the same backend-private ops headers and builds
# a detached session the same way, so it takes the identical src/ include +
# internal-build opt-in.
target_include_directories(ManagePinOperationTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_definitions(ManagePinOperationTest PRIVATE LIBRESCRS_INTERNAL_BUILD)

# SocketFrontendTest drives the credentials ops end-to-end over the socket: it
# includes the src-private CardRemovalCaches.h (the shared removal-invalidation
# helper under test) and opens detached sessions via the same LM-internal
# factory, so it takes the identical src/ include + internal-build opt-in.
target_include_directories(SocketFrontendTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_definitions(SocketFrontendTest PRIVATE LIBRESCRS_INTERNAL_BUILD)
