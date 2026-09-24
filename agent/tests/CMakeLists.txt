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
add_test(NAME OsLogSinkTest COMMAND OsLogSinkTest)

# Backend: peer identity + the socket transport (real bound socket + GCD loop).
foreach(backend_test PeerIdentityTest PeerCodeSigningTest AgentCoreSeamsTest SocketTransportTest SecCodeAuthorizerTest PrompterProtocolTest MacPrompterClientTest SocketOperationChannelTest SocketFrontendTest SystemLifecycleTest ProcessHardeningTest SignHwSmokeTest ReadCertificatesOperationTest ManagePinOperationTest PluginDirectoryTest AppGroupPathsProductionTest)
    add_executable(${backend_test} ${backend_test}.cpp)
    target_link_libraries(${backend_test}
        PRIVATE
            LibreDarwinAgentBackend
            GTest::gtest
            GTest::gtest_main)
    add_test(NAME ${backend_test} COMMAND ${backend_test})
endforeach()

# The hardware smoke skips without LIBRESCRS_HW or a card; ctest would call
# that Passed, so the summary would claim a hardware gate that never ran. The
# pattern is anchored at the END of the output, on the last line of gtest's
# skipped list: a bare "[  SKIPPED ]" also matches when another case in the
# same binary FAILED, and ctest lets a skip match outrank the failure -- the
# run then reports Skipped and exits 0. With a failure the output ends on
# gtest's failed list instead, so the pattern misses and the failure stands.
set_tests_properties(SignHwSmokeTest PROPERTIES SKIP_REGULAR_EXPRESSION "\\[  SKIPPED \\] [^ \n]+\n*$")

# ReadCertificatesOperationTest drives the agent's own operation, reached through
# LibreAgent::Core's public headers like every other consumer (this host carried
# a copy of it until the core exported one). It builds a session via the
# LM-internal detached-session factory
# LibreSCRS::SmartCard::detail::makeDetachedCardSession, whose prototype in
# <LibreSCRS/SmartCard/CardSession.h> is guarded behind LIBRESCRS_INTERNAL_BUILD.
# Only this TEST TU opts in; production agent targets never define it, so the
# internal surface stays out of the shipped binaries.
target_compile_definitions(ReadCertificatesOperationTest PRIVATE LIBRESCRS_INTERNAL_BUILD)

# ManagePinOperationTest builds a detached session the same way, so it takes the
# identical internal-build opt-in.
target_compile_definitions(ManagePinOperationTest PRIVATE LIBRESCRS_INTERNAL_BUILD)

# SocketFrontendTest drives the credentials ops end-to-end over the socket: it
# includes the src-private CardRemovalCaches.h (the shared removal-invalidation
# helper under test) and opens detached sessions via the same LM-internal
# factory, so it takes the identical src/ include + internal-build opt-in.
target_include_directories(SocketFrontendTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_definitions(SocketFrontendTest PRIVATE LIBRESCRS_INTERNAL_BUILD)

# ImportCscaMasterList end to end over the socket: the authorise -> rate-limit
# -> read ORDER (proved by the descriptor's own file offset and by a pipe, not
# by the error name, which an implementation with the checks reversed also
# returns), the descriptor discipline, the accepted path, and that building the
# frontend reconciles a remembered report against the cache without touching
# the cache. Links the agent's own signed-master-list fixture archive; the
# OpenSSL that mints its certificates rides with that imported target and
# reaches nothing under test.
add_executable(CscaImportSocketTest CscaImportSocketTest.cpp)
target_link_libraries(CscaImportSocketTest
    PRIVATE
        LibreDarwinAgentBackend
        LibreAgent::TestSupport
        GTest::gtest
        GTest::gtest_main)
add_test(NAME CscaImportSocketTest COMMAND CscaImportSocketTest)
