# SPDX-License-Identifier: LGPL-2.1-or-later
#
# LibreDarwin agent-backend tests. The codec/framing/message-model wire tests
# and the CDDL wire-contract guard moved to LibreAgent alongside the shared
# LibreAgent::Wire library; the suites here cover backend/transport/frontend/
# config/credential behavior against a fake socket peer (LibreAgent::Wire is
# just a consumed, already-tested dependency from this repo's point of view).
find_package(GTest REQUIRED)

# The wire core and the prompter server are middleware-free by their link lines,
# but their headers include two headers from the agent library's Core tree, so
# the link lines alone no longer say it. This object library compiles all of
# their headers with nothing on the include path but this tree and the fetched
# agent's include/ -- no middleware prefix, no linked target -- so the first
# middleware include reaching them fails the build. Built from source only: an
# installed agent may share its include prefix with the middleware, which would
# let that include resolve and prove nothing.
if(TARGET LibreAgentWire)
    get_target_property(wire_core_purity_agent_dir LibreAgentWire SOURCE_DIR)
    add_library(WireCoreHeaderPurityCheck OBJECT WireCoreHeaderPurity.cpp)
    target_include_directories(WireCoreHeaderPurityCheck
        PRIVATE
            ${PROJECT_SOURCE_DIR}/agent/include
            ${PROJECT_SOURCE_DIR}/prompter
            ${wire_core_purity_agent_dir}/include)
    target_compile_features(WireCoreHeaderPurityCheck PRIVATE cxx_std_23)
endif()

# OsLogSink smoke: the sink is constructible + emits each severity (os_log has no
# public readback, so this is a crash/throw smoke only).
add_executable(OsLogSinkTest OsLogSinkTest.cpp)
target_link_libraries(OsLogSinkTest
    PRIVATE
        LibreDarwinAgentBackend
        GTest::gtest
        GTest::gtest_main)
add_test(NAME OsLogSinkTest COMMAND OsLogSinkTest)

# Backend: the socket transport (real bound socket + GCD loop) and what sits on it.
foreach(backend_test SocketTransportTest SecCodeAuthorizerTest PrompterProtocolTest MacPrompterClientTest SocketOperationChannelTest SocketFrontendTest SystemLifecycleTest ProcessHardeningTest SignHwSmokeTest ManagePinOperationTest PluginDirectoryTest AppGroupPathsProductionTest)
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

# CryptoTokenKit shows a process without com.apple.security.smartcard no reader
# and opens it no card. The binaries that build a real MonitorService or call the
# real CardSession::open (SocketFrontendTest's sign flows open "Test Reader") are
# signed ad hoc with the entitlement after every link, so they see what the
# agent sees and the hardware smoke does not skip as if no card were present.
# The rest keep the linker's signature.
foreach(card_test SignHwSmokeTest SocketFrontendTest)
    add_custom_command(TARGET ${card_test} POST_BUILD
        COMMAND codesign --force --sign - --identifier ${card_test}
                --entitlements ${CMAKE_CURRENT_SOURCE_DIR}/smartcard-entitlement.plist $<TARGET_FILE:${card_test}>
        VERBATIM)
endforeach()

# ManagePinOperationTest and SocketFrontendTest open sessions with no card
# behind them through LibreMiddleware's declared test support (a static
# archive, never in a shipped library), so no target here compiles against
# LibreMiddleware's internal surface.
foreach(session_test ManagePinOperationTest SocketFrontendTest)
    target_link_libraries(${session_test} PRIVATE LibreSCRS::SmartCardTesting)
endforeach()

# The authorizer that grants everything is a test double the agent library
# ships with its test support, never with the headers a host is built from.
# CscaImportSocketTest (below) links the same component for its fixture.
foreach(granting_test SocketFrontendTest SignHwSmokeTest)
    target_link_libraries(${granting_test} PRIVATE LibreAgent::TestSupport)
endforeach()

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
