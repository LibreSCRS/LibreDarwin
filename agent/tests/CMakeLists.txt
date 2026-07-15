# SPDX-License-Identifier: LGPL-2.1-or-later
#
# LibreDarwin agent-backend tests. Task 1 wires the WireContractGuard (the
# cross-stack drift anchor pinning the CBOR/CDDL wire literals to the upstream
# LibreAgent/LibreMiddleware enums). Tasks 3-9 add the CBOR/framing/message/
# transport/frontend/config unit tests against a fake socket peer.
find_package(GTest REQUIRED)

# WireContractGuard: compile-time static_asserts tying the wire enums to the
# core symbols (a renumber breaks the build). Links the backend lib ->
# LibreAgent::Core -> LibreMiddleware Plugin/Auth, so the asserts see the
# upstream enums. Mirrors LibreLinux/agent/tests/WireContractGuardTest.cpp.
add_executable(WireContractGuardTest WireContractGuardTest.cpp)
target_link_libraries(WireContractGuardTest
    PRIVATE
        LibreDarwinAgentBackend
        GTest::gtest
        GTest::gtest_main)
target_compile_options(WireContractGuardTest PRIVATE -fexperimental-library -Werror=switch)
target_link_options(WireContractGuardTest PRIVATE -fexperimental-library)
# The CDDL is the wire contract of record; the guard parses its `error-code`
# group and compares it value-for-value with the upstream taxonomy.
target_compile_definitions(WireContractGuardTest PRIVATE
    LIBREDARWIN_WIRE_CDDL="${CMAKE_CURRENT_SOURCE_DIR}/../wire/librescrs-agent.cddl")
add_test(NAME WireContractGuardTest COMMAND WireContractGuardTest)

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

# Wire layer: canonical CBOR round-trips + framing/SCM_RIGHTS/FD_CLOEXEC + messages.
foreach(wire_test CborRoundTripTest FramingTest FrameReassemblerTest)
    add_executable(${wire_test} ${wire_test}.cpp)
    target_link_libraries(${wire_test}
        PRIVATE
            LibreDarwinAgentBackend
            GTest::gtest
            GTest::gtest_main)
    target_compile_options(${wire_test} PRIVATE -fexperimental-library)
    target_link_options(${wire_test} PRIVATE -fexperimental-library)
    add_test(NAME ${wire_test} COMMAND ${wire_test})
endforeach()

# MessagesRoundTripTest supplies its own main() (unlike the other wire_test
# targets): besides the normal gtest run it doubles as the cross-implementation
# fixture generator for the LibreMac Swift client's decode tests
# (`--dump-fixtures <dir>` writes one canonical frame body per reply/event
# shape instead of running the test suite), so it links GTest::gtest, not
# GTest::gtest_main.
add_executable(MessagesRoundTripTest MessagesRoundTripTest.cpp)
target_link_libraries(MessagesRoundTripTest
    PRIVATE
        LibreDarwinAgentBackend
        GTest::gtest)
target_compile_options(MessagesRoundTripTest PRIVATE -fexperimental-library)
target_link_options(MessagesRoundTripTest PRIVATE -fexperimental-library)
add_test(NAME MessagesRoundTripTest COMMAND MessagesRoundTripTest)

# Backend: peer identity + the socket transport (real bound socket + GCD loop).
foreach(backend_test PeerIdentityTest SocketTransportTest SecCodeAuthorizerTest PrompterProtocolTest MacPrompterClientTest SocketOperationChannelTest SocketFrontendTest SystemLifecycleTest ProcessHardeningTest SignHwSmokeTest ReadCertificatesOperationTest)
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

# libFuzzer target for the CBOR decoder (untrusted-parser hardening, D1). Off by
# default; needs a clang WITH the libFuzzer runtime (e.g. Homebrew LLVM) — Apple
# Clang ships none, so CI runs the fuzz on a Linux leg (the `fuzz-cbor` job
# builds CborFuzzTest.cpp + Cbor.cpp + QCBOR standalone with
# -fsanitize=fuzzer,address over agent/tests/corpus/cbor). Scoped to just the
# codec + qcbor (instrumented), NOT the whole backend lib, so coverage focuses
# on the parser. Local decoder robustness is otherwise covered by
# CborRoundTrip.MalformedInput*.
option(LIBREDARWIN_BUILD_FUZZERS "Build the libFuzzer decoder target (needs a fuzzer-capable clang)" OFF)
if(LIBREDARWIN_BUILD_FUZZERS)
    add_executable(CborFuzz
        CborFuzzTest.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/backend/wire/Cbor.cpp)
    target_include_directories(CborFuzz PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
    target_link_libraries(CborFuzz PRIVATE qcbor::qcbor)
    target_compile_options(CborFuzz PRIVATE -fexperimental-library -fsanitize=fuzzer,address)
    target_link_options(CborFuzz PRIVATE -fexperimental-library -fsanitize=fuzzer,address)
endif()
