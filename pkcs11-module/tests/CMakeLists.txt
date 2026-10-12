# SPDX-License-Identifier: LGPL-2.1-or-later
#
# The shape of the built module, per architecture: one export, no foreign
# library, the deployment target, no socket override.
add_test(NAME check-module.sh
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/check-module.sh
        --module=$<TARGET_FILE:librescrs-pkcs11-agent>
        --min=${CMAKE_OSX_DEPLOYMENT_TARGET})

# The factory the module is built from, compiled into a test: it must refuse a
# socket served by anything but the agent.
find_package(GTest REQUIRED)
add_executable(SocketAgentClientFactoryTest SocketAgentClientFactoryTest.cpp ../src/SocketAgentClientFactory.cpp)
target_include_directories(SocketAgentClientFactoryTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(SocketAgentClientFactoryTest
    PRIVATE
        LibreAgent::Pkcs11SocketClient
        LibreDarwinWireCore
        GTest::gtest
        GTest::gtest_main)
add_test(NAME SocketAgentClientFactoryTest COMMAND SocketAgentClientFactoryTest)
