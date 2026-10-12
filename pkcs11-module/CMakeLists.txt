# SPDX-License-Identifier: LGPL-2.1-or-later
#
# librescrs-pkcs11-agent.dylib -- the PKCS#11 module other applications load
# (Firefox, Thunderbird, ssh). It holds no secret and touches no card: every
# call goes to the user's agent over the App Group socket, after checking that
# the process serving that socket is the agent this build trusts. The Cryptoki
# surface is the shared facade; only the factory is this platform's.
add_library(librescrs-pkcs11-agent MODULE src/SocketAgentClientFactory.cpp)
set_target_properties(librescrs-pkcs11-agent PROPERTIES
    PREFIX ""
    SUFFIX ".dylib"
    OUTPUT_NAME "librescrs-pkcs11-agent")
target_link_libraries(librescrs-pkcs11-agent PRIVATE
    LibreAgent::Pkcs11SocketClient
    LibreDarwinWireCore)
# The facade, whole, and one exported name. Never LibreAgent::Pkcs11Facade by
# bare name: that builds a module with no entry point in it.
librescrs_pkcs11_module_link(librescrs-pkcs11-agent)
install(TARGETS librescrs-pkcs11-agent LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/librescrs)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
