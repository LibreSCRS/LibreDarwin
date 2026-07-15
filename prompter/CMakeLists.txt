# SPDX-License-Identifier: LGPL-2.1-or-later
#
# The agent-owned macOS credential window (secure PIN / CAN / MRZ). The Linux
# twin is LibreLinux/prompter (librescrs-pinentry-kde). LM-free: the server logic
# links only the wire core; the AppKit window is the secure-input surface. The
# secret flows prompter -> agent only, never through a client; the prompter
# peer-authenticates that the caller is the agent.

# Testable server logic (peer-auth + protocol dispatch), LM-free.
add_library(LibreDarwinPrompterServer STATIC PrompterServer.cpp)
target_include_directories(LibreDarwinPrompterServer PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(LibreDarwinPrompterServer PUBLIC LibreDarwinWireCore)
set_target_properties(LibreDarwinPrompterServer PROPERTIES POSITION_INDEPENDENT_CODE ON)

# The AppKit prompter binary.
find_library(APPKIT_FRAMEWORK AppKit REQUIRED)
find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
find_library(SECURITY_FRAMEWORK Security REQUIRED)
add_executable(librescrs-prompter PrompterMain.mm PromptWindow.mm)
target_compile_options(librescrs-prompter PRIVATE -fexperimental-library)
target_link_options(librescrs-prompter PRIVATE -fexperimental-library)
target_link_libraries(librescrs-prompter
    PRIVATE
        LibreDarwinPrompterServer
        ${APPKIT_FRAMEWORK}
        ${FOUNDATION_FRAMEWORK}
        ${SECURITY_FRAMEWORK})

# Bundle-ready: the LibreMac host stages this binary as a sibling of
# librescrs-agent at Contents/MacOS/librescrs-prompter, with LM-free deps only —
# the Frameworks entry is kept for symmetry / any future homebrew dep closure.
set_target_properties(librescrs-prompter PROPERTIES
    INSTALL_RPATH "@executable_path;@executable_path/../Frameworks"
    BUILD_WITH_INSTALL_RPATH ON)
# Embedded __info_plist: same secinitd container-keying requirement as the
# agent — see prompter/librescrs-prompter-info.plist.
target_link_options(librescrs-prompter PRIVATE
    "-Wl,-sectcreate,__TEXT,__info_plist,${CMAKE_CURRENT_SOURCE_DIR}/librescrs-prompter-info.plist")
set_property(TARGET librescrs-prompter APPEND PROPERTY LINK_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/librescrs-prompter-info.plist)

install(TARGETS librescrs-prompter RUNTIME DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})

if(PROJECT_IS_TOP_LEVEL)
    find_package(GTest REQUIRED)
    add_executable(PrompterServerTest tests/PrompterServerTest.cpp)
    target_compile_options(PrompterServerTest PRIVATE -fexperimental-library)
    target_link_options(PrompterServerTest PRIVATE -fexperimental-library)
    target_link_libraries(PrompterServerTest PRIVATE LibreDarwinPrompterServer GTest::gtest GTest::gtest_main)
    add_test(NAME PrompterServerTest COMMAND PrompterServerTest)
endif()
