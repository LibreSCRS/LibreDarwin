# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Vendored CBOR codec for the socket wire transport (plan D1). QCBOR is the
# FIDO-Alliance CBOR library (deterministic / preferred serialization, small,
# zero-dep, BSD-3 -> LGPL/facade compatible). Pinned by tag and built static from
# source via FetchContent (mirrors FindOrUseLibreAgent.cmake). Provides the
# imported target qcbor::qcbor, linked PRIVATE by the wire layer + (P2) the
# card-less PKCS#11 facade. Dev builds may re-point it with
#   -DFETCHCONTENT_SOURCE_DIR_QCBOR=/path/to/QCBOR
include(FetchContent)

# Build QCBOR the way the wire layer needs it: static, no test suite, preferred
# (deterministic) serialization ON. Scope the option overrides to the FetchContent
# subdirectory (CMP0077 NEW honors normal variables in option()/BUILD_SHARED_LIBS)
# and RESTORE BUILD_SHARED_LIBS afterwards so we never FORCE a project-global cache
# var onto the sibling targets (the pkcs11 facade IS a dylib) or nested deps.
set(_libredarwin_saved_shared "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF)
set(BUILD_QCBOR_TEST "OFF")
set(BUILD_QCBOR_WARN OFF)

FetchContent_Declare(qcbor
    GIT_REPOSITORY https://github.com/laurencelundblade/QCBOR.git
    GIT_TAG v1.6.1)
FetchContent_MakeAvailable(qcbor) # provides qcbor::qcbor

set(BUILD_SHARED_LIBS "${_libredarwin_saved_shared}")
unset(_libredarwin_saved_shared)

# QCBOR is a C library with no ABI-affecting C++ concerns; keep it out of the
# project's -fexperimental-library / C++23 flags (it compiles as C).
