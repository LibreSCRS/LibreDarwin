# SPDX-License-Identifier: LGPL-2.1-or-later
#
# CBOR codec for the socket wire transport. QCBOR is a small, zero-dep, BSD-3
# C codec (BSD-3 -> LGPL/facade compatible) used for raw CBOR encode/decode
# only: RFC 8949 §4.2 canonical map-key ordering and strict decoding are
# enforced by LibreDarwin's own Cbor.cpp (CanonicalKeyLess), NOT by QCBOR
# (v1.6.1 has no map-key sorting). Pinned by immutable commit SHA and built
# static from source via FetchContent (mirrors FindOrUseLibreAgent.cmake).
# Provides the imported target qcbor::qcbor, linked PRIVATE by the wire layer
# and the card-less PKCS#11 facade. Dev builds may re-point it with
#   -DFETCHCONTENT_SOURCE_DIR_QCBOR=/path/to/QCBOR
include(FetchContent)

# Build QCBOR the way the wire layer needs it: static, no test suite. Scope
# the option overrides to the FetchContent
# subdirectory (CMP0077 NEW honors normal variables in option()/BUILD_SHARED_LIBS)
# and RESTORE BUILD_SHARED_LIBS afterwards so we never FORCE a project-global cache
# var onto the sibling targets (the pkcs11 facade IS a dylib) or nested deps.
set(_libredarwin_saved_shared "${BUILD_SHARED_LIBS}")
set(BUILD_SHARED_LIBS OFF)
set(BUILD_QCBOR_TEST "OFF")
set(BUILD_QCBOR_WARN OFF)

FetchContent_Declare(qcbor
    GIT_REPOSITORY https://github.com/laurencelundblade/QCBOR.git
    # Immutable SHA the (mutable) tag v1.6.1 resolves to.
    GIT_TAG 930708bb86481e88879eb1d87fd4d664f1d69503)
FetchContent_MakeAvailable(qcbor) # provides qcbor::qcbor

set(BUILD_SHARED_LIBS "${_libredarwin_saved_shared}")
unset(_libredarwin_saved_shared)

# QCBOR is a C library with no ABI-affecting C++ concerns; keep it out of the
# project's -fexperimental-library / C++23 flags (it compiles as C).
