# SPDX-License-Identifier: LGPL-2.1-or-later
#
# SKELETON. TODO(P1b + formalize-wire-contract-schema): pull GoogleTest via
# FetchContent (as LibreAgent does) and build the WireContractGuard test that
# pins the CBOR/CDDL message shapes + enum ordinals against drift, plus the
# backend unit tests (peer-identity resolution, lease/rate-limit, framing
# encode/decode round-trips) against a fake socket peer.
#
# No test target is wired yet; this file exists so the tree + add_subdirectory
# are in place. WireContractGuardTest.cpp is a documented placeholder.
message(STATUS "LibreDarwin: tests are a P1b skeleton (no targets yet)")
