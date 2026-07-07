// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// SKELETON / placeholder — NOT yet compiled (see tests/CMakeLists.txt).
//
// The macOS twin of LibreKDE's tests/agentclient/WireContractGuardTest: it pins
// the wire contract so the socket protocol and the shared CDDL schema cannot
// drift silently. Once formalize-wire-contract-schema lands the CDDL, this test
// MUST assert, at minimum:
//
//   - every message type name + its required/optional fields matches the CDDL;
//   - the ErrorCode enum ordinals (18 stable, append-only) match LibreAgent's
//     value/ErrorTaxonomy.h — a renumber or removal fails the test;
//   - the OperationPhase set {Created, Connecting, AwaitingConsent,
//     Authenticating, Reading, Signing, Timestamping, Done} is exhaustive;
//   - the Capabilities bits {Pki, IdentityData, EmrtdCrypto, PinManagement} and
//     PreReadAuth {None, BacMrz, PaceCan} match the core;
//   - a CBOR encode/decode round-trip is byte-stable for each message;
//   - fd-bearing messages (SignResult, PhotoResult) reference fds by index only.
//
// TODO(P1b + formalize-wire-contract-schema): implement against GoogleTest.
