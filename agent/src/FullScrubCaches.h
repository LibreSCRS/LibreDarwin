// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>

namespace LibreSCRS::Agent {

// The exact set of caches the full lifecycle scrub (system sleep /
// fast-user-switch away) clears wholesale. This is the SINGLE source of truth
// shared by main.cpp's fullScrub lambda and its regression test, so *which*
// caches die with the session is genuinely under test rather than re-mirrored
// by hand: dropping one from here breaks both production and the test together.
//
// The reader-session invalidation and PKCS#11 lease revocation stay in the
// lambda itself — they iterate the object registry and need the operation
// manager / broker, not just the caches.
inline void clearFullScrubCaches(CredentialCache& credentialCache, CredentialSnapshotCache& snapshotCache)
{
    // The CAN/MRZ secret cache.
    credentialCache.clear();
    // The per-card ListCredentials snapshots die with the session too: their id
    // namespace is void after a power-cycle; a wake re-lists.
    snapshotCache.clear();
}

} // namespace LibreSCRS::Agent
