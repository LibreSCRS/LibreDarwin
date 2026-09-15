// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/Identity.h> // ObjectId
#include <LibreSCRS/Agent/cache/CardReadCache.h>
#include <LibreSCRS/Agent/cache/CredentialCache.h>
#include <LibreSCRS/Agent/cache/CredentialSnapshotCache.h>
#include <LibreSCRS/Agent/operations/OperationManager.h>
#include <string>

namespace LibreSCRS::Agent {

// The exact set of per-card caches dropped when a card (or its reader) is
// removed, all keyed on the card object path. This is the SINGLE source of truth
// shared by the AgentService card-removal hook (setOnKeyRemoved) and its
// regression test, so *which* caches are invalidated on removal is genuinely
// under test rather than re-mirrored by hand: dropping one from here breaks both
// production and the test together.
//
// The PKCS#11 login-lease revocation stays in the hook itself — it needs the
// frontend. The reader-side sequence lives in releaseReaderOnCardRemoved()
// below, for the same reason this function exists: so the hook's release is
// genuinely under test rather than re-mirrored by hand.
inline void invalidateCardRemovalCaches(CredentialCache& credentialCache, CardReadCache& cardReadCache,
                                        CredentialSnapshotCache& snapshotCache, const std::string& cardPath)
{
    // CAN/MRZ secret cache + the identity/certificate read cache.
    credentialCache.invalidate(cardPath);
    cardReadCache.invalidate(cardPath);
    // The per-card ListCredentials snapshot: its id namespace is void once the
    // card is gone (a re-insert re-lists afresh).
    snapshotCache.invalidate(cardPath);
}

// The reader-side half of card removal: release the power hold (a no-op for a
// reader that was never held) and invalidate the session. With the card gone
// there is nothing left to keep powered, and the next op must re-open against
// whatever comes next. The worker drops the hold handle on the invalidate as
// well; clearing the FLAG here keeps a later idle sweep from re-acquiring one
// on an empty reader. Release-then-invalidate is the documented convention (the
// Linux hook's order); the worker handles both in one pass, so the order has no
// observable effect and no test claims it. Shared by the main.cpp hook and its
// regression test, so dropping the release breaks both together. A reader that
// is already gone hands this an invalid id, on which both calls are no-ops:
// the reader's withdraw stopped its worker, flag and all.
inline void releaseReaderOnCardRemoved(Operations::OperationManager& operations, ObjectId reader)
{
    operations.setReaderHold(reader, false);
    operations.invalidateReaderSession(reader);
}

} // namespace LibreSCRS::Agent
