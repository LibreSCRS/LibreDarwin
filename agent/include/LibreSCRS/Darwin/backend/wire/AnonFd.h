// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Agent/wire/UniqueFd.h>

#include <cstdint>
#include <optional>
#include <span>

namespace LibreSCRS::Darwin::wire {

using LibreSCRS::Agent::Wire::UniqueFd;

// The memfd_create analog for Darwin (which has none): create a regular file
// with mkstemp, unlink it immediately (anonymous — no name in the filesystem),
// write @p bytes, rewind, and return the owning fd. The fd is passed to a client
// via SCM_RIGHTS; a regular-file fd fully supports the client's pread/read/mmap
// (unlike a POSIX shared-memory shm_open object, which is mmap-only). Mode is
// 0600. Returns nullopt on any syscall failure so the caller can fail closed
// rather than deliver a truncated artifact. The artifact is the user's own
// public document/photo, not a secret, so no F_SEAL / read-only re-dup is needed.
[[nodiscard]] std::optional<UniqueFd> anonFdFromBytes(std::span<const std::uint8_t> bytes);

} // namespace LibreSCRS::Darwin::wire
