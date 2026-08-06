// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

namespace LibreSCRS::Darwin {

// Ask the device owner to confirm `req` (Touch ID, or the account password when
// biometrics are unavailable or unenrolled). Blocking: it returns only once the
// human has answered or the mechanism has failed. Call it off the socket
// server's serial queue.
[[nodiscard]] wire::ConfirmReply confirmWithDeviceOwner(const wire::ConfirmAction& req);

} // namespace LibreSCRS::Darwin
