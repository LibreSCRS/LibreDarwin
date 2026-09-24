// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "PrompterComposition.h"

namespace LibreSCRS::Darwin::PrompterComposition {

int run(const Hooks& hooks)
{
    if (!hooks.harden()) {
        hooks.warn("process hardening incomplete (PT_DENY_ATTACH / RLIMIT_CORE=0 failed)");
    }
    if (!hooks.selfCheck()) {
        hooks.warn("built with a team id but not signed by that team; refusing to start");
        return 2;
    }
    hooks.appInit();
    if (auto bound = hooks.bind(); !bound) {
        hooks.warn(bound.error());
        return 1;
    }
    hooks.runLoop();
    return 0;
}

} // namespace LibreSCRS::Darwin::PrompterComposition
