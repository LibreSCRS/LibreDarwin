// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Isolation proof for the WireCoreHeaderPurityCheck target (tests/CMakeLists.txt):
// this TU is compiled with an include path of ONLY this tree's agent/include and
// prompter/ and the fetched agent library's include/, and links nothing at all.
//
// LibreDarwinWireCore and the prompter server link no LibreMiddleware and no
// LibreAgent::Core, which is what lets the credential window and the PKCS#11
// module ship without the card stack. Their headers do reach into the agent
// library's Core tree for the prompter vocabulary (backend/PrompterWire.h,
// operations/PromptPolicy.h); those are std-only, and nothing in the agent
// library holds them to it. A passing compile here is the evidence that every
// header below, and everything it includes, still pulls in no middleware: the
// first such include fails this target with file-not-found.
#include <LibreSCRS/Darwin/backend/AppGroupPaths.h>
#include <LibreSCRS/Darwin/backend/ProcessHardening.h>
#include <LibreSCRS/Darwin/backend/SingleInstanceLock.h>
#include <LibreSCRS/Darwin/backend/SocketPathIdentity.h>
#include <LibreSCRS/Darwin/backend/wire/AnonFd.h>
#include <LibreSCRS/Darwin/backend/wire/PrompterProtocol.h>

#include <PrompterComposition.h>
#include <PrompterServer.h>
