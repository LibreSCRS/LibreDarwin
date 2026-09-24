// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Every Darwin implementation of a LibreAgent interface, compiled against the
// agent headers it is handed. check-agent-interface.sh compiles this with
// -fsyntax-only as its rule R6; nothing links it.
//
// Two defects, two instruments. A base signature that moves leaves an
// `override` here that overrides nothing, which the compiler rejects while
// reading the header. A pure virtual ADDED to a base leaves every header well
// formed and makes the implementation abstract, which nothing notices until a
// `make_unique` somewhere fails to build -- so each class is asserted concrete.
#include <LibreSCRS/Darwin/backend/MacPrompterClient.h>
#include <LibreSCRS/Darwin/backend/SecCodeAuthorizer.h>
#include <LibreSCRS/Darwin/backend/SocketOperationChannel.h>
#include <LibreSCRS/Darwin/backend/SocketTransport.h>

#include <type_traits>

static_assert(!std::is_abstract_v<LibreSCRS::Darwin::SecCodeAuthorizer>,
              "SecCodeAuthorizer leaves a pure virtual of Agent::Authorizer unimplemented");
static_assert(!std::is_abstract_v<LibreSCRS::Darwin::SocketTransport>,
              "SocketTransport leaves a pure virtual of Agent::AgentTransport unimplemented");
static_assert(!std::is_abstract_v<LibreSCRS::Darwin::SocketOperationChannel>,
              "SocketOperationChannel leaves a pure virtual of Agent::Operations::OperationChannel unimplemented");
static_assert(!std::is_abstract_v<LibreSCRS::Darwin::MacPrompterClient>,
              "MacPrompterClient leaves a pure virtual of Agent::Operations::PrompterClientBase unimplemented");
