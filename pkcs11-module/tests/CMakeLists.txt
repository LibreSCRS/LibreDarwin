# SPDX-License-Identifier: LGPL-2.1-or-later
#
# The shape of the built module, per architecture: one export, no foreign
# library, the deployment target, no socket override.
add_test(NAME check-module.sh
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/check-module.sh
        --module=$<TARGET_FILE:librescrs-pkcs11-agent>
        --min=${CMAKE_OSX_DEPLOYMENT_TARGET})
