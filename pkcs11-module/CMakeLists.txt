# SPDX-License-Identifier: LGPL-2.1-or-later
#
# SKELETON — the card-less, secret-less PKCS#11 facade dylib (design §11, P2).
# Browsers (Firefox/Chrome) and the CTK extension load it; it forwards the
# 5-method seam (CertDer / Login / Logout / SignRaw / Decrypt, NO PIN args) to
# the agent over the App-Group socket, advertising CKF_PROTECTED_AUTHENTICATION_PATH.
# It links NO LibreMiddleware and does NO card I/O. The Linux twin is
# LibreLinux/pkcs11-module (librescrs-pkcs11-agent).
#
# TODO(P2) build-macos-pkcs11-facade: implement the Cryptoki C_* ABI over the
# socket; sign + notarize as its own browser-loadable unit. No target yet.
message(STATUS "LibreDarwin: pkcs11-module is a P2 skeleton (no targets yet)")
