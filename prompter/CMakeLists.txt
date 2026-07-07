# SPDX-License-Identifier: LGPL-2.1-or-later
#
# SKELETON — the agent-owned macOS credential window (secure PIN / CAN / MRZ).
# The Linux twin is LibreLinux/prompter (librescrs-pinentry-kde). Here it is a
# native macOS secure-input helper the daemon drives over the App-Group socket;
# the secret flows prompter -> agent only, never through a client. The window
# shows the platform-derived (SecCode) client identity so the user authorizes a
# NAMED requester.
#
# TODO(P1b) implement-macos-backend: build the SwiftUI/AppKit helper + its IPC to
# the daemon. No target is wired yet.
message(STATUS "LibreDarwin: prompter is a P1b skeleton (no targets yet)")
