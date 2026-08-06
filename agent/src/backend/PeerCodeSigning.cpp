// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Shared SecTask-based peer code-signing resolution: audit_token -> signing
// identifier + app-group entitlements, plus the expected-identity match both
// ends of the private prompter socket enforce.
#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecTask.h>

#include <algorithm>
#include <cstring>

namespace LibreSCRS::Darwin {
namespace {

std::optional<std::string> cfStringToStd(CFStringRef s)
{
    if (s == nullptr) {
        return std::nullopt;
    }
    if (const char* fast = CFStringGetCStringPtr(s, kCFStringEncodingUTF8)) {
        return std::string(fast);
    }
    const CFIndex len = CFStringGetLength(s);
    const CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string out(static_cast<std::size_t>(max), '\0');
    if (CFStringGetCString(s, out.data(), max, kCFStringEncodingUTF8) == false) {
        return std::nullopt;
    }
    out.resize(std::strlen(out.c_str()));
    return out;
}

} // namespace

PeerCodeSigning resolvePeerCodeSigning(const PeerCredentials& creds)
{
    PeerCodeSigning out;
    SecTaskRef task = SecTaskCreateWithAuditToken(nullptr, creds.auditToken);
    if (task == nullptr) {
        return out; // unidentifiable -> empty (callers fail closed)
    }

    CFErrorRef err = nullptr;
    if (CFStringRef sid = SecTaskCopySigningIdentifier(task, &err)) {
        out.signingId = cfStringToStd(sid);
        CFRelease(sid);
    }
    if (err != nullptr) {
        CFRelease(err);
        err = nullptr;
    }

    CFStringRef key = CFSTR("com.apple.security.application-groups");
    if (CFTypeRef value = SecTaskCopyValueForEntitlement(task, key, &err)) {
        if (CFGetTypeID(value) == CFArrayGetTypeID()) {
            auto array = static_cast<CFArrayRef>(value);
            const CFIndex n = CFArrayGetCount(array);
            for (CFIndex i = 0; i < n; ++i) {
                auto item = static_cast<CFStringRef>(CFArrayGetValueAtIndex(array, i));
                if (CFGetTypeID(item) == CFStringGetTypeID()) {
                    if (auto g = cfStringToStd(item)) {
                        out.appGroups.push_back(std::move(*g));
                    }
                }
            }
        }
        CFRelease(value);
    }
    if (err != nullptr) {
        CFRelease(err);
    }
    CFRelease(task);
    return out;
}

bool matchesExpectedPeer(const PeerCodeSigning& peer, const ExpectedPeerIdentity& expected)
{
    if (!peer.signingId || *peer.signingId != expected.signingId) {
        return false;
    }
    return std::find(peer.appGroups.begin(), peer.appGroups.end(), expected.appGroup) != peer.appGroups.end();
}

bool verifyConnectedPeer(int connectedFd, const ExpectedPeerIdentity& expected)
{
    const auto creds = capturePeerCredentials(connectedFd);
    if (!creds) {
        return false; // fail closed
    }
    return matchesExpectedPeer(resolvePeerCodeSigning(*creds), expected);
}

} // namespace LibreSCRS::Darwin
