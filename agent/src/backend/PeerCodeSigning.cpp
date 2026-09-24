// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Shared SecTask-based peer code-signing resolution: audit_token -> signing
// identifier + app-group entitlements, the designated-requirement check when a
// team id is configured, plus the expected-identity match both ends of the
// private prompter socket enforce.
#include <LibreSCRS/Darwin/backend/PeerCodeSigning.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCode.h>
#include <Security/SecRequirement.h>
#include <Security/SecTask.h>

#include <algorithm>
#include <cstring>
#include <string_view>

#ifndef LIBRESCRS_TEAM_ID
#error "the build must define LIBRESCRS_TEAM_ID (empty for no team id)"
#endif

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

bool isPlain(std::string_view text, std::string_view extra)
{
    return !text.empty() && std::all_of(text.begin(), text.end(), [extra](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               extra.find(c) != std::string_view::npos;
    });
}

// Holds a CoreFoundation reference and releases it once.
template <typename T>
struct CfRef
{
    T ref = nullptr;
    CfRef() = default;
    explicit CfRef(T r) : ref(r) {}
    CfRef(const CfRef&) = delete;
    CfRef& operator=(const CfRef&) = delete;
    ~CfRef()
    {
        if (ref != nullptr) {
            CFRelease(ref);
        }
    }
};

// SecCodeCheckValidity of `code` against the designated requirement for
// `signingId` signed by `teamId`. Anything that cannot be built or checked is a
// failure.
bool satisfiesDesignatedRequirement(SecCodeRef code, std::string_view teamId, std::string_view signingId)
{
    const auto text = designatedRequirementFor(teamId, signingId);
    if (!text) {
        return false;
    }
    CfRef<CFStringRef> cfText(CFStringCreateWithBytes(nullptr, reinterpret_cast<const UInt8*>(text->data()),
                                                      static_cast<CFIndex>(text->size()), kCFStringEncodingUTF8,
                                                      false));
    if (cfText.ref == nullptr) {
        return false;
    }
    CfRef<SecRequirementRef> requirement;
    if (SecRequirementCreateWithString(cfText.ref, kSecCSDefaultFlags, &requirement.ref) != errSecSuccess ||
        requirement.ref == nullptr) {
        return false;
    }
    return SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement.ref) == errSecSuccess;
}

// The peer's code, reached by its audit token (public API; the audit token
// carries the pid version, so a reused pid cannot stand in for the peer).
bool peerSatisfiesDesignatedRequirement(const audit_token_t& token, std::string_view teamId, std::string_view signingId)
{
    CfRef<CFDataRef> tokenData(CFDataCreate(nullptr, reinterpret_cast<const UInt8*>(&token), sizeof(token)));
    if (tokenData.ref == nullptr) {
        return false;
    }
    const void* keys[] = {kSecGuestAttributeAudit};
    const void* values[] = {tokenData.ref};
    CfRef<CFDictionaryRef> attributes(
        CFDictionaryCreate(nullptr, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    if (attributes.ref == nullptr) {
        return false;
    }
    CfRef<SecCodeRef> code;
    if (SecCodeCopyGuestWithAttributes(nullptr, attributes.ref, kSecCSDefaultFlags, &code.ref) != errSecSuccess ||
        code.ref == nullptr) {
        return false;
    }
    return satisfiesDesignatedRequirement(code.ref, teamId, signingId);
}

} // namespace

std::optional<std::string> configuredTeamId()
{
    constexpr std::string_view teamId = LIBRESCRS_TEAM_ID;
    if (teamId.empty()) {
        return std::nullopt;
    }
    return std::string(teamId);
}

std::optional<std::string> designatedRequirementFor(std::string_view teamId, std::string_view signingId)
{
    if (!isPlain(teamId, {}) || !isPlain(signingId, ".-_")) {
        return std::nullopt;
    }
    std::string text = "anchor apple generic and certificate leaf[subject.OU] = \"";
    text += teamId;
    text += "\" and identifier \"";
    text += signingId;
    text += '"';
    return text;
}

PeerCodeSigning resolvePeerCodeSigning(const PeerCredentials& creds, const std::optional<std::string>& teamId)
{
    PeerCodeSigning out;
    if (teamId) {
        out.designatedRequirementValid = false; // until it is evaluated and holds
    }
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

    if (teamId) {
        // The requirement names the identifier SecTask reported, so a pass
        // means that identifier is really the peer's and our team signed it;
        // the caller still compares the identifier with the one it expects.
        out.designatedRequirementValid =
            out.signingId && peerSatisfiesDesignatedRequirement(creds.auditToken, *teamId, *out.signingId);
    }
    return out;
}

bool matchesExpectedPeer(const PeerCodeSigning& peer, const ExpectedPeerIdentity& expected)
{
    if (!peer.signingId || *peer.signingId != expected.signingId) {
        return false;
    }
    if (expected.teamId && peer.designatedRequirementValid != true) {
        return false; // not evaluated counts as failed
    }
    return std::find(peer.appGroups.begin(), peer.appGroups.end(), expected.appGroup) != peer.appGroups.end();
}

bool verifyConnectedPeer(int connectedFd, const ExpectedPeerIdentity& expected)
{
    const auto creds = capturePeerCredentials(connectedFd);
    if (!creds) {
        return false; // fail closed
    }
    return matchesExpectedPeer(resolvePeerCodeSigning(*creds, expected.teamId), expected);
}

bool selfSatisfiesDesignatedRequirement(std::string_view teamId, std::string_view signingId)
{
    CfRef<SecCodeRef> self;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &self.ref) != errSecSuccess || self.ref == nullptr) {
        return false;
    }
    return satisfiesDesignatedRequirement(self.ref, teamId, signingId);
}

bool selfMatchesConfiguredTeam(std::string_view selfSigningId)
{
    const auto teamId = configuredTeamId();
    return !teamId || selfSatisfiesDesignatedRequirement(*teamId, selfSigningId);
}

} // namespace LibreSCRS::Darwin
