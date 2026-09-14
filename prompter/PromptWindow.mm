// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// AppKit credential surface: ONE non-modal floating panel per prompt, held in a
// registry keyed by the prompt id. Each panel carries its own entry budget as a
// visible M:SS countdown, answers Timeout when the budget runs out, and can be
// closed by the id it answers to (or swept together with every other panel).
//
// Nothing here runs a modal loop. The calling worker waits on its panel's
// semaphore while the main thread keeps running, so a second prompt stands
// beside the first instead of queueing behind it, and a dismissal arriving on
// another connection is served while both are up. No panel activates this
// process: a window that took the foreground would collect one card's secret
// into another card's field.
//
// The secrets are read out of the fields BEFORE the panel comes down
// (read-before-hide) and the fields are scrubbed on every outcome.
#include "PromptWindow.h"

#import <AppKit/AppKit.h>
#include <dispatch/dispatch.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

// Declared in PromptWindow.h and defined below, in LibreSCRS::Darwin. Named
// here at file scope because both halves of this file reach it: the C++
// helpers in the anonymous namespace and the panel's own Objective-C methods,
// which are at global scope and cannot see into a namespace.
using LibreSCRS::Darwin::localized;

namespace {

namespace wire = LibreSCRS::Darwin::wire;

NSString* nsstr(const std::string& s)
{
    return [NSString stringWithUTF8String:s.c_str()];
}

// What one panel carries across the thread boundary: the answer the main thread
// fills in before it signals, plus the change flow's OK-gate bounds (unused by
// the single-secret panel). Owned by the panel; the waiting worker reads it
// only AFTER the semaphore is signalled and MOVES the secrets out, so no copy
// stays behind in the panel.
struct PanelState
{
    // No prompt id here: the registry key IS the id, and every question asked
    // about a panel's address is asked of the registry. A second copy would be
    // a second answer to maintain.
    wire::PromptReplyStatus status{wire::PromptReplyStatus::Cancelled};
    std::vector<std::uint8_t> primary;   // the single secret / the CURRENT credential
    std::vector<std::uint8_t> secondary; // the NEW credential (change flow only)
    std::uint32_t primaryMinLength{0};
    std::uint32_t primaryMaxLength{0};
    std::uint32_t newMinLength{0};
    std::uint32_t newMaxLength{0};
};

// Recognised `lastError` msgKey (mirrors
// LibreSCRS::Auth::ErrorKeys::preReadAuthFailed().key on the agent's LM
// dependency; duplicated here as a documented literal, the same
// cross-binary vocabulary convention the Linux PromptDialog.cpp uses for its
// own copy of this same string — this file has no LM dependency to share the
// constant with). The only source of a retry `lastError` today is the
// eMRTD read flows' AuthFailed path (CredentialCache::markCredentialWrong).
constexpr const char* kErrorPreReadAuthFailed = "librescrs.error.preRead.authFailed";

// Retry-context inline error line (req.attempt > 0 -- a genuine re-prompt
// after the card rejected the value collected last time for this card): nil
// on the first-ever prompt for a card (attempt == 0). An unrecognised or
// empty lastError key still returns a generic retry line rather than
// leaking the raw wire key to the user, mirroring the Linux
// PromptDialog.cpp retryErrorText() helper. No attempts counter is ever
// rendered -- parity with the GUI's inline-error-without-a-counter bar.
NSString* retryErrorLine(std::uint32_t attempt, const std::string& lastError)
{
    if (attempt == 0) {
        return nil;
    }
    // The wire key IS a catalogue key, so it is looked up as one: an agent
    // error the host application already translates is shown in the holder's
    // own words. A key the catalogue does not carry resolves to the sentence
    // beside it and never to the key itself, which is what keeps the raw wire
    // vocabulary off the screen.
    if (lastError.empty()) {
        return localized("prompter_retry_generic", "The value you entered was not accepted. Please try again.");
    }
    if (lastError == kErrorPreReadAuthFailed) {
        return localized(kErrorPreReadAuthFailed, "The value you entered was not accepted. Please try again.");
    }
    return localized("prompter_retry_rejected", "Your previous entry was not accepted. Please try again.");
}

// Shared informative-text chrome (retry error / description / requester /
// artifact) — identical for the single-secret and change panels;
// `retryError` is nil for the change panel (RequestSecrets carries no
// retry context -- change_pin is never a CAN/MRZ retry) and shown FIRST,
// immediately above the rest of the informative text, mirroring the Linux
// PromptDialog placing its retry label above the input widget.
NSString* informativeText(const std::string& description, const std::string& requester, const std::string& artifact,
                          const std::vector<std::string>& artifacts, NSString* retryError)
{
    NSMutableString* info = [NSMutableString string];
    if (retryError.length) {
        [info appendString:retryError];
    }
    if (!description.empty()) {
        [info appendFormat:@"%@%@", info.length ? @"\n" : @"", nsstr(description)];
    }
    if (!requester.empty()) {
        [info appendFormat:@"%@%@ %@", info.length ? @"\n" : @"", localized("prompter_requested_by", "Requested by:"),
                           nsstr(requester)];
    }
    // A batch sign carries the UNTRUSTED per-document names in `artifacts`: list
    // them plainly BELOW the trusted requester line (the formatter neutralizes
    // and elides each name). A single-document request instead names its one
    // trusted artifact inline; for a batch, `artifact` is only the category
    // token ("signature-batch"), so it is not shown as a document.
    if (!artifacts.empty()) {
        const std::string block = wire::formatUntrustedArtifactList(artifacts, 8);
        if (!block.empty()) {
            [info appendFormat:@"%@%@", info.length ? @"\n" : @"", nsstr(block)];
        }
    } else if (!artifact.empty()) {
        [info appendFormat:@"%@%@ %@", info.length ? @"\n" : @"", localized("prompter_document", "Document:"),
                           nsstr(artifact)];
    }
    return info;
}

// The change panel's OK gate, pure so it is testable by inspection: current
// within the primary bounds AND new within the new bounds AND confirm equal
// to new. Lengths are UTF-8 byte counts — the unit that crosses the wire. A
// zero bound is "unset" on the wire (the request codec omits zero fields):
// min 0 imposes no lower limit and max 0 no upper limit, so unknown card
// policy degrades to "let the card decide" rather than a permanently
// disabled OK.
bool withinBounds(std::size_t len, std::uint32_t minLen, std::uint32_t maxLen)
{
    return len >= minLen && (maxLen == 0 || len <= maxLen);
}

bool changeInputsAcceptable(const PanelState& state, std::size_t currentLen, std::size_t newLen, bool confirmMatchesNew)
{
    return withinBounds(currentLen, state.primaryMinLength, state.primaryMaxLength) &&
           withinBounds(newLen, state.newMinLength, state.newMaxLength) && confirmMatchesNew;
}

std::size_t utf8Length(NSString* value)
{
    return static_cast<std::size_t>([value lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
}

// The bytes a secure field holds right now. The caller scrubs the field.
std::vector<std::uint8_t> readSecret(NSSecureTextField* field)
{
    const char* utf8 = field.stringValue.UTF8String;
    if (utf8 == nullptr) {
        return {};
    }
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(utf8);
    return std::vector<std::uint8_t>(bytes, bytes + std::strlen(utf8));
}

// Monotonic seconds: the countdown the holder is watching must not jump because
// the wall clock moved under it.
double monotonicSeconds()
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

// The remaining entry time as M:SS behind a stopwatch glyph — language-neutral
// by design and rendered exactly as the Linux dialog renders it. It is the one
// thing on the panel with no catalogue key: digits and a glyph read the same in
// every language, so there is nothing here to translate.
NSString* formatRemaining(double remaining)
{
    const long total = remaining > 0 ? static_cast<long>(remaining) : 0;
    return [NSString stringWithFormat:@"⏱ %ld:%02ld", total / 60, total % 60];
}

// The credential this prompt asks for, in the title bar (which names the window
// in the window list) and in the panel's own heading line.
NSString* windowTitleForKind(wire::PromptKind kind)
{
    switch (kind) {
    case wire::PromptKind::Can:
        return localized("prompter_title_can", "Card Access Number");
    case wire::PromptKind::Mrz:
        return localized("prompter_title_mrz", "Machine-Readable Zone");
    case wire::PromptKind::Pin:
        break;
    }
    return localized("prompter_title_pin", "PIN");
}

NSString* promptHeading(const wire::PromptRequest& req)
{
    if (!req.title.empty()) {
        return nsstr(req.title);
    }
    switch (req.kind) {
    case wire::PromptKind::Can:
        return localized("prompter_heading_can", "Enter your Card Access Number (CAN)");
    case wire::PromptKind::Mrz:
        return localized("prompter_heading_mrz", "Enter your Machine-Readable Zone (MRZ)");
    case wire::PromptKind::Pin:
        break;
    }
    return localized("prompter_heading_pin", "Enter your PIN");
}

} // namespace

// One non-modal credential panel: its floating window, its secure fields, its
// countdown and the semaphore the calling worker waits on. Every method is
// main-thread only, except `done` and `state`, which the worker reads after the
// semaphore is signalled — by which time the panel has stopped touching them.
//
// The view ivars are NOT owned: the window's content view holds them, and the
// window is released last, in dealloc. What this object does own is the window,
// the semaphore and the state.
@interface LibreSCRSPromptPanel : NSObject <NSWindowDelegate, NSTextFieldDelegate>
// Called once, on the main thread, when the panel has answered — with the panel
// itself, so the registry can drop it. It never captures the panel, so there is
// no ownership cycle to break.
@property(copy) void (^onFinished)(LibreSCRSPromptPanel*);
- (instancetype)initWithWindowTitle:(NSString*)windowTitle
                            heading:(NSString*)heading
                               info:(NSString*)info
                         changeFlow:(BOOL)isChangeFlow NS_DESIGNATED_INITIALIZER;
// There is no such thing as a panel without a window, a semaphore and a state:
// a bare init would hand out an object whose every accessor returns nothing.
- (instancetype)init NS_UNAVAILABLE;
- (void)showWithDeadlineMs:(std::uint32_t)deadlineMs cascadeStep:(NSInteger)cascadeStep soleStanding:(BOOL)soleStanding;
- (void)refreshOkGate;
- (void)finishWithStatus:(wire::PromptReplyStatus)status;
- (dispatch_semaphore_t)done;
- (PanelState*)state;
@end

@implementation LibreSCRSPromptPanel {
    NSPanel* panel;
    NSSecureTextField* primaryField;
    NSSecureTextField* newField;     // change flow only, nil otherwise
    NSSecureTextField* confirmField; // change flow only, nil otherwise
    NSTextField* countdownLabel;
    NSButton* okButton;
    NSTimer* deadlineTimer;  // held by the run loop while armed
    NSTimer* countdownTimer; // held by the run loop while armed
    double budgetSeconds;
    double shownAtSeconds;
    dispatch_semaphore_t doneSemaphore;
    PanelState* panelState;
    BOOL changeFlow;
    BOOL finished;
}

- (void)addWrappingLabel:(NSTextField*)label toStack:(NSStackView*)stack width:(CGFloat)width
{
    label.usesSingleLineMode = NO;
    label.maximumNumberOfLines = 0;
    label.lineBreakMode = NSLineBreakByWordWrapping;
    label.preferredMaxLayoutWidth = width;
    [stack addArrangedSubview:label];
    [[label.widthAnchor constraintEqualToConstant:width] setActive:YES];
}

- (NSSecureTextField*)addSecureRowWithCaption:(NSString*)caption toStack:(NSStackView*)stack width:(CGFloat)width
{
    if (caption.length != 0) {
        NSTextField* captionLabel = [NSTextField labelWithString:caption];
        captionLabel.font = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
        [stack addArrangedSubview:captionLabel];
    }
    NSSecureTextField* field = [[[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, width, 24)] autorelease];
    field.delegate = self;
    [stack addArrangedSubview:field];
    [[field.widthAnchor constraintEqualToConstant:width] setActive:YES];
    return field; // owned by the stack from here on
}

- (instancetype)initWithWindowTitle:(NSString*)windowTitle
                            heading:(NSString*)heading
                               info:(NSString*)info
                         changeFlow:(BOOL)isChangeFlow
{
    self = [super init];
    if (self == nil) {
        return nil;
    }
    panelState = new PanelState();
    doneSemaphore = dispatch_semaphore_create(0);
    changeFlow = isChangeFlow;

    const CGFloat contentWidth = 320;
    NSStackView* stack = [[[NSStackView alloc] initWithFrame:NSZeroRect] autorelease];
    stack.orientation = NSUserInterfaceLayoutOrientationVertical;
    stack.alignment = NSLayoutAttributeLeading;
    stack.spacing = 8;
    stack.edgeInsets = NSEdgeInsetsMake(18, 18, 18, 18);

    if (heading.length != 0) {
        NSTextField* headingLabel = [NSTextField labelWithString:heading];
        headingLabel.font = [NSFont boldSystemFontOfSize:[NSFont systemFontSize]];
        [self addWrappingLabel:headingLabel toStack:stack width:contentWidth];
    }
    if (info.length != 0) {
        NSTextField* infoLabel = [NSTextField labelWithString:info];
        infoLabel.font = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
        [self addWrappingLabel:infoLabel toStack:stack width:contentWidth];
    }

    if (changeFlow) {
        primaryField = [self addSecureRowWithCaption:localized("prompter_label_current_pin", "Current PIN")
                                             toStack:stack
                                               width:contentWidth];
        newField = [self addSecureRowWithCaption:localized("prompter_label_new_pin", "New PIN")
                                         toStack:stack
                                           width:contentWidth];
        confirmField = [self addSecureRowWithCaption:localized("prompter_label_confirm_pin", "Confirm new PIN")
                                             toStack:stack
                                               width:contentWidth];
        primaryField.nextKeyView = newField;
        newField.nextKeyView = confirmField;
        confirmField.nextKeyView = primaryField;
    } else {
        primaryField = [self addSecureRowWithCaption:nil toStack:stack width:contentWidth];
    }

    // Created up front and empty: the row is only filled (and the window only
    // re-fitted around it) when the request actually carries a budget.
    countdownLabel = [NSTextField labelWithString:@""];
    countdownLabel.font = [NSFont monospacedDigitSystemFontOfSize:[NSFont smallSystemFontSize]
                                                           weight:NSFontWeightRegular];
    countdownLabel.hidden = YES;
    [stack addArrangedSubview:countdownLabel];

    NSButton* cancelButton = [NSButton buttonWithTitle:localized("prompter_button_cancel", "Cancel")
                                                target:self
                                                action:@selector(cancelPressed:)];
    cancelButton.keyEquivalent = @"\033"; // Escape cancels, as the modal's did
    okButton = [NSButton buttonWithTitle:localized("prompter_button_ok", "OK")
                                  target:self
                                  action:@selector(okPressed:)];
    okButton.keyEquivalent = @"\r"; // the default button: Return in a field answers
    NSStackView* buttonRow = [[[NSStackView alloc] initWithFrame:NSZeroRect] autorelease];
    buttonRow.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    buttonRow.spacing = 8;
    [buttonRow addView:cancelButton inGravity:NSStackViewGravityTrailing];
    [buttonRow addView:okButton inGravity:NSStackViewGravityTrailing];
    [stack addArrangedSubview:buttonRow];
    [[buttonRow.widthAnchor constraintEqualToConstant:contentWidth] setActive:YES];

    const NSSize fitting = stack.fittingSize;
    panel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, fitting.width, fitting.height)
                                       styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable)
                                         backing:NSBackingStoreBuffered
                                           defer:NO];
    panel.title = windowTitle;
    // Above the person's own windows, because a credential prompt they cannot
    // see is a credential prompt that expires in silence.
    panel.level = NSFloatingWindowLevel;
    // A panel hides itself when its app deactivates unless told otherwise, and
    // this process is never the active one: without this the prompt would
    // vanish the moment the person clicked back into their own work.
    panel.hidesOnDeactivate = NO;
    panel.releasedWhenClosed = NO; // this object owns the window
    panel.delegate = self;
    panel.contentView = stack;
    [panel setContentSize:fitting];
    [panel setInitialFirstResponder:primaryField];
    return self;
}

- (void)dealloc
{
    // Reached only after the answer has been taken: by then the timers are
    // invalidated, the window is off screen and nothing is waiting.
    //
    // Every delegate slot pointing at this object is cleared first. They are all
    // unretained back-references, and the view hierarchy is torn down by the
    // window release below — after this object is already half gone.
    panel.delegate = nil;
    primaryField.delegate = nil;
    newField.delegate = nil;
    confirmField.delegate = nil;
    [panel release];
    delete panelState;
    if (doneSemaphore != nullptr) {
        dispatch_release(doneSemaphore);
    }
    self.onFinished = nil;
    [super dealloc];
}

- (dispatch_semaphore_t)done
{
    return doneSemaphore;
}

- (PanelState*)state
{
    return panelState;
}

- (void)renderRemaining
{
    countdownLabel.stringValue = formatRemaining(budgetSeconds - (monotonicSeconds() - shownAtSeconds));
}

- (void)showWithDeadlineMs:(std::uint32_t)deadlineMs cascadeStep:(NSInteger)cascadeStep soleStanding:(BOOL)soleStanding
{
    // The budget is a DURATION and it starts HERE, at the moment the window is
    // shown: what elapses is exactly what the holder sees counting down, and
    // the time the request spent in transit is not charged to them.
    shownAtSeconds = monotonicSeconds();
    if (deadlineMs != 0) { // 0 is "unset" and must never read as an instant expiry
        budgetSeconds = static_cast<double>(deadlineMs) / 1000.0;
        countdownLabel.hidden = NO;
        [self renderRemaining];
        [panel setContentSize:((NSView*)panel.contentView).fittingSize];
        deadlineTimer = [NSTimer timerWithTimeInterval:budgetSeconds
                                                target:self
                                              selector:@selector(deadlineFired:)
                                              userInfo:nil
                                               repeats:NO];
        countdownTimer = [NSTimer timerWithTimeInterval:1.0
                                                 target:self
                                               selector:@selector(countdownFired:)
                                               userInfo:nil
                                                repeats:YES];
        // Common modes, not the default mode alone: a menu or a window drag
        // puts the main run loop into event-tracking mode, where a default-mode
        // timer stops firing — the clock must not pause because someone opened
        // a menu.
        [[NSRunLoop mainRunLoop] addTimer:deadlineTimer forMode:NSRunLoopCommonModes];
        [[NSRunLoop mainRunLoop] addTimer:countdownTimer forMode:NSRunLoopCommonModes];
    }

    [panel center];
    if (cascadeStep > 0) {
        // Offset each further panel so two prompts are two visible windows
        // rather than one hiding the other; wrapped so a long-running helper
        // does not walk them off the screen.
        const CGFloat offset = 26 * static_cast<CGFloat>(cascadeStep % 6);
        const NSRect frame = panel.frame;
        [panel setFrameOrigin:NSMakePoint(frame.origin.x + offset, frame.origin.y - offset)];
    }
    // A new window never steals focus: it is ordered in, and this process never
    // activates itself. The first panel standing may take the app's key status
    // so the person can type the moment they turn to it; a later one must not
    // pull the caret out of the panel they are already answering — that is how
    // one card's secret ends up in another card's field.
    if (soleStanding && [NSApp keyWindow] == nil) {
        [panel makeKeyAndOrderFront:nil];
    } else {
        [panel orderFront:nil];
    }
}

- (void)refreshOkGate
{
    if (!changeFlow) {
        return;
    }
    // Per-role length gating: OK stays disabled until every field passes
    // (current within the primary bounds, new within the new bounds, confirm
    // equal to new). The equality check is the confirm entry's ONLY consumer —
    // its value never leaves the panel.
    okButton.enabled =
        changeInputsAcceptable(*panelState, utf8Length(primaryField.stringValue), utf8Length(newField.stringValue),
                               [confirmField.stringValue isEqualToString:newField.stringValue]);
}

- (void)finishWithStatus:(wire::PromptReplyStatus)status
{
    if (finished) {
        return; // idempotent: a dismissal can race the person's own answer
    }
    finished = YES;
    // The pool is what makes the residual claim below true: the autoreleased
    // NSString the plaintext passes through is drained HERE, when this block
    // ends, and not at some later turn of the run loop.
    @autoreleasepool {
        if (status == wire::PromptReplyStatus::Ok) {
            // Read-before-hide: pull the secrets out of the fields NOW, while
            // they are still up. Documented residual: the NSSecureTextField /
            // NSString internals (autoreleased, immutable) cannot be
            // deterministically zeroed from here; their lifetime is minimised
            // (this pool) and everything downstream — the reply, the CBOR tree,
            // the encoded frame — is zeroed after the send
            // (sendPromptReplyScrubbed).
            panelState->primary = readSecret(primaryField);
            if (changeFlow) {
                panelState->secondary = readSecret(newField);
            }
        }
        panelState->status = status;
        // Clear EVERY field on EVERY outcome. The confirm entry was never read
        // into the answer — validation was its only consumer — but its buffer
        // holds a copy of the new PIN, so its residual is cleared explicitly too.
        primaryField.stringValue = @"";
        newField.stringValue = @"";
        confirmField.stringValue = @"";
        [deadlineTimer invalidate];
        deadlineTimer = nil;
        [countdownTimer invalidate];
        countdownTimer = nil;
        [panel orderOut:nil];
        if (self.onFinished != nil) {
            self.onFinished(self);
            self.onFinished = nil; // the registry no longer holds this panel
        }
    }
    // LAST, after every main-thread mutation and after the pool has drained:
    // the waiting worker reads the answer the moment this returns, and must
    // never see a half-filled one.
    dispatch_semaphore_signal(doneSemaphore);
}

- (void)okPressed:(id)sender
{
    (void)sender;
    [self finishWithStatus:wire::PromptReplyStatus::Ok];
}

- (void)cancelPressed:(id)sender
{
    (void)sender;
    [self finishWithStatus:wire::PromptReplyStatus::Cancelled];
}

- (void)deadlineFired:(NSTimer*)timer
{
    (void)timer;
    // The clock took it, not the person: Timeout, never Cancelled.
    [self finishWithStatus:wire::PromptReplyStatus::Timeout];
}

- (void)countdownFired:(NSTimer*)timer
{
    (void)timer;
    [self renderRemaining];
}

- (void)controlTextDidChange:(NSNotification*)note
{
    (void)note;
    [self refreshOkGate];
}

- (BOOL)windowShouldClose:(NSWindow*)sender
{
    (void)sender;
    // The title bar's close button is the person declining. Answer it here and
    // order the window out from there; NO keeps AppKit from closing a window
    // this object still owns.
    [self finishWithStatus:wire::PromptReplyStatus::Cancelled];
    return NO;
}

@end

namespace LibreSCRS::Darwin {

// The whole of this repository's localisation: one lookup in the catalogue of
// the bundle the prompter is running out of. Inside LibreMac.app that bundle
// IS the host application (the helper sits in Contents/MacOS), so the words
// below come from the same Localizable.xcstrings the rest of the app reads,
// keyed by the ids the .ts pair carries. Outside a bundle -- a development or
// build-directory prompter -- nothing resolves and the English fallback shows,
// which is the text this file carried before there were keys.
NSString* localized(const char* key, const std::string& fallback)
{
    NSString* k = [NSString stringWithUTF8String:key];
    NSString* s = [[NSBundle mainBundle] localizedStringForKey:k value:nsstr(fallback) table:nil];
    return s.length ? s : nsstr(fallback);
}

namespace {

// The panels standing right now, keyed by the id their prompt was addressed
// with. A multimap, not a map: a caller that addresses nothing (the counterpart
// of the unaddressed dismissal) can have two panels standing under the same
// empty id, and refusing the second would refuse exactly the concurrency this
// registry exists for.
using PanelRegistry = std::multimap<std::string, LibreSCRSPromptPanel*>;

// Run @p block on the main thread and wait for it. Used by the calls that only
// TOUCH the registry (they never wait for a human), so running inline is the
// honest answer for a main-thread caller, where dispatch_sync would deadlock.
// The two calls that wait for an answer refuse the main thread outright rather
// than come through here.
void runOnMain(dispatch_block_t block)
{
    if ([NSThread isMainThread]) {
        block();
        return;
    }
    dispatch_sync(dispatch_get_main_queue(), block);
}

// Which panels a dismissal reaches.
enum class Sweep : std::uint8_t {
    // Everything standing (the reset verb).
    Everything,
    // The panel the id names, PLUS any panel raised without an id at all: both
    // sides have to know an address for one to be matched by it, so a panel
    // that carries none must not be strandable by a dismissal that does. That
    // matters most for the change panel, which this wire gives no deadline —
    // an unmatchable id would leave it standing with nothing left to close it.
    Addressed,
    // A dismissal that names nothing: the OLDEST unaddressed panel, and only
    // that one. A caller that knows no ids is cancelling the one prompt it
    // knows about, not every prompt on the screen.
    Unaddressed,
};

// Close the panels the dismissal selects and answer each waiting caller
// Cancelled; returns how many were closed. Main thread only.
//
// The targets are snapshotted first because finishing a panel removes it from
// the registry through its own completion — iterating and erasing at once would
// be walking a container while it is being edited.
std::uint32_t finishPanels(PanelRegistry& panels, Sweep sweep, const std::string& wanted)
{
    std::vector<LibreSCRSPromptPanel*> targets;
    // Registry order is age order among equal keys: a multimap keeps elements
    // with equivalent keys in insertion order, and the empty key sorts first —
    // so the first unaddressed panel this loop meets is the oldest one, which
    // is what Sweep::Unaddressed takes.
    for (const auto& [promptId, panel] : panels) {
        bool selected = false;
        switch (sweep) {
        case Sweep::Everything:
            selected = true;
            break;
        case Sweep::Addressed:
            selected = promptId.empty() || promptId == wanted;
            break;
        case Sweep::Unaddressed:
            selected = promptId.empty();
            break;
        }
        if (!selected) {
            continue;
        }
        targets.push_back(panel);
        if (sweep == Sweep::Unaddressed) {
            break; // the oldest one only
        }
    }
    for (LibreSCRSPromptPanel* panel : targets) {
        [panel finishWithStatus:wire::PromptReplyStatus::Cancelled];
    }
    return static_cast<std::uint32_t>(targets.size());
}

} // namespace

struct PromptWindow::Impl
{
    PanelRegistry panels; // main-thread only
    NSInteger cascade{0}; // main-thread only: where on screen the next panel lands
};

PromptWindow::PromptWindow() : m_impl(new Impl) {}

PromptWindow::~PromptWindow()
{
    // Close what is still standing BEFORE the registry goes: every live panel's
    // completion block holds this Impl, and a panel answered after the delete
    // would write through a dangling one. The sweep also releases the waiting
    // callers instead of leaving them blocked on a window nobody can answer.
    static_cast<void>(dismissAll());
    delete m_impl;
}

wire::PromptReply PromptWindow::showPrompt(const wire::PromptRequest& req)
{
    // This call waits until the panel is answered, and only the main run loop
    // can answer it: waiting on the main thread would stop the very thread that
    // has to signal, and the hang would be silent. Fail closed instead.
    if ([NSThread isMainThread]) {
        wire::PromptReply refusal;
        refusal.status = wire::PromptReplyStatus::Error;
        refusal.userMessage = "prompt requested on the main thread";
        return refusal;
    }
    Impl* impl = m_impl;
    __block LibreSCRSPromptPanel* panel = nil;
    // dispatch_sync, not the inline-on-main helper: the refusal above has
    // already established that this is not the main thread.
    dispatch_sync(dispatch_get_main_queue(), ^{
      @autoreleasepool {
          panel = [[LibreSCRSPromptPanel alloc]
              initWithWindowTitle:windowTitleForKind(req.kind)
                          heading:promptHeading(req)
                             info:informativeText(req.description, req.requester, req.artifact, req.artifacts,
                                                  retryErrorLine(req.attempt, req.lastError))
                       changeFlow:NO];
          const BOOL soleStanding = impl->panels.empty() ? YES : NO;
          // The registry entry goes in BEFORE the window appears, so a
          // dismissal that arrives in the same breath finds something to close.
          // The iterator stays valid until this very panel is erased through
          // it: a map node outlives every erase but its own.
          const PanelRegistry::iterator entry = impl->panels.emplace(req.promptId, panel);
          panel.onFinished = ^(LibreSCRSPromptPanel* answered) {
            (void)answered;
            impl->panels.erase(entry);
          };
          [panel showWithDeadlineMs:req.deadlineMs cascadeStep:impl->cascade++ soleStanding:soleStanding];
          // req.altDeadlineMs is the budget of an ALTERNATIVE entry form (the
          // MRZ a holder may switch to under a CAN prompt). This panel offers
          // no such switch — one request, one form — so there is no clock here
          // for it to re-base, and it is deliberately applied nowhere.
      }
    });

    // Waiting off the main thread, which keeps running the panel. The semaphore
    // is signalled only after the main thread has filled the answer in and let
    // the panel go, so what is read below cannot be half-written.
    dispatch_semaphore_wait(panel.done, DISPATCH_TIME_FOREVER);
    PanelState* state = panel.state;
    wire::PromptReply reply;
    reply.status = state->status;
    reply.secret = std::move(state->primary); // MOVED: no copy stays in the panel
    LibreSCRSPromptPanel* answered = panel;
    // AppKit objects are deallocated on the main thread, never on this worker.
    dispatch_async(dispatch_get_main_queue(), ^{
      [answered release];
    });
    return reply;
}

wire::MultiPromptReply PromptWindow::showChangePrompt(const wire::RequestSecrets& req)
{
    // Fail closed on a flow this window does not implement (`kind` is an open
    // discriminator at the wire layer): no UI, no secrets.
    if (req.kind != "change_pin") {
        wire::MultiPromptReply refusal;
        refusal.status = wire::PromptReplyStatus::Error;
        refusal.userMessage = "unsupported RequestSecrets kind";
        return refusal;
    }
    // Same refusal, same reason, as the single-secret path: a wait on the main
    // thread is a silent hang, never a prompt.
    if ([NSThread isMainThread]) {
        wire::MultiPromptReply refusal;
        refusal.status = wire::PromptReplyStatus::Error;
        refusal.userMessage = "prompt requested on the main thread";
        return refusal;
    }
    Impl* impl = m_impl;
    __block LibreSCRSPromptPanel* panel = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{
      @autoreleasepool {
          panel = [[LibreSCRSPromptPanel alloc]
              initWithWindowTitle:localized("prompter_title_change_pin", "Change PIN")
                          heading:req.title.empty() ? localized("prompter_heading_change_pin", "Change your PIN")
                                                    : nsstr(req.title)
                             // RequestSecrets carries no retry context (change_pin is never a
                             // CAN/MRZ retry) and no per-document artifacts list.
                             info:informativeText(req.description, req.requester, req.artifact, {}, nil)
                       changeFlow:YES];
          PanelState* state = panel.state;
          state->primaryMinLength = req.primaryMinLength;
          state->primaryMaxLength = req.primaryMaxLength;
          state->newMinLength = req.newMinLength;
          state->newMaxLength = req.newMaxLength;
          [panel refreshOkGate];
          const BOOL soleStanding = impl->panels.empty() ? YES : NO;
          const PanelRegistry::iterator entry = impl->panels.emplace(req.promptId, panel);
          panel.onFinished = ^(LibreSCRSPromptPanel* answered) {
            (void)answered;
            impl->panels.erase(entry);
          };
          // RequestSecrets carries no deadline on this wire, so the change
          // panel stands until it is answered or dismissed — a clock it was
          // never given must not be invented here.
          [panel showWithDeadlineMs:0 cascadeStep:impl->cascade++ soleStanding:soleStanding];
      }
    });

    dispatch_semaphore_wait(panel.done, DISPATCH_TIME_FOREVER);
    PanelState* state = panel.state;
    wire::MultiPromptReply reply;
    reply.status = state->status;
    reply.primary = std::move(state->primary);
    reply.secondary = std::move(state->secondary);
    LibreSCRSPromptPanel* answered = panel;
    dispatch_async(dispatch_get_main_queue(), ^{
      [answered release];
    });
    return reply;
}

void PromptWindow::dismiss(const std::string& promptId)
{
    Impl* impl = m_impl;
    const std::string wanted = promptId;
    // async, never sync: this runs inline on the server's serial queue, which
    // must not block. With no modal loop left anywhere, a main-queue block is
    // drained on the next turn of the run loop rather than after a modal ends.
    dispatch_async(dispatch_get_main_queue(), ^{
      @autoreleasepool {
          static_cast<void>(finishPanels(impl->panels, wanted.empty() ? Sweep::Unaddressed : Sweep::Addressed, wanted));
      }
    });
}

std::uint32_t PromptWindow::dismissAll()
{
    Impl* impl = m_impl;
    __block std::uint32_t closed = 0;
    // Synchronous, unlike dismiss: the caller answers with the COUNT, and a
    // count reported before the sweep would be a guess.
    runOnMain(^{
      @autoreleasepool {
          closed = finishPanels(impl->panels, Sweep::Everything, std::string());
      }
    });
    return closed;
}

std::vector<std::string> PromptWindow::liveIds() const
{
    Impl* impl = m_impl;
    __block std::vector<std::string> ids;
    runOnMain(^{
      for (const auto& [promptId, panel] : impl->panels) {
          static_cast<void>(panel);
          ids.push_back(promptId);
      }
    });
    return ids;
}

} // namespace LibreSCRS::Darwin
