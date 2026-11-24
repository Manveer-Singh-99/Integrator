//
//  touchbar_hud.swift
//  Integrator TouchBar HUD - Liquid Glass Controls & Telemetry Streamer
//
//  ========================================================================================
//  1. MODULE PURPOSE & ARCHITECTURAL SCOPE
//  ========================================================================================
//  This file provides the native macOS TouchBar (`NSTouchBar`) HUD controller for MacBook Pro
//  models, implementing tactile hardware-level monitoring, remote clipboard paste interception,
//  and interactive liquid-glass controls.
//
//  Key Subsystem Capabilities:
//  - Viscous Liquid Glass Pill Views (`GoopyLiquidGlassPillView`): Implements squishy, rubber-band
//    drag-stretch physics with Spring animations, Frosted HUD blur materials (`NSVisualEffectView`
//    with `.hudWindow`), and continuous corner curves.
//  - Live Telemetry Streamer: Displays real-time GPU metrics from the connected Windows 11 host
//    (GPU temperature °C, clock speed MHz, power consumption W, VRAM utilization %, display latency ms,
//    and frame rates).
//  - Remote File Paste Interceptor (`PasteboardShortcutInterceptor`): Installs a passive `CGEventTap`
//    listening for `Cmd+V`. When a remote file announcement is pending, it intercepts the shortcut,
//    updates the TouchBar with a haptic pulse, and triggers asynchronous zero-RAM streaming via
//    `trigger_rust_remote_paste()`.
//  - In-App Pasteboard Native File Helper: Implements `read_pasteboard_files_in_app` and
//    `write_pasteboard_files_in_app` using `\0`-delimited UTF-8 byte arrays directly on the main
//    AppKit thread, avoiding external helper process spawn latency.
//
//  ========================================================================================
//  2. ARCHITECTURAL LINKAGES & CALL FLOW
//  ========================================================================================
//  Upstream Callers:
//  - `src/clipboard/service.rs`: Invokes C-ABI functions:
//    - `notify_touchbar_remote_file`: Announces pending remote files on TouchBar.
//    - `update_touchbar_paste_progress`: Telemeters transfer % and MB/s stream velocity.
//    - `reset_touchbar_paste_progress`: Clears transfer indicators upon completion.
//  - `src/clipboard/file_helper.rs`: Calls `read_pasteboard_files_in_app` and `write_pasteboard_files_in_app`.
//
//  Downstream Callees:
//  - AppKit TouchBar Framework (`NSTouchBar`, `NSTouchBarItem`, `NSCustomTouchBarItem`).
//  - Quartz Core Graphics (`CGEventTapCreate`, `CGEventPost`).
//  - Rust FFI: Calls `trigger_rust_remote_paste()` to initiate asynchronous file streaming.
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - AppKit Main Thread: All TouchBar UI item creation and label updates execute on `DispatchQueue.main`.
//  - Shortcut Interceptor RunLoop: The `CGEventTap` executes on a dedicated Mach port `Thread`.
//  - Async Rust Handoff: Shortcut triggers dispatch to `DispatchQueue.global(qos: .userInitiated)`
//    before invoking `trigger_rust_remote_paste()`, ensuring the UI thread is never blocked.
//
//  ========================================================================================
//  4. SECURITY & SAFETY INVARIANTS
//  ========================================================================================
//  - Stale Paste Expiration: In-flight paste sessions automatically expire after 60 seconds if
//    the remote host fails to stream data, unblocking future paste shortcuts.
//  - Buffer Capacity Verification: `read_pasteboard_files_in_app` strictly verifies output buffer
//    capacities before copying NUL-delimited bytes, returning `-1` on overflow.
//

import AppKit
import Foundation
import IOKit

/// macOS Control Strip daemon bundle identifier probed to verify Touch Bar runtime presence.
private let controlStripBundleId = "com.apple.controlstrip"

/// macOS Finder bundle identifier scoped for intercepting remote file Cmd+V shortcuts.
private let finderBundleId = "com.apple.finder"

// MARK: - RPC Data Models
struct GpuTelemetryData: Codable {
    let gpu_name: String
    let temperature_c: UInt32
    let power_usage_watts: Float
    let gpu_utilization_percent: UInt32
    let memory_utilization_percent: UInt32
    let memory_used_mb: UInt64
    let memory_total_mb: UInt64
    let core_clock_mhz: UInt32
}

struct DisplayRpcResponseData: Codable {
    let success: Bool
    let message: String
    let is_active: Bool
    let active_mode: String?
    let gpu_telemetry: GpuTelemetryData?
}

struct MediaPlaybackStateData: Codable {
    let title: String
    let artist: String
    let app_name: String
    let is_playing: Bool
    let position_secs: Double
    let duration_secs: Double
    let has_session: Bool
}

struct TouchBarLiveSnapshotData: Codable {
    let gpu_telemetry: GpuTelemetryData?
    let media_state: MediaPlaybackStateData?
    let camera_active: Bool
    let camera_muted: Bool
    let kvm_locked: Bool
    let audio_balance: Float
    let audio_muted: Bool
    let display_active: Bool
    let display_width: UInt32
    let display_height: UInt32
    let display_fps: UInt32
    let display_hdr: Bool
}

// MARK: - Feature 1: Visual Touch ID Passkey & UAC Animated Sensor Pointer View
/// Illuminated animated Touch Bar strip pinned to the far-right corner pointing directly
/// toward the MacBook Pro physical Touch ID sensor (`[ 🛡️ Approve ... ] ───────> 👆 [Touch ID]`).
final class TouchIdPromptGlowView: NSView {
    private let bgEffect = NSVisualEffectView()
    private let sweepLayer = CAGradientLayer()
    private let label = NSTextField(labelWithString: "")
    private let arrowLabel = NSTextField(labelWithString: "───────▶  👆 Touch ID")
    private let pulseRing = CALayer()
    private let stripWidth: CGFloat = 460

    override init(frame frameRect: NSRect) {
        super.init(frame: NSRect(x: 0, y: 0, width: 460, height: 30))
        setup()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setup()
    }

    override var intrinsicContentSize: NSSize {
        return NSSize(width: stripWidth, height: 30)
    }

    private func setup() {
        wantsLayer = true
        layer?.cornerRadius = 9
        layer?.masksToBounds = true

        bgEffect.frame = bounds
        bgEffect.autoresizingMask = [.width, .height]
        bgEffect.material = .hudWindow
        bgEffect.blendingMode = .withinWindow
        bgEffect.state = .active
        bgEffect.wantsLayer = true
        bgEffect.layer?.cornerRadius = 9
        bgEffect.layer?.borderWidth = 1.0
        bgEffect.layer?.borderColor = NSColor.systemTeal.withAlphaComponent(0.75).cgColor
        bgEffect.layer?.backgroundColor = NSColor(red: 0.04, green: 0.24, blue: 0.22, alpha: 0.65).cgColor
        addSubview(bgEffect)

        // Sweeping emerald/cyan light pulse pointing left -> right directly toward the Touch ID sensor
        sweepLayer.frame = bounds
        sweepLayer.startPoint = CGPoint(x: 0.0, y: 0.5)
        sweepLayer.endPoint = CGPoint(x: 1.0, y: 0.5)
        sweepLayer.colors = [
            NSColor.clear.cgColor,
            NSColor.systemTeal.withAlphaComponent(0.45).cgColor,
            NSColor.systemGreen.withAlphaComponent(0.65).cgColor,
            NSColor.clear.cgColor
        ]
        sweepLayer.locations = [-0.4, -0.2, 0.0, 0.2]
        bgEffect.layer?.addSublayer(sweepLayer)

        // Glowing circular beacon at the far-right edge beside the physical Touch ID sensor
        pulseRing.frame = CGRect(x: stripWidth - 26, y: 5, width: 20, height: 20)
        pulseRing.cornerRadius = 10
        pulseRing.backgroundColor = NSColor.systemGreen.withAlphaComponent(0.45).cgColor
        pulseRing.borderWidth = 1.5
        pulseRing.borderColor = NSColor.systemGreen.cgColor
        bgEffect.layer?.addSublayer(pulseRing)

        label.translatesAutoresizingMaskIntoConstraints = false
        label.font = NSFont.systemFont(ofSize: 12, weight: .bold)
        label.textColor = .white
        label.backgroundColor = .clear
        label.isBezeled = false
        label.isEditable = false
        label.isSelectable = false
        label.lineBreakMode = .byTruncatingTail
        label.stringValue = "🛡️ Approve Windows Hello Login"
        addSubview(label)

        arrowLabel.translatesAutoresizingMaskIntoConstraints = false
        arrowLabel.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .heavy)
        arrowLabel.textColor = NSColor(red: 0.45, green: 1.0, blue: 0.72, alpha: 1.0)
        arrowLabel.backgroundColor = .clear
        arrowLabel.isBezeled = false
        arrowLabel.isEditable = false
        arrowLabel.isSelectable = false
        addSubview(arrowLabel)

        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 12),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
            arrowLabel.leadingAnchor.constraint(greaterThanOrEqualTo: label.trailingAnchor, constant: 10),
            arrowLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -32),
            arrowLabel.centerYAnchor.constraint(equalTo: centerYAnchor)
        ])

        startPulseAnimations()
    }

    func updateLabel(_ text: String) {
        let clean = text.trimmingCharacters(in: .whitespacesAndNewlines)
        label.stringValue = clean.isEmpty ? "🛡️ Approve Windows Hello Login" : "🛡️ \(clean)"
        startPulseAnimations()
    }

    func startPulseAnimations() {
        sweepLayer.removeAllAnimations()
        let sweep = CABasicAnimation(keyPath: "locations")
        sweep.fromValue = [-0.4, -0.2, 0.0, 0.2]
        sweep.toValue = [0.8, 1.0, 1.2, 1.4]
        sweep.duration = 1.15
        sweep.repeatCount = .infinity
        sweep.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        sweepLayer.add(sweep, forKey: "touchIdSweep")

        pulseRing.removeAllAnimations()
        let glow = CABasicAnimation(keyPath: "transform.scale")
        glow.fromValue = 0.78
        glow.toValue = 1.22
        glow.duration = 0.65
        glow.autoreverses = true
        glow.repeatCount = .infinity
        glow.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        pulseRing.add(glow, forKey: "touchIdBeacon")
    }
}

// MARK: - Liquid Glass Pill View (Crisp, Critically-Damped Tactile Physics)
class GoopyLiquidGlassPillView: NSView {
    let visualEffectView = NSVisualEffectView()
    let label = NSTextField(labelWithString: "")
    var accentColor: NSColor = .systemGreen {
        didSet { updateRestingStyle() }
    }
    var onTap: (() -> Void)?

    private var initialTouchPoint: CGPoint = .zero
    private var activeTouchIdentity: AnyObject? = nil
    private var isHeld: Bool = false
    private var isTouchInside: Bool = false
    private let pillWidth: CGFloat

    init(text: String, accent: NSColor, width: CGFloat = 88) {
        self.pillWidth = width
        self.accentColor = accent
        super.init(frame: NSRect(x: 0, y: 0, width: width, height: 30))
        setup(text: text)
    }

    required init?(coder: NSCoder) {
        self.pillWidth = 88
        super.init(coder: coder)
    }

    override var intrinsicContentSize: NSSize {
        return NSSize(width: pillWidth, height: 30)
    }

    func setup(text: String) {
        wantsLayer = true
        layer?.masksToBounds = false
        allowedTouchTypes = [.direct]
        wantsRestingTouches = false

        // 1. Frosted Glass Blur Backdrop
        visualEffectView.frame = bounds
        visualEffectView.autoresizingMask = [.width, .height]
        visualEffectView.material = .hudWindow
        visualEffectView.blendingMode = .withinWindow
        visualEffectView.state = .active
        visualEffectView.wantsLayer = true
        visualEffectView.layer?.cornerRadius = 9
        visualEffectView.layer?.masksToBounds = true
        addSubview(visualEffectView)

        // 2. High-Legibility Monospace Centered Typography via AutoLayout
        label.translatesAutoresizingMaskIntoConstraints = false
        label.alignment = .center
        label.font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .bold)
        label.textColor = .white
        label.backgroundColor = .clear
        label.isBezeled = false
        label.isEditable = false
        label.isSelectable = false
        label.maximumNumberOfLines = 1
        label.lineBreakMode = .byTruncatingTail
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        label.stringValue = text
        addSubview(label)

        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: centerXAnchor),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
            label.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: 6),
            label.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -6)
        ])

        updateRestingStyle()
    }

    func setText(_ newText: String) {
        DispatchQueue.main.async { [weak self] in
            self?.label.stringValue = newText
        }
    }

    func setAccent(_ color: NSColor) {
        DispatchQueue.main.async { [weak self] in
            self?.accentColor = color
        }
    }

    func updateRestingStyle() {
        guard !isHeld else { return }
        layer?.shadowColor = accentColor.cgColor
        layer?.shadowOffset = .zero
        layer?.shadowRadius = 4.0
        layer?.shadowOpacity = 0.0

        visualEffectView.layer?.borderWidth = 0.5
        visualEffectView.layer?.borderColor = NSColor(white: 1.0, alpha: 0.20).cgColor
        visualEffectView.layer?.backgroundColor = accentColor.withAlphaComponent(0.14).cgColor
    }

    private func centeredTransform(sx: CGFloat, sy: CGFloat, tx: CGFloat = 0) -> CATransform3D {
        let cx = bounds.midX
        let cy = bounds.midY
        var t = CATransform3DIdentity
        t = CATransform3DTranslate(t, cx + tx, cy, 0)
        t = CATransform3DScale(t, sx, sy, 1.0)
        t = CATransform3DTranslate(t, -cx, -cy, 0)
        return t
    }

    private func isPointWithinTapSlop(_ pt: CGPoint) -> Bool {
        return bounds.insetBy(dx: -18, dy: -20).contains(pt)
    }

    // MARK: - Direct Touch & Mouse Interaction
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { return true }
    override var acceptsFirstResponder: Bool { return true }

    override func touchesBegan(with event: NSEvent) {
        guard activeTouchIdentity == nil,
              let touch = event.touches(matching: .began, in: self).first else { return }
        activeTouchIdentity = touch.identity as AnyObject
        beginInteraction(at: touch.location(in: self))
    }

    override func touchesMoved(with event: NSEvent) {
        guard isHeld, let id = activeTouchIdentity else { return }
        let touches = event.touches(matching: .moved, in: self)
        guard let touch = touches.first(where: { ($0.identity as AnyObject).isEqual(id) }) ?? touches.first else {
            return
        }
        updateInteraction(at: touch.location(in: self))
    }

    override func touchesEnded(with event: NSEvent) {
        guard isHeld else { return }
        let ended = event.touches(matching: .ended, in: self)
        let matching: NSTouch?
        if let id = activeTouchIdentity {
            matching = ended.first(where: { ($0.identity as AnyObject).isEqual(id) }) ?? ended.first
        } else {
            matching = ended.first
        }
        guard let touch = matching else {
            if event.touches(matching: .touching, in: self).isEmpty {
                activeTouchIdentity = nil
                endInteraction(triggerTap: isTouchInside)
            }
            return
        }
        activeTouchIdentity = nil
        let inside = isPointWithinTapSlop(touch.location(in: self))
        endInteraction(triggerTap: inside)
    }

    override func touchesCancelled(with event: NSEvent) {
        activeTouchIdentity = nil
        endInteraction(triggerTap: false)
    }

    override func mouseDown(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        beginInteraction(at: pt)
    }

    override func mouseDragged(with event: NSEvent) {
        guard isHeld else { return }
        let pt = convert(event.locationInWindow, from: nil)
        updateInteraction(at: pt)
    }

    override func mouseUp(with event: NSEvent) {
        let pt = convert(event.locationInWindow, from: nil)
        endInteraction(triggerTap: isPointWithinTapSlop(pt))
    }

    // MARK: - Subtle Critically-Damped Liquid Glass Tactile Feedback
    private func beginInteraction(at point: CGPoint) {
        guard !isHeld else { return }
        isHeld = true
        isTouchInside = true
        initialTouchPoint = point

        NSHapticFeedbackManager.defaultPerformer.perform(.generic, performanceTime: .default)
        layer?.removeAnimation(forKey: "liquidSettle")

        let pressed = centeredTransform(sx: 0.96, sy: 0.94)
        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.08
            ctx.timingFunction = CAMediaTimingFunction(name: .easeOut)
            self.layer?.shadowColor = self.accentColor.cgColor
            self.layer?.shadowRadius = 8.0
            self.layer?.shadowOpacity = 0.38
            self.layer?.transform = pressed
            self.visualEffectView.layer?.backgroundColor = self.accentColor.withAlphaComponent(0.30).cgColor
            self.visualEffectView.layer?.borderWidth = 0.8
            self.visualEffectView.layer?.borderColor = self.accentColor.withAlphaComponent(0.55).cgColor
        }
    }

    private func updateInteraction(at currentPoint: CGPoint) {
        let inside = isPointWithinTapSlop(currentPoint)
        isTouchInside = inside
        if inside {
            // Subtle tactile micro-give strictly clamped to ±1.5pt (no wild stretching or rotation)
            let dx = max(-1.5, min(1.5, (currentPoint.x - initialTouchPoint.x) * 0.06))
            CATransaction.begin()
            CATransaction.setDisableActions(true)
            self.layer?.transform = centeredTransform(sx: 0.96, sy: 0.94, tx: dx)
            self.visualEffectView.layer?.backgroundColor = self.accentColor.withAlphaComponent(0.30).cgColor
            self.visualEffectView.layer?.borderColor = self.accentColor.withAlphaComponent(0.55).cgColor
            CATransaction.commit()
        } else {
            NSAnimationContext.runAnimationGroup { ctx in
                ctx.duration = 0.12
                ctx.timingFunction = CAMediaTimingFunction(name: .easeOut)
                self.layer?.transform = CATransform3DIdentity
                self.layer?.shadowOpacity = 0.0
                self.visualEffectView.layer?.backgroundColor = self.accentColor.withAlphaComponent(0.14).cgColor
                self.visualEffectView.layer?.borderWidth = 0.5
                self.visualEffectView.layer?.borderColor = NSColor(white: 1.0, alpha: 0.20).cgColor
            }
        }
    }

    private func endInteraction(triggerTap: Bool) {
        guard isHeld else { return }
        isHeld = false
        isTouchInside = false

        let currentT = self.layer?.presentation()?.transform ?? self.layer?.transform ?? CATransform3DIdentity
        // Critically-damped settle (zeta = 1.00): smooth, crisp, zero overshoot or jiggle
        let settle = CASpringAnimation(keyPath: "transform")
        settle.mass = 1.0
        settle.stiffness = 420.0
        settle.damping = 41.0
        settle.initialVelocity = 0.0
        settle.fromValue = NSValue(caTransform3D: currentT)
        settle.toValue = NSValue(caTransform3D: CATransform3DIdentity)
        settle.duration = settle.settlingDuration

        self.layer?.transform = CATransform3DIdentity
        self.layer?.add(settle, forKey: "liquidSettle")

        NSAnimationContext.runAnimationGroup { ctx in
            ctx.duration = 0.16
            ctx.timingFunction = CAMediaTimingFunction(name: .easeOut)
            self.layer?.shadowOpacity = 0.0
            self.layer?.shadowRadius = 4.0
            self.visualEffectView.layer?.backgroundColor = self.accentColor.withAlphaComponent(0.14).cgColor
            self.visualEffectView.layer?.borderWidth = 0.5
            self.visualEffectView.layer?.borderColor = NSColor(white: 1.0, alpha: 0.20).cgColor
        }

        if triggerTap {
            NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)
            onTap?()
        }
    }
}

// MARK: - Rounded Liquid Glass Media Scrubber Pill
/// Fully rounded Liquid Glass pill containing a capsule progress bar, glowing circular thumb,
/// and elapsed/total timestamps with zero-snap-back touch scrubbing.
final class LiquidGlassMediaScrubPillView: NSView {
    private let bgEffect = NSVisualEffectView()
    private let elapsedLabel = NSTextField(labelWithString: "0:00")
    private let totalLabel = NSTextField(labelWithString: "0:00")
    private let trackContainer = NSView()
    private let trackBg = CALayer()
    private let trackFill = CALayer()
    private let thumbLayer = CALayer()

    private let pillWidth: CGFloat
    private let trackHeight: CGFloat = 6.0

    private var activeTouchIdentity: AnyObject? = nil
    private var isScrubbing: Bool = false
    private var scrubHoldUntil: Date = .distantPast
    private var lastPreviewSentAt: Date = .distantPast

    private var positionSecs: Double = 0.0
    private var durationSecs: Double = 0.0
    private var isPlaying: Bool = false
    private var hasSession: Bool = false

    var onPreviewSeek: ((Double) -> Void)?
    var onCommitSeek: ((Double) -> Void)?

    init(width: CGFloat = 176) {
        self.pillWidth = width
        super.init(frame: NSRect(x: 0, y: 0, width: width, height: 30))
        setup()
    }

    required init?(coder: NSCoder) {
        self.pillWidth = 176
        super.init(coder: coder)
        setup()
    }

    override var intrinsicContentSize: NSSize {
        return NSSize(width: pillWidth, height: 30)
    }

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { return true }
    override var acceptsFirstResponder: Bool { return true }

    private static func formatTime(_ secs: Double) -> String {
        guard secs.isFinite && secs >= 0 else { return "0:00" }
        let total = Int(secs.rounded(.down))
        let mins = total / 60
        let rem = total % 60
        return String(format: "%d:%02d", mins, rem)
    }

    private func configureTimeLabel(_ lbl: NSTextField, alignment: NSTextAlignment, alpha: CGFloat) {
        lbl.alignment = alignment
        lbl.font = NSFont.monospacedDigitSystemFont(ofSize: 9.5, weight: .semibold)
        lbl.textColor = NSColor(white: 1.0, alpha: alpha)
        lbl.backgroundColor = .clear
        lbl.isBezeled = false
        lbl.isEditable = false
        lbl.isSelectable = false
        lbl.maximumNumberOfLines = 1
    }

    private func setup() {
        wantsLayer = true
        layer?.cornerRadius = 9
        layer?.masksToBounds = true
        allowedTouchTypes = [.direct]
        wantsRestingTouches = false

        bgEffect.frame = bounds
        bgEffect.autoresizingMask = [.width, .height]
        bgEffect.material = .hudWindow
        bgEffect.blendingMode = .withinWindow
        bgEffect.state = .active
        bgEffect.wantsLayer = true
        bgEffect.layer?.cornerRadius = 9
        bgEffect.layer?.masksToBounds = true
        bgEffect.layer?.borderWidth = 0.5
        bgEffect.layer?.borderColor = NSColor(white: 1.0, alpha: 0.20).cgColor
        bgEffect.layer?.backgroundColor = NSColor.systemPink.withAlphaComponent(0.12).cgColor
        addSubview(bgEffect)

        configureTimeLabel(elapsedLabel, alignment: .right, alpha: 0.82)
        configureTimeLabel(totalLabel, alignment: .left, alpha: 0.55)
        addSubview(elapsedLabel)
        addSubview(totalLabel)

        trackContainer.wantsLayer = true
        trackContainer.layer?.masksToBounds = false
        addSubview(trackContainer)

        trackBg.cornerRadius = trackHeight / 2.0
        trackBg.masksToBounds = true
        trackBg.backgroundColor = NSColor(white: 1.0, alpha: 0.22).cgColor
        trackContainer.layer?.addSublayer(trackBg)

        trackFill.cornerRadius = trackHeight / 2.0
        trackFill.masksToBounds = true
        trackFill.backgroundColor = NSColor.systemPink.cgColor
        trackContainer.layer?.addSublayer(trackFill)

        thumbLayer.cornerRadius = 6.0
        thumbLayer.backgroundColor = NSColor.white.cgColor
        thumbLayer.shadowColor = NSColor.black.cgColor
        thumbLayer.shadowOffset = .zero
        thumbLayer.shadowRadius = 3.0
        thumbLayer.shadowOpacity = 0.45
        trackContainer.layer?.addSublayer(thumbLayer)

        layoutSublayersAndFrames(animated: false)
    }

    override func layout() {
        super.layout()
        layoutSublayersAndFrames(animated: false)
    }

    func update(position: Double, duration: Double, isPlaying: Bool, hasSession: Bool) {
        self.durationSecs = duration.isFinite ? max(duration, 0.0) : 0.0
        self.isPlaying = isPlaying
        self.hasSession = hasSession
        self.totalLabel.stringValue = hasSession && self.durationSecs > 0.5 ? Self.formatTime(self.durationSecs) : "--:--"

        if !self.isScrubbing {
            let now = Date()
            if now < self.scrubHoldUntil {
                // Keep showing the user's scrubbed position until Windows confirms the seek
                if abs(position - self.positionSecs) <= 3.0 {
                    self.scrubHoldUntil = .distantPast
                    self.positionSecs = min(max(position, 0.0), max(self.durationSecs, 0.0))
                }
            } else {
                self.positionSecs = hasSession ? min(max(position, 0.0), max(self.durationSecs, 0.0)) : 0.0
            }
        }

        layoutSublayersAndFrames(animated: false)
    }

    private func layoutSublayersAndFrames(animated: Bool) {
        let w = bounds.width
        let h = bounds.height
        let sidePad: CGFloat = 6.0
        let lblW: CGFloat = 30.0
        let gap: CGFloat = 5.0

        elapsedLabel.frame = NSRect(x: sidePad, y: (h - 12.0) / 2.0, width: lblW, height: 12.0)
        totalLabel.frame = NSRect(x: w - sidePad - lblW, y: (h - 12.0) / 2.0, width: lblW, height: 12.0)

        let trackX = sidePad + lblW + gap
        let trackW = max(w - 2.0 * (sidePad + lblW + gap), 16.0)
        trackContainer.frame = NSRect(x: trackX, y: 0, width: trackW, height: h)

        let frac: CGFloat
        if hasSession && durationSecs > 0.5 {
            frac = CGFloat(min(max(positionSecs / durationSecs, 0.0), 1.0))
        } else {
            frac = 0.0
        }

        let thumbDia: CGFloat = isScrubbing ? 14.0 : 11.0
        let trackY = (h - trackHeight) / 2.0
        let usableTravel = max(trackW - thumbDia, 0.0)
        let thumbCenterX = (thumbDia / 2.0) + frac * usableTravel
        let fillW = hasSession && durationSecs > 0.5 ? max(thumbCenterX, trackHeight) : 0.0

        elapsedLabel.stringValue = hasSession && durationSecs > 0.5 ? Self.formatTime(positionSecs) : "--:--"

        CATransaction.begin()
        CATransaction.setDisableActions(!animated)
        trackBg.frame = CGRect(x: 0, y: trackY, width: trackW, height: trackHeight)
        trackBg.cornerRadius = trackHeight / 2.0
        trackFill.frame = CGRect(x: 0, y: trackY, width: min(fillW, trackW), height: trackHeight)
        trackFill.cornerRadius = trackHeight / 2.0
        trackFill.backgroundColor = (isPlaying || isScrubbing)
            ? NSColor.systemPink.cgColor
            : NSColor(white: 1.0, alpha: 0.55).cgColor

        thumbLayer.isHidden = !(hasSession && durationSecs > 0.5)
        thumbLayer.frame = CGRect(
            x: thumbCenterX - thumbDia / 2.0,
            y: (h - thumbDia) / 2.0,
            width: thumbDia,
            height: thumbDia
        )
        thumbLayer.cornerRadius = thumbDia / 2.0

        bgEffect.layer?.backgroundColor = (isPlaying || isScrubbing)
            ? NSColor.systemPink.withAlphaComponent(isScrubbing ? 0.24 : 0.13).cgColor
            : NSColor.systemGray.withAlphaComponent(0.14).cgColor
        bgEffect.layer?.borderWidth = isScrubbing ? 0.8 : 0.5
        bgEffect.layer?.borderColor = isScrubbing
            ? NSColor.systemPink.withAlphaComponent(0.60).cgColor
            : NSColor(white: 1.0, alpha: 0.20).cgColor
        CATransaction.commit()
    }

    private func positionForPoint(_ pt: CGPoint) -> Double {
        let trackMinX = trackContainer.frame.minX
        let trackW = max(trackContainer.frame.width, 1.0)
        let frac = min(max(Double((pt.x - trackMinX) / trackW), 0.0), 1.0)
        return frac * max(durationSecs, 0.0)
    }

    private func beginScrub(at pt: CGPoint) {
        guard hasSession && durationSecs > 0.5 else { return }
        isScrubbing = true
        positionSecs = positionForPoint(pt)
        NSHapticFeedbackManager.defaultPerformer.perform(.generic, performanceTime: .default)
        layoutSublayersAndFrames(animated: false)
    }

    private func moveScrub(to pt: CGPoint) {
        guard isScrubbing && hasSession && durationSecs > 0.5 else { return }
        positionSecs = positionForPoint(pt)
        layoutSublayersAndFrames(animated: false)
        let now = Date()
        if now.timeIntervalSince(lastPreviewSentAt) >= 0.35 {
            lastPreviewSentAt = now
            onPreviewSeek?(positionSecs)
        }
    }

    private func endScrub(at pt: CGPoint?, commit: Bool) {
        guard isScrubbing else { return }
        if let p = pt, hasSession && durationSecs > 0.5 {
            positionSecs = positionForPoint(p)
        }
        isScrubbing = false
        if commit && hasSession && durationSecs > 0.5 {
            scrubHoldUntil = Date().addingTimeInterval(2.4)
            NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)
            onCommitSeek?(positionSecs)
        }
        layoutSublayersAndFrames(animated: false)
    }

    override func touchesBegan(with event: NSEvent) {
        guard activeTouchIdentity == nil,
              let touch = event.touches(matching: .began, in: self).first else { return }
        activeTouchIdentity = touch.identity as AnyObject
        beginScrub(at: touch.location(in: self))
    }

    override func touchesMoved(with event: NSEvent) {
        guard isScrubbing, let id = activeTouchIdentity else { return }
        let touches = event.touches(matching: .moved, in: self)
        guard let touch = touches.first(where: { ($0.identity as AnyObject).isEqual(id) }) ?? touches.first else {
            return
        }
        moveScrub(to: touch.location(in: self))
    }

    override func touchesEnded(with event: NSEvent) {
        guard isScrubbing else { return }
        let ended = event.touches(matching: .ended, in: self)
        let matching: NSTouch?
        if let id = activeTouchIdentity {
            matching = ended.first(where: { ($0.identity as AnyObject).isEqual(id) }) ?? ended.first
        } else {
            matching = ended.first
        }
        activeTouchIdentity = nil
        endScrub(at: matching?.location(in: self), commit: true)
    }

    override func touchesCancelled(with event: NSEvent) {
        activeTouchIdentity = nil
        endScrub(at: nil, commit: false)
    }

    override func mouseDown(with event: NSEvent) {
        beginScrub(at: convert(event.locationInWindow, from: nil))
    }

    override func mouseDragged(with event: NSEvent) {
        moveScrub(to: convert(event.locationInWindow, from: nil))
    }

    override func mouseUp(with event: NSEvent) {
        endScrub(at: convert(event.locationInWindow, from: nil), commit: true)
    }
}

// MARK: - Touch Bar Controller (Singleton within Main App)
@objc public class TouchBarHudController: NSObject, NSTouchBarDelegate {
    public static let shared = TouchBarHudController()

    /// Fallback control RPC port used only if Rust has not yet pushed `config::CONTROL_PORT`.
    private static let defaultControlPort: UInt16 = 58281
    private var _rpcPort: UInt16 = TouchBarHudController.defaultControlPort
    /// Active Integrator control RPC port configured dynamically from Rust `config::CONTROL_PORT`.
    public var rpcPort: UInt16 {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return _rpcPort
        }
        set {
            stateLock.lock()
            _rpcPort = newValue > 0 ? newValue : Self.defaultControlPort
            stateLock.unlock()
        }
    }
    private let stateLock = NSLock()

    private var _isActive: Bool = false
    public var isActive: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _isActive
    }

    private var _peerIp: String? = nil
    var peerIp: String? {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }
            return _peerIp
        }
        set {
            stateLock.lock()
            _peerIp = Self.normalizedIp(newValue)
            stateLock.unlock()
        }
    }

    private enum TouchBarPanelMode {
        case main
        case media
        case display
        case audio
        case gpu
    }

    private static let dfrHandle: UnsafeMutableRawPointer? = {
        dlopen("/System/Library/PrivateFrameworks/DFRFoundation.framework/DFRFoundation", RTLD_LAZY)
    }()

    private static func setDfrShowsCloseBox(_ shows: Bool) {
        guard let handle = dfrHandle,
              let sym = dlsym(handle, "DFRSystemModalShowsCloseBoxWhenFrontMost") else { return }
        typealias Fn = @convention(c) (Bool) -> Void
        unsafeBitCast(sym, to: Fn.self)(shows)
    }

    private static func setDfrControlStripPresence(_ identifier: NSTouchBarItem.Identifier, present: Bool) {
        guard let handle = dfrHandle,
              let sym = dlsym(handle, "DFRElementSetControlStripPresenceForIdentifier") else { return }
        typealias Fn = @convention(c) (CFString, Bool) -> Void
        unsafeBitCast(sym, to: Fn.self)(identifier.rawValue as CFString, present)
    }

    private let systemTrayItemId = NSTouchBarItem.Identifier("com.manveersingh.integrator.touchbar.tray")
    private var systemTrayItem: NSCustomTouchBarItem? = nil
    private var visibilityObservation: NSKeyValueObservation? = nil
    private var hasEverBeenVisible: Bool = false
    private var activeMode: TouchBarPanelMode = .main

    private var _generation: UInt64 = 0
    private var isPollingInFlight: Bool = false
    private var lastKnownGpuName: String? = nil
    private var lastGpuTelemetry: GpuTelemetryData? = nil
    private var pendingPasteText: String? = nil

    private func isGenerationCurrent(_ gen: UInt64) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _isActive && _generation == gen
    }

    var touchBar: NSTouchBar?
    var pollTimer: Timer?

    // Liquid Glass Pill Views (Telemetry + Quick Actions)
    var viewGpu: GoopyLiquidGlassPillView?
    var viewTemp: GoopyLiquidGlassPillView?
    var viewPower: GoopyLiquidGlassPillView?
    var viewClock: GoopyLiquidGlassPillView?
    var viewVram: GoopyLiquidGlassPillView?
    var viewUtil: GoopyLiquidGlassPillView?
    var viewPaste: GoopyLiquidGlassPillView?

    // Feature 1: Visual Touch ID Passkey Prompt
    var viewTouchIdPrompt: TouchIdPromptGlowView?
    private var touchIdPromptActive: Bool = false
    private var touchIdPromptLabel: String = "Approve Windows Hello Login"
    private var hudWasActiveBeforeTouchId: Bool = false

    // Feature 2: Display Refresh Rate & Mode Quick-Slider
    var viewDisplayTrigger: GoopyLiquidGlassPillView?
    var displayFpsSliderItem: NSSliderTouchBarItem?
    var viewDisplayResBtn: GoopyLiquidGlassPillView?
    var viewDisplayHdrBtn: GoopyLiquidGlassPillView?
    private var currentDisplayFps: UInt32 = 120
    private var currentDisplayResIndex: Int = 2 // 0 = 1080p, 1 = 1440p, 2 = Native Retina
    private var currentDisplayHdr: Bool = false
    private let displayResPresets: [(label: String, w: UInt32, h: UInt32)] = [
        ("1080p", 1920, 1080),
        ("1440p", 2560, 1440),
        ("Retina", 0, 0)
    ]

    // Feature 3: Hardware Camera Privacy Killswitch
    var viewCameraPrivacy: GoopyLiquidGlassPillView?
    private var cameraIsActive: Bool = false
    private var cameraIsMuted: Bool = false

    // Feature 4: Cross-Platform Audio Mixer & Soundbar Slider
    var viewAudioTrigger: GoopyLiquidGlassPillView?
    var audioBalanceSliderItem: NSSliderTouchBarItem?
    var viewAudioMuteBtn: GoopyLiquidGlassPillView?
    private var currentAudioBalance: Float = 0.0
    private var currentAudioMuted: Bool = false

    // Feature 5: KVM Gaming Boundary Lock
    var viewKvmLock: GoopyLiquidGlassPillView?
    private var kvmBoundaryLocked: Bool = false

    // Feature 6: Windows Media Controls
    var viewMediaTrigger: GoopyLiquidGlassPillView?
    var viewMediaPlayPause: GoopyLiquidGlassPillView?
    var viewMediaTrackLabel: GoopyLiquidGlassPillView?
    var viewMediaScrub: LiquidGlassMediaScrubPillView?
    private var currentMediaState: MediaPlaybackStateData? = nil

    private static func normalizedIp(_ raw: String?) -> String? {
        guard let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else {
            return nil
        }
        var addr4 = in_addr()
        var addr6 = in6_addr()
        if inet_pton(AF_INET, trimmed, &addr4) == 1 || inet_pton(AF_INET6, trimmed, &addr6) == 1 {
            return trimmed
        }
        return nil
    }

    private static let cachedTouchBarSupported: Bool = {
        let presentSelPlacement = NSSelectorFromString("presentSystemModalTouchBar:placement:systemTrayItemIdentifier:")
        let presentSelLegacy = NSSelectorFromString("presentSystemModalTouchBar:systemTrayItemIdentifier:")
        let hasModalApi =
            (NSTouchBar.responds(to: presentSelPlacement) && class_getClassMethod(NSTouchBar.self, presentSelPlacement) != nil) ||
            (NSTouchBar.responds(to: presentSelLegacy) && class_getClassMethod(NSTouchBar.self, presentSelLegacy) != nil)
        guard hasModalApi else { return false }

        if !NSRunningApplication.runningApplications(withBundleIdentifier: controlStripBundleId).isEmpty {
            return true
        }

        if let dfrHandle = dlopen("/System/Library/PrivateFrameworks/DFRFoundation.framework/DFRFoundation", RTLD_LAZY) {
            defer { dlclose(dfrHandle) }
            if let dfrSym = dlsym(dfrHandle, "DFRGetScreenSize") {
                typealias DfrSizeFn = @convention(c) () -> CGSize
                let fn = unsafeBitCast(dfrSym, to: DfrSizeFn.self)
                let size = fn()
                if size.width > 0 && size.height > 0 {
                    return true
                }
            }
        }

        let mainPort: mach_port_t = 0
        if let matchDispdfr = IOServiceNameMatching("dispdfr") {
            let service = IOServiceGetMatchingService(mainPort, matchDispdfr)
            if service != 0 {
                IOObjectRelease(service)
                return true
            }
        }

        if let matchDfr = IOServiceMatching("AppleDFR") {
            let service = IOServiceGetMatchingService(mainPort, matchDfr)
            if service != 0 {
                IOObjectRelease(service)
                return true
            }
        }

        return false
    }()

    /// Detects whether this Mac has Touch Bar hardware / ControlStrip / DFR runtime
    /// and NSTouchBar system-modal presentation support (cached after first probe).
    public static func isTouchBarSupported() -> Bool {
        return cachedTouchBarSupported
    }

    private static func formatByteSize(_ totalBytes: UInt64) -> String {
        let bytes = Double(totalBytes)
        let gb = 1024.0 * 1024.0 * 1024.0
        let mb = 1024.0 * 1024.0
        let kb = 1024.0
        if bytes >= gb {
            return String(format: "%.1f GB", bytes / gb)
        }
        if bytes >= 10.0 * mb {
            return String(format: "%.0f MB", bytes / mb)
        }
        if bytes >= mb {
            return String(format: "%.1f MB", bytes / mb)
        }
        if totalBytes >= 1024 {
            return String(format: "%.0f KB", bytes / kb)
        }
        return "\(totalBytes) B"
    }

    public func showRemotePasteButton(name: String, totalBytes: UInt64) {
        guard Self.isTouchBarSupported() else { return }

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let sizeStr = Self.formatByteSize(totalBytes)
            let btnText = "📥 Paste \(name) (\(sizeStr))"
            self.pendingPasteText = btnText

            if !self.isActive {
                self.activateOnMainThread()
            }

            if let existing = self.viewPaste {
                existing.setText(btnText)
                existing.setAccent(NSColor.systemCyan)
                existing.isHidden = false
            }

            if let tb = self.touchBar {
                let idPaste = NSTouchBarItem.Identifier("paste_remote")
                if !tb.defaultItemIdentifiers.contains(idPaste) {
                    var items = tb.defaultItemIdentifiers
                    items.insert(idPaste, at: 0)
                    tb.defaultItemIdentifiers = items
                }
            }
        }
    }

    public func updatePasteProgress(percent: Float, mbPerSec: Float) {
        guard Self.isTouchBarSupported() else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self, let view = self.viewPaste else { return }
            view.setText(String(format: "📥 %.0f%% • %.0f MB/s", percent, mbPerSec))
            view.setAccent(NSColor.systemGreen)
        }
    }

    public func resetPasteButton() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.pendingPasteText = nil
            if let tb = self.touchBar {
                let idPaste = NSTouchBarItem.Identifier("paste_remote")
                tb.defaultItemIdentifiers.removeAll { $0 == idPaste }
            }
            self.viewPaste?.isHidden = true
        }
    }

    private override init() {
        super.init()
    }

    public func launch_touchbar_hud(peerIp: String? = nil) {
        start(peerIp: peerIp)
    }

    // MARK: - Control Strip Persistent System Tray Button (∫)
    public func setSystemTrayEnabled(_ enabled: Bool) {
        guard Self.isTouchBarSupported() else { return }
        let block = { [weak self] in
            guard let self = self else { return }
            if enabled {
                self.installSystemTrayItemOnMain()
            } else {
                self.removeSystemTrayItemOnMain()
            }
        }
        if Thread.isMainThread {
            block()
        } else {
            DispatchQueue.main.async(execute: block)
        }
    }

    private func installSystemTrayItemOnMain() {
        guard Self.isTouchBarSupported() else { return }
        Self.setDfrShowsCloseBox(true)
        if systemTrayItem != nil {
            Self.setDfrControlStripPresence(systemTrayItemId, present: true)
            return
        }
        let addSel = NSSelectorFromString("addSystemTrayItem:")
        guard NSTouchBarItem.responds(to: addSel),
              let method = class_getClassMethod(NSTouchBarItem.self, addSel) else {
            return
        }
        let item = NSCustomTouchBarItem(identifier: systemTrayItemId)
        let btn = NSButton(title: "∫", target: self, action: #selector(onSystemTrayButtonTapped(_:)))
        btn.font = NSFont.systemFont(ofSize: 19, weight: .semibold)
        btn.isBordered = true
        btn.bezelStyle = .rounded
        btn.contentTintColor = .white
        item.view = btn
        typealias AddTrayFn = @convention(c) (AnyClass, Selector, AnyObject) -> Void
        let fn = unsafeBitCast(method_getImplementation(method), to: AddTrayFn.self)
        fn(NSTouchBarItem.self, addSel, item)
        Self.setDfrControlStripPresence(systemTrayItemId, present: true)
        self.systemTrayItem = item
        NSLog("🚀 [TouchBarHud] Registered persistent ∫ Control Strip system tray button.")
    }

    private func removeSystemTrayItemOnMain() {
        Self.setDfrControlStripPresence(systemTrayItemId, present: false)
        guard let item = systemTrayItem else { return }
        let remSel = NSSelectorFromString("removeSystemTrayItem:")
        if NSTouchBarItem.responds(to: remSel),
           let method = class_getClassMethod(NSTouchBarItem.self, remSel) {
            typealias RemoveTrayFn = @convention(c) (AnyClass, Selector, AnyObject) -> Void
            let fn = unsafeBitCast(method_getImplementation(method), to: RemoveTrayFn.self)
            fn(NSTouchBarItem.self, remSel, item)
        }
        systemTrayItem = nil
    }

    @objc private func onSystemTrayButtonTapped(_ sender: Any?) {
        NSHapticFeedbackManager.defaultPerformer.perform(.generic, performanceTime: .default)
        if self.isActive, let tb = self.touchBar, tb.isVisible {
            self.dismiss()
        } else {
            if self.isActive {
                self.cleanupAfterDismissalOnMain(clearSystemBar: false)
            }
            self.activeMode = .main
            self.activateOnMainThread()
        }
    }

    public func start(peerIp: String? = nil) {
        guard Self.isTouchBarSupported() else {
            NSLog("ℹ️ [TouchBarHud] Touch Bar DF/NSTouchBar support not detected on this Mac; skipping HUD launch.")
            return
        }

        if let raw = peerIp {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                self.peerIp = nil
            } else if let normalized = Self.normalizedIp(trimmed) {
                self.peerIp = normalized
            } else {
                NSLog("⚠️ [TouchBarHud] Ignoring invalid peer IP argument; refusing launch.")
                self.peerIp = nil
                return
            }
        }

        let block = { [weak self] in
            guard let self = self else { return }
            if self.isActive {
                if let tb = self.touchBar, tb.isVisible {
                    self.queryTelemetry()
                    return
                }
                // System dismissed the modal Touch Bar (e.g., user tapped X); clean up and re-present
                self.cleanupAfterDismissalOnMain(clearSystemBar: false)
            }
            self.activeMode = .main
            self.activateOnMainThread()
        }

        if Thread.isMainThread {
            block()
        } else {
            DispatchQueue.main.async(execute: block)
        }
    }

    private func activateOnMainThread() {
        guard Self.isTouchBarSupported() else { return }
        guard !self.isActive else { return }
        guard self.setupTouchBar() else { return }

        stateLock.lock()
        _generation &+= 1
        _isActive = true
        stateLock.unlock()

        self.startPolling()
        NSLog("🚀 Integrator Touch Bar GPU HUD active.")
    }

    private func cleanupAfterDismissalOnMain(clearSystemBar: Bool) {
        self.stateLock.lock()
        let wasActive = self._isActive
        self._isActive = false
        self._generation &+= 1
        self.stateLock.unlock()

        self.visibilityObservation?.invalidate()
        self.visibilityObservation = nil
        self.hasEverBeenVisible = false

        guard wasActive || self.touchBar != nil || self.pollTimer != nil else { return }

        self.pollTimer?.invalidate()
        self.pollTimer = nil

        if clearSystemBar, let tb = self.touchBar {
            let sel = NSSelectorFromString("dismissSystemModalTouchBar:")
            if NSTouchBar.responds(to: sel),
               let method = class_getClassMethod(NSTouchBar.self, sel) {
                typealias DismissFunc = @convention(c) (AnyClass, Selector, AnyObject) -> Void
                let imp = method_getImplementation(method)
                let fn = unsafeBitCast(imp, to: DismissFunc.self)
                fn(NSTouchBar.self, sel, tb)
            }
        }

        self.touchBar = nil
        self.activeMode = .main
        self.viewGpu = nil
        self.viewTemp = nil
        self.viewPower = nil
        self.viewClock = nil
        self.viewVram = nil
        self.viewUtil = nil
        self.viewPaste = nil
        self.viewTouchIdPrompt = nil
        self.viewDisplayTrigger = nil
        self.displayFpsSliderItem = nil
        self.viewDisplayResBtn = nil
        self.viewDisplayHdrBtn = nil
        self.viewCameraPrivacy = nil
        self.viewAudioTrigger = nil
        self.audioBalanceSliderItem = nil
        self.viewAudioMuteBtn = nil
        self.viewKvmLock = nil
        self.viewMediaTrigger = nil
        self.viewMediaPlayPause = nil
        self.viewMediaTrackLabel = nil
        self.viewMediaScrub = nil
        self.touchIdPromptActive = false

        // Keep persistent ∫ icon visible in Control Strip so user can reopen anytime with one tap
        if self.systemTrayItem != nil {
            Self.setDfrControlStripPresence(self.systemTrayItemId, present: true)
        }
        NSLog("🚀 Integrator Touch Bar GPU HUD dismissed (tap ∫ in Control Strip to restore).")
    }

    private func handleExternalDismissalIfNeeded(bar: NSTouchBar) {
        guard self.touchBar === bar, !bar.isVisible, self.isActive else { return }
        self.cleanupAfterDismissalOnMain(clearSystemBar: false)
    }

    public func dismiss() {
        let block: () -> Void = { [weak self] in
            self?.cleanupAfterDismissalOnMain(clearSystemBar: true)
        }

        if Thread.isMainThread {
            block()
        } else {
            DispatchQueue.main.async(execute: block)
        }
    }

    private func buildNormalItemIdentifiers() -> [NSTouchBarItem.Identifier] {
        switch activeMode {
        case .main:
            var ids: [NSTouchBarItem.Identifier] = []
            if pendingPasteText != nil {
                ids.append(NSTouchBarItem.Identifier("paste_remote"))
            }
            if cameraIsActive {
                ids.append(NSTouchBarItem.Identifier("camera_privacy"))
            }
            // Expanded Windows Media Controls + compact GPU telemetry pill (~558–628pt)
            ids.append(contentsOf: [
                NSTouchBarItem.Identifier("gpu"),
                NSTouchBarItem.Identifier("media_prev"),
                NSTouchBarItem.Identifier("media_play_pause"),
                NSTouchBarItem.Identifier("media_next"),
                NSTouchBarItem.Identifier("media_title"),
                NSTouchBarItem.Identifier("media_scrub_slider")
            ])
            return ids

        case .media:
            return [
                NSTouchBarItem.Identifier("back_to_main"),
                NSTouchBarItem.Identifier("media_prev"),
                NSTouchBarItem.Identifier("media_play_pause"),
                NSTouchBarItem.Identifier("media_next"),
                NSTouchBarItem.Identifier("media_title"),
                NSTouchBarItem.Identifier("media_scrub_slider")
            ]

        case .display:
            return [
                NSTouchBarItem.Identifier("back_to_main"),
                NSTouchBarItem.Identifier("display_fps_slider"),
                NSTouchBarItem.Identifier("display_res_btn"),
                NSTouchBarItem.Identifier("display_hdr_btn")
            ]

        case .audio:
            return [
                NSTouchBarItem.Identifier("back_to_main"),
                NSTouchBarItem.Identifier("audio_balance_slider"),
                NSTouchBarItem.Identifier("audio_mute_btn")
            ]

        case .gpu:
            return [
                NSTouchBarItem.Identifier("back_to_main"),
                NSTouchBarItem.Identifier("temp"),
                NSTouchBarItem.Identifier("power"),
                NSTouchBarItem.Identifier("clock"),
                NSTouchBarItem.Identifier("vram"),
                NSTouchBarItem.Identifier("util")
            ]
        }
    }

    private func switchMode(_ newMode: TouchBarPanelMode) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.isActive, !self.touchIdPromptActive else { return }
            self.activeMode = newMode
            self.refreshTouchBarIdentifiersOnMain()
            switch newMode {
            case .main:
                self.applyDisplayModeUi()
                self.applyAudioMixerUi()
                self.applyKvmLockStyle()
                self.applyCameraPillStyle()
                self.applyMediaUi(self.currentMediaState)
                self.stateLock.lock()
                let cached = self.lastGpuTelemetry
                self.stateLock.unlock()
                if let t = cached {
                    self.updateUi(with: t)
                }
            case .media:
                self.applyMediaUi(self.currentMediaState)
                self.queryTelemetry()
            case .display:
                self.applyDisplayModeUi()
            case .audio:
                self.applyAudioMixerUi()
            case .gpu:
                self.stateLock.lock()
                let cached = self.lastGpuTelemetry
                self.stateLock.unlock()
                if let t = cached {
                    self.updateUi(with: t)
                }
                self.queryTelemetry()
            }
        }
    }

    private func refreshTouchBarIdentifiersOnMain() {
        guard let tb = self.touchBar else { return }
        if touchIdPromptActive {
            tb.defaultItemIdentifiers = [
                .flexibleSpace,
                NSTouchBarItem.Identifier("touchid_prompt")
            ]
        } else {
            tb.defaultItemIdentifiers = buildNormalItemIdentifiers()
        }
    }

    // MARK: - Feature 1: Visual Touch ID Passkey Prompt Control
    public func showTouchIdPrompt(label: String, active: Bool) {
        guard Self.isTouchBarSupported() else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if active {
                if !self.touchIdPromptActive {
                    self.hudWasActiveBeforeTouchId = self.isActive
                }
                self.touchIdPromptLabel = label
                self.touchIdPromptActive = true
                NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .default)
                if !self.isActive {
                    self.activateOnMainThread()
                }
                self.refreshTouchBarIdentifiersOnMain()
                self.viewTouchIdPrompt?.updateLabel(label)
            } else {
                guard self.touchIdPromptActive else { return }
                self.touchIdPromptActive = false
                if self.hudWasActiveBeforeTouchId {
                    self.refreshTouchBarIdentifiersOnMain()
                } else {
                    self.dismiss()
                }
            }
        }
    }

    // MARK: - Feature 3: Camera Privacy State Sync
    public func updateCameraState(active: Bool, muted: Bool) {
        guard Self.isTouchBarSupported() else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            let activeChanged = (self.cameraIsActive != active)
            self.cameraIsActive = active
            self.cameraIsMuted = muted
            self.applyCameraPillStyle()
            if activeChanged && self.isActive && !self.touchIdPromptActive {
                self.refreshTouchBarIdentifiersOnMain()
            }
        }
    }

    private func applyCameraPillStyle() {
        guard let v = self.viewCameraPrivacy else { return }
        if cameraIsMuted {
            v.setText("🚫 Cam Muted")
            v.setAccent(.systemRed)
        } else {
            v.setText("🟢 FaceTime HD")
            v.setAccent(.systemGreen)
        }
    }

    // MARK: - Feature 5: KVM Boundary Lock State Sync
    public func updateKvmLockState(locked: Bool) {
        guard Self.isTouchBarSupported() else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.kvmBoundaryLocked = locked
            self.applyKvmLockStyle()
        }
    }

    private func applyKvmLockStyle() {
        guard let v = self.viewKvmLock else { return }
        if kvmBoundaryLocked {
            v.setText("🔒 Locked")
            v.setAccent(.systemOrange)
        } else {
            v.setText("🔓 Lock")
            v.setAccent(.systemGray)
        }
    }

    // MARK: - Feature 2: Display Mode State Sync
    public func updateDisplayModeState(width: UInt32, height: UInt32, fps: UInt32, hdr: Bool) {
        guard Self.isTouchBarSupported() else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.currentDisplayFps = fps > 0 ? fps : 120
            self.currentDisplayHdr = hdr
            if width == 1920 && height == 1080 {
                self.currentDisplayResIndex = 0
            } else if width == 2560 && height == 1440 {
                self.currentDisplayResIndex = 1
            } else {
                self.currentDisplayResIndex = 2
            }
            self.applyDisplayModeUi()
        }
    }

    private func applyDisplayModeUi() {
        let hdrTag = currentDisplayHdr ? " HDR" : ""
        viewDisplayTrigger?.setText("🎚️ \(currentDisplayFps)Hz\(hdrTag)")
        viewDisplayTrigger?.setAccent(currentDisplayHdr ? .systemYellow : .systemIndigo)
        displayFpsSliderItem?.slider.doubleValue = Double(currentDisplayFps)
        displayFpsSliderItem?.label = "\(currentDisplayFps)Hz"
        let preset = displayResPresets[currentDisplayResIndex]
        viewDisplayResBtn?.setText("🖥️ \(preset.label)")
        viewDisplayHdrBtn?.setText(currentDisplayHdr ? "✨ HDR On" : "HDR Off")
        viewDisplayHdrBtn?.setAccent(currentDisplayHdr ? .systemYellow : .systemGray)
    }

    private func pushCurrentDisplayModeToRust() {
        let preset = displayResPresets[currentDisplayResIndex]
        let fps = currentDisplayFps
        let hdr = currentDisplayHdr
        applyDisplayModeUi()
        DispatchQueue.global(qos: .userInitiated).async {
            _ = set_rust_display_mode(preset.w, preset.h, fps, hdr)
        }
    }

    @objc private func onDisplayFpsSliderChanged(_ sender: NSSliderTouchBarItem) {
        let raw = sender.slider.doubleValue
        // Snap smoothly to standard 60Hz, 120Hz, 165Hz detents with tactile haptic click
        let snapped: UInt32
        if raw < 90.0 {
            snapped = 60
        } else if raw < 142.5 {
            snapped = 120
        } else {
            snapped = 165
        }
        if snapped != currentDisplayFps {
            currentDisplayFps = snapped
            NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)
            pushCurrentDisplayModeToRust()
        }
        sender.slider.doubleValue = Double(snapped)
    }

    // MARK: - Feature 4: Cross-Platform Audio Mixer Control
    private func applyAudioMixerUi() {
        let pct = Int(round(currentAudioBalance * 100.0))
        if currentAudioMuted {
            viewAudioTrigger?.setText("🔇 Mix")
            viewAudioTrigger?.setAccent(.systemRed)
            viewAudioMuteBtn?.setText("🔇 Win Muted")
            viewAudioMuteBtn?.setAccent(.systemRed)
        } else {
            let icon = pct < -15 ? "🍎 Mix" : (pct > 15 ? "🎮 Mix" : "🎛️ Mix")
            viewAudioTrigger?.setText(icon)
            viewAudioTrigger?.setAccent(.systemPurple)
            viewAudioMuteBtn?.setText("🔊 Win Live")
            viewAudioMuteBtn?.setAccent(.systemGreen)
        }
        audioBalanceSliderItem?.slider.doubleValue = Double(currentAudioBalance)
        if pct < -10 {
            audioBalanceSliderItem?.label = "Mac +\(-pct)%"
        } else if pct > 10 {
            audioBalanceSliderItem?.label = "PC +\(pct)%"
        } else {
            audioBalanceSliderItem?.label = "Balanced"
        }
    }

    @objc private func onAudioBalanceSliderChanged(_ sender: NSSliderTouchBarItem) {
        var val = Float(sender.slider.doubleValue)
        if abs(val) < 0.06 {
            if abs(currentAudioBalance) >= 0.06 {
                NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .default)
            }
            val = 0.0
            sender.slider.doubleValue = 0.0
        }
        currentAudioBalance = val
        let muted = currentAudioMuted
        applyAudioMixerUi()
        DispatchQueue.global(qos: .userInitiated).async {
            set_rust_audio_mixer(val, muted)
        }
    }

    // MARK: - Feature 6: Windows Media Control Actions
    private func applyMediaUi(_ st: MediaPlaybackStateData?) {
        currentMediaState = st
        if let m = st, m.has_session, !m.title.isEmpty {
            let shortTitle = m.title.count > 12 ? String(m.title.prefix(11)) + "…" : m.title
            viewMediaTrigger?.setText(m.is_playing ? "🎵 \(shortTitle)" : "⏸️ \(shortTitle)")
            viewMediaTrigger?.setAccent(m.is_playing ? .systemPink : .systemGray)
            viewMediaPlayPause?.setText(m.is_playing ? "⏸️" : "▶️")
            viewMediaPlayPause?.setAccent(m.is_playing ? .systemGreen : .systemCyan)
            let subtitle = m.artist.isEmpty ? m.title : "\(m.title) — \(m.artist)"
            viewMediaTrackLabel?.setText(m.is_playing ? "🎵 \(subtitle)" : "⏸️ \(subtitle)")
            viewMediaTrackLabel?.setAccent(m.is_playing ? .systemPink : .systemGray)
            viewMediaScrub?.update(
                position: m.position_secs,
                duration: m.duration_secs,
                isPlaying: m.is_playing,
                hasSession: true
            )
        } else {
            viewMediaTrigger?.setText("🎵 Media")
            viewMediaTrigger?.setAccent(.systemGray)
            viewMediaPlayPause?.setText("▶️")
            viewMediaPlayPause?.setAccent(.systemGray)
            viewMediaTrackLabel?.setText("🎵 No Windows Media")
            viewMediaTrackLabel?.setAccent(.systemGray)
            viewMediaScrub?.update(position: 0.0, duration: 0.0, isPlaying: false, hasSession: false)
        }
    }

    private func dispatchWindowsSeek(_ targetSecs: Double, refreshAfter: Bool) {
        DispatchQueue.global(qos: .userInitiated).async {
            _ = send_rust_windows_media_cmd(3, targetSecs)
        }
        if refreshAfter {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.45) { [weak self] in
                self?.queryTelemetry()
            }
        }
    }

    @discardableResult
    func setupTouchBar() -> Bool {
        guard Self.isTouchBarSupported() else { return false }

        // Ensure persistent ∫ Control Strip tray button is registered so tapping X never leaves user stranded
        self.installSystemTrayItemOnMain()

        let tb = NSTouchBar()
        tb.delegate = self
        tb.defaultItemIdentifiers = touchIdPromptActive
            ? [.flexibleSpace, NSTouchBarItem.Identifier("touchid_prompt")]
            : buildNormalItemIdentifiers()

        let trayIdObj: NSString? = (self.systemTrayItem != nil) ? (self.systemTrayItemId.rawValue as NSString) : nil

        // Placement: 0 (NSTouchBarPlacementDefault) keeps the native macOS Control Strip intact.
        let sel = NSSelectorFromString("presentSystemModalTouchBar:placement:systemTrayItemIdentifier:")
        var presented = false
        if NSTouchBar.responds(to: sel),
           let method = class_getClassMethod(NSTouchBar.self, sel) {
            self.touchBar = tb
            typealias PresentFunc = @convention(c) (AnyClass, Selector, AnyObject, Int64, AnyObject?) -> Void
            let imp = method_getImplementation(method)
            let fn = unsafeBitCast(imp, to: PresentFunc.self)
            fn(NSTouchBar.self, sel, tb, 0, trayIdObj)
            NSLog("🚀 Integrator Touch Bar GPU HUD presented (placement 0, Control Strip preserved)")
            presented = true
        } else {
            let sel2 = NSSelectorFromString("presentSystemModalTouchBar:systemTrayItemIdentifier:")
            if NSTouchBar.responds(to: sel2),
               let method2 = class_getClassMethod(NSTouchBar.self, sel2) {
                self.touchBar = tb
                typealias PresentFunc2 = @convention(c) (AnyClass, Selector, AnyObject, AnyObject?) -> Void
                let imp2 = method_getImplementation(method2)
                let fn2 = unsafeBitCast(imp2, to: PresentFunc2.self)
                fn2(NSTouchBar.self, sel2, tb, trayIdObj)
                NSLog("🚀 Integrator Touch Bar GPU HUD presented (legacy modal API)")
                presented = true
            }
        }

        if presented {
            self.hasEverBeenVisible = tb.isVisible
            self.visibilityObservation?.invalidate()
            self.visibilityObservation = tb.observe(\.isVisible, options: [.initial, .old, .new]) { [weak self] bar, change in
                DispatchQueue.main.async { [weak self] in
                    guard let self = self, self.touchBar === bar else { return }
                    let nowVisible = change.newValue ?? bar.isVisible
                    if nowVisible {
                        self.hasEverBeenVisible = true
                    } else if self.hasEverBeenVisible {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
                            self?.handleExternalDismissalIfNeeded(bar: bar)
                        }
                    }
                }
            }
        }

        return presented
    }

    public func touchBar(_ touchBar: NSTouchBar, makeItemForIdentifier identifier: NSTouchBarItem.Identifier) -> NSTouchBarItem? {
        switch identifier.rawValue {
        // MARK: Back navigation pill for sub-bars (Media / Display / Audio / GPU)
        case "back_to_main":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = GoopyLiquidGlassPillView(text: "◀", accent: .systemGray, width: 42)
            v.onTap = { [weak self] in self?.switchMode(.main) }
            item.view = v
            item.visibilityPriority = .high
            return item

        // MARK: Feature 1 — Visual Touch ID Passkey Prompt (far-right glowing pointer)
        case "touchid_prompt":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = TouchIdPromptGlowView()
            v.updateLabel(self.touchIdPromptLabel)
            self.viewTouchIdPrompt = v
            item.view = v
            item.visibilityPriority = .high
            return item

        // MARK: Feature 2 — Display Refresh Rate & Mode Quick-Slider
        case "display_mode":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let trigger = GoopyLiquidGlassPillView(text: "🎚️ \(currentDisplayFps)Hz", accent: .systemIndigo, width: 70)
            trigger.onTap = { [weak self] in self?.switchMode(.display) }
            self.viewDisplayTrigger = trigger
            item.view = trigger
            item.visibilityPriority = .high
            applyDisplayModeUi()
            return item

        case "display_fps_slider":
            let sliderItem = NSSliderTouchBarItem(identifier: identifier)
            sliderItem.label = "\(currentDisplayFps)Hz"
            sliderItem.slider.minValue = 60.0
            sliderItem.slider.maxValue = 165.0
            sliderItem.slider.doubleValue = Double(currentDisplayFps)
            sliderItem.target = self
            sliderItem.action = #selector(onDisplayFpsSliderChanged(_:))
            sliderItem.minimumSliderWidth = 170
            sliderItem.maximumSliderWidth = 240
            sliderItem.visibilityPriority = .high
            self.displayFpsSliderItem = sliderItem
            return sliderItem

        case "display_res_btn":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let preset = displayResPresets[currentDisplayResIndex]
            let v = GoopyLiquidGlassPillView(text: "🖥️ \(preset.label)", accent: .systemBlue, width: 88)
            v.onTap = { [weak self] in
                guard let self = self else { return }
                self.currentDisplayResIndex = (self.currentDisplayResIndex + 1) % self.displayResPresets.count
                self.pushCurrentDisplayModeToRust()
            }
            self.viewDisplayResBtn = v
            item.view = v
            item.visibilityPriority = .high
            return item

        case "display_hdr_btn":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = GoopyLiquidGlassPillView(text: currentDisplayHdr ? "✨ HDR On" : "HDR Off", accent: currentDisplayHdr ? .systemYellow : .systemGray, width: 84)
            v.onTap = { [weak self] in
                guard let self = self else { return }
                self.currentDisplayHdr.toggle()
                self.pushCurrentDisplayModeToRust()
            }
            self.viewDisplayHdrBtn = v
            item.view = v
            item.visibilityPriority = .high
            return item

        // MARK: Feature 3 — Hardware Camera Privacy Killswitch
        case "camera_privacy":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = GoopyLiquidGlassPillView(
                text: cameraIsMuted ? "🚫 Cam Muted" : "🟢 FaceTime HD",
                accent: cameraIsMuted ? .systemRed : .systemGreen,
                width: 112
            )
            v.onTap = { [weak self] in
                DispatchQueue.global(qos: .userInitiated).async {
                    let muted = toggle_rust_camera_privacy_mute()
                    self?.updateCameraState(active: self?.cameraIsActive ?? true, muted: muted)
                }
            }
            self.viewCameraPrivacy = v
            item.view = v
            item.visibilityPriority = .high
            return item

        // MARK: Feature 4 — Cross-Platform Audio Mixer & Soundbar Slider
        case "audio_mixer":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let trigger = GoopyLiquidGlassPillView(text: "🎛️ Mix", accent: .systemPurple, width: 62)
            trigger.onTap = { [weak self] in self?.switchMode(.audio) }
            self.viewAudioTrigger = trigger
            item.view = trigger
            item.visibilityPriority = .high
            applyAudioMixerUi()
            return item

        case "audio_balance_slider":
            let sliderItem = NSSliderTouchBarItem(identifier: identifier)
            sliderItem.label = "Balanced"
            sliderItem.slider.minValue = -1.0
            sliderItem.slider.maxValue = 1.0
            sliderItem.slider.doubleValue = Double(currentAudioBalance)
            sliderItem.target = self
            sliderItem.action = #selector(onAudioBalanceSliderChanged(_:))
            sliderItem.minimumSliderWidth = 210
            sliderItem.maximumSliderWidth = 290
            sliderItem.visibilityPriority = .high
            self.audioBalanceSliderItem = sliderItem
            applyAudioMixerUi()
            return sliderItem

        case "audio_mute_btn":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = GoopyLiquidGlassPillView(text: currentAudioMuted ? "🔇 Win Muted" : "🔊 Win Live", accent: currentAudioMuted ? .systemRed : .systemGreen, width: 108)
            v.onTap = { [weak self] in
                guard let self = self else { return }
                self.currentAudioMuted.toggle()
                let bal = self.currentAudioBalance
                let muted = self.currentAudioMuted
                self.applyAudioMixerUi()
                DispatchQueue.global(qos: .userInitiated).async {
                    set_rust_audio_mixer(bal, muted)
                }
            }
            self.viewAudioMuteBtn = v
            item.view = v
            item.visibilityPriority = .high
            return item

        // MARK: Feature 5 — KVM Gaming Boundary Lock Toggle
        case "kvm_lock":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = GoopyLiquidGlassPillView(
                text: kvmBoundaryLocked ? "🔒 Locked" : "🔓 Lock",
                accent: kvmBoundaryLocked ? .systemOrange : .systemGray,
                width: 76
            )
            v.onTap = { [weak self] in
                guard let self = self else { return }
                // Optimistic UI feedback while syncing lock state to Rust & peer
                self.kvmBoundaryLocked.toggle()
                self.applyKvmLockStyle()
                DispatchQueue.global(qos: .userInitiated).async {
                    let locked = toggle_rust_kvm_boundary_lock()
                    self.updateKvmLockState(locked: locked)
                }
            }
            self.viewKvmLock = v
            item.view = v
            item.visibilityPriority = .high
            return item

        // MARK: Feature 6 — Windows Media Controls
        case "win_media":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let trigger = GoopyLiquidGlassPillView(text: "🎵 Media", accent: .systemPink, width: 136)
            trigger.onTap = { [weak self] in self?.switchMode(.media) }
            self.viewMediaTrigger = trigger
            item.view = trigger
            item.visibilityPriority = .high
            applyMediaUi(currentMediaState)
            return item

        case "media_prev":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = GoopyLiquidGlassPillView(text: "⏮️", accent: .systemCyan, width: 40)
            v.onTap = { [weak self] in
                DispatchQueue.global(qos: .userInitiated).async { _ = send_rust_windows_media_cmd(2, 0.0) }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.30) { self?.queryTelemetry() }
            }
            item.view = v
            item.visibilityPriority = .high
            return item

        case "media_play_pause":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let isPlaying = currentMediaState?.is_playing ?? false
            let v = GoopyLiquidGlassPillView(
                text: isPlaying ? "⏸️" : "▶️",
                accent: isPlaying ? .systemGreen : .systemCyan,
                width: 44
            )
            v.onTap = { [weak self] in
                guard let self = self else { return }
                if let m = self.currentMediaState {
                    let toggled = MediaPlaybackStateData(
                        title: m.title,
                        artist: m.artist,
                        app_name: m.app_name,
                        is_playing: !m.is_playing,
                        position_secs: m.position_secs,
                        duration_secs: m.duration_secs,
                        has_session: m.has_session
                    )
                    self.applyMediaUi(toggled)
                }
                DispatchQueue.global(qos: .userInitiated).async { _ = send_rust_windows_media_cmd(0, 0.0) }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.30) { self.queryTelemetry() }
            }
            self.viewMediaPlayPause = v
            item.view = v
            item.visibilityPriority = .high
            return item

        case "media_next":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = GoopyLiquidGlassPillView(text: "⏭️", accent: .systemCyan, width: 40)
            v.onTap = { [weak self] in
                DispatchQueue.global(qos: .userInitiated).async { _ = send_rust_windows_media_cmd(1, 0.0) }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.30) { self?.queryTelemetry() }
            }
            item.view = v
            item.visibilityPriority = .high
            return item

        case "media_title":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = GoopyLiquidGlassPillView(text: "🎵 No Windows Media", accent: .systemGray, width: 168)
            v.onTap = { [weak self] in
                guard let self = self else { return }
                if let m = self.currentMediaState {
                    let toggled = MediaPlaybackStateData(
                        title: m.title,
                        artist: m.artist,
                        app_name: m.app_name,
                        is_playing: !m.is_playing,
                        position_secs: m.position_secs,
                        duration_secs: m.duration_secs,
                        has_session: m.has_session
                    )
                    self.applyMediaUi(toggled)
                }
                DispatchQueue.global(qos: .userInitiated).async { _ = send_rust_windows_media_cmd(0, 0.0) }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.30) { self.queryTelemetry() }
            }
            self.viewMediaTrackLabel = v
            item.view = v
            item.visibilityPriority = .high
            applyMediaUi(currentMediaState)
            return item

        case "media_scrub_slider":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = LiquidGlassMediaScrubPillView(width: 176)
            v.onPreviewSeek = { [weak self] pos in
                self?.dispatchWindowsSeek(pos, refreshAfter: false)
            }
            v.onCommitSeek = { [weak self] pos in
                self?.dispatchWindowsSeek(pos, refreshAfter: true)
            }
            self.viewMediaScrub = v
            item.view = v
            item.visibilityPriority = .normal
            applyMediaUi(currentMediaState)
            return item

        default:
            break
        }

        let item = NSCustomTouchBarItem(identifier: identifier)
        switch identifier.rawValue {
        case "gpu":
            let v = GoopyLiquidGlassPillView(text: "Peer Offline", accent: .systemGray, width: 102)
            v.onTap = { [weak self] in self?.switchMode(.gpu) }
            self.viewGpu = v
            item.view = v
            item.visibilityPriority = .high
        case "temp":
            let v = GoopyLiquidGlassPillView(text: "🌡️ --°C", accent: .systemGray, width: 68)
            self.viewTemp = v
            item.view = v
            item.visibilityPriority = .high
        case "power":
            let v = GoopyLiquidGlassPillView(text: "⚡ --W", accent: .systemGray, width: 72)
            self.viewPower = v
            item.view = v
            item.visibilityPriority = .high
        case "clock":
            let v = GoopyLiquidGlassPillView(text: "🚀 -- MHz", accent: .systemGray, width: 86)
            self.viewClock = v
            item.view = v
            item.visibilityPriority = .high
        case "vram":
            let v = GoopyLiquidGlassPillView(text: "💾 -- / -- GB", accent: .systemGray, width: 102)
            self.viewVram = v
            item.view = v
            item.visibilityPriority = .normal
        case "util":
            let v = GoopyLiquidGlassPillView(text: "📊 --%", accent: .systemGray, width: 64)
            self.viewUtil = v
            item.view = v
            item.visibilityPriority = .normal
        case "paste_remote":
            let initialText = self.pendingPasteText ?? "📥 Paste"
            let v = GoopyLiquidGlassPillView(text: initialText, accent: NSColor.systemCyan, width: 145)
            v.onTap = { [weak v] in
                v?.setText("⏳ Streaming...")
                DispatchQueue.global(qos: .userInitiated).async {
                    trigger_rust_remote_paste()
                }
            }
            self.viewPaste = v
            item.view = v
            item.visibilityPriority = .high
        default:
            return nil
        }
        return item
    }

    func startPolling() {
        self.pollTimer?.invalidate()
        queryTelemetry()
        let timer = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            if let tb = self.touchBar {
                if tb.isVisible {
                    self.hasEverBeenVisible = true
                } else if self.hasEverBeenVisible {
                    self.handleExternalDismissalIfNeeded(bar: tb)
                    return
                }
            }
            self.queryTelemetry()
        }
        RunLoop.main.add(timer, forMode: .common)
        self.pollTimer = timer
    }

    func queryTelemetry() {
        stateLock.lock()
        guard _isActive, !isPollingInFlight else {
            stateLock.unlock()
            return
        }
        let gen = _generation
        isPollingInFlight = true
        stateLock.unlock()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            defer {
                self.stateLock.lock()
                self.isPollingInFlight = false
                self.stateLock.unlock()
            }
            guard self.isGenerationCurrent(gen) else { return }

            if let snap = self.fetchTouchBarSnapshot(host: self.peerIp) {
                guard self.isGenerationCurrent(gen) else { return }
                if let telemetry = snap.gpu_telemetry {
                    self.updateUi(with: telemetry, expectedGeneration: gen)
                } else {
                    self.updateOfflineUi(statusText: self.peerIp == nil ? "Peer Offline" : "Telemetry N/A", expectedGeneration: gen)
                }
                DispatchQueue.main.async { [weak self] in
                    guard let self = self, self.isGenerationCurrent(gen) else { return }
                    self.applyMediaUi(snap.media_state)
                    let camChanged = (self.cameraIsActive != snap.camera_active)
                    self.cameraIsActive = snap.camera_active
                    self.cameraIsMuted = snap.camera_muted
                    self.applyCameraPillStyle()
                    if camChanged && !self.touchIdPromptActive {
                        self.refreshTouchBarIdentifiersOnMain()
                    }
                    self.kvmBoundaryLocked = snap.kvm_locked
                    self.applyKvmLockStyle()
                    self.currentAudioBalance = snap.audio_balance
                    self.currentAudioMuted = snap.audio_muted
                    self.applyAudioMixerUi()
                }
            } else if let host = self.peerIp,
                      let response = self.sendRpcRequest(host: host, port: self.rpcPort, requestJson: "\"GetGpuTelemetry\""),
                      response.success,
                      let telemetry = response.gpu_telemetry {
                guard self.isGenerationCurrent(gen) else { return }
                self.updateUi(with: telemetry, expectedGeneration: gen)
            } else {
                self.updateOfflineUi(statusText: "Peer Offline", expectedGeneration: gen)
            }
        }
    }

    private func fetchTouchBarSnapshot(host: String?) -> TouchBarLiveSnapshotData? {
        let bufCap = 65_536
        var outBuf = [UInt8](repeating: 0, count: bufCap)
        let n: Int
        if let h = host {
            n = h.withCString { cHost in
                outBuf.withUnsafeMutableBufferPointer { bufPtr in
                    fetch_rust_touchbar_snapshot_json(cHost, bufPtr.baseAddress, bufCap)
                }
            }
        } else {
            n = outBuf.withUnsafeMutableBufferPointer { bufPtr in
                fetch_rust_touchbar_snapshot_json(nil, bufPtr.baseAddress, bufCap)
            }
        }
        guard n > 0 && n <= bufCap else { return nil }
        let data = Data(outBuf.prefix(n))
        return try? JSONDecoder().decode(TouchBarLiveSnapshotData.self, from: data)
    }

    private func sendRpcRequest(host: String, port: UInt16, requestJson: String) -> DisplayRpcResponseData? {
        let _ = port
        let _ = requestJson
        let bufCap = 65_536
        var outBuf = [UInt8](repeating: 0, count: bufCap)
        let n = host.withCString { cHost -> Int in
            outBuf.withUnsafeMutableBufferPointer { bufPtr -> Int in
                fetch_rust_gpu_telemetry_json(cHost, bufPtr.baseAddress, bufCap)
            }
        }
        guard n > 0 && n <= bufCap else { return nil }
        let respData = Data(outBuf.prefix(n))
        guard let decoded = try? JSONDecoder().decode(DisplayRpcResponseData.self, from: respData) else {
            return nil
        }
        if let t = decoded.gpu_telemetry, !t.power_usage_watts.isFinite {
            return nil
        }
        return decoded
    }

    private func compactGpuName(_ raw: String) -> String {
        var name = raw
            .replacingOccurrences(of: "(R)", with: "")
            .replacingOccurrences(of: "(TM)", with: "")
            .replacingOccurrences(of: "®", with: "")
            .replacingOccurrences(of: "™", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        while name.contains("  ") {
            name = name.replacingOccurrences(of: "  ", with: " ")
        }

        if name.isEmpty {
            return "GPU"
        }

        let removableSuffixes = [" Laptop GPU", " Graphics"]
        for suffix in removableSuffixes where name.count > 14 && name.hasSuffix(suffix) {
            name = String(name.dropLast(suffix.count)).trimmingCharacters(in: .whitespaces)
        }

        let removablePrefixes = ["NVIDIA ", "GeForce ", "AMD ", "Radeon ", "Intel "]
        for prefix in removablePrefixes where name.count > 14 && name.hasPrefix(prefix) {
            name = String(name.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
        }

        let maxChars = 14
        if name.count > maxChars {
            return String(name.prefix(maxChars - 1)) + "…"
        }
        return name
    }

    func updateOfflineUi(statusText: String = "Peer Offline", expectedGeneration: UInt64? = nil) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if let gen = expectedGeneration {
                guard self.isGenerationCurrent(gen) else { return }
            } else {
                guard self.isActive else { return }
            }
            self.viewGpu?.setText(statusText)
            self.viewGpu?.setAccent(.systemGray)

            self.viewTemp?.setText("🌡️ --°C")
            self.viewTemp?.setAccent(.systemGray)

            self.viewPower?.setText("⚡ --W")
            self.viewPower?.setAccent(.systemGray)

            self.viewClock?.setText("🚀 -- MHz")
            self.viewClock?.setAccent(.systemGray)

            self.viewVram?.setText("💾 -- / -- GB")
            self.viewVram?.setAccent(.systemGray)

            self.viewUtil?.setText("📊 --% GPU")
            self.viewUtil?.setAccent(.systemGray)
        }
    }

    func updateUi(with t: GpuTelemetryData, expectedGeneration: UInt64? = nil) {
        self.stateLock.lock()
        self.lastKnownGpuName = t.gpu_name
        self.lastGpuTelemetry = t
        self.stateLock.unlock()

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if let gen = expectedGeneration {
                guard self.isGenerationCurrent(gen) else { return }
            } else {
                guard self.isActive else { return }
            }
            let hasLiveCounters =
                t.temperature_c > 0 ||
                t.power_usage_watts > 0.05 ||
                t.core_clock_mhz > 0 ||
                t.gpu_utilization_percent > 0

            // 0. Dynamic GPU Name + Live Thermal Temp combined cleanly for compact Touch Bar width
            if let v = self.viewGpu {
                let compact = self.compactGpuName(t.gpu_name)
                if t.temperature_c > 0 {
                    v.setText("🎮 \(compact) \(t.temperature_c)°")
                    if t.temperature_c < 55 {
                        v.setAccent(NSColor(red: 0.1, green: 0.75, blue: 0.35, alpha: 1.0))
                    } else if t.temperature_c < 75 {
                        v.setAccent(NSColor(red: 0.95, green: 0.55, blue: 0.1, alpha: 1.0))
                    } else {
                        v.setAccent(NSColor(red: 0.95, green: 0.2, blue: 0.2, alpha: 1.0))
                    }
                } else {
                    v.setText("🎮 \(compact)")
                    v.setAccent(NSColor(red: 0.25, green: 0.72, blue: 0.95, alpha: 1.0))
                }
            }

            // 1. Temperature with Dynamic Thermal Color
            if let v = self.viewTemp {
                if t.temperature_c > 0 {
                    v.setText("🌡️ \(t.temperature_c)°C")
                    if t.temperature_c < 55 {
                        v.setAccent(NSColor(red: 0.1, green: 0.75, blue: 0.35, alpha: 1.0))
                    } else if t.temperature_c < 75 {
                        v.setAccent(NSColor(red: 0.95, green: 0.55, blue: 0.1, alpha: 1.0))
                    } else {
                        v.setAccent(NSColor(red: 0.95, green: 0.2, blue: 0.2, alpha: 1.0))
                    }
                } else {
                    v.setText("🌡️ --°C")
                    v.setAccent(.systemGray)
                }
            }

            // 2. Power Draw
            if let v = self.viewPower {
                if t.power_usage_watts > 0.05 {
                    v.setText(String(format: "⚡ %.1fW", t.power_usage_watts))
                    v.setAccent(NSColor(red: 0.95, green: 0.65, blue: 0.1, alpha: 1.0))
                } else {
                    v.setText("⚡ --W")
                    v.setAccent(.systemGray)
                }
            }

            // 3. Core Clock
            if let v = self.viewClock {
                if t.core_clock_mhz > 0 {
                    v.setText("🚀 \(t.core_clock_mhz) MHz")
                    v.setAccent(NSColor(red: 0.05, green: 0.7, blue: 0.85, alpha: 1.0))
                } else {
                    v.setText("🚀 -- MHz")
                    v.setAccent(.systemGray)
                }
            }

            // 4. VRAM Usage
            if let v = self.viewVram {
                if t.memory_total_mb > 0 {
                    let totalGb = Double(t.memory_total_mb) / 1024.0
                    if t.memory_used_mb > 0 || hasLiveCounters {
                        let usedGb = Double(t.memory_used_mb) / 1024.0
                        v.setText(String(format: "💾 %.1f/%.1f GB", usedGb, totalGb))
                    } else {
                        v.setText(String(format: "💾 --/%.1f GB", totalGb))
                    }
                    v.setAccent(NSColor(red: 0.25, green: 0.5, blue: 0.95, alpha: 1.0))
                } else if t.memory_used_mb > 0 {
                    let usedGb = Double(t.memory_used_mb) / 1024.0
                    v.setText(String(format: "💾 %.1f GB", usedGb))
                    v.setAccent(NSColor(red: 0.25, green: 0.5, blue: 0.95, alpha: 1.0))
                } else {
                    v.setText("💾 -- GB")
                    v.setAccent(.systemGray)
                }
            }

            // 5. Utilization
            if let v = self.viewUtil {
                if hasLiveCounters {
                    v.setText("📊 \(t.gpu_utilization_percent)% GPU")
                    v.setAccent(NSColor(red: 0.65, green: 0.35, blue: 0.95, alpha: 1.0))
                } else {
                    v.setText("📊 --% GPU")
                    v.setAccent(.systemGray)
                }
            }
        }
    }

    public func updateUiExplicit(temp: UInt32, power: Float, clock: UInt32, vramUsed: UInt64, vramTotal: UInt64, util: UInt32) {
        stateLock.lock()
        let gpuName = lastKnownGpuName ?? "Remote GPU"
        stateLock.unlock()

        let memPercent: UInt32
        if vramTotal > 0 {
            let pct = (Double(vramUsed) * 100.0) / Double(vramTotal)
            memPercent = UInt32(min(100.0, max(0.0, pct)))
        } else {
            memPercent = 0
        }

        let t = GpuTelemetryData(
            gpu_name: gpuName,
            temperature_c: temp,
            power_usage_watts: power.isFinite ? power : 0.0,
            gpu_utilization_percent: util,
            memory_utilization_percent: memPercent,
            memory_used_mb: vramUsed,
            memory_total_mb: vramTotal,
            core_clock_mhz: clock
        )
        updateUi(with: t)
    }
}

// MARK: - C FFI Interface for Main App Integration
@_cdecl("set_touchbar_rpc_port_in_app")
public func set_touchbar_rpc_port_in_app(port: UInt16) {
    TouchBarHudController.shared.rpcPort = port
}

@_cdecl("init_touchbar_in_app")
public func init_touchbar_in_app(peerIpPtr: UnsafePointer<CChar>?) {
    let peerIp = peerIpPtr != nil ? String(cString: peerIpPtr!) : nil
    TouchBarHudController.shared.launch_touchbar_hud(peerIp: peerIp)
}

@_cdecl("dismiss_touchbar_in_app")
public func dismiss_touchbar_in_app() {
    TouchBarHudController.shared.dismiss()
}

@_cdecl("is_touchbar_active_in_app")
public func is_touchbar_active_in_app() -> Bool {
    return TouchBarHudController.shared.isActive
}

@_cdecl("set_touchbar_tray_enabled_in_app")
public func set_touchbar_tray_enabled_in_app(enabled: Bool) {
    TouchBarHudController.shared.setSystemTrayEnabled(enabled)
}

@_cdecl("update_touchbar_telemetry_in_app")
public func update_touchbar_telemetry_in_app(
    temp: UInt32,
    power: Float,
    clock: UInt32,
    vramUsed: UInt64,
    vramTotal: UInt64,
    util: UInt32
) {
    TouchBarHudController.shared.updateUiExplicit(
        temp: temp,
        power: power,
        clock: clock,
        vramUsed: vramUsed,
        vramTotal: vramTotal,
        util: util
    )
}

private var touchBarCliSignalSources: [DispatchSourceSignal] = []

@_cdecl("run_touchbar_cli_loop")
public func run_touchbar_cli_loop(peerIpPtr: UnsafePointer<CChar>?) {
    guard TouchBarHudController.isTouchBarSupported() else {
        NSLog("ℹ️ [TouchBarHud] Touch Bar DF/NSTouchBar support not detected on this Mac; exiting CLI loop.")
        return
    }

    let peerIp = peerIpPtr != nil ? String(cString: peerIpPtr!) : nil
    let initMain = {
        let app = NSApplication.shared
        if app.activationPolicy() == .prohibited {
            app.setActivationPolicy(.accessory)
        }
        TouchBarHudController.shared.launch_touchbar_hud(peerIp: peerIp)
    }
    if Thread.isMainThread {
        initMain()
    } else {
        DispatchQueue.main.sync(execute: initMain)
    }

    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    touchBarCliSignalSources.forEach { $0.cancel() }
    touchBarCliSignalSources.removeAll()

    for sig in [SIGINT, SIGTERM] {
        let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
        src.setEventHandler {
            TouchBarHudController.shared.dismiss()
            CFRunLoopStop(CFRunLoopGetMain())
        }
        src.resume()
        touchBarCliSignalSources.append(src)
    }

    CFRunLoopRun()
    touchBarCliSignalSources.forEach { $0.cancel() }
    touchBarCliSignalSources.removeAll()
}

// MARK: - On-Demand Remote Paste, Telemetry & TouchBar Controls C FFI Bridge
@_silgen_name("trigger_rust_remote_paste")
func trigger_rust_remote_paste()

@_silgen_name("fetch_rust_gpu_telemetry_json")
func fetch_rust_gpu_telemetry_json(_ peerIp: UnsafePointer<CChar>?, _ outBuf: UnsafeMutablePointer<UInt8>?, _ cap: Int) -> Int

@_silgen_name("fetch_rust_touchbar_snapshot_json")
func fetch_rust_touchbar_snapshot_json(_ peerIp: UnsafePointer<CChar>?, _ outBuf: UnsafeMutablePointer<UInt8>?, _ cap: Int) -> Int

@_silgen_name("set_rust_display_mode")
func set_rust_display_mode(_ width: UInt32, _ height: UInt32, _ fps: UInt32, _ hdr: Bool) -> Bool

@_silgen_name("toggle_rust_camera_privacy_mute")
func toggle_rust_camera_privacy_mute() -> Bool

@_silgen_name("set_rust_audio_mixer")
func set_rust_audio_mixer(_ balance: Float, _ muted: Bool)

@_silgen_name("toggle_rust_kvm_boundary_lock")
func toggle_rust_kvm_boundary_lock() -> Bool

@_silgen_name("send_rust_windows_media_cmd")
func send_rust_windows_media_cmd(_ cmdCode: Int32, _ seekSecs: Double) -> Bool

@_cdecl("notify_touchbar_touchid_prompt_in_app")
public func notify_touchbar_touchid_prompt_in_app(labelPtr: UnsafePointer<CChar>?, active: Bool) {
    let label = labelPtr != nil ? String(cString: labelPtr!) : "Approve Windows Hello Login"
    TouchBarHudController.shared.showTouchIdPrompt(label: label, active: active)
}

@_cdecl("notify_touchbar_camera_state_in_app")
public func notify_touchbar_camera_state_in_app(active: Bool, muted: Bool) {
    TouchBarHudController.shared.updateCameraState(active: active, muted: muted)
}

@_cdecl("notify_touchbar_kvm_lock_state_in_app")
public func notify_touchbar_kvm_lock_state_in_app(locked: Bool) {
    TouchBarHudController.shared.updateKvmLockState(locked: locked)
}

@_cdecl("notify_touchbar_display_mode_in_app")
public func notify_touchbar_display_mode_in_app(width: UInt32, height: UInt32, fps: UInt32, hdr: Bool) {
    TouchBarHudController.shared.updateDisplayModeState(width: width, height: height, fps: fps, hdr: hdr)
}

@_cdecl("notify_touchbar_remote_file")
public func notify_touchbar_remote_file(namePtr: UnsafePointer<CChar>?, totalBytes: UInt64) {
    guard let namePtr = namePtr else { return }
    let name = String(cString: namePtr)
    TouchBarHudController.shared.showRemotePasteButton(name: name, totalBytes: totalBytes)
}

@_cdecl("update_touchbar_paste_progress")
public func update_touchbar_paste_progress(percent: Float, mbPerSec: Float) {
    PasteboardShortcutInterceptor.shared.touchPasteActivity()
    TouchBarHudController.shared.updatePasteProgress(percent: percent, mbPerSec: mbPerSec)
}

@_cdecl("reset_touchbar_paste_progress")
public func reset_touchbar_paste_progress() {
    PasteboardShortcutInterceptor.shared.isPasting = false
    TouchBarHudController.shared.resetPasteButton()
}

// MARK: - Native Finder Cmd+V Shortcut Interceptor
public class PasteboardShortcutInterceptor: NSObject {
    public static let shared = PasteboardShortcutInterceptor()

    private let lock = NSLock()
    private var _hasPendingRemoteFile: Bool = false
    private var _isPasting: Bool = false
    private var _pasteStartedAt: Date? = nil
    private var eventTap: CFMachPort?
    private var runLoopSource: CFRunLoopSource?

    public var hasPendingRemoteFile: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return _hasPendingRemoteFile
        }
        set {
            lock.lock()
            _hasPendingRemoteFile = newValue
            if !newValue {
                _isPasting = false
                _pasteStartedAt = nil
            }
            lock.unlock()
        }
    }

    public var isPasting: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            expireStalePastingLocked()
            return _isPasting
        }
        set {
            lock.lock()
            _isPasting = newValue
            _pasteStartedAt = newValue ? Date() : nil
            lock.unlock()
        }
    }

    func touchPasteActivity() {
        lock.lock()
        if _isPasting {
            _pasteStartedAt = Date()
        }
        lock.unlock()
    }

    private func expireStalePastingLocked() {
        if _isPasting, let started = _pasteStartedAt, Date().timeIntervalSince(started) > 30.0 {
            _isPasting = false
            _pasteStartedAt = nil
        }
    }

    private override init() {
        super.init()
    }

    public func start() {
        let block = { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            let alreadyStarted = self.eventTap != nil
            self.lock.unlock()
            guard !alreadyStarted else { return }

            if !AXIsProcessTrusted() {
                NSLog("ℹ️ [PasteboardShortcutInterceptor] Accessibility permissions not granted. Using automatic background stream & native pasteboard registration.")
                return
            }

            let mask = (1 << CGEventType.keyDown.rawValue)
            guard let tap = CGEvent.tapCreate(
                tap: .cgSessionEventTap,
                place: .headInsertEventTap,
                options: .defaultTap,
                eventsOfInterest: CGEventMask(mask),
                callback: { (proxy, type, event, refcon) -> Unmanaged<CGEvent>? in
                    return PasteboardShortcutInterceptor.shared.handleEvent(proxy: proxy, type: type, event: event)
                },
                userInfo: nil
            ) else {
                NSLog("ℹ️ [PasteboardShortcutInterceptor] Could not create CGEventTap; falling back to direct clipboard registration.")
                return
            }

            let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0)
            self.lock.lock()
            self.eventTap = tap
            self.runLoopSource = source
            self.lock.unlock()

            CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
            CFRunLoopAddSource(CFRunLoopGetMain(), source, .defaultMode)
            CGEvent.tapEnable(tap: tap, enable: true)
            NSLog("🎯 [PasteboardShortcutInterceptor] Native Finder Cmd+V interceptor active")
        }

        if Thread.isMainThread {
            block()
        } else {
            DispatchQueue.main.async(execute: block)
        }
    }

    private func isPasteShortcutEvent(_ event: CGEvent) -> Bool {
        let flags = event.flags
        guard flags.contains(.maskCommand),
              !flags.contains(.maskAlternate),
              !flags.contains(.maskControl) else {
            return false
        }
        if let nsEvent = NSEvent(cgEvent: event),
           let chars = nsEvent.charactersIgnoringModifiers?.lowercased(),
           !chars.isEmpty {
            return chars == "v"
        }
        return event.getIntegerValueField(.keyboardEventKeycode) == 9
    }

    func handleEvent(proxy: CGEventTapProxy, type: CGEventType, event: CGEvent) -> Unmanaged<CGEvent>? {
        if type == .tapDisabledByTimeout {
            lock.lock()
            let tap = eventTap
            lock.unlock()
            if let tap = tap {
                CGEvent.tapEnable(tap: tap, enable: true)
            }
            return Unmanaged.passUnretained(event)
        }
        if type == .tapDisabledByUserInput {
            NSLog("ℹ️ [PasteboardShortcutInterceptor] CGEventTap disabled by user input / permission change; not forcing re-enable.")
            return Unmanaged.passUnretained(event)
        }

        guard type == .keyDown else {
            return Unmanaged.passUnretained(event)
        }

        if isPasteShortcutEvent(event) {
            let frontApp = NSWorkspace.shared.frontmostApplication?.bundleIdentifier ?? ""
            lock.lock()
            expireStalePastingLocked()
            let pending = _hasPendingRemoteFile
            let pasting = _isPasting
            lock.unlock()

            if pending && !pasting && frontApp == finderBundleId {
                NSLog("🎯 [PasteboardShortcutInterceptor] Intercepting Cmd+V in Finder! Streaming remote files...")
                triggerPaste()
                return nil // Intercept & swallow event so Finder does not paste stale text clippings or beep!
            }
        }

        return Unmanaged.passUnretained(event)
    }

    func triggerPaste() {
        lock.lock()
        expireStalePastingLocked()
        guard _hasPendingRemoteFile && !_isPasting else {
            lock.unlock()
            return
        }
        _isPasting = true
        _pasteStartedAt = Date()
        lock.unlock()

        DispatchQueue.main.async {
            NSHapticFeedbackManager.defaultPerformer.perform(.generic, performanceTime: .default)
            TouchBarHudController.shared.viewPaste?.setText("⏳ Streaming...")
            TouchBarHudController.shared.viewPaste?.setAccent(NSColor.systemGreen)
        }

        DispatchQueue.global(qos: .userInitiated).async {
            trigger_rust_remote_paste()
        }
    }
}

// MARK: - C FFI Interface for Shortcut Interceptor & Pasteboard
@_cdecl("init_shortcut_interceptor")
public func init_shortcut_interceptor() {
    PasteboardShortcutInterceptor.shared.start()
}

@_cdecl("set_has_pending_remote_file")
public func set_has_pending_remote_file(pending: Bool) {
    PasteboardShortcutInterceptor.shared.hasPendingRemoteFile = pending
}

private func onMainPasteboardSync<T>(_ work: () -> T) -> T {
    if Thread.isMainThread || !(NSApp?.isRunning ?? false) {
        return work()
    }
    return DispatchQueue.main.sync(execute: work)
}

@_cdecl("clear_pasteboard_in_app")
public func clear_pasteboard_in_app() {
    onMainPasteboardSync {
        NSPasteboard.general.clearContents()
    }
}

/// Reads file URLs from `NSPasteboard.general` into `outBuf` as `\0`-delimited UTF-8 paths.
/// Returns `0` when no file URLs are present, `-1` when `outBuf` is invalid or `cap` is too small,
/// or the exact byte count written into `outBuf`.
@_cdecl("read_pasteboard_files_in_app")
public func read_pasteboard_files_in_app(_ outBuf: UnsafeMutablePointer<UInt8>?, _ cap: Int) -> Int {
    guard let outBuf = outBuf, cap > 0 else { return -1 }
    let ordered: [String] = onMainPasteboardSync {
        let pb = NSPasteboard.general
        let options: [NSPasteboard.ReadingOptionKey: Any] = [
            .urlReadingFileURLsOnly: true
        ]
        guard let urls = pb.readObjects(forClasses: [NSURL.self], options: options) as? [URL], !urls.isEmpty else {
            return []
        }
        var seen = Set<String>()
        var result: [String] = []
        for url in urls {
            guard url.isFileURL else { continue }
            let path = url.path
            guard !path.isEmpty, !path.contains("\0") else { continue }
            if seen.insert(path).inserted {
                result.append(path)
            }
        }
        return result
    }
    if ordered.isEmpty {
        return 0
    }
    var bytes: [UInt8] = []
    for (idx, path) in ordered.enumerated() {
        if idx > 0 {
            bytes.append(0)
        }
        bytes.append(contentsOf: path.utf8)
    }
    if bytes.isEmpty {
        return 0
    }
    guard bytes.count <= cap else {
        return -1
    }
    for i in 0..<bytes.count {
        outBuf[i] = bytes[i]
    }
    return bytes.count
}

/// Writes `\0`-delimited UTF-8 file paths in `pathsPtr[0..<len]` onto `NSPasteboard.general`.
@_cdecl("write_pasteboard_files_in_app")
public func write_pasteboard_files_in_app(_ pathsPtr: UnsafePointer<UInt8>?, _ len: Int) -> Bool {
    guard let pathsPtr = pathsPtr, len > 0 else { return false }
    let buf = UnsafeBufferPointer(start: pathsPtr, count: len)
    var seen = Set<String>()
    var urls: [NSURL] = []
    for slice in buf.split(separator: 0, omittingEmptySubsequences: true) {
        let path = String(decoding: slice, as: UTF8.self)
        guard !path.isEmpty else { continue }
        if seen.insert(path).inserted {
            urls.append(URL(fileURLWithPath: path) as NSURL)
        }
    }
    guard !urls.isEmpty else { return false }
    return onMainPasteboardSync {
        let pb = NSPasteboard.general
        pb.clearContents()
        return pb.writeObjects(urls)
    }
}

