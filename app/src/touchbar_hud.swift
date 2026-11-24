//
//  touchbar_hud.swift
//  Integrator TouchBar HUD - Liquid Glass Controls & Telemetry Streamer
//
//  ========================================================================================
//  1. MODULE PURPOSE & ARCHITECTURAL SCOPE
//  ========================================================================================
//  This file provides the native macOS TouchBar (`NSTouchBar`) HUD controller for MacBook Pro
//  models, implementing tactile hardware-level GPU monitoring, expanded Windows media playback
//  controls with a rounded Liquid Glass scrubber, Visual Touch ID biometric prompts, a Hardware
//  Camera Privacy Killswitch pill, remote clipboard paste interception, and a persistent `∫`
//  Control Strip tray button.
//
//  Key Subsystem Capabilities:
//  - Viscous Liquid Glass Pill Views (`GoopyLiquidGlassPillView`): Implements critically-damped
//    tactile spring physics, Frosted HUD blur materials (`NSVisualEffectView` with `.hudWindow`),
//    and continuous corner curves.
//  - Rounded Liquid Glass Media Scrubber (`LiquidGlassMediaScrubPillView`): Capsule progress bar
//    with glowing circular thumb, elapsed/total timestamps (`mm:ss`), and zero-snap-back direct
//    touch scrubbing for Windows GSMTC / browser / Spotify / VLC sessions.
//  - Visual Touch ID Passkey & UAC Animated Sensor Pointer (`TouchIdPromptGlowView`): Illuminated
//    emerald/teal strip pinned to the far-right corner pointing directly toward the physical
//    MacBook Pro Touch ID sensor (`───────▶ 👆 Touch ID`).
//  - Hardware Camera Privacy Killswitch (`camera_privacy`): One-tap hardware privacy shutter
//    pill (`🟢 FaceTime HD` / `🚫 Cam Muted`) visible whenever the Mac camera is streaming.
//  - Live GPU Telemetry Streamer (`gpu` pill + `.gpu` detail strip): Displays real-time GPU
//    metrics from the connected Windows 11 host (GPU name, temperature °C, power draw W, core
//    clock MHz, VRAM usage GB, and GPU utilization %).
//  - Persistent Control Strip System Tray (`∫`): Registers a persistent `NSCustomTouchBarItem`
//    in the macOS Control Strip and observes `NSTouchBar.isVisible` via KVO so dismissing the
//    modal bar via the system `X` close button cleans up timers and allows instant 1-tap restore.
//  - Remote File Paste Interceptor (`PasteboardShortcutInterceptor`): Installs a `CGEventTap`
//    listening for `Cmd+V` in Finder. When a remote file announcement is pending, it intercepts
//    the shortcut, updates the TouchBar with a haptic pulse, and triggers asynchronous zero-RAM
//    streaming via `trigger_rust_remote_paste()`.
//  - In-App Pasteboard Native File Helper: Implements `clear_pasteboard_in_app`,
//    `read_pasteboard_files_in_app`, and `write_pasteboard_files_in_app` using `\0`-delimited
//    UTF-8 byte arrays directly on the main AppKit thread.
//
//  ========================================================================================
//  2. ARCHITECTURAL LINKAGES & CALL FLOW
//  ========================================================================================
//  Upstream Callers:
//  - `src/core.rs`: Invokes C-ABI lifecycle and notification entry points:
//    - `set_touchbar_rpc_port_in_app`, `init_touchbar_in_app`, `dismiss_touchbar_in_app`,
//      `is_touchbar_active_in_app`, `set_touchbar_tray_enabled_in_app`, `run_touchbar_cli_loop`.
//    - `notify_touchbar_touchid_prompt_in_app`, `notify_touchbar_camera_state_in_app`,
//      `notify_touchbar_kvm_lock_state_in_app`, `notify_touchbar_display_mode_in_app`.
//  - `src/clipboard/service.rs`: Invokes C-ABI functions:
//    - `notify_touchbar_remote_file`: Announces pending remote files on TouchBar.
//    - `update_touchbar_paste_progress`: Telemeters transfer % and MB/s stream velocity.
//    - `reset_touchbar_paste_progress`: Clears transfer indicators upon completion.
//    - `init_shortcut_interceptor`, `set_has_pending_remote_file`.
//  - `src/clipboard/file_helper.rs`: Calls `clear_pasteboard_in_app`,
//    `read_pasteboard_files_in_app`, and `write_pasteboard_files_in_app`.
//
//  Downstream Callees:
//  - AppKit TouchBar Framework (`NSTouchBar`, `NSTouchBarItem`, `NSCustomTouchBarItem`) &
//    private `DFRFoundation.framework` (`DFRSystemModalShowsCloseBoxWhenFrontMost`,
//    `DFRElementSetControlStripPresenceForIdentifier`, `DFRGetScreenSize`).
//  - Quartz Core Graphics (`CGEventTapCreate`, `CGEvent.tapEnable`).
//  - Rust FFI Callbacks: `trigger_rust_remote_paste`, `fetch_rust_touchbar_snapshot_json`,
//    `fetch_rust_gpu_telemetry_json`, `toggle_rust_camera_privacy_mute`,
//    `send_rust_windows_media_cmd`.
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - AppKit Main Thread: All TouchBar UI item creation, KVO callbacks, and label updates execute
//    strictly on `DispatchQueue.main`.
//  - Telemetry Poll Worker: 1 Hz timer dispatches `fetch_rust_touchbar_snapshot_json` to
//    `DispatchQueue.global(qos: .userInitiated)` guarded by `_generation` and `isPollingInFlight`
//    under `stateLock` (`NSLock`) so stale responses from a dismissed session are discarded.
//  - Async Rust Handoff: Touch actions dispatch to `DispatchQueue.global(qos: .userInitiated)`
//    before invoking Rust C-ABI callbacks, ensuring the main UI thread is never blocked.
//
//  ========================================================================================
//  4. SECURITY & SAFETY INVARIANTS
//  ========================================================================================
//  - Stale Paste Expiration: In-flight paste sessions automatically expire after 30 seconds of
//    inactivity if the remote host fails to stream data, unblocking future Finder paste shortcuts.
//  - IP Literal Validation: `normalizedIp` validates peer IP addresses with `inet_pton` (`AF_INET`
//    and `AF_INET6`) before passing host hints across FFI.
//  - Buffer Capacity Verification: `read_pasteboard_files_in_app` and snapshot FFI buffers strictly
//    verify non-null pointers and output buffer capacities before copying bytes.
//

import AppKit
import Foundation
import IOKit

/// macOS Control Strip daemon bundle identifier probed to verify Touch Bar runtime presence.
private let controlStripBundleId = "com.apple.controlstrip"

/// macOS Finder bundle identifier scoped for intercepting remote file Cmd+V shortcuts.
private let finderBundleId = "com.apple.finder"

// MARK: - RPC Data Models

/// Deserialized GPU hardware telemetry metrics sampled from the paired Windows 11 workstation.
struct GpuTelemetryData: Codable {
    /// Human-readable GPU adapter model name (e.g., `"NVIDIA GeForce RTX 4080"`).
    let gpu_name: String
    /// Core die temperature in degrees Celsius (`°C`).
    let temperature_c: UInt32
    /// Real-time board power draw in Watts (`W`).
    let power_usage_watts: Float
    /// Compute / 3D engine utilization percentage (`0..100%`).
    let gpu_utilization_percent: UInt32
    /// Dedicated video memory controller utilization percentage (`0..100%`).
    let memory_utilization_percent: UInt32
    /// Currently allocated dedicated VRAM in megabytes (`MB`).
    let memory_used_mb: UInt64
    /// Total physical dedicated VRAM capacity in megabytes (`MB`).
    let memory_total_mb: UInt64
    /// Active graphics core clock frequency in megahertz (`MHz`).
    let core_clock_mhz: UInt32
}

/// Deserialized fallback response payload from `fetch_rust_gpu_telemetry_json`.
struct DisplayRpcResponseData: Codable {
    /// Indicates whether the remote RPC query succeeded.
    let success: Bool
    /// Diagnostic status message from the remote display controller.
    let message: String
    /// Whether the remote virtual display stream is currently active.
    let is_active: Bool
    /// Optional human-readable mode string (e.g., `"2560x1440@120Hz"`).
    let active_mode: String?
    /// Optional GPU telemetry snapshot attached to the display response.
    let gpu_telemetry: GpuTelemetryData?
}

/// Deserialized Windows Global System Media Transport Controls (GSMTC) playback state.
struct MediaPlaybackStateData: Codable {
    /// Current media track title.
    let title: String
    /// Current media artist or channel name.
    let artist: String
    /// Source media application identifier or display name.
    let app_name: String
    /// `true` when playback is actively running; `false` when paused or stopped.
    let is_playing: Bool
    /// Current playback elapsed position in seconds (`s`).
    let position_secs: Double
    /// Total track duration in seconds (`s`).
    let duration_secs: Double
    /// `true` if an active media session exists on the paired Windows machine.
    let has_session: Bool
}

/// Aggregated live Touch Bar state snapshot returned by `fetch_rust_touchbar_snapshot_json`.
struct TouchBarLiveSnapshotData: Codable {
    /// Optional live GPU hardware telemetry from the Windows peer.
    let gpu_telemetry: GpuTelemetryData?
    /// Optional live Windows GSMTC media playback state.
    let media_state: MediaPlaybackStateData?
    /// Whether the macOS Shared Camera stream is currently active.
    let camera_active: Bool
    /// Whether the Hardware Camera Privacy Killswitch shutter is currently engaged (muted).
    let camera_muted: Bool
}

// MARK: - Feature 1: Visual Touch ID Passkey & UAC Animated Sensor Pointer View
/// Illuminated animated Touch Bar strip pinned to the far-right corner pointing directly
/// toward the MacBook Pro physical Touch ID sensor (`[ 🛡️ Approve ... ] ───────> 👆 [Touch ID]`).
final class TouchIdPromptGlowView: NSView {
    /// Frosted dark-emerald HUD backdrop container.
    private let bgEffect = NSVisualEffectView()
    /// Sweeping horizontal cyan/green light gradient indicating physical Touch ID direction.
    private let sweepLayer = CAGradientLayer()
    /// Primary prompt description text shown on the left side of the strip.
    private let label = NSTextField(labelWithString: "")
    /// Monospaced directional pointer leading to the physical Touch ID key.
    private let arrowLabel = NSTextField(labelWithString: "───────▶  👆 Touch ID")
    /// Pulsing green beacon ring aligned at the far-right edge beside Touch ID.
    private let pulseRing = CALayer()
    /// Fixed horizontal layout width in AppKit points (`460 pt`).
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

    /// Configures subviews, gradient layers, AutoLayout constraints, and initial sweep animations.
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

    /// Updates the displayed authentication prompt string and restarts pulse animations.
    func updateLabel(_ text: String) {
        let clean = text.trimmingCharacters(in: .whitespacesAndNewlines)
        label.stringValue = clean.isEmpty ? "🛡️ Approve Windows Hello Login" : "🛡️ \(clean)"
        startPulseAnimations()
    }

    /// Starts continuous left-to-right gradient sweep and beacon scale animations.
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

/// Frosted Liquid Glass Touch Bar button view featuring critically-damped tactile spring settle
/// (`zeta = 1.0`), haptic feedback, and direct NSTouch/mouse hit-slop tracking.
class GoopyLiquidGlassPillView: NSView {
    /// Frosted `.hudWindow` blur layer rendering the tinted glass pill body.
    let visualEffectView = NSVisualEffectView()
    /// Centered single-line monospaced label rendered atop `visualEffectView`.
    let label = NSTextField(labelWithString: "")
    /// Semantic tint accent applied to the glass background and active glow border.
    var accentColor: NSColor = .systemGreen {
        didSet { updateRestingStyle() }
    }
    /// Tap action closure invoked cleanly when touch/mouse ends inside tap slop.
    var onTap: (() -> Void)?

    /// Starting point of the current touch/drag gesture for micro-translation clamping.
    private var initialTouchPoint: CGPoint = .zero
    /// Active `NSTouch.identity` tracked exclusively until touch end/cancel.
    private var activeTouchIdentity: AnyObject? = nil
    /// Whether the pill is currently depressed under a touch or mouse click.
    private var isHeld: Bool = false
    /// Whether the tracked pointer remains inside expanded tap slop bounds.
    private var isTouchInside: Bool = false
    /// Intrinsic pill width in Touch Bar points (`30 pt` fixed height).
    private let pillWidth: CGFloat

    /// Creates a new Liquid Glass pill view with the specified initial label, accent color, and width.
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

    override func viewWillMove(toWindow newWindow: NSWindow?) {
        super.viewWillMove(toWindow: newWindow)
        if newWindow == nil && isHeld {
            activeTouchIdentity = nil
            endInteraction(triggerTap: false)
        }
    }

    /// Configures frosted glass subviews and AutoLayout label centering.
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

    /// Updates the pill text safely on the main AppKit thread.
    func setText(_ newText: String) {
        DispatchQueue.main.async { [weak self] in
            self?.label.stringValue = newText
        }
    }

    /// Updates the pill accent tint safely on the main AppKit thread.
    func setAccent(_ color: NSColor) {
        DispatchQueue.main.async { [weak self] in
            self?.accentColor = color
        }
    }

    /// Applies the unpressed Liquid Glass surface border, tint, and resting glow parameters.
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

    /// Builds a center-pivoted 3D transform (`sx`, `sy`, horizontal micro-translation `tx`) around `bounds`.
    private func centeredTransform(sx: CGFloat, sy: CGFloat, tx: CGFloat = 0) -> CATransform3D {
        let cx = bounds.midX
        let cy = bounds.midY
        var t = CATransform3DIdentity
        t = CATransform3DTranslate(t, cx + tx, cy, 0)
        t = CATransform3DScale(t, sx, sy, 1.0)
        t = CATransform3DTranslate(t, -cx, -cy, 0)
        return t
    }

    /// Returns `true` if `pt` lies within forgiving Touch Bar finger slop bounds (`dx = -18pt, dy = -20pt`).
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
    /// Frosted `.hudWindow` blur container rendering the scrubber pill backdrop.
    private let bgEffect = NSVisualEffectView()
    /// Formatted `m:ss` current playback or scrub position indicator.
    private let elapsedLabel = NSTextField(labelWithString: "0:00")
    /// Formatted `m:ss` total duration indicator (`--:--` when no active session).
    private let totalLabel = NSTextField(labelWithString: "0:00")
    /// Container view hosting Core Animation track, fill, and circular thumb layers.
    private let trackContainer = NSView()
    /// Capsule background rail layer representing `0%..100%` track length.
    private let trackBg = CALayer()
    /// Active filled progress capsule tracking `positionSecs / durationSecs`.
    private let trackFill = CALayer()
    /// Interactive circular scrubber thumb expanding from `11pt` to `14pt` while scrubbing.
    private let thumbLayer = CALayer()

    /// Intrinsic horizontal pill width in Touch Bar points (`176 pt`).
    private let pillWidth: CGFloat
    /// Capsule progress rail thickness in Touch Bar points (`6 pt`).
    private let trackHeight: CGFloat = 6.0

    /// Active `NSTouch.identity` during a direct Touch Bar drag scrub gesture.
    private var activeTouchIdentity: AnyObject? = nil
    /// True while the user is actively dragging along the scrubber rail.
    private var isScrubbing: Bool = false
    /// Hold-off timestamp preventing 1 Hz telemetry polls from snapping the thumb back while Windows seeks.
    private var scrubHoldUntil: Date = .distantPast
    /// Rate-limiter timestamp spacing live preview seeks at `>= 350 ms`.
    private var lastPreviewSentAt: Date = .distantPast

    /// Displayed playback position in seconds (`>= 0`).
    private var positionSecs: Double = 0.0
    /// Total track duration in seconds (`>= 0`).
    private var durationSecs: Double = 0.0
    /// True when the remote Windows GSMTC media session is actively playing.
    private var isPlaying: Bool = false
    /// True when Windows reports an active media transport session.
    private var hasSession: Bool = false

    /// Throttled live-preview callback invoked during dragging with target seek time in seconds.
    var onPreviewSeek: ((Double) -> Void)?
    /// Final seek commit callback invoked upon finger lift / mouse release with target seconds.
    var onCommitSeek: ((Double) -> Void)?

    /// Initializes the Liquid Glass media scrubber pill with the given Touch Bar width (`176 pt` default).
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

    /// Formats non-negative finite seconds as `m:ss` (`0:00` on non-finite or negative input).
    private static func formatTime(_ secs: Double) -> String {
        guard secs.isFinite && secs >= 0 else { return "0:00" }
        let total = Int(secs.rounded(.down))
        let mins = total / 60
        let rem = total % 60
        return String(format: "%d:%02d", mins, rem)
    }

    /// Configures monospaced timestamp typography for elapsed and total duration labels.
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

    /// Initializes frosted glass backdrop, timestamp fields, and track/thumb sublayers.
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

    /// Updates track playback position, duration, and active session visual state on the main thread.
    ///
    /// Respects active scrubbing gestures and the 2.4-second seek-confirmation hold window to prevent
    /// remote polling jitter from snapping the scrubber thumb backwards.
    func update(position: Double, duration: Double, isPlaying: Bool, hasSession: Bool) {
        self.durationSecs = duration.isFinite ? max(duration, 0.0) : 0.0
        self.isPlaying = isPlaying
        self.hasSession = hasSession
        self.totalLabel.stringValue = hasSession && self.durationSecs > 0.5 ? Self.formatTime(self.durationSecs) : "--:--"

        let safePos = position.isFinite ? position : 0.0
        if !self.isScrubbing {
            let now = Date()
            if now < self.scrubHoldUntil {
                // Keep showing the user's scrubbed position until Windows confirms the seek
                if abs(safePos - self.positionSecs) <= 3.0 {
                    self.scrubHoldUntil = .distantPast
                    self.positionSecs = min(max(safePos, 0.0), max(self.durationSecs, 0.0))
                }
            } else {
                self.positionSecs = hasSession ? min(max(safePos, 0.0), max(self.durationSecs, 0.0)) : 0.0
            }
        }

        layoutSublayersAndFrames(animated: false)
    }

    /// Recomputes elapsed/total label bounds, progress fill geometry, and thumb diameter.
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

/// Singleton coordinator managing the macOS system-modal Touch Bar HUD, persistent `∫` Control
/// Strip tray item, 1 Hz telemetry/media polling, and dynamic Touch Bar layout switching.
@objc public class TouchBarHudController: NSObject, NSTouchBarDelegate {
    /// Shared singleton instance driving in-process and standalone Touch Bar HUD lifecycles.
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
    /// Mutex synchronizing `peerIp`, `rpcPort`, `_isActive`, `_generation`, `isPollingInFlight`, and cached GPU telemetry.
    private let stateLock = NSLock()

    /// Internal active-HUD flag synchronized under `stateLock`.
    private var _isActive: Bool = false
    /// Returns `true` when the system-modal Touch Bar HUD is currently active.
    public var isActive: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _isActive
    }

    /// Validated peer IPv4/IPv6 string synchronized under `stateLock`.
    private var _peerIp: String? = nil
    /// Normalized remote peer IPv4/IPv6 literal used as an optional RPC telemetry target hint.
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

    /// Active Touch Bar presentation mode: primary HUD strip (`.main`) or expanded GPU metrics strip (`.gpu`).
    private enum TouchBarPanelMode {
        case main
        case gpu
    }

    /// Dynamically loaded handle to `/System/Library/PrivateFrameworks/DFRFoundation.framework/DFRFoundation`.
    private static let dfrHandle: UnsafeMutableRawPointer? = {
        dlopen("/System/Library/PrivateFrameworks/DFRFoundation.framework/DFRFoundation", RTLD_LAZY)
    }()

    /// Enables or disables the native system `X` close box when the system-modal Touch Bar is frontmost.
    private static func setDfrShowsCloseBox(_ shows: Bool) {
        guard let handle = dfrHandle,
              let sym = dlsym(handle, "DFRSystemModalShowsCloseBoxWhenFrontMost") else { return }
        typealias Fn = @convention(c) (Bool) -> Void
        unsafeBitCast(sym, to: Fn.self)(shows)
    }

    /// Sets the visibility presence of the persistent `∫` item in the macOS Control Strip.
    private static func setDfrControlStripPresence(_ identifier: NSTouchBarItem.Identifier, present: Bool) {
        guard let handle = dfrHandle,
              let sym = dlsym(handle, "DFRElementSetControlStripPresenceForIdentifier") else { return }
        typealias Fn = @convention(c) (CFString, Bool) -> Void
        unsafeBitCast(sym, to: Fn.self)(identifier.rawValue as CFString, present)
    }

    /// Persistent Control Strip item identifier for the `∫` restore button.
    private let systemTrayItemId = NSTouchBarItem.Identifier("com.manveersingh.integrator.touchbar.tray")
    /// Retained reference to the persistent Control Strip `NSCustomTouchBarItem`.
    private var systemTrayItem: NSCustomTouchBarItem? = nil
    /// KVO observation token tracking `NSTouchBar.isVisible` to detect external dismissal via the `X` close button.
    private var visibilityObservation: NSKeyValueObservation? = nil
    /// Tracks whether the current modal `NSTouchBar` instance has completed initial presentation.
    private var hasEverBeenVisible: Bool = false
    /// Current sub-panel mode (`.main` or `.gpu`).
    private var activeMode: TouchBarPanelMode = .main

    /// Monotonically increasing session generation counter used to discard stale async poll callbacks.
    private var _generation: UInt64 = 0
    /// Guards against overlapping background telemetry RPC polls.
    private var isPollingInFlight: Bool = false
    /// Cached GPU telemetry metrics from the most recent poll cycle.
    private var lastGpuTelemetry: GpuTelemetryData? = nil
    /// Formatted label for an announced pending remote clipboard file (`📥 Paste <name> (<size>)`).
    private var pendingPasteText: String? = nil

    /// Checks whether the given session generation matches the currently active Touch Bar generation.
    private func isGenerationCurrent(_ gen: UInt64) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _isActive && _generation == gen
    }

    /// Active system-modal `NSTouchBar` instance.
    var touchBar: NSTouchBar?
    /// 1 Hz main-RunLoop timer driving background telemetry and media state polling.
    var pollTimer: Timer?

    /// Compact GPU name + die temperature pill shown in `.main` strip (taps into `.gpu` detail strip).
    var viewGpu: GoopyLiquidGlassPillView?
    /// GPU core temperature (`°C`) pill in `.gpu` detail strip.
    var viewTemp: GoopyLiquidGlassPillView?
    /// GPU board power draw (`W`) pill in `.gpu` detail strip.
    var viewPower: GoopyLiquidGlassPillView?
    /// GPU graphics core clock (`MHz`) pill in `.gpu` detail strip.
    var viewClock: GoopyLiquidGlassPillView?
    /// GPU dedicated VRAM utilization (`used / total GB`) pill in `.gpu` detail strip.
    var viewVram: GoopyLiquidGlassPillView?
    /// GPU 3D engine utilization percentage (`%`) pill in `.gpu` detail strip.
    var viewUtil: GoopyLiquidGlassPillView?
    /// Dynamic Remote Paste announcement & transfer progress pill (`📥 Paste ...`).
    var viewPaste: GoopyLiquidGlassPillView?

    /// Far-right animated Touch ID prompt banner (`touchid_prompt`).
    var viewTouchIdPrompt: TouchIdPromptGlowView?
    /// True while the full-width Touch ID prompt takeover banner is displayed.
    private var touchIdPromptActive: Bool = false
    /// Display prompt text shown inside `viewTouchIdPrompt`.
    private var touchIdPromptLabel: String = "Approve Windows Hello Login"
    /// Remembers whether the standard HUD was active prior to Touch ID takeover so dismissal restores cleanly.
    private var hudWasActiveBeforeTouchId: Bool = false

    /// Hardware Camera Privacy Killswitch pill (`🟢 FaceTime HD` / `🚫 Cam Muted`).
    var viewCameraPrivacy: GoopyLiquidGlassPillView?
    /// True while macOS Shared Camera video capture is actively streaming to Windows.
    private var cameraIsActive: Bool = false
    /// True while the Hardware Camera Privacy Killswitch shutter is engaged.
    private var cameraIsMuted: Bool = false

    /// Windows media transport Play/Pause pill (`▶️` / `⏸️`).
    var viewMediaPlayPause: GoopyLiquidGlassPillView?
    /// Active track title & artist ticker pill in `.main` strip.
    var viewMediaTrackLabel: GoopyLiquidGlassPillView?
    /// Rounded Liquid Glass media scrub bar (`LiquidGlassMediaScrubPillView`).
    var viewMediaScrub: LiquidGlassMediaScrubPillView?
    /// Most recently polled Windows GSMTC media state cached for optimistic play/pause feedback.
    private var currentMediaState: MediaPlaybackStateData? = nil

    /// Validates an optional raw IP string as a syntactically valid IPv4 or IPv6 literal via `inet_pton`.
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

    /// One-time probe checking system-modal `NSTouchBar` selector availability plus physical DFR / ControlStrip presence.
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

    /// Formats an arbitrary byte size into a compact Touch Bar display string (`B`, `KB`, `MB`, `GB`).
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

    /// Displays and activates the Remote Paste announcement pill on the Touch Bar for an announced file.
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

    /// Updates the Remote Paste pill with finite, clamped completion percentage (`0..100%`) and rate (`MB/s`).
    public func updatePasteProgress(percent: Float, mbPerSec: Float) {
        guard Self.isTouchBarSupported() else { return }
        let safePct = percent.isFinite ? min(max(percent, 0.0), 100.0) : 0.0
        let safeRate = mbPerSec.isFinite ? max(mbPerSec, 0.0) : 0.0
        DispatchQueue.main.async { [weak self] in
            guard let self = self, let view = self.viewPaste else { return }
            view.setText(String(format: "📥 %.0f%% • %.0f MB/s", safePct, safeRate))
            view.setAccent(NSColor.systemGreen)
        }
    }

    /// Removes and resets the Remote Paste Touch Bar pill after transfer finishes or cancels.
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

    /// Launches or refreshes the Touch Bar HUD targeting an optional peer IP hint.
    public func launch_touchbar_hud(peerIp: String? = nil) {
        start(peerIp: peerIp)
    }

    // MARK: - Control Strip Persistent System Tray Button (∫)

    /// Enables or removes the persistent `∫` Control Strip system tray button on main thread.
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

    /// Registers the persistent `∫` button inside the macOS Control Strip (`DispatchQueue.main` only).
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

    /// Unregisters and releases the persistent `∫` button from the macOS Control Strip (`DispatchQueue.main` only).
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

    /// Toggles system-modal Touch Bar HUD visibility when the user taps `∫` in Control Strip.
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

    /// Validates `peerIp` (if provided) and presents or refreshes the system-modal Touch Bar HUD.
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

    /// Instantiates the modal `NSTouchBar`, bumps session generation, and starts 1 Hz polling.
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

    /// Tears down active KVO tokens, timers, and pill view references while keeping `∫` in Control Strip.
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
        self.viewCameraPrivacy = nil
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

    /// Handles external system dismissal (such as tapping macOS's `X` close box) observed via KVO.
    private func handleExternalDismissalIfNeeded(bar: NSTouchBar) {
        guard self.touchBar === bar, !bar.isVisible, self.isActive else { return }
        self.cleanupAfterDismissalOnMain(clearSystemBar: false)
    }

    /// Programmatically dismisses the system-modal Touch Bar HUD if active.
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

    /// Computes the ordered `NSTouchBarItem.Identifier` list for the current `activeMode` (`.main` or `.gpu`).
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

    /// Switches between `.main` and `.gpu` strips on the main thread when not overridden by Touch ID.
    private func switchMode(_ newMode: TouchBarPanelMode) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.isActive, !self.touchIdPromptActive else { return }
            self.activeMode = newMode
            self.refreshTouchBarIdentifiersOnMain()
            switch newMode {
            case .main:
                self.applyCameraPillStyle()
                self.applyMediaUi(self.currentMediaState)
                self.stateLock.lock()
                let cached = self.lastGpuTelemetry
                self.stateLock.unlock()
                if let t = cached {
                    self.updateUi(with: t)
                }
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

    /// Reapplies `defaultItemIdentifiers` on the active `NSTouchBar` prioritizing Touch ID takeover when active.
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

    /// Shows or dismisses the full-width glowing Touch ID directional prompt banner (`touchid_prompt`).
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

    /// Synchronizes Camera Privacy pill visibility and muted/live appearance cleanly on main thread.
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

    /// Updates the Camera Privacy Killswitch pill text and semantic color (green live / red muted).
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

    // MARK: - Expanded Windows Media Control Actions

    /// Refreshes Windows GSMTC track title, Play/Pause pill, and Liquid Glass scrub bar on main thread.
    private func applyMediaUi(_ st: MediaPlaybackStateData?) {
        currentMediaState = st
        if let m = st, m.has_session, !m.title.isEmpty {
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
            viewMediaPlayPause?.setText("▶️")
            viewMediaPlayPause?.setAccent(.systemGray)
            viewMediaTrackLabel?.setText("🎵 No Windows Media")
            viewMediaTrackLabel?.setAccent(.systemGray)
            viewMediaScrub?.update(position: 0.0, duration: 0.0, isPlaying: false, hasSession: false)
        }
    }

    /// Dispatches a non-blocking Windows GSMTC seek command across C FFI and optionally refreshes telemetry.
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

    /// Instantiates and presents the system-modal `NSTouchBar` and installs the `isVisible` KVO watcher.
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

    /// NSTouchBarDelegate factory constructing each active Liquid Glass pill, media scrubber, or Touch ID view.
    public func touchBar(_ touchBar: NSTouchBar, makeItemForIdentifier identifier: NSTouchBarItem.Identifier) -> NSTouchBarItem? {
        switch identifier.rawValue {
        // MARK: Back navigation pill for GPU detail sub-bar
        case "back_to_main":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = GoopyLiquidGlassPillView(text: "◀", accent: .systemGray, width: 42)
            v.onTap = { [weak self] in self?.switchMode(.main) }
            item.view = v
            item.visibilityPriority = .high
            return item

        // MARK: Visual Touch ID Passkey Prompt (far-right glowing pointer)
        case "touchid_prompt":
            let item = NSCustomTouchBarItem(identifier: identifier)
            let v = TouchIdPromptGlowView()
            v.updateLabel(self.touchIdPromptLabel)
            self.viewTouchIdPrompt = v
            item.view = v
            item.visibilityPriority = .high
            return item

        // MARK: Hardware Camera Privacy Killswitch
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
                    // Read main-thread-owned `cameraIsActive` strictly on DispatchQueue.main to avoid data races.
                    DispatchQueue.main.async {
                        guard let self = self else { return }
                        self.updateCameraState(active: self.cameraIsActive, muted: muted)
                    }
                }
            }
            self.viewCameraPrivacy = v
            item.view = v
            item.visibilityPriority = .high
            return item

        // MARK: Expanded Windows Media Controls
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

    /// Starts the 1 Hz common-modes telemetry timer and watches for external system dismissal.
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

    /// Dispatches an asynchronous C FFI snapshot query guarded by `_generation` and `isPollingInFlight`.
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
                }
            } else if let host = self.peerIp,
                      let response = self.fetchFallbackGpuTelemetry(host: host),
                      response.success,
                      let telemetry = response.gpu_telemetry {
                guard self.isGenerationCurrent(gen) else { return }
                self.updateUi(with: telemetry, expectedGeneration: gen)
            } else {
                self.updateOfflineUi(statusText: "Peer Offline", expectedGeneration: gen)
            }
        }
    }

    /// Queries the unified Touch Bar live snapshot from Rust across C FFI (`<= 64 KiB` JSON).
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

    /// Queries standalone GPU telemetry from Rust if the aggregated snapshot is unavailable.
    private func fetchFallbackGpuTelemetry(host: String) -> DisplayRpcResponseData? {
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

    /// Normalizes and truncates long GPU adapter names (to `<= 14` chars) to fit the compact GPU pill.
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

    /// Updates all GPU telemetry pills to a neutral offline placeholder state on the main thread.
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

    /// Updates the compact GPU pill and `.gpu` detail strip metrics with color-coded thermal states.
    func updateUi(with t: GpuTelemetryData, expectedGeneration: UInt64? = nil) {
        self.stateLock.lock()
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
                (t.power_usage_watts.isFinite && t.power_usage_watts > 0.05) ||
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
                if t.power_usage_watts.isFinite && t.power_usage_watts > 0.05 {
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
}

// MARK: - C FFI Interface for Main App Integration

/// Configures the TCP control RPC port forwarded from Rust (`config::CONTROL_PORT`).
@_cdecl("set_touchbar_rpc_port_in_app")
public func set_touchbar_rpc_port_in_app(port: UInt16) {
    TouchBarHudController.shared.rpcPort = port
}

/// Initializes or refreshes the system-modal Touch Bar HUD targeting an optional peer IP string.
@_cdecl("init_touchbar_in_app")
public func init_touchbar_in_app(peerIpPtr: UnsafePointer<CChar>?) {
    let peerIp = peerIpPtr != nil ? String(cString: peerIpPtr!) : nil
    TouchBarHudController.shared.launch_touchbar_hud(peerIp: peerIp)
}

/// Dismisses the system-modal Touch Bar HUD while keeping the persistent `∫` Control Strip tray item.
@_cdecl("dismiss_touchbar_in_app")
public func dismiss_touchbar_in_app() {
    TouchBarHudController.shared.dismiss()
}

/// Returns `true` while the system-modal Touch Bar HUD is active.
@_cdecl("is_touchbar_active_in_app")
public func is_touchbar_active_in_app() -> Bool {
    return TouchBarHudController.shared.isActive
}

/// Installs or removes the persistent `∫` Control Strip tray restore item.
@_cdecl("set_touchbar_tray_enabled_in_app")
public func set_touchbar_tray_enabled_in_app(enabled: Bool) {
    TouchBarHudController.shared.setSystemTrayEnabled(enabled)
}

/// Retained GCD signal sources ensuring clean `SIGINT`/`SIGTERM` shutdown in standalone Touch Bar CLI mode.
private var touchBarCliSignalSources: [DispatchSourceSignal] = []

/// Runs the blocking AppKit Touch Bar HUD event loop for standalone CLI invocation (`core.rs`),
/// exiting cleanly on `SIGINT` or `SIGTERM` via main-queue GCD signal sources.
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

/// Rust C-ABI entrypoint triggering on-demand zero-RAM remote file paste streaming (`clipboard/service.rs`).
@_silgen_name("trigger_rust_remote_paste")
func trigger_rust_remote_paste()

/// Rust C-ABI fallback query returning standalone GPU telemetry JSON (`display/controller.rs`).
@_silgen_name("fetch_rust_gpu_telemetry_json")
func fetch_rust_gpu_telemetry_json(_ peerIp: UnsafePointer<CChar>?, _ outBuf: UnsafeMutablePointer<UInt8>?, _ cap: Int) -> Int

/// Rust C-ABI query returning the unified Touch Bar snapshot JSON (`core.rs`).
@_silgen_name("fetch_rust_touchbar_snapshot_json")
func fetch_rust_touchbar_snapshot_json(_ peerIp: UnsafePointer<CChar>?, _ outBuf: UnsafeMutablePointer<UInt8>?, _ cap: Int) -> Int

/// Rust C-ABI toggle switching the Hardware Camera Privacy Killswitch shutter (`core.rs`).
@_silgen_name("toggle_rust_camera_privacy_mute")
func toggle_rust_camera_privacy_mute() -> Bool

/// Rust C-ABI command dispatching Windows GSMTC media control (`0=PlayPause, 1=Next, 2=Prev, 3=Seek`) (`core.rs`).
@_silgen_name("send_rust_windows_media_cmd")
func send_rust_windows_media_cmd(_ cmdCode: Int32, _ seekSecs: Double) -> Bool

/// Presents or dismisses the illuminated Visual Touch ID Passkey & UAC prompt on the Touch Bar.
@_cdecl("notify_touchbar_touchid_prompt_in_app")
public func notify_touchbar_touchid_prompt_in_app(labelPtr: UnsafePointer<CChar>?, active: Bool) {
    let label = labelPtr != nil ? String(cString: labelPtr!) : "Approve Windows Hello Login"
    TouchBarHudController.shared.showTouchIdPrompt(label: label, active: active)
}

/// Synchronizes the Hardware Camera Privacy Killswitch pill state on the Touch Bar.
@_cdecl("notify_touchbar_camera_state_in_app")
public func notify_touchbar_camera_state_in_app(active: Bool, muted: Bool) {
    TouchBarHudController.shared.updateCameraState(active: active, muted: muted)
}

/// C-ABI linkage entry point declared by `core.rs` for KVM boundary lock state notifications.
/// Retained as a no-op because the KVM lock Touch Bar pill was removed from the active strip layout.
@_cdecl("notify_touchbar_kvm_lock_state_in_app")
public func notify_touchbar_kvm_lock_state_in_app(locked: Bool) {
    _ = locked
}

/// C-ABI linkage entry point declared by `core.rs` for display mode notifications.
/// Retained as a no-op because the display mode Touch Bar sub-panel was removed from the active strip layout.
@_cdecl("notify_touchbar_display_mode_in_app")
public func notify_touchbar_display_mode_in_app(width: UInt32, height: UInt32, fps: UInt32, hdr: Bool) {
    _ = (width, height, fps, hdr)
}

/// Announces a pending remote clipboard file on the Touch Bar (`📥 Paste <name> (<size>)`).
@_cdecl("notify_touchbar_remote_file")
public func notify_touchbar_remote_file(namePtr: UnsafePointer<CChar>?, totalBytes: UInt64) {
    guard let namePtr = namePtr else { return }
    let name = String(cString: namePtr)
    TouchBarHudController.shared.showRemotePasteButton(name: name, totalBytes: totalBytes)
}

/// Updates the Touch Bar remote paste pill with live transfer percentage and MB/s throughput.
@_cdecl("update_touchbar_paste_progress")
public func update_touchbar_paste_progress(percent: Float, mbPerSec: Float) {
    PasteboardShortcutInterceptor.shared.touchPasteActivity()
    TouchBarHudController.shared.updatePasteProgress(percent: percent, mbPerSec: mbPerSec)
}

/// Resets and hides the Touch Bar remote paste pill after transfer completion or cancellation.
@_cdecl("reset_touchbar_paste_progress")
public func reset_touchbar_paste_progress() {
    PasteboardShortcutInterceptor.shared.isPasting = false
    TouchBarHudController.shared.resetPasteButton()
}

// MARK: - Native Finder Cmd+V Shortcut Interceptor
/// Intercepts `Cmd+V` inside macOS Finder when a remote file announcement is pending,
/// triggering zero-RAM on-demand file streaming from the paired Windows workstation.
public class PasteboardShortcutInterceptor: NSObject {
    /// Singleton interceptor registered on the main `CFRunLoop`.
    public static let shared = PasteboardShortcutInterceptor()

    /// Mutex guarding pending announcement flags and stale paste timestamps.
    private let lock = NSLock()
    /// True while remote Windows files await paste on the local clipboard.
    private var _hasPendingRemoteFile: Bool = false
    /// True while a streamed remote paste operation is actively downloading.
    private var _isPasting: Bool = false
    /// Timestamp of the last paste trigger or progress update (expires after 30 seconds).
    private var _pasteStartedAt: Date? = nil
    /// Installed Quartz session-level key-down event tap (`CGEventTap`).
    private var eventTap: CFMachPort?
    /// `CFRunLoopSource` attaching `eventTap` to `CFRunLoopGetMain()`.
    private var runLoopSource: CFRunLoopSource?

    /// Thread-safe toggle tracking whether a remote file announcement is currently pending.
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

    /// Thread-safe indicator tracking an active remote paste transfer (auto-expiring after 30s inactivity).
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

    /// Refreshes the inactivity timeout timestamp while remote paste progress packets arrive.
    func touchPasteActivity() {
        lock.lock()
        if _isPasting {
            _pasteStartedAt = Date()
        }
        lock.unlock()
    }

    /// Clears stale in-flight paste state if 30 seconds elapse without progress or reset (`lock` held).
    private func expireStalePastingLocked() {
        if _isPasting, let started = _pasteStartedAt, Date().timeIntervalSince(started) > 30.0 {
            _isPasting = false
            _pasteStartedAt = nil
        }
    }

    private override init() {
        super.init()
    }

    /// Installs the Accessibility-gated Finder `Cmd+V` Quartz `CGEventTap` once on main thread.
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
            ), let source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0) else {
                NSLog("ℹ️ [PasteboardShortcutInterceptor] Could not create CGEventTap; falling back to direct clipboard registration.")
                return
            }

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

    /// Returns `true` when `event` represents `Cmd+V` (without Option or Control modifiers).
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

    /// Processes `CGEventTap` events, swallowing Finder `Cmd+V` to launch streaming when a remote file is pending.
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

    /// Marks paste active, updates the Touch Bar pill with haptic feedback, and invokes `trigger_rust_remote_paste()`.
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

/// Starts the Finder `Cmd+V` remote paste shortcut interceptor.
@_cdecl("init_shortcut_interceptor")
public func init_shortcut_interceptor() {
    PasteboardShortcutInterceptor.shared.start()
}

/// Updates whether a remote file announcement is pending on the local Mac clipboard.
@_cdecl("set_has_pending_remote_file")
public func set_has_pending_remote_file(pending: Bool) {
    PasteboardShortcutInterceptor.shared.hasPendingRemoteFile = pending
}

/// Executes a closure synchronously on the main AppKit thread for safe `NSPasteboard` access.
private func onMainPasteboardSync<T>(_ work: () -> T) -> T {
    if Thread.isMainThread || !(NSApp?.isRunning ?? false) {
        return work()
    }
    return DispatchQueue.main.sync(execute: work)
}

/// Clears all contents from `NSPasteboard.general` on the main AppKit thread.
@_cdecl("clear_pasteboard_in_app")
public func clear_pasteboard_in_app() {
    _ = onMainPasteboardSync {
        NSPasteboard.general.clearContents()
    }
}

/// Reads file URLs from `NSPasteboard.general` into `outBuf` as `\0`-delimited UTF-8 paths.
///
/// - Parameters:
///   - outBuf: Caller-allocated byte buffer receiving `\0`-separated file paths.
///   - cap: Capacity of `outBuf` in bytes.
/// - Returns: `0` when no file URLs are present, `-1` when `outBuf` is null or `cap` is insufficient,
///   or exact byte count copied into `outBuf`.
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
///
/// Rejects invalid UTF-8 byte sequences cleanly rather than substituting replacement characters.
/// - Returns: `true` if one or more valid file URLs were written to `NSPasteboard.general`.
@_cdecl("write_pasteboard_files_in_app")
public func write_pasteboard_files_in_app(_ pathsPtr: UnsafePointer<UInt8>?, _ len: Int) -> Bool {
    guard let pathsPtr = pathsPtr, len > 0 else { return false }
    let buf = UnsafeBufferPointer(start: pathsPtr, count: len)
    var seen = Set<String>()
    var urls: [NSURL] = []
    for slice in buf.split(separator: 0, omittingEmptySubsequences: true) {
        guard let path = String(bytes: slice, encoding: .utf8), !path.isEmpty else { continue }
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

