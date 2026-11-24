/*
 * ============================================================================
 * Integrator Extended Desktop: macOS In-Process CGVirtualDisplay Generator
 * ============================================================================
 *
 * 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
 * ----------------------------------------------------------------------------
 * This module implements in-process macOS virtual display creation using private
 * CoreGraphics SPI (`CGVirtualDisplay`). It allows Integrator to instantiate native,
 * fully hardware-accelerated extended desktop monitors on macOS without requiring
 * third-party kernel extensions (KEXTs), DriverKit system extensions, or external
 * dummy HDMI/DisplayPort dongles.
 *
 * 2. END-TO-END CROSS-PLATFORM DISPLAY & CAMERA PIPELINE
 * ----------------------------------------------------------------------------
 * 1. In-Process Virtual Display (macOS, This File):
 *    - Dynamically loads private CoreGraphics classes (`CGVirtualDisplayDescriptor`,
 *      `CGVirtualDisplay`, `CGVirtualDisplayMode`, `CGVirtualDisplaySettings`) via
 *      `NSClassFromString` to support macOS 12 Monterey through macOS 15 Sequoia.
 *    - Injects custom vendor/product metadata:
 *      * Vendor ID:  0x494E ("IN" for Integrator)
 *      * Product ID: 0x0165
 *      * Serial No:  0x00010001
 *    - Configures native pixel geometry (`width` x `height` at `fps` Hz) and optional
 *      HiDPI modes with calculated physical millimeter dimensions (`sizeInMillimeters`).
 *    - Registers display with macOS Window Server, obtaining a valid `CGDirectDisplayID`.
 * 2. Sunshine Capture & Hardware Encoding (macOS):
 *    - `MacDisplayManager` writes `output_name = <display_id>` into `sunshine.conf`.
 *    - Sunshine captures the virtual screen via ScreenCaptureKit / Desktop Duplication.
 *    - Encodes imagery into H.264/HEVC using Apple Silicon VideoToolbox hardware encoders.
 * 3. Client Reception & Rendering (Windows 11):
 *    - Moonlight client on Windows receives stream over TCP/UDP ports 47989/48010.
 *    - Decodes with low latency using DirectX 11 / NVDEC / AMF / Intel QSV and renders
 *      in exclusive fullscreen.
 *
 * 3. COEXISTENCE WITH SHARED CAMERA SUBSYSTEM
 * ----------------------------------------------------------------------------
 * While this module provides the extended display screen for Sunshine, the Mac's
 * camera (built-in FaceTime HD, external USB, or Continuity Camera) operates concurrently:
 * - AVFoundation captures 720p30 NV12 bi-planar video (`camera_macos.swift`).
 * - Frames stream across `TransportSessionV2` on port 58287 into Windows 11 Media
 *   Foundation FrameServer (`integrator_vcam.dll` / `Integrator Mac Camera`).
 * - The Windows virtual camera operates standalone without requiring physical webcam
 *   hardware or wrapper attributes (`MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES`).
 * Both display streaming and camera capture run simultaneously with zero thread contention
 * or GPU encoder resource starvation.
 *
 * 4. THREADING & CONCURRENCY MODEL
 * ----------------------------------------------------------------------------
 * - Synchronization: Synchronized lock object `vd_lock_obj()` guards global state
 *   (`g_virtual_display`, `g_virtual_display_id`, `g_vd_queue`).
 * - Dedicated Dispatch Queue: A serial GCD queue labeled dynamically from
 *   `[[NSBundle mainBundle] bundleIdentifier]` + `.vd` (fallback `com.integrator.vd`)
 *   handles asynchronous termination callbacks from CoreGraphics.
 * - Spontaneous Teardown Handling: The `terminationHandler` block automatically
 *   resets global state if the display is terminated by the OS (e.g. system sleep/wake).
 *
 * 5. SAFETY & COMPATIBILITY INVARIANTS
 * ----------------------------------------------------------------------------
 * - Dynamic SPI Verification: Uses `NSClassFromString` and `respondsToSelector:` before
 *   invoking private methods, preventing crashes on unsupported or future macOS releases.
 * - Exception Containment: All CoreGraphics interactions are wrapped in `@try / @catch`
 *   blocks to isolate Objective-C exceptions from crossing the FFI boundary into Rust.
 * - ARC Memory Management: Compiled with Automatic Reference Counting (`-fobjc-arc`).
 * ============================================================================
 */

#if !__has_feature(objc_arc)
#error "virtual_display.m requires ARC (-fobjc-arc)"
#endif

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <dispatch/dispatch.h>
#import <objc/runtime.h>
#import <math.h>
#import <stdint.h>
#import <stdbool.h>

/// Custom vendor ID ('IN' in ASCII = 0x494E) for unambiguous Integrator identification.
static const uint32_t INTEGRATOR_VD_VENDOR  = 0x494E;

/// Custom product ID (0x0165) for Integrator Virtual Display.
static const uint32_t INTEGRATOR_VD_PRODUCT = 0x0165;

/// Custom serial number (0x00010001) for Integrator Virtual Display.
static const uint32_t INTEGRATOR_VD_SERIAL  = 0x00010001;

/// Fallback horizontal display resolution in pixels when caller passes 0.
static const uint32_t kDefaultVirtualDisplayWidth  = 1920;

/// Fallback vertical display resolution in pixels when caller passes 0.
static const uint32_t kDefaultVirtualDisplayHeight = 1080;

/// Fallback display refresh rate in Hertz when caller passes 0 or OS reports 0 Hz.
static const uint32_t kDefaultVirtualDisplayFps    = 60;

/// User-facing monitor display name registered with CoreGraphics Window Server.
static NSString * const kDefaultVirtualDisplayName = @"Integrator Extended Display";

/// Fallback GCD queue label when host application has no bundle identifier.
static NSString * const kFallbackVdQueueLabel = @"com.integrator.vd";

/// Maximum supported virtual display pixel width or height (16K upper bound).
static const uint32_t kMaxVirtualDisplayDimension = 16384;

/// Maximum supported virtual display refresh rate in Hertz (`480 Hz`).
static const uint32_t kMaxVirtualDisplayFps = 480;

/// Objective-C protocol interface describing the private `CGVirtualDisplayMode` class.
/// Parameter types (`uint32_t`, `double`, `BOOL`) match Apple CoreGraphics SPI ObjC type encodings
/// (`I`, `d`, `B`) verified directly on macOS ARM64.
@interface IntegratorVDModeProto : NSObject
- (instancetype)initWithWidth:(uint32_t)width height:(uint32_t)height refreshRate:(double)refreshRate;
@end

/// Objective-C protocol interface describing the private `CGVirtualDisplaySettings` class.
@interface IntegratorVDSettingsProto : NSObject
- (void)setHiDPI:(uint32_t)hiDPI;
- (void)setModes:(NSArray *)modes;
@end

/// Objective-C protocol interface describing the private `CGVirtualDisplayDescriptor` class.
@interface IntegratorVDDescriptorProto : NSObject
- (void)setName:(NSString *)name;
- (void)setMaxPixelsWide:(uint32_t)w;
- (void)setMaxPixelsHigh:(uint32_t)h;
- (void)setSizeInMillimeters:(CGSize)sz;
- (void)setProductID:(uint32_t)pid;
- (void)setVendorID:(uint32_t)vid;
- (void)setSerialNum:(uint32_t)sn;
- (void)setQueue:(dispatch_queue_t)q;
- (void)setTerminationHandler:(void (^)(id display, NSError *error))handler;
@end

/// Objective-C protocol interface describing the private `CGVirtualDisplay` class.
@interface IntegratorVDProto : NSObject
- (CGDirectDisplayID)displayID;
- (instancetype)initWithDescriptor:(id)descriptor;
- (BOOL)applySettings:(id)settings;
@end

/// Retained reference to the active `CGVirtualDisplay` instance.
static id g_virtual_display = nil;

/// Dedicated serial GCD queue for CoreGraphics virtual display event handling.
static dispatch_queue_t g_vd_queue = nil;

/// Active CoreGraphics display identifier assigned by Window Server.
static CGDirectDisplayID g_virtual_display_id = 0;

/// Returns a shared singleton synchronization object for `@synchronized` locking.
static NSObject *vd_lock_obj(void) {
    static NSObject *lock = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        lock = [[NSObject alloc] init];
    });
    return lock;
}

/// Instantiates an in-process virtual display on macOS using private CoreGraphics SPI.
///
/// - Parameters:
///   - width: Display width in pixels (`1..16384`; defaults to `1920` when `0` or out-of-range).
///   - height: Display height in pixels (`1..16384`; defaults to `1080` when `0` or out-of-range).
///   - fps: Refresh rate in Hertz (`1..480`; defaults to `60` when `0` or out-of-range).
///   - hi_dpi: Whether to synthesize 2x HiDPI scaled logical modes.
/// - Returns: CoreGraphics `CGDirectDisplayID` on success, or `0` on failure.
uint32_t start_virtual_display_in_app(uint32_t width, uint32_t height, uint32_t fps, bool hi_dpi) {
    @autoreleasepool {
        @try {
            // Dynamically resolve private SPI classes
            Class descCls = NSClassFromString(@"CGVirtualDisplayDescriptor");
            Class dispCls = NSClassFromString(@"CGVirtualDisplay");
            Class modeCls = NSClassFromString(@"CGVirtualDisplayMode");
            Class setCls  = NSClassFromString(@"CGVirtualDisplaySettings");

            if (!descCls || !dispCls || !modeCls || !setCls) {
                NSLog(@"[Integrator] CGVirtualDisplay private classes unavailable on this macOS version");
                return 0;
            }

            if (width == 0 || width > kMaxVirtualDisplayDimension) width = kDefaultVirtualDisplayWidth;
            if (height == 0 || height > kMaxVirtualDisplayDimension) height = kDefaultVirtualDisplayHeight;
            if (fps == 0 || fps > kMaxVirtualDisplayFps) fps = kDefaultVirtualDisplayFps;

            @synchronized(vd_lock_obj()) {
                if (!g_vd_queue) {
                    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
                    NSString *queueLabel = (bundleId.length > 0)
                        ? [bundleId stringByAppendingString:@".vd"]
                        : kFallbackVdQueueLabel;
                    g_vd_queue = dispatch_queue_create([queueLabel UTF8String], DISPATCH_QUEUE_SERIAL);
                }

                // Tear down any previous virtual display cleanly before creating a new one with the same serial.
                g_virtual_display = nil;
                g_virtual_display_id = 0;

                id desc = [[descCls alloc] init];
                if (!desc ||
                    ![desc respondsToSelector:@selector(setName:)] ||
                    ![desc respondsToSelector:@selector(setMaxPixelsWide:)] ||
                    ![desc respondsToSelector:@selector(setMaxPixelsHigh:)] ||
                    ![desc respondsToSelector:@selector(setSizeInMillimeters:)] ||
                    ![desc respondsToSelector:@selector(setProductID:)] ||
                    ![desc respondsToSelector:@selector(setVendorID:)] ||
                    ![desc respondsToSelector:@selector(setSerialNum:)] ||
                    ![desc respondsToSelector:@selector(setQueue:)]) {
                    NSLog(@"[Integrator] CGVirtualDisplayDescriptor missing expected SPI selectors");
                    return 0;
                }

                [(IntegratorVDDescriptorProto *)desc setName:kDefaultVirtualDisplayName];
                [(IntegratorVDDescriptorProto *)desc setMaxPixelsWide:width];
                [(IntegratorVDDescriptorProto *)desc setMaxPixelsHigh:height];

                // Calculate realistic physical monitor size in millimeters (25.4 mm/inch)
                double ppi = hi_dpi ? 220.0 : 140.0;
                double mmW = (double)width * 25.4 / ppi;
                double mmH = (double)height * 25.4 / ppi;
                [(IntegratorVDDescriptorProto *)desc setSizeInMillimeters:CGSizeMake(mmW, mmH)];
                [(IntegratorVDDescriptorProto *)desc setProductID:INTEGRATOR_VD_PRODUCT];
                [(IntegratorVDDescriptorProto *)desc setVendorID:INTEGRATOR_VD_VENDOR];
                [(IntegratorVDDescriptorProto *)desc setSerialNum:INTEGRATOR_VD_SERIAL];
                [(IntegratorVDDescriptorProto *)desc setQueue:g_vd_queue];

                // Handle spontaneous termination from Window Server
                if ([desc respondsToSelector:@selector(setTerminationHandler:)]) {
                    [(IntegratorVDDescriptorProto *)desc setTerminationHandler:^(id _Nullable terminatedDisp, NSError * _Nullable err) {
                        @synchronized(vd_lock_obj()) {
                            if (terminatedDisp == g_virtual_display ||
                                (terminatedDisp && [terminatedDisp respondsToSelector:@selector(displayID)] &&
                                 [(IntegratorVDProto *)terminatedDisp displayID] == g_virtual_display_id)) {
                                g_virtual_display = nil;
                                g_virtual_display_id = 0;
                            }
                        }
                        if (err) {
                            NSLog(@"[Integrator] CGVirtualDisplay terminated with error: %@", err);
                        }
                    }];
                }

                id dispAlloc = [dispCls alloc];
                if (![dispAlloc respondsToSelector:@selector(initWithDescriptor:)]) {
                    NSLog(@"[Integrator] CGVirtualDisplay missing initWithDescriptor:");
                    return 0;
                }
                id disp = [(IntegratorVDProto *)dispAlloc initWithDescriptor:desc];
                if (!disp ||
                    ![disp respondsToSelector:@selector(displayID)] ||
                    ![disp respondsToSelector:@selector(applySettings:)]) {
                    NSLog(@"[Integrator] Failed to instantiate CGVirtualDisplay");
                    return 0;
                }

                CGDirectDisplayID did = [(IntegratorVDProto *)disp displayID];
                if (did == 0) {
                    NSLog(@"[Integrator] CGVirtualDisplay returned displayID 0");
                    return 0;
                }

                // Construct primary native display mode
                id modeAlloc = [modeCls alloc];
                if (![modeAlloc respondsToSelector:@selector(initWithWidth:height:refreshRate:)]) {
                    NSLog(@"[Integrator] CGVirtualDisplayMode missing initWithWidth:height:refreshRate:");
                    return 0;
                }
                id primaryMode = [(IntegratorVDModeProto *)modeAlloc initWithWidth:width height:height refreshRate:(double)fps];
                NSMutableArray *modes = [NSMutableArray array];
                if (primaryMode) {
                    [modes addObject:primaryMode];
                }
                // Construct half-resolution logical mode for Retina HiDPI scaling
                if (hi_dpi && width >= 1600 && height >= 1200) {
                    uint32_t logicalW = (width / 2) & ~1u;
                    uint32_t logicalH = (height / 2) & ~1u;
                    if (logicalW >= 800 && logicalH >= 600) {
                        id loAlloc = [modeCls alloc];
                        if ([loAlloc respondsToSelector:@selector(initWithWidth:height:refreshRate:)]) {
                            id loDpiMode = [(IntegratorVDModeProto *)loAlloc initWithWidth:logicalW height:logicalH refreshRate:(double)fps];
                            if (loDpiMode) {
                                [modes addObject:loDpiMode];
                            }
                        }
                    }
                }
                if ([modes count] == 0) {
                    NSLog(@"[Integrator] Failed to construct CGVirtualDisplayMode list");
                    return 0;
                }

                id settings = [[setCls alloc] init];
                if (!settings ||
                    ![settings respondsToSelector:@selector(setHiDPI:)] ||
                    ![settings respondsToSelector:@selector(setModes:)]) {
                    NSLog(@"[Integrator] CGVirtualDisplaySettings missing expected selectors");
                    return 0;
                }
                [(IntegratorVDSettingsProto *)settings setHiDPI:(hi_dpi ? 1u : 0u)];
                [(IntegratorVDSettingsProto *)settings setModes:modes];

                BOOL ok = [(IntegratorVDProto *)disp applySettings:settings];
                if (!ok || !CGDisplayIsOnline(did)) {
                    NSLog(@"[Integrator] CGVirtualDisplay applySettings failed or display %u offline (%ux%u @ %uHz)", (unsigned)did, width, height, fps);
                    return 0;
                }

                g_virtual_display = disp;
                g_virtual_display_id = did;
                return (uint32_t)did;
            }
        } @catch (NSException *ex) {
            NSLog(@"[Integrator] Objective-C exception in start_virtual_display_in_app: %@ (%@)", ex.name, ex.reason);
            return 0;
        }
    }
}

/// Destroys and cleans up the active in-process virtual display.
void stop_virtual_display_in_app(void) {
    @autoreleasepool {
        @try {
            @synchronized(vd_lock_obj()) {
                g_virtual_display = nil;
                g_virtual_display_id = 0;
            }
        } @catch (NSException *ex) {
            NSLog(@"[Integrator] Exception in stop_virtual_display_in_app: %@ (%@)", ex.name, ex.reason);
        }
    }
}

/// Returns the `CGDirectDisplayID` of the active Integrator virtual display, or `0` if inactive.
uint32_t get_virtual_display_id_in_app(void) {
    @autoreleasepool {
        @try {
            @synchronized(vd_lock_obj()) {
                if (g_virtual_display != nil && g_virtual_display_id != 0) {
                    if (CGDisplayIsOnline(g_virtual_display_id)) {
                        return (uint32_t)g_virtual_display_id;
                    }
                    // Clear stale display state if CoreGraphics dropped the virtual display across sleep/wake.
                    g_virtual_display = nil;
                    g_virtual_display_id = 0;
                }
            }

            // Fallback scan for an active virtual display created by Integrator (even in a sibling CLI/process)
            uint32_t count = 0;
            if (CGGetOnlineDisplayList(0, NULL, &count) == kCGErrorSuccess && count > 0) {
                uint32_t cap = (count > 64u) ? 64u : count;
                CGDirectDisplayID *list = (CGDirectDisplayID *)calloc(cap, sizeof(CGDirectDisplayID));
                if (list) {
                    uint32_t actual = 0;
                    if (CGGetOnlineDisplayList(cap, list, &actual) == kCGErrorSuccess) {
                        for (uint32_t i = 0; i < actual; i++) {
                            if (CGDisplayIsOnline(list[i]) &&
                                CGDisplayVendorNumber(list[i]) == INTEGRATOR_VD_VENDOR &&
                                CGDisplayModelNumber(list[i]) == INTEGRATOR_VD_PRODUCT) {
                                uint32_t found = (uint32_t)list[i];
                                free(list);
                                return found;
                            }
                        }
                    }
                    free(list);
                }
            }
        } @catch (NSException *ex) {
            NSLog(@"[Integrator] Exception in get_virtual_display_id_in_app: %@ (%@)", ex.name, ex.reason);
        }
        return 0;
    }
}

/// Returns whether an Integrator virtual display is currently active.
bool is_virtual_display_active_in_app(void) {
    return get_virtual_display_id_in_app() != 0;
}

/// Selects the primary physical online display on macOS, ignoring Integrator's own virtual display.
static CGDirectDisplayID select_physical_primary_display(void) {
    CGDirectDisplayID main_id = CGMainDisplayID();
    if (main_id != kCGNullDirectDisplay &&
        CGDisplayIsOnline(main_id) &&
        !(CGDisplayVendorNumber(main_id) == INTEGRATOR_VD_VENDOR &&
          CGDisplayModelNumber(main_id) == INTEGRATOR_VD_PRODUCT)) {
        return main_id;
    }

    uint32_t count = 0;
    if (CGGetOnlineDisplayList(0, NULL, &count) == kCGErrorSuccess && count > 0) {
        uint32_t cap = (count > 64u) ? 64u : count;
        CGDirectDisplayID *list = (CGDirectDisplayID *)calloc(cap, sizeof(CGDirectDisplayID));
        if (list) {
            uint32_t actual = 0;
            if (CGGetOnlineDisplayList(cap, list, &actual) == kCGErrorSuccess) {
                for (uint32_t i = 0; i < actual; i++) {
                    if (CGDisplayIsOnline(list[i]) &&
                        !(CGDisplayVendorNumber(list[i]) == INTEGRATOR_VD_VENDOR &&
                          CGDisplayModelNumber(list[i]) == INTEGRATOR_VD_PRODUCT)) {
                        CGDirectDisplayID phys = list[i];
                        free(list);
                        return phys;
                    }
                }
            }
            free(list);
        }
    }
    return main_id;
}

/// Queries the primary physical display dimensions and refresh rate on macOS.
///
/// Falls back cleanly to `1920x1080 @ 60Hz` if headless or when ProMotion/VRR reports `0.0` Hz.
///
/// - Parameters:
///   - out_w: Optional pointer receiving primary width in pixels.
///   - out_h: Optional pointer receiving primary height in pixels.
///   - out_fps: Optional pointer receiving refresh rate in Hertz (`1..480`).
void get_primary_display_info_mac(uint32_t *out_w, uint32_t *out_h, uint32_t *out_fps) {
    @autoreleasepool {
        CGDirectDisplayID target_id = select_physical_primary_display();
        uint32_t w = 0;
        uint32_t h = 0;
        uint32_t fps = kDefaultVirtualDisplayFps;

        if (target_id != kCGNullDirectDisplay && CGDisplayIsOnline(target_id)) {
            w = (uint32_t)CGDisplayPixelsWide(target_id);
            h = (uint32_t)CGDisplayPixelsHigh(target_id);

            CGDisplayModeRef mode = CGDisplayCopyDisplayMode(target_id);
            if (mode != NULL) {
                size_t pw = CGDisplayModeGetPixelWidth(mode);
                size_t ph = CGDisplayModeGetPixelHeight(mode);
                double rr = CGDisplayModeGetRefreshRate(mode);
                if (pw > 0 && pw <= kMaxVirtualDisplayDimension) w = (uint32_t)pw;
                if (ph > 0 && ph <= kMaxVirtualDisplayDimension) h = (uint32_t)ph;
                if (isfinite(rr) && rr > 1.0 && rr <= (double)kMaxVirtualDisplayFps) {
                    fps = (uint32_t)llround(rr);
                }
                CGDisplayModeRelease(mode);
            }
        }

        if (w == 0) w = kDefaultVirtualDisplayWidth;
        if (h == 0) h = kDefaultVirtualDisplayHeight;
        if (fps == 0) fps = kDefaultVirtualDisplayFps;

        if (out_w) *out_w = w;
        if (out_h) *out_h = h;
        if (out_fps) *out_fps = fps;
    }
}
