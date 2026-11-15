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

// Custom vendor & product IDs ("IN" = Integrator) so virtual displays created
// by Integrator are unambiguously identifiable even alongside physical monitors.
static const uint32_t INTEGRATOR_VD_VENDOR  = 0x494E;
static const uint32_t INTEGRATOR_VD_PRODUCT = 0x0165;
static const uint32_t INTEGRATOR_VD_SERIAL  = 0x00010001;

@interface IntegratorVDModeProto : NSObject
- (instancetype)initWithWidth:(uint32_t)width height:(uint32_t)height refreshRate:(double)refreshRate;
@end

@interface IntegratorVDSettingsProto : NSObject
- (void)setHiDPI:(uint32_t)hiDPI;
- (void)setModes:(NSArray *)modes;
@end

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

@interface IntegratorVDProto : NSObject
- (CGDirectDisplayID)displayID;
- (instancetype)initWithDescriptor:(id)descriptor;
- (BOOL)applySettings:(id)settings;
@end

static id g_virtual_display = nil;
static dispatch_queue_t g_vd_queue = nil;
static CGDirectDisplayID g_virtual_display_id = 0;

static NSObject *vd_lock_obj(void) {
    static NSObject *lock = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        lock = [[NSObject alloc] init];
    });
    return lock;
}

uint32_t start_virtual_display_in_app(uint32_t width, uint32_t height, uint32_t fps, bool hi_dpi) {
    @autoreleasepool {
        @try {
            Class descCls = NSClassFromString(@"CGVirtualDisplayDescriptor");
            Class dispCls = NSClassFromString(@"CGVirtualDisplay");
            Class modeCls = NSClassFromString(@"CGVirtualDisplayMode");
            Class setCls  = NSClassFromString(@"CGVirtualDisplaySettings");

            if (!descCls || !dispCls || !modeCls || !setCls) {
                NSLog(@"[Integrator] CGVirtualDisplay private classes unavailable on this macOS version");
                return 0;
            }

            if (width == 0) width = 1920;
            if (height == 0) height = 1080;
            if (fps == 0) fps = 60;

            @synchronized(vd_lock_obj()) {
                if (!g_vd_queue) {
                    g_vd_queue = dispatch_queue_create("com.manveersingh.integrator.vd", DISPATCH_QUEUE_SERIAL);
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

                [(IntegratorVDDescriptorProto *)desc setName:@"Integrator Extended Display"];
                [(IntegratorVDDescriptorProto *)desc setMaxPixelsWide:width];
                [(IntegratorVDDescriptorProto *)desc setMaxPixelsHigh:height];

                double ppi = hi_dpi ? 220.0 : 140.0;
                double mmW = (double)width * 25.4 / ppi;
                double mmH = (double)height * 25.4 / ppi;
                [(IntegratorVDDescriptorProto *)desc setSizeInMillimeters:CGSizeMake(mmW, mmH)];
                [(IntegratorVDDescriptorProto *)desc setProductID:INTEGRATOR_VD_PRODUCT];
                [(IntegratorVDDescriptorProto *)desc setVendorID:INTEGRATOR_VD_VENDOR];
                [(IntegratorVDDescriptorProto *)desc setSerialNum:INTEGRATOR_VD_SERIAL];
                [(IntegratorVDDescriptorProto *)desc setQueue:g_vd_queue];

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
                if (hi_dpi && width >= 1600 && height >= 1200) {
                    uint32_t logicalW = (width / 2) & ~1u;
                    uint32_t logicalH = (height / 2) & ~1u;
                    if (logicalW >= 800 && logicalH >= 600) {
                        id loDpiMode = [(IntegratorVDModeProto *)[modeCls alloc] initWithWidth:logicalW height:logicalH refreshRate:(double)fps];
                        if (loDpiMode) {
                            [modes addObject:loDpiMode];
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

uint32_t get_virtual_display_id_in_app(void) {
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
        CGDirectDisplayID *list = (CGDirectDisplayID *)calloc(count, sizeof(CGDirectDisplayID));
        if (list) {
            if (CGGetOnlineDisplayList(count, list, &count) == kCGErrorSuccess) {
                for (uint32_t i = 0; i < count; i++) {
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
    return 0;
}

bool is_virtual_display_active_in_app(void) {
    return get_virtual_display_id_in_app() != 0;
}

void get_primary_display_info_mac(uint32_t *out_w, uint32_t *out_h, uint32_t *out_fps) {
    CGDirectDisplayID main_id = CGMainDisplayID();
    uint32_t w = (uint32_t)CGDisplayPixelsWide(main_id);
    uint32_t h = (uint32_t)CGDisplayPixelsHigh(main_id);
    uint32_t fps = 60;

    CGDisplayModeRef mode = CGDisplayCopyDisplayMode(main_id);
    if (mode != NULL) {
        size_t pw = CGDisplayModeGetPixelWidth(mode);
        size_t ph = CGDisplayModeGetPixelHeight(mode);
        double rr = CGDisplayModeGetRefreshRate(mode);
        if (pw > 0) w = (uint32_t)pw;
        if (ph > 0) h = (uint32_t)ph;
        if (rr > 1.0) fps = (uint32_t)llround(rr);
        CGDisplayModeRelease(mode);
    }

    if (out_w) *out_w = w;
    if (out_h) *out_h = h;
    if (out_fps) *out_fps = fps;
}
