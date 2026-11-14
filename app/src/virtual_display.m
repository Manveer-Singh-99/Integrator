#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
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
@end

@interface IntegratorVDProto : NSObject
- (CGDirectDisplayID)displayID;
- (instancetype)initWithDescriptor:(id)descriptor;
- (BOOL)applySettings:(id)settings;
@end

static id g_virtual_display = nil;
static dispatch_queue_t g_vd_queue = nil;
static CGDirectDisplayID g_virtual_display_id = 0;

uint32_t start_virtual_display_in_app(uint32_t width, uint32_t height, uint32_t fps, bool hi_dpi) {
    @autoreleasepool {
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

        @synchronized([NSProcessInfo processInfo]) {
            g_virtual_display = nil;
            g_virtual_display_id = 0;

            if (!g_vd_queue) {
                g_vd_queue = dispatch_queue_create("com.manveersingh.integrator.vd", DISPATCH_QUEUE_SERIAL);
            }

            id desc = [[descCls alloc] init];
            [(IntegratorVDDescriptorProto *)desc setName:@"Integrator Extended Display"];
            [(IntegratorVDDescriptorProto *)desc setMaxPixelsWide:width];
            [(IntegratorVDDescriptorProto *)desc setMaxPixelsHigh:height];

            // Approximate physical dimensions (~110-140 PPI laptop screen equivalence)
            double mmW = (double)width * 25.4 / (hi_dpi ? 220.0 : 140.0);
            double mmH = (double)height * 25.4 / (hi_dpi ? 220.0 : 140.0);
            [(IntegratorVDDescriptorProto *)desc setSizeInMillimeters:CGSizeMake(mmW, mmH)];
            [(IntegratorVDDescriptorProto *)desc setProductID:INTEGRATOR_VD_PRODUCT];
            [(IntegratorVDDescriptorProto *)desc setVendorID:INTEGRATOR_VD_VENDOR];
            [(IntegratorVDDescriptorProto *)desc setSerialNum:INTEGRATOR_VD_SERIAL];
            [(IntegratorVDDescriptorProto *)desc setQueue:g_vd_queue];

            id disp = [(IntegratorVDProto *)[dispCls alloc] initWithDescriptor:desc];
            if (!disp) {
                NSLog(@"[Integrator] Failed to instantiate CGVirtualDisplay");
                return 0;
            }

            CGDirectDisplayID did = [(IntegratorVDProto *)disp displayID];
            id mode = [(IntegratorVDModeProto *)[modeCls alloc] initWithWidth:width height:height refreshRate:(double)fps];
            id settings = [[setCls alloc] init];
            [(IntegratorVDSettingsProto *)settings setHiDPI:(hi_dpi ? 1 : 0)];
            [(IntegratorVDSettingsProto *)settings setModes:@[mode]];

            BOOL ok = [(IntegratorVDProto *)disp applySettings:settings];
            if (!ok) {
                NSLog(@"[Integrator] CGVirtualDisplay applySettings failed (%ux%u @ %uHz)", width, height, fps);
                return 0;
            }

            g_virtual_display = disp;
            g_virtual_display_id = did;
            return (uint32_t)did;
        }
    }
}

void stop_virtual_display_in_app(void) {
    @synchronized([NSProcessInfo processInfo]) {
        g_virtual_display = nil;
        g_virtual_display_id = 0;
    }
}

uint32_t get_virtual_display_id_in_app(void) {
    @synchronized([NSProcessInfo processInfo]) {
        if (g_virtual_display != nil && g_virtual_display_id != 0) {
            return (uint32_t)g_virtual_display_id;
        }
    }

    // Fallback scan for an active virtual display created by Integrator (even in a sibling CLI/process)
    uint32_t count = 0;
    if (CGGetOnlineDisplayList(0, NULL, &count) == kCGErrorSuccess && count > 0) {
        CGDirectDisplayID *list = (CGDirectDisplayID *)calloc(count, sizeof(CGDirectDisplayID));
        if (list) {
            if (CGGetOnlineDisplayList(count, list, &count) == kCGErrorSuccess) {
                for (uint32_t i = 0; i < count; i++) {
                    if (CGDisplayVendorNumber(list[i]) == INTEGRATOR_VD_VENDOR &&
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
