// ==============================================================================================
// Integrator CoreAudio Audio Server Plugin Driver (`IntegratorAudioDriver.c`)
//
// Exposes "Windows PC (Integrator)" as a native CoreAudio output device in macOS System Settings,
// Menu Bar Volume slider, and Control Center. Captures system audio via `kAudioServerPlugInIOOperationWriteMix`
// and streams it into a lock-free POSIX shared memory ring buffer (`/com.manveersingh.integrator.audio.sink.shm`)
// for the Integrator engine to transmit over authenticated UDP `IUA2` to the paired Windows PC.
// ==============================================================================================

#include <CoreAudio/AudioServerPlugIn.h>
#include <CoreAudio/AudioHardwareBase.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach_time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <string.h>
#include <stdatomic.h>

#include "integrator_audio_shm.h"

// ----------------------------------------------------------------------------------------------
// UUID & Object Identifiers
// ----------------------------------------------------------------------------------------------

#define kFactoryUUID_Bytes 0x8A, 0x7B, 0x54, 0x92, 0x9C, 0x4F, 0x4E, 0x82, 0x9B, 0x7E, 0x7F, 0x89, 0xB4, 0x89, 0x62, 0x01

#define kObjectID_PlugIn 1
#define kObjectID_Device 2
#define kObjectID_Stream 3
#define kObjectID_Volume 4
#define kObjectID_Mute   5

#define kDevice_UID      CFSTR("com.manveersingh.integrator.audio.sink")
#define kDevice_ModelUID CFSTR("com.manveersingh.integrator.audio.sink.model")
#define kDevice_Name     CFSTR("Windows PC (Integrator)")
#define kManufacturer    CFSTR("Integrator")

// ----------------------------------------------------------------------------------------------
// Driver State & Shared Memory
// ----------------------------------------------------------------------------------------------

typedef struct {
    AudioServerPlugInDriverInterface* mInterface;
    CFUUIDRef                         mFactoryUUID;
    UInt32                            mRefCount;
    AudioServerPlugInHostRef          mHost;
} IntegratorAudioDriver;

static AudioServerPlugInDriverInterface g_driver_interface;
static IntegratorAudioDriver g_driver = {
    &g_driver_interface,
    NULL,
    1,
    NULL
};
static AudioServerPlugInDriverRef g_driver_ref = (AudioServerPlugInDriverRef)&g_driver;

// State Variables
static _Atomic uint32_t g_device_running = 0;
static Float32 g_volume = 1.0f;
static UInt32 g_mute = 0;
static const Float64 kSampleRate = 48000.0;
static const UInt32 kZeroTimeStampPeriod = 16384;

// Shared Memory Handle
static int g_shm_fd = -1;
static IntegratorAudioShmHeader* g_shm = NULL;

// Timeline Tracking
static mach_timebase_info_data_t g_timebase = { 0, 0 };
static uint64_t g_timeline_start_host_time = 0;
static Float64 g_timeline_start_sample_time = 0.0;
static uint64_t g_timeline_seed = 1;

// ----------------------------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------------------------

static void ensure_shm_mapped(void) {
    if (g_shm != NULL && g_shm != MAP_FAILED) return;

    g_shm_fd = shm_open(INTEGRATOR_AUDIO_SHM_NAME, O_RDWR | O_CREAT, 0666);
    if (g_shm_fd < 0) return;

    // Ensure capacity
    ftruncate(g_shm_fd, sizeof(IntegratorAudioShmHeader));

    void* ptr = mmap(NULL, sizeof(IntegratorAudioShmHeader), PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd, 0);
    if (ptr == MAP_FAILED) {
        close(g_shm_fd);
        g_shm_fd = -1;
        return;
    }

    g_shm = (IntegratorAudioShmHeader*)ptr;
    if (g_shm->magic != INTEGRATOR_AUDIO_SHM_MAGIC) {
        memset(g_shm, 0, sizeof(IntegratorAudioShmHeader));
        g_shm->magic = INTEGRATOR_AUDIO_SHM_MAGIC;
        g_shm->version = 1;
        g_shm->format = 0; // Int16 PCM 48kHz
        g_shm->sample_rate = 48000;
        g_shm->channels = 2;
    }
}

// ----------------------------------------------------------------------------------------------
// IUnknown Implementation
// ----------------------------------------------------------------------------------------------

static HRESULT Driver_QueryInterface(void* inDriver, REFIID inUUID, LPVOID* outInterface) {
    if (!outInterface) return kAudioHardwareIllegalOperationError;
    *outInterface = NULL;

    CFUUIDRef req = CFUUIDCreateFromUUIDBytes(kCFAllocatorDefault, inUUID);
    if (!req) return kAudioHardwareIllegalOperationError;

    if (CFEqual(req, IUnknownUUID) || CFEqual(req, kAudioServerPlugInDriverInterfaceUUID)) {
        g_driver.mRefCount++;
        *outInterface = g_driver_ref;
        CFRelease(req);
        return 0;
    }

    CFRelease(req);
    return 0x80004002L; // E_NOINTERFACE
}

static ULONG Driver_AddRef(void* inDriver) {
    return ++g_driver.mRefCount;
}

static ULONG Driver_Release(void* inDriver) {
    if (g_driver.mRefCount > 0) {
        return --g_driver.mRefCount;
    }
    return 0;
}

// ----------------------------------------------------------------------------------------------
// Basic Driver Operations
// ----------------------------------------------------------------------------------------------

static OSStatus Driver_Initialize(AudioServerPlugInDriverRef inDriver, AudioServerPlugInHostRef inHost) {
    g_driver.mHost = inHost;
    mach_timebase_info(&g_timebase);
    ensure_shm_mapped();
    return kAudioHardwareNoError;
}

static OSStatus Driver_CreateDevice(AudioServerPlugInDriverRef inDriver, CFDictionaryRef inDescription, const AudioServerPlugInClientInfo* inClientInfo, AudioObjectID* outDeviceObjectID) {
    return kAudioHardwareUnsupportedOperationError;
}

static OSStatus Driver_DestroyDevice(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID) {
    return kAudioHardwareUnsupportedOperationError;
}

static OSStatus Driver_AddDeviceClient(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, const AudioServerPlugInClientInfo* inClientInfo) {
    return kAudioHardwareNoError;
}

static OSStatus Driver_RemoveDeviceClient(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, const AudioServerPlugInClientInfo* inClientInfo) {
    return kAudioHardwareNoError;
}

static OSStatus Driver_PerformDeviceConfigurationChange(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt64 inChangeAction, void* inChangeInfo) {
    return kAudioHardwareNoError;
}

static OSStatus Driver_AbortDeviceConfigurationChange(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt64 inChangeAction, void* inChangeInfo) {
    return kAudioHardwareNoError;
}

// ----------------------------------------------------------------------------------------------
// Property Query Implementation
// ----------------------------------------------------------------------------------------------

static Boolean Driver_HasProperty(AudioServerPlugInDriverRef inDriver, AudioObjectID inObjectID, pid_t inClientProcessID, const AudioObjectPropertyAddress* inAddress) {
    if (!inAddress) return false;

    switch (inObjectID) {
        case kObjectID_PlugIn:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                case kAudioObjectPropertyManufacturer:
                case kAudioPlugInPropertyDeviceList:
                case kAudioPlugInPropertyTranslateUIDToDevice:
                case kAudioPlugInPropertyResourceBundle:
                    return true;
            }
            break;

        case kObjectID_Device:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                case kAudioObjectPropertyName:
                case kAudioObjectPropertyManufacturer:
                case kAudioDevicePropertyDeviceUID:
                case kAudioDevicePropertyModelUID:
                case kAudioDevicePropertyTransportType:
                case kAudioDevicePropertyRelatedDevices:
                case kAudioDevicePropertyClockDomain:
                case kAudioDevicePropertyDeviceIsAlive:
                case kAudioDevicePropertyDeviceIsRunning:
                case kAudioDevicePropertyDeviceCanBeDefaultDevice:
                case kAudioDevicePropertyDeviceCanBeDefaultSystemDevice:
                case kAudioDevicePropertyLatency:
                case kAudioDevicePropertySafetyOffset:
                case kAudioDevicePropertyNominalSampleRate:
                case kAudioDevicePropertyAvailableNominalSampleRates:
                case kAudioDevicePropertyZeroTimeStampPeriod:
                case kAudioDevicePropertyStreams:
                case kAudioObjectPropertyControlList:
                    return true;
            }
            break;

        case kObjectID_Stream:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                case kAudioStreamPropertyDirection:
                case kAudioStreamPropertyTerminalType:
                case kAudioStreamPropertyStartingChannel:
                case kAudioStreamPropertyLatency:
                case kAudioStreamPropertyVirtualFormat:
                case kAudioStreamPropertyPhysicalFormat:
                case kAudioStreamPropertyAvailableVirtualFormats:
                case kAudioStreamPropertyAvailablePhysicalFormats:
                    return true;
            }
            break;

        case kObjectID_Volume:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                case kAudioControlPropertyScope:
                case kAudioControlPropertyElement:
                case kAudioLevelControlPropertyScalarValue:
                case kAudioLevelControlPropertyDecibelValue:
                case kAudioLevelControlPropertyDecibelRange:
                    return true;
            }
            break;

        case kObjectID_Mute:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                case kAudioControlPropertyScope:
                case kAudioControlPropertyElement:
                case kAudioBooleanControlPropertyValue:
                    return true;
            }
            break;
    }
    return false;
}

static OSStatus Driver_IsPropertySettable(AudioServerPlugInDriverRef inDriver, AudioObjectID inObjectID, pid_t inClientProcessID, const AudioObjectPropertyAddress* inAddress, Boolean* outIsSettable) {
    if (!outIsSettable || !inAddress) return kAudioHardwareIllegalOperationError;
    *outIsSettable = false;

    if (inObjectID == kObjectID_Volume && inAddress->mSelector == kAudioLevelControlPropertyScalarValue) {
        *outIsSettable = true;
    } else if (inObjectID == kObjectID_Mute && inAddress->mSelector == kAudioBooleanControlPropertyValue) {
        *outIsSettable = true;
    }
    return kAudioHardwareNoError;
}

static OSStatus Driver_GetPropertyDataSize(AudioServerPlugInDriverRef inDriver, AudioObjectID inObjectID, pid_t inClientProcessID, const AudioObjectPropertyAddress* inAddress, UInt32 inQualifierDataSize, const void* inQualifierData, UInt32* outDataSize) {
    if (!outDataSize || !inAddress) return kAudioHardwareIllegalOperationError;

    switch (inObjectID) {
        case kObjectID_PlugIn:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyManufacturer:
                case kAudioPlugInPropertyResourceBundle:
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioPlugInPropertyDeviceList:
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
                case kAudioPlugInPropertyTranslateUIDToDevice:
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
            }
            break;

        case kObjectID_Device:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyName:
                case kAudioObjectPropertyManufacturer:
                case kAudioDevicePropertyDeviceUID:
                case kAudioDevicePropertyModelUID:
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyTransportType:
                case kAudioDevicePropertyClockDomain:
                case kAudioDevicePropertyDeviceIsAlive:
                case kAudioDevicePropertyDeviceIsRunning:
                case kAudioDevicePropertyDeviceCanBeDefaultDevice:
                case kAudioDevicePropertyDeviceCanBeDefaultSystemDevice:
                case kAudioDevicePropertyLatency:
                case kAudioDevicePropertySafetyOffset:
                case kAudioDevicePropertyZeroTimeStampPeriod:
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyRelatedDevices:
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyNominalSampleRate:
                    *outDataSize = sizeof(Float64);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyAvailableNominalSampleRates:
                    *outDataSize = sizeof(AudioValueRange);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyStreams:
                    if (inAddress->mScope == kAudioObjectPropertyScopeOutput || inAddress->mScope == kAudioObjectPropertyScopeGlobal) {
                        *outDataSize = sizeof(AudioObjectID);
                    } else {
                        *outDataSize = 0;
                    }
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyControlList:
                    *outDataSize = 2 * sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
            }
            break;

        case kObjectID_Stream:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyDirection:
                case kAudioStreamPropertyTerminalType:
                case kAudioStreamPropertyStartingChannel:
                case kAudioStreamPropertyLatency:
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyVirtualFormat:
                case kAudioStreamPropertyPhysicalFormat:
                    *outDataSize = sizeof(AudioStreamBasicDescription);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyAvailableVirtualFormats:
                case kAudioStreamPropertyAvailablePhysicalFormats:
                    *outDataSize = sizeof(AudioStreamRangedDescription);
                    return kAudioHardwareNoError;
            }
            break;

        case kObjectID_Volume:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyScope:
                    *outDataSize = sizeof(AudioObjectPropertyScope);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyElement:
                    *outDataSize = sizeof(AudioObjectPropertyElement);
                    return kAudioHardwareNoError;
                case kAudioLevelControlPropertyScalarValue:
                case kAudioLevelControlPropertyDecibelValue:
                    *outDataSize = sizeof(Float32);
                    return kAudioHardwareNoError;
                case kAudioLevelControlPropertyDecibelRange:
                    *outDataSize = sizeof(AudioValueRange);
                    return kAudioHardwareNoError;
            }
            break;

        case kObjectID_Mute:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyScope:
                    *outDataSize = sizeof(AudioObjectPropertyScope);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyElement:
                    *outDataSize = sizeof(AudioObjectPropertyElement);
                    return kAudioHardwareNoError;
                case kAudioBooleanControlPropertyValue:
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
            }
            break;
    }
    return kAudioHardwareUnknownPropertyError;
}

static OSStatus Driver_GetPropertyData(AudioServerPlugInDriverRef inDriver, AudioObjectID inObjectID, pid_t inClientProcessID, const AudioObjectPropertyAddress* inAddress, UInt32 inQualifierDataSize, const void* inQualifierData, UInt32 inDataSize, UInt32* outDataSize, void* outData) {
    if (!outDataSize || !outData || !inAddress) return kAudioHardwareIllegalOperationError;

    static AudioStreamBasicDescription streamFormat = {
        .mSampleRate = 48000.0,
        .mFormatID = kAudioFormatLinearPCM,
        .mFormatFlags = kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked,
        .mBytesPerPacket = 8,
        .mFramesPerPacket = 1,
        .mBytesPerFrame = 8,
        .mChannelsPerFrame = 2,
        .mBitsPerChannel = 32
    };

    switch (inObjectID) {
        case kObjectID_PlugIn:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                    *(AudioClassID*)outData = kAudioPlugInClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyClass:
                    *(AudioClassID*)outData = kAudioPlugInClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyOwner:
                    *(AudioClassID*)outData = kAudioObjectUnknown;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyManufacturer:
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, kManufacturer);
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioPlugInPropertyResourceBundle:
                    *(CFStringRef*)outData = CFSTR("");
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioPlugInPropertyDeviceList:
                    *(AudioObjectID*)outData = kObjectID_Device;
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
                case kAudioPlugInPropertyTranslateUIDToDevice:
                    if (inQualifierData && inQualifierDataSize >= sizeof(CFStringRef)) {
                        CFStringRef queryUID = *(CFStringRef*)inQualifierData;
                        if (CFStringCompare(queryUID, kDevice_UID, 0) == kCFCompareEqualTo) {
                            *(AudioObjectID*)outData = kObjectID_Device;
                            *outDataSize = sizeof(AudioObjectID);
                            return kAudioHardwareNoError;
                        }
                    }
                    *(AudioObjectID*)outData = kAudioObjectUnknown;
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
            }
            break;

        case kObjectID_Device:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                    *(AudioClassID*)outData = kAudioObjectClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyClass:
                    *(AudioClassID*)outData = kAudioDeviceClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyOwner:
                    *(AudioClassID*)outData = kObjectID_PlugIn;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyName:
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, kDevice_Name);
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyManufacturer:
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, kManufacturer);
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyDeviceUID:
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, kDevice_UID);
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyModelUID:
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, kDevice_ModelUID);
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyTransportType:
                    *(UInt32*)outData = kAudioDeviceTransportTypeVirtual;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyRelatedDevices:
                    *(AudioObjectID*)outData = kObjectID_Device;
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyClockDomain:
                    *(UInt32*)outData = 0;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyDeviceIsAlive:
                    *(UInt32*)outData = 1;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyDeviceIsRunning:
                    *(UInt32*)outData = atomic_load(&g_device_running);
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyDeviceCanBeDefaultDevice:
                case kAudioDevicePropertyDeviceCanBeDefaultSystemDevice:
                    *(UInt32*)outData = 1;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyLatency:
                case kAudioDevicePropertySafetyOffset:
                    *(UInt32*)outData = 0;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyNominalSampleRate:
                    *(Float64*)outData = kSampleRate;
                    *outDataSize = sizeof(Float64);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyAvailableNominalSampleRates:
                    {
                        AudioValueRange range = { kSampleRate, kSampleRate };
                        *(AudioValueRange*)outData = range;
                        *outDataSize = sizeof(AudioValueRange);
                        return kAudioHardwareNoError;
                    }
                case kAudioDevicePropertyZeroTimeStampPeriod:
                    *(UInt32*)outData = kZeroTimeStampPeriod;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyStreams:
                    if (inAddress->mScope == kAudioObjectPropertyScopeOutput || inAddress->mScope == kAudioObjectPropertyScopeGlobal) {
                        *(AudioObjectID*)outData = kObjectID_Stream;
                        *outDataSize = sizeof(AudioObjectID);
                    } else {
                        *outDataSize = 0;
                    }
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyControlList:
                    {
                        AudioObjectID controls[2] = { kObjectID_Volume, kObjectID_Mute };
                        memcpy(outData, controls, sizeof(controls));
                        *outDataSize = sizeof(controls);
                        return kAudioHardwareNoError;
                    }
            }
            break;

        case kObjectID_Stream:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                    *(AudioClassID*)outData = kAudioObjectClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyClass:
                    *(AudioClassID*)outData = kAudioStreamClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyOwner:
                    *(AudioClassID*)outData = kObjectID_Device;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyDirection:
                    *(UInt32*)outData = 0; // Output
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyTerminalType:
                    *(UInt32*)outData = kAudioStreamTerminalTypeSpeaker;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyStartingChannel:
                    *(UInt32*)outData = 1;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyLatency:
                    *(UInt32*)outData = 0;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyVirtualFormat:
                case kAudioStreamPropertyPhysicalFormat:
                    *(AudioStreamBasicDescription*)outData = streamFormat;
                    *outDataSize = sizeof(AudioStreamBasicDescription);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyAvailableVirtualFormats:
                case kAudioStreamPropertyAvailablePhysicalFormats:
                    {
                        AudioStreamRangedDescription ranged = {
                            .mFormat = streamFormat,
                            .mSampleRateRange = { kSampleRate, kSampleRate }
                        };
                        *(AudioStreamRangedDescription*)outData = ranged;
                        *outDataSize = sizeof(AudioStreamRangedDescription);
                        return kAudioHardwareNoError;
                    }
            }
            break;

        case kObjectID_Volume:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                    *(AudioClassID*)outData = kAudioControlClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyClass:
                    *(AudioClassID*)outData = kAudioVolumeControlClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyOwner:
                    *(AudioClassID*)outData = kObjectID_Device;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyScope:
                    *(AudioObjectPropertyScope*)outData = kAudioObjectPropertyScopeOutput;
                    *outDataSize = sizeof(AudioObjectPropertyScope);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyElement:
                    *(AudioObjectPropertyElement*)outData = kAudioObjectPropertyElementMain;
                    *outDataSize = sizeof(AudioObjectPropertyElement);
                    return kAudioHardwareNoError;
                case kAudioLevelControlPropertyScalarValue:
                    *(Float32*)outData = g_volume;
                    *outDataSize = sizeof(Float32);
                    return kAudioHardwareNoError;
                case kAudioLevelControlPropertyDecibelValue:
                    *(Float32*)outData = 20.0f * log10f(fmaxf(g_volume, 0.00001f));
                    *outDataSize = sizeof(Float32);
                    return kAudioHardwareNoError;
                case kAudioLevelControlPropertyDecibelRange:
                    {
                        AudioValueRange range = { -96.0, 0.0 };
                        *(AudioValueRange*)outData = range;
                        *outDataSize = sizeof(AudioValueRange);
                        return kAudioHardwareNoError;
                    }
            }
            break;

        case kObjectID_Mute:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                    *(AudioClassID*)outData = kAudioControlClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyClass:
                    *(AudioClassID*)outData = kAudioMuteControlClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyOwner:
                    *(AudioClassID*)outData = kObjectID_Device;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyScope:
                    *(AudioObjectPropertyScope*)outData = kAudioObjectPropertyScopeOutput;
                    *outDataSize = sizeof(AudioObjectPropertyScope);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyElement:
                    *(AudioObjectPropertyElement*)outData = kAudioObjectPropertyElementMain;
                    *outDataSize = sizeof(AudioObjectPropertyElement);
                    return kAudioHardwareNoError;
                case kAudioBooleanControlPropertyValue:
                    *(UInt32*)outData = g_mute;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
            }
            break;
    }
    return kAudioHardwareUnknownPropertyError;
}

static OSStatus Driver_SetPropertyData(AudioServerPlugInDriverRef inDriver, AudioObjectID inObjectID, pid_t inClientProcessID, const AudioObjectPropertyAddress* inAddress, UInt32 inQualifierDataSize, const void* inQualifierData, UInt32 inDataSize, const void* inData) {
    if (!inAddress || !inData) return kAudioHardwareIllegalOperationError;

    if (inObjectID == kObjectID_Volume && inAddress->mSelector == kAudioLevelControlPropertyScalarValue) {
        if (inDataSize >= sizeof(Float32)) {
            g_volume = fminf(fmaxf(*(const Float32*)inData, 0.0f), 1.0f);
            return kAudioHardwareNoError;
        }
    } else if (inObjectID == kObjectID_Mute && inAddress->mSelector == kAudioBooleanControlPropertyValue) {
        if (inDataSize >= sizeof(UInt32)) {
            g_mute = (*(const UInt32*)inData != 0) ? 1 : 0;
            return kAudioHardwareNoError;
        }
    }
    return kAudioHardwareUnknownPropertyError;
}

// ----------------------------------------------------------------------------------------------
// IO Cycle Implementation
// ----------------------------------------------------------------------------------------------

static OSStatus Driver_StartIO(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID) {
    ensure_shm_mapped();
    atomic_store(&g_device_running, 1);
    g_timeline_start_host_time = mach_absolute_time();
    g_timeline_start_sample_time = 0.0;
    g_timeline_seed++;

    if (g_shm) {
        atomic_store(&g_shm->active, 1);
    }
    return kAudioHardwareNoError;
}

static OSStatus Driver_StopIO(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID) {
    atomic_store(&g_device_running, 0);
    if (g_shm) {
        atomic_store(&g_shm->active, 0);
    }
    return kAudioHardwareNoError;
}

static OSStatus Driver_GetZeroTimeStamp(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID, Float64* outSampleTime, UInt64* outHostTime, UInt64* outSeed) {
    if (!outSampleTime || !outHostTime || !outSeed) return kAudioHardwareIllegalOperationError;

    uint64_t now = mach_absolute_time();
    uint64_t elapsed_ticks = (now > g_timeline_start_host_time) ? (now - g_timeline_start_host_time) : 0;
    uint64_t elapsed_nanos = elapsed_ticks * g_timebase.numer / g_timebase.denom;
    Float64 elapsed_samples = (Float64)elapsed_nanos * kSampleRate / 1000000000.0;

    *outSampleTime = g_timeline_start_sample_time + elapsed_samples;
    *outHostTime = now;
    *outSeed = g_timeline_seed;
    return kAudioHardwareNoError;
}

static OSStatus Driver_WillDoIOOperation(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID, UInt32 inOperationID, Boolean* outWillDo, Boolean* outWillDoInPlace) {
    if (!outWillDo || !outWillDoInPlace) return kAudioHardwareIllegalOperationError;

    if (inOperationID == kAudioServerPlugInIOOperationWriteMix) {
        *outWillDo = true;
        *outWillDoInPlace = true;
    } else {
        *outWillDo = false;
        *outWillDoInPlace = true;
    }
    return kAudioHardwareNoError;
}

static OSStatus Driver_BeginIOOperation(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID, UInt32 inOperationID, UInt32 inIOBufferFrameSize, const AudioServerPlugInIOCycleInfo* inIOCycleInfo) {
    return kAudioHardwareNoError;
}

static inline int16_t float_to_int16(float f) {
    if (f > 1.0f) f = 1.0f;
    else if (f < -1.0f) f = -1.0f;
    return (int16_t)(f * 32767.0f);
}

static OSStatus Driver_DoIOOperation(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, AudioObjectID inStreamObjectID, UInt32 inClientID, UInt32 inOperationID, UInt32 inIOBufferFrameSize, const AudioServerPlugInIOCycleInfo* inIOCycleInfo, void* ioMainBuffer, void* ioSecondaryBuffer) {
    if (inOperationID != kAudioServerPlugInIOOperationWriteMix || !ioMainBuffer) {
        return kAudioHardwareNoError;
    }

    if (!g_shm) {
        ensure_shm_mapped();
        if (!g_shm) return kAudioHardwareNoError;
    }

    // Interleaved stereo 32-bit float PCM
    const float* in_samples = (const float*)ioMainBuffer;
    uint32_t total_samples = inIOBufferFrameSize * 2; // stereo
    float vol = g_mute ? 0.0f : g_volume;

    // Convert to canonical 16-bit PCM and write to ring buffer
    uint32_t curr_write = atomic_load_explicit(&g_shm->write_pos, memory_order_relaxed);
    uint32_t curr_read = atomic_load_explicit(&g_shm->read_pos, memory_order_acquire);
    uint32_t bytes_to_write = total_samples * sizeof(int16_t);

    // Check capacity: if write overtakes read, increment underrun counter
    uint32_t used_bytes = (curr_write >= curr_read)
        ? (curr_write - curr_read)
        : (INTEGRATOR_AUDIO_RING_BUFFER_BYTES - (curr_read - curr_write));

    if (used_bytes + bytes_to_write >= INTEGRATOR_AUDIO_RING_BUFFER_BYTES) {
        atomic_fetch_add_explicit(&g_shm->underruns, 1, memory_order_relaxed);
        // Advance read pointer to discard oldest frame and prevent deadlock
        uint32_t skip_bytes = bytes_to_write;
        atomic_store_explicit(&g_shm->read_pos, (curr_read + skip_bytes) % INTEGRATOR_AUDIO_RING_BUFFER_BYTES, memory_order_release);
    }

    for (uint32_t i = 0; i < total_samples; i++) {
        int16_t pcm = float_to_int16(in_samples[i] * vol);
        *(int16_t*)&g_shm->buffer[curr_write] = pcm;
        curr_write = (curr_write + sizeof(int16_t)) % INTEGRATOR_AUDIO_RING_BUFFER_BYTES;
    }

    atomic_store_explicit(&g_shm->write_pos, curr_write, memory_order_release);
    atomic_fetch_add_explicit(&g_shm->total_frames_written, inIOBufferFrameSize, memory_order_relaxed);

    return kAudioHardwareNoError;
}

static OSStatus Driver_EndIOOperation(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID, UInt32 inOperationID, UInt32 inIOBufferFrameSize, const AudioServerPlugInIOCycleInfo* inIOCycleInfo) {
    return kAudioHardwareNoError;
}

// ----------------------------------------------------------------------------------------------
// Function Table Initialization
// ----------------------------------------------------------------------------------------------

static AudioServerPlugInDriverInterface g_driver_interface = {
    ._reserved = NULL,
    .QueryInterface = Driver_QueryInterface,
    .AddRef = Driver_AddRef,
    .Release = Driver_Release,
    .Initialize = Driver_Initialize,
    .CreateDevice = Driver_CreateDevice,
    .DestroyDevice = Driver_DestroyDevice,
    .AddDeviceClient = Driver_AddDeviceClient,
    .RemoveDeviceClient = Driver_RemoveDeviceClient,
    .PerformDeviceConfigurationChange = Driver_PerformDeviceConfigurationChange,
    .AbortDeviceConfigurationChange = Driver_AbortDeviceConfigurationChange,
    .HasProperty = Driver_HasProperty,
    .IsPropertySettable = Driver_IsPropertySettable,
    .GetPropertyDataSize = Driver_GetPropertyDataSize,
    .GetPropertyData = Driver_GetPropertyData,
    .SetPropertyData = Driver_SetPropertyData,
    .StartIO = Driver_StartIO,
    .StopIO = Driver_StopIO,
    .GetZeroTimeStamp = Driver_GetZeroTimeStamp,
    .WillDoIOOperation = Driver_WillDoIOOperation,
    .BeginIOOperation = Driver_BeginIOOperation,
    .DoIOOperation = Driver_DoIOOperation,
    .EndIOOperation = Driver_EndIOOperation
};

// ----------------------------------------------------------------------------------------------
// Factory Function Entry Point
// ----------------------------------------------------------------------------------------------

__attribute__((visibility("default")))
void* IntegratorAudioDriver_Create(CFAllocatorRef inAllocator, CFUUIDRef inTypeUUID) {
    if (!inTypeUUID) return NULL;

    if (CFEqual(inTypeUUID, kAudioServerPlugInTypeUUID)) {
        Driver_AddRef(g_driver_ref);
        return g_driver_ref;
    }
    return NULL;
}
