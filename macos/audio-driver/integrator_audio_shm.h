#ifndef INTEGRATOR_AUDIO_SHM_H
#define INTEGRATOR_AUDIO_SHM_H

#include <stdint.h>
#include <stdatomic.h>

#define INTEGRATOR_AUDIO_SHM_NAME "/com.manveersingh.integrator.audio.sink.shm"
#define INTEGRATOR_AUDIO_SHM_MAGIC 0x49544753U // 'ITGS' (Integrator Audio Sink)
#define INTEGRATOR_AUDIO_RING_BUFFER_BYTES (128 * 1024) // 128 KB buffer (~341 ms of 48kHz stereo 16-bit PCM)

#pragma pack(push, 8)
typedef struct {
    uint32_t magic;              // INTEGRATOR_AUDIO_SHM_MAGIC
    uint32_t version;            // 1
    _Atomic uint32_t active;     // 1 = IO actively running in coreaudiod, 0 = idle
    _Atomic uint32_t format;     // 0 = Int16 48kHz 2ch, 1 = Float32 48kHz 2ch
    _Atomic uint32_t sample_rate;// 48000
    _Atomic uint32_t channels;   // 2
    _Atomic uint64_t total_frames_written;
    _Atomic uint64_t total_frames_read;
    _Atomic uint32_t write_pos;  // byte offset in buffer [0 .. INTEGRATOR_AUDIO_RING_BUFFER_BYTES - 1]
    _Atomic uint32_t read_pos;   // byte offset in buffer [0 .. INTEGRATOR_AUDIO_RING_BUFFER_BYTES - 1]
    _Atomic uint32_t underruns;  // buffer overflows
    uint8_t buffer[INTEGRATOR_AUDIO_RING_BUFFER_BYTES];
} IntegratorAudioShmHeader;
#pragma pack(pop)

#endif // INTEGRATOR_AUDIO_SHM_H
