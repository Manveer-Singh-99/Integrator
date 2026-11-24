// ==============================================================================================
// Integrator Windows Native Core P/Invoke Bridge & Data Contracts (`ui-windows/CoreBridge.cs`)
//
// 1. Module Purpose & System Scope:
//    - Defines the managed-to-unmanaged interop boundary (P/Invoke) between the .NET CLR and the
//      underlying Rust core shared library (`integrator_core.dll`).
//    - Exposes strongly typed, generic JSON-RPC dispatch mechanisms (`Invoke<T>`) for querying status,
//      updating configuration, and executing hardware actions.
//    - Implements unmanaged string allocation and deallocation (`AllocUtf8`, `ReadUtf8`, `integrator_core_free_string`),
//      guaranteeing zero native memory leaks across the FFI boundary.
//    - Hosts the complete suite of C# DTO records mirroring Rust RPC payloads and bridge snapshots.
//
// 2. Architectural Linkages & Native Core Bridge:
//    - Downstream Callee: `integrator_core.dll` exported C-ABI functions:
//        * `integrator_core_init`: Bootstraps Tokio, discovery, and registers `UiEventCallback`.
//        * `integrator_core_invoke`: Synchronous JSON-RPC call returning heap-allocated UTF-8 JSON.
//        * `integrator_core_free_string`: Releases native C-string allocated by Rust allocator.
//        * `integrator_core_tray_action`: One-way tray event dispatch.
//        * `integrator_core_shutdown`: Performs Tokio cancellation and runtime termination.
//        * `integrator_core_try_focus_existing`: Secondary instance activation request.
//        * `integrator_core_run_cli`: Direct headless CLI sub-command execution.
//    - Upstream Callers:
//        * `Program.cs`: Early CLI interception, single-instance activation, core init/shutdown.
//        * `App.xaml.cs`: Event routing, tray actions, and application lifecycle termination.
//        * `MainWindow.xaml.cs`: 2-second polling loop, button click RPC dispatches, feature toggles.
//        * `TrayIconManager.cs`: Context menu action triggers dispatched via thread pool.
//
// 3. Threading & Concurrency Model:
//    - Thread-Safe RPC Invocations: `Invoke<T>` can be safely invoked concurrently from any thread
//      (e.g., UI STA thread, background `Task.Run` workers, or ThreadPool threads).
//    - Reverse Event Dispatch: `OnNativeUiEvent` executes on arbitrary Tokio worker threads originating
//      inside Rust. Handlers must marshal work onto the UI thread via `DispatcherQueue`.
//    - Native Delegate Pinning: The static field `_nativeCallback` permanently holds a reference to the
//      unmanaged delegate trampoline, preventing garbage collection while the native DLL holds the function pointer.
//
// 4. Security & Safety Invariants:
//    - Exception Boundary Containment: `OnNativeUiEvent` wraps all managed execution in a catch-all block,
//      preventing CLR exceptions from unwinding across the native C-ABI boundary (which would abort the process).
//    - Native Pointer Hygiene: Every allocated `HGlobal` buffer is guaranteed to be freed in a `finally` block,
//      and all native strings returned by Rust are freed via `integrator_core_free_string`.
//    - DllImport Search Path Hardening: Uses `[DefaultDllImportSearchPaths]` restricted to `ApplicationDirectory`
//      and `System32` to mitigate DLL pre-loading and binary planting vulnerabilities.
// ==============================================================================================

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace IntegratorUI
{
    /// <summary>
    /// Direct P/Invoke declarations for exported C-ABI functions in integrator_core.dll.
    /// </summary>
    internal static class CoreNative
    {
        private const string DllName = "integrator_core.dll";

        /// <summary>
        /// Unmanaged Cdecl callback signature for reverse event notifications from Rust to C#.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void UiEventCallback(IntPtr eventNameUtf8, IntPtr payloadJsonUtf8);

        /// <summary>
        /// Attempts to signal an existing running instance of Integrator to bring its window to focus.
        /// </summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory | DllImportSearchPath.System32)]
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool integrator_core_try_focus_existing();

        /// <summary>
        /// Runs headless CLI subroutines (mount helpers, clipboard helpers) without starting the UI.
        /// </summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory | DllImportSearchPath.System32)]
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int integrator_core_run_cli(int argc, IntPtr[] argv);

        /// <summary>
        /// Registers or clears the reverse UI event callback delegate in the native core.
        /// </summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory | DllImportSearchPath.System32)]
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void integrator_core_set_ui_callback(UiEventCallback? cb);

        /// <summary>
        /// Initializes the Rust backend core runtime and registers the initial reverse UI event callback.
        /// </summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory | DllImportSearchPath.System32)]
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int integrator_core_init(UiEventCallback? cb);

        /// <summary>
        /// Synchronously invokes a JSON-RPC method on the native core.
        /// </summary>
        /// <param name="methodUtf8">Null-terminated UTF-8 method name pointer.</param>
        /// <param name="paramsJsonUtf8">Null-terminated UTF-8 JSON parameter string pointer.</param>
        /// <returns>Pointer to heap-allocated UTF-8 JSON response string (must be freed with integrator_core_free_string).</returns>
        [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory | DllImportSearchPath.System32)]
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr integrator_core_invoke(IntPtr methodUtf8, IntPtr paramsJsonUtf8);

        /// <summary>
        /// Frees a native string buffer previously allocated by Rust and returned from integrator_core_invoke.
        /// </summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory | DllImportSearchPath.System32)]
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void integrator_core_free_string(IntPtr ptr);

        /// <summary>
        /// Dispatches a one-way notification string from the system tray menu into the Rust core.
        /// </summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory | DllImportSearchPath.System32)]
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void integrator_core_tray_action(IntPtr actionUtf8);

        /// <summary>
        /// Gracefully shuts down the native runtime, canceling active Tokio tasks and closing network listeners.
        /// </summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.ApplicationDirectory | DllImportSearchPath.System32)]
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void integrator_core_shutdown();
    }

    /// <summary>
    /// High-level managed wrapper providing strongly-typed JSON-RPC dispatch, memory safety,
    /// and event routing to and from integrator_core.dll.
    /// </summary>
    internal static class CoreBridge
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private static readonly JsonSerializerOptions JsonOptionsIncludeNulls = new()
        {
            PropertyNameCaseInsensitive = true
        };

        /// <summary>
        /// Strongly held reference to the native callback delegate to prevent garbage collection.
        /// </summary>
        private static CoreNative.UiEventCallback? _nativeCallback;

        /// <summary>
        /// Atomic flag ensuring core shutdown logic is executed exactly once.
        /// </summary>
        private static int _shutdownDone;

        /// <summary>
        /// Event fired whenever an asynchronous notification is pushed from the native core backend.
        /// </summary>
        public static event Action<string, string>? UiEventReceived;

        /// <summary>
        /// Allocates a null-terminated UTF-8 byte array in unmanaged process memory.
        /// </summary>
        private static IntPtr AllocUtf8(string value)
        {
            string sanitized = (value ?? string.Empty).Replace("\0", string.Empty);
            byte[] bytes = Encoding.UTF8.GetBytes(sanitized + "\0");
            IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            return ptr;
        }

        /// <summary>
        /// Marshals an unmanaged null-terminated UTF-8 byte array into a managed string.
        /// </summary>
        private static string ReadUtf8(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return string.Empty;
            return Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
        }

        /// <summary>
        /// Executes CLI subcommands via the native core if requested by command-line arguments.
        /// </summary>
        public static int RunCliIfRequested(string[] args)
        {
            string exePath = Environment.ProcessPath ?? "Integrator.exe";
            string[] fullArgs = new string[args.Length + 1];
            fullArgs[0] = exePath;
            Array.Copy(args, 0, fullArgs, 1, args.Length);

            IntPtr[] ptrs = new IntPtr[fullArgs.Length];
            try
            {
                for (int i = 0; i < fullArgs.Length; i++)
                {
                    ptrs[i] = AllocUtf8(fullArgs[i]);
                }
                return CoreNative.integrator_core_run_cli(fullArgs.Length, ptrs);
            }
            finally
            {
                foreach (IntPtr p in ptrs)
                {
                    if (p != IntPtr.Zero) Marshal.FreeHGlobal(p);
                }
            }
        }

        /// <summary>
        /// Signals an existing running instance of Integrator to bring its window to the foreground.
        /// </summary>
        public static bool TryFocusExisting()
        {
            return CoreNative.integrator_core_try_focus_existing();
        }

        /// <summary>
        /// Initializes the native core backend runtime and registers the reverse UI event callback.
        /// </summary>
        public static bool Initialize()
        {
            System.Threading.Interlocked.Exchange(ref _shutdownDone, 0);
            _nativeCallback = OnNativeUiEvent;
            return CoreNative.integrator_core_init(_nativeCallback) == 0;
        }

        /// <summary>
        /// Internal Cdecl callback trampoline receiving asynchronous events from the native Rust runtime.
        /// </summary>
        private static void OnNativeUiEvent(IntPtr eventPtr, IntPtr payloadPtr)
        {
            try
            {
                string evt = ReadUtf8(eventPtr);
                string payload = ReadUtf8(payloadPtr);
                UiEventReceived?.Invoke(evt, payload);
            }
            catch
            {
                // Never allow managed exceptions to unwind across native C ABI callbacks.
            }
        }

        /// <summary>
        /// Invokes a JSON-RPC method synchronously on integrator_core.dll and deserializes the typed response.
        /// </summary>
        /// <typeparam name="T">Target data type for payload deserialization.</typeparam>
        /// <param name="method">RPC method name (e.g., "get_bridge_status").</param>
        /// <param name="parameters">Optional parameter payload to serialize into JSON.</param>
        /// <param name="preserveNulls">Whether to explicitly serialize null properties.</param>
        /// <returns>RpcResult containing success status, data payload, or error message.</returns>
        public static RpcResult<T> Invoke<T>(string method, object? parameters = null, bool preserveNulls = false)
        {
            string paramsJson = parameters switch
            {
                null => "{}",
                string s => s,
                _ => JsonSerializer.Serialize(parameters, preserveNulls ? JsonOptionsIncludeNulls : JsonOptions)
            };

            IntPtr mPtr = IntPtr.Zero;
            IntPtr pPtr = IntPtr.Zero;
            IntPtr resPtr = IntPtr.Zero;
            try
            {
                mPtr = AllocUtf8(method);
                pPtr = AllocUtf8(paramsJson);
                resPtr = CoreNative.integrator_core_invoke(mPtr, pPtr);
                if (resPtr == IntPtr.Zero)
                {
                    return new RpcResult<T>(false, default, "Null RPC response from core");
                }
                string raw = ReadUtf8(resPtr);
                var env = JsonSerializer.Deserialize<RpcEnvelope<T>>(raw, JsonOptions);
                if (env == null)
                {
                    return new RpcResult<T>(false, default, "Failed to parse RPC response");
                }
                return new RpcResult<T>(env.Ok, env.Data, env.Error);
            }
            catch (Exception ex)
            {
                return new RpcResult<T>(false, default, ex.Message);
            }
            finally
            {
                if (resPtr != IntPtr.Zero) CoreNative.integrator_core_free_string(resPtr);
                if (mPtr != IntPtr.Zero) Marshal.FreeHGlobal(mPtr);
                if (pPtr != IntPtr.Zero) Marshal.FreeHGlobal(pPtr);
            }
        }

        /// <summary>
        /// Dispatches a one-way notification action into the native core's tray handler.
        /// </summary>
        /// <param name="action">Action key string (e.g., "paste_remote", "toggle_display").</param>
        public static void TrayAction(string action)
        {
            IntPtr aPtr = IntPtr.Zero;
            try
            {
                aPtr = AllocUtf8(action);
                CoreNative.integrator_core_tray_action(aPtr);
            }
            finally
            {
                if (aPtr != IntPtr.Zero) Marshal.FreeHGlobal(aPtr);
            }
        }

        /// <summary>
        /// Performs idempotent graceful shutdown of the native core runtime.
        /// </summary>
        public static void Shutdown()
        {
            if (System.Threading.Interlocked.Exchange(ref _shutdownDone, 1) != 0)
            {
                return;
            }
            try { CoreNative.integrator_core_set_ui_callback(null); } catch { }
            _nativeCallback = null;
            try { CoreNative.integrator_core_shutdown(); } catch { }
        }
    }

    /// <summary>
    /// Standard JSON-RPC response envelope returned by integrator_core_invoke.
    /// </summary>
    /// <typeparam name="T">Payload data type.</typeparam>
    internal sealed class RpcEnvelope<T>
    {
        /// <summary>True if native execution succeeded; false on error.</summary>
        [JsonPropertyName("ok")] public bool Ok { get; set; }
        /// <summary>Deserialized data payload returned on success.</summary>
        [JsonPropertyName("data")] public T? Data { get; set; }
        /// <summary>Error message string returned on failure.</summary>
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    /// <summary>
    /// Strongly-typed result struct capturing RPC execution status and data.
    /// </summary>
    internal readonly record struct RpcResult<T>(bool Ok, T? Data, string? Error);

    /// <summary>
    /// Payload structure for reverse toast notification events from the native core.
    /// </summary>
    internal sealed class UiToastPayload
    {
        /// <summary>Message body text.</summary>
        [JsonPropertyName("message")] public string? Message { get; set; }
        /// <summary>Notification severity kind: "info", "success", "warn", or "error".</summary>
        [JsonPropertyName("kind")] public string? Kind { get; set; }
    }

    /// <summary>
    /// Geometry and scaling factors of the workstation's primary display monitor.
    /// </summary>
    internal sealed class PrimaryDisplayInfo
    {
        /// <summary>Native horizontal resolution in pixels.</summary>
        [JsonPropertyName("width")] public uint Width { get; set; }
        /// <summary>Native vertical resolution in pixels.</summary>
        [JsonPropertyName("height")] public uint Height { get; set; }
        /// <summary>Display refresh rate in frames per second.</summary>
        [JsonPropertyName("fps")] public uint Fps { get; set; } = 60;
        /// <summary>DPI display scaling factor (e.g., 1.0 = 100%, 1.5 = 150%).</summary>
        [JsonPropertyName("scale_factor")] public double ScaleFactor { get; set; } = 1.0;
    }

    /// <summary>
    /// Hardware attributes of a graphics adapter detected on the machine.
    /// </summary>
    internal sealed class GpuDeviceInfo
    {
        /// <summary>Adapter index in DXGI / Metal enumeration.</summary>
        [JsonPropertyName("index")] public uint Index { get; set; }
        /// <summary>Device name of the graphics card.</summary>
        [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
        /// <summary>Hardware manufacturer name (NVIDIA, AMD, Intel, Apple).</summary>
        [JsonPropertyName("vendor")] public string Vendor { get; set; } = string.Empty;
        /// <summary>True for discrete dedicated GPUs; false for integrated graphics.</summary>
        [JsonPropertyName("is_discrete")] public bool IsDiscrete { get; set; }
        /// <summary>Dedicated video RAM in megabytes, if available.</summary>
        [JsonPropertyName("vram_mb")] public ulong? VramMb { get; set; }
    }

    /// <summary>
    /// Screen dimensions and refresh rate geometry.
    /// </summary>
    internal sealed class DisplayGeometryModel
    {
        /// <summary>Width in physical pixels.</summary>
        [JsonPropertyName("width")] public uint Width { get; set; }
        /// <summary>Height in physical pixels.</summary>
        [JsonPropertyName("height")] public uint Height { get; set; }
        /// <summary>Refresh rate in hertz.</summary>
        [JsonPropertyName("fps")] public uint Fps { get; set; }
    }

    /// <summary>
    /// Network interface descriptor capturing IP address, link speed, and adapter type.
    /// </summary>
    internal sealed class LocalInterfaceInfo
    {
        /// <summary>System device name (e.g., "Ethernet 2").</summary>
        [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
        /// <summary>User-friendly label.</summary>
        [JsonPropertyName("friendly_name")] public string? FriendlyName { get; set; }
        /// <summary>Bound IP address string.</summary>
        [JsonPropertyName("ip")] public string Ip { get; set; } = string.Empty;
        /// <summary>Subnet mask string.</summary>
        [JsonPropertyName("netmask")] public string? Netmask { get; set; }
        /// <summary>Directed broadcast address string.</summary>
        [JsonPropertyName("broadcast")] public string? Broadcast { get; set; }
        /// <summary>CIDR prefix length (e.g., 24).</summary>
        [JsonPropertyName("cidr_prefix")] public byte? CidrPrefix { get; set; }
        /// <summary>Physical transport type (Thunderbolt, Ethernet, Wi-Fi).</summary>
        [JsonPropertyName("transport")] public string? Transport { get; set; }
        /// <summary>Link speed in megabits per second.</summary>
        [JsonPropertyName("link_speed_mbps")] public uint? LinkSpeedMbps { get; set; }
        /// <summary>Diagnostic link description.</summary>
        [JsonPropertyName("description")] public string? Description { get; set; }
    }

    /// <summary>
    /// Discovered peer device awaiting pairing authentication.
    /// </summary>
    internal sealed class PendingPeerInfo
    {
        /// <summary>Cryptographic device identifier.</summary>
        [JsonPropertyName("device_id")] public string DeviceId { get; set; } = string.Empty;
        /// <summary>Network hostname of the pending peer.</summary>
        [JsonPropertyName("hostname")] public string Hostname { get; set; } = string.Empty;
        /// <summary>Reachable IP address of the peer.</summary>
        [JsonPropertyName("ip")] public string Ip { get; set; } = string.Empty;
        /// <summary>True if connected via point-to-point cable.</summary>
        [JsonPropertyName("is_direct_cable")] public bool IsDirectCable { get; set; }
        /// <summary>Trust authentication status flag.</summary>
        [JsonPropertyName("trusted")] public bool Trusted { get; set; }
        /// <summary>Administrative block status flag.</summary>
        [JsonPropertyName("blocked")] public bool Blocked { get; set; }
    }

    /// <summary>
    /// Record of a trusted, paired peer stored in the persistent keystore.
    /// </summary>
    internal sealed class TrustedPeerRecord
    {
        /// <summary>Cryptographic device identifier.</summary>
        [JsonPropertyName("device_id")] public string DeviceId { get; set; } = string.Empty;
        /// <summary>Hostname of the trusted peer.</summary>
        [JsonPropertyName("hostname")] public string Hostname { get; set; } = string.Empty;
        /// <summary>Last known IP address.</summary>
        [JsonPropertyName("last_ip")] public string LastIp { get; set; } = string.Empty;
        /// <summary>Unix timestamp when pairing was established.</summary>
        [JsonPropertyName("paired_at_epoch")] public ulong? PairedAtEpoch { get; set; }
        /// <summary>True if paired over direct cable.</summary>
        [JsonPropertyName("via_direct_cable")] public bool ViaDirectCable { get; set; }
        /// <summary>Hex-encoded Ed25519 identity public key.</summary>
        [JsonPropertyName("ed25519_pubkey_hex")] public string? Ed25519PubkeyHex { get; set; }
        /// <summary>Key ID derived from peer public key.</summary>
        [JsonPropertyName("key_id_hex")] public string? KeyIdHex { get; set; }
    }

    /// <summary>
    /// Discovered peer actively advertising services over mDNS or UDP beacons.
    /// </summary>
    internal sealed class DiscoveredPeerInfo
    {
        /// <summary>Cryptographic device identifier.</summary>
        [JsonPropertyName("device_id")] public string DeviceId { get; set; } = string.Empty;
        /// <summary>Peer hostname.</summary>
        [JsonPropertyName("hostname")] public string Hostname { get; set; } = string.Empty;
        /// <summary>Operating system string (macOS, Windows).</summary>
        [JsonPropertyName("os")] public string Os { get; set; } = string.Empty;
        /// <summary>Hardware model description.</summary>
        [JsonPropertyName("hardware_model")] public string HardwareModel { get; set; } = string.Empty;
        /// <summary>Hardware chassis form factor ("laptop", "desktop", or "unknown").</summary>
        [JsonPropertyName("form_factor")] public string? FormFactor { get; set; }
        /// <summary>Reachable IP address.</summary>
        [JsonPropertyName("ip")] public string Ip { get; set; } = string.Empty;
        /// <summary>Local interface IP address used to contact peer.</summary>
        [JsonPropertyName("local_ip_used")] public string? LocalIpUsed { get; set; }
        /// <summary>Transport label (e.g., "Thunderbolt 4").</summary>
        [JsonPropertyName("transport_label")] public string TransportLabel { get; set; } = string.Empty;
        /// <summary>True if direct point-to-point link.</summary>
        [JsonPropertyName("is_direct_cable")] public bool IsDirectCable { get; set; }
        /// <summary>Link throughput in Mbps.</summary>
        [JsonPropertyName("link_speed_mbps")] public uint? LinkSpeedMbps { get; set; }
        /// <summary>Link description.</summary>
        [JsonPropertyName("link_description")] public string LinkDescription { get; set; } = string.Empty;
        /// <summary>Measured round-trip ping time in milliseconds.</summary>
        [JsonPropertyName("rtt_ms")] public double? RttMs { get; set; }
        /// <summary>Peer primary display geometry.</summary>
        [JsonPropertyName("display")] public DisplayGeometryModel Display { get; set; } = new();
        /// <summary>List of GPU names detected on the peer.</summary>
        [JsonPropertyName("gpus")] public List<string> Gpus { get; set; } = new();
        /// <summary>Published storage share name.</summary>
        [JsonPropertyName("share_name")] public string? ShareName { get; set; }
        /// <summary>True if peer is present in the trust store.</summary>
        [JsonPropertyName("trusted")] public bool Trusted { get; set; }
        /// <summary>True if peer is administratively blocked.</summary>
        [JsonPropertyName("blocked")] public bool Blocked { get; set; }
        /// <summary>Discovery transport provenance (e.g., "udp", "bonjour", "ble", "udp+bonjour+ble").</summary>
        [JsonPropertyName("discovery_source")] public string? DiscoverySource { get; set; }
    }

    /// <summary>
    /// Comprehensive snapshot of cryptographic pairing state and trust store.
    /// </summary>
    internal sealed class TrustSnapshotInfo
    {
        /// <summary>Active 6-digit SPAKE2 pairing PIN code.</summary>
        [JsonPropertyName("pairing_pin")] public string PairingPin { get; set; } = string.Empty;
        /// <summary>Auto-trust direct cable connection policy.</summary>
        [JsonPropertyName("auto_trust_direct_cable")] public bool AutoTrustDirectCable { get; set; }
        /// <summary>Require manual PIN pairing over LAN policy.</summary>
        [JsonPropertyName("require_pairing_on_lan")] public bool RequirePairingOnLan { get; set; }
        /// <summary>List of pending pairing requests.</summary>
        [JsonPropertyName("pending_peers")] public List<PendingPeerInfo> PendingPeers { get; set; } = new();
        /// <summary>List of verified trusted peers.</summary>
        [JsonPropertyName("trusted_peers")] public List<TrustedPeerRecord> TrustedPeers { get; set; } = new();
        /// <summary>List of blocked device identifiers.</summary>
        [JsonPropertyName("blocked_device_ids")] public List<string> BlockedDeviceIds { get; set; } = new();
    }

    /// <summary>
    /// Status of the automated shared storage network volume mount.
    /// </summary>
    internal sealed class StorageStatusModel
    {
        /// <summary>True if the remote share is mounted locally.</summary>
        [JsonPropertyName("is_mounted")] public bool IsMounted { get; set; }
        /// <summary>Local drive letter or mount directory path.</summary>
        [JsonPropertyName("mount_path")] public string MountPath { get; set; } = string.Empty;
        /// <summary>Remote host IP address hosting the SMB share.</summary>
        [JsonPropertyName("remote_ip")] public string RemoteIp { get; set; } = string.Empty;
        /// <summary>Remote share name.</summary>
        [JsonPropertyName("remote_share")] public string RemoteShare { get; set; } = string.Empty;
        /// <summary>Diagnostic mount status message.</summary>
        [JsonPropertyName("message")] public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Operational status of the low-latency spatial audio UDP routing pipeline.
    /// </summary>
    internal sealed class AudioRoutingStatusModel
    {
        /// <summary>Default UDP transport port for spatial audio streaming when omitted by core.</summary>
        public const ushort DefaultAudioPort = 58284;

        /// <summary>Active audio routing topology description.</summary>
        [JsonPropertyName("topology")] public string Topology { get; set; } = string.Empty;
        /// <summary>Measured latency in milliseconds.</summary>
        [JsonPropertyName("latency_ms")] public float LatencyMs { get; set; }
        /// <summary>Audio sample rate in Hz.</summary>
        [JsonPropertyName("sample_rate")] public uint SampleRate { get; set; }
        /// <summary>PCM bit depth per sample.</summary>
        [JsonPropertyName("bit_depth")] public byte BitDepth { get; set; }
        /// <summary>True if audio streaming session is active.</summary>
        [JsonPropertyName("is_active")] public bool IsActive { get; set; }
        /// <summary>Active UDP transport port bound for spatial audio streaming.</summary>
        [JsonPropertyName("port")] public ushort Port { get; set; } = DefaultAudioPort;
        /// <summary>Cross-platform audio mixer balance (-1.0 Mac boost to +1.0 Windows boost).</summary>
        [JsonPropertyName("mixer_balance")] public float MixerBalance { get; set; }
        /// <summary>True if the remote Windows soundbar sink is muted.</summary>
        [JsonPropertyName("sink_muted")] public bool SinkMuted { get; set; }
    }

    /// <summary>
    /// Operational status of the shared virtual camera streaming pipeline.
    /// </summary>
    internal sealed class CameraStatusModel
    {
        /// <summary>Default virtual camera video frame width in pixels.</summary>
        public const uint DefaultCameraWidth = 1280;
        /// <summary>Default virtual camera video frame height in pixels.</summary>
        public const uint DefaultCameraHeight = 720;
        /// <summary>Default virtual camera frame rate in FPS.</summary>
        public const uint DefaultCameraFps = 30;
        /// <summary>Default encrypted TCP transport port for shared virtual camera streaming.</summary>
        public const ushort DefaultCameraPort = 58287;
        /// <summary>Default user-facing Windows virtual camera display name.</summary>
        public const string DefaultCameraDeviceName = "Integrator Mac Camera";

        /// <summary>True if virtual camera drivers are installed and supported.</summary>
        [JsonPropertyName("supported")] public bool Supported { get; set; } = true;
        /// <summary>True if a video capture source or virtual camera is available.</summary>
        [JsonPropertyName("camera_available")] public bool CameraAvailable { get; set; } = true;
        /// <summary>True if camera stream is actively transmitting/receiving.</summary>
        [JsonPropertyName("active")] public bool Active { get; set; }
        /// <summary>Operational role: sender or receiver.</summary>
        [JsonPropertyName("role")] public string Role { get; set; } = string.Empty;
        /// <summary>Human-readable state string.</summary>
        [JsonPropertyName("state")] public string State { get; set; } = "Disabled";
        /// <summary>Camera permissions granted status.</summary>
        [JsonPropertyName("permission_granted")] public bool PermissionGranted { get; set; } = true;
        /// <summary>Video frame width in pixels.</summary>
        [JsonPropertyName("width")] public uint Width { get; set; } = DefaultCameraWidth;
        /// <summary>Video frame height in pixels.</summary>
        [JsonPropertyName("height")] public uint Height { get; set; } = DefaultCameraHeight;
        /// <summary>Video frame rate in FPS.</summary>
        [JsonPropertyName("fps")] public uint Fps { get; set; } = DefaultCameraFps;
        /// <summary>Cumulative frame count received.</summary>
        [JsonPropertyName("frames_transferred")] public ulong FramesTransferred { get; set; }
        /// <summary>Last error string encountered in the camera pipeline.</summary>
        [JsonPropertyName("last_error")] public string? LastError { get; set; }
        /// <summary>Active encrypted TCP transport port bound for virtual camera streaming.</summary>
        [JsonPropertyName("port")] public ushort Port { get; set; } = DefaultCameraPort;
        /// <summary>Friendly display name advertised by the Windows virtual camera.</summary>
        [JsonPropertyName("device_name")] public string DeviceName { get; set; } = DefaultCameraDeviceName;
        /// <summary>True if the hardware camera privacy shutter killswitch is engaged.</summary>
        [JsonPropertyName("privacy_muted")] public bool PrivacyMuted { get; set; }
    }

    /// <summary>
    /// Discovered camera hardware/continuity device.
    /// </summary>
    internal sealed class CameraDeviceModel
    {
        [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;
        [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
        [JsonPropertyName("is_active")] public bool IsActive { get; set; }
    }

    /// <summary>
    /// Feature flag toggles controlling active background daemon tasks.
    /// </summary>
    internal sealed class FeatureFlagsModel
    {
        /// <summary>Extended display streaming toggle.</summary>
        [JsonPropertyName("display")] public bool Display { get; set; } = true;
        /// <summary>Universal input KVM toggle.</summary>
        [JsonPropertyName("input_kvm")] public bool InputKvm { get; set; } = true;
        /// <summary>Universal clipboard toggle.</summary>
        [JsonPropertyName("clipboard")] public bool Clipboard { get; set; } = true;
        /// <summary>Cross-screen drag and drop toggle.</summary>
        [JsonPropertyName("dragdrop")] public bool Dragdrop { get; set; } = true;
        /// <summary>True Tone calibration toggle.</summary>
        [JsonPropertyName("truetone")] public bool Truetone { get; set; } = true;
        /// <summary>Touch Bar telemetry toggle.</summary>
        [JsonPropertyName("touchbar")] public bool Touchbar { get; set; } = true;
        /// <summary>Shared storage auto-mounting toggle.</summary>
        [JsonPropertyName("storage")] public bool Storage { get; set; } = true;
        /// <summary>Spatial audio routing toggle.</summary>
        [JsonPropertyName("audio")] public bool Audio { get; set; } = true;
        /// <summary>Live throughput speed benchmark toggle.</summary>
        [JsonPropertyName("benchmark")] public bool Benchmark { get; set; } = true;
        /// <summary>Shared virtual camera streaming toggle.</summary>
        [JsonPropertyName("camera")] public bool Camera { get; set; }
    }

    /// <summary>
    /// Multi-monitor desk geometry layout settings and cursor transition preferences.
    /// </summary>
    internal sealed class KvmLayoutConfigModel
    {
        /// <summary>Target edge where peer display resides: "left", "right", "top", or "bottom".</summary>
        [JsonPropertyName("peer_edge")] public string PeerEdge { get; set; } = "left";
        /// <summary>Alignment offset ratio along the transition edge (-0.5 to +0.5).</summary>
        [JsonPropertyName("alignment_offset")] public float AlignmentOffset { get; set; }
        /// <summary>Cursor dwell delay in milliseconds before hopping across screen boundaries.</summary>
        [JsonPropertyName("hop_delay_ms")] public uint HopDelayMs { get; set; } = 40;
        /// <summary>Prevents cursor transitions in screen corners.</summary>
        [JsonPropertyName("dead_corners")] public bool DeadCorners { get; set; } = true;
        /// <summary>Translates Windows Ctrl keys to macOS Command keys and vice versa.</summary>
        [JsonPropertyName("modifier_translation")] public bool ModifierTranslation { get; set; } = true;
        /// <summary>Translates high-precision trackpad scrolling and gestures.</summary>
        [JsonPropertyName("precision_touchpad")] public bool PrecisionTouchpad { get; set; } = true;
        /// <summary>Shows translucent ghost thumbnail during file drag operations.</summary>
        [JsonPropertyName("ghost_thumbnail")] public bool GhostThumbnail { get; set; } = true;
        /// <summary>Clamps bandwidth during file drag transfers to prevent link saturation.</summary>
        [JsonPropertyName("qos_clamp")] public bool QosClamp { get; set; } = true;
        /// <summary>Default target folder name for cross-screen dropped files.</summary>
        [JsonPropertyName("drop_folder")] public string DropFolder { get; set; } = "downloads";
        /// <summary>Timestamp in milliseconds when layout was last updated.</summary>
        [JsonPropertyName("updated_at_ms")] public ulong UpdatedAtMs { get; set; }
    }

    /// <summary>
    /// Operational status snapshot of the Universal Input KVM subsystem.
    /// </summary>
    internal sealed class KvmStatusSnapshotModel
    {
        /// <summary>True if KVM subsystem is enabled.</summary>
        [JsonPropertyName("enabled")] public bool Enabled { get; set; }
        /// <summary>True if cross-screen drag and drop is enabled.</summary>
        [JsonPropertyName("dragdrop_enabled")] public bool DragdropEnabled { get; set; }
        /// <summary>True if low-level OS keyboard/mouse hook is active.</summary>
        [JsonPropertyName("hook_active")] public bool? HookActive { get; set; } = true;
        /// <summary>Operational role: "idle", "controlling", or "controlled".</summary>
        [JsonPropertyName("role")] public string Role { get; set; } = "idle";
        /// <summary>IP address of connected peer.</summary>
        [JsonPropertyName("connected_peer_ip")] public string? ConnectedPeerIp { get; set; }
        /// <summary>Operating system of connected peer.</summary>
        [JsonPropertyName("peer_os")] public string? PeerOs { get; set; }
        /// <summary>Width of peer monitor.</summary>
        [JsonPropertyName("peer_width")] public uint PeerWidth { get; set; }
        /// <summary>Height of peer monitor.</summary>
        [JsonPropertyName("peer_height")] public uint PeerHeight { get; set; }
        /// <summary>Filename label of payload currently being dragged across displays.</summary>
        [JsonPropertyName("active_drag_label")] public string? ActiveDragLabel { get; set; }
        /// <summary>True if KVM Gaming Boundary Lock is freezing cursor edge-hopping.</summary>
        [JsonPropertyName("boundary_locked")] public bool BoundaryLocked { get; set; }
        /// <summary>Desk monitor arrangement layout settings.</summary>
        [JsonPropertyName("layout")] public KvmLayoutConfigModel Layout { get; set; } = new();
    }

    /// <summary>
    /// Structured log entry emitted by the Rust core tracing layer.
    /// </summary>
    internal sealed class LogEntryModel
    {
        /// <summary>Timestamp in milliseconds since Unix epoch.</summary>
        [JsonPropertyName("ts_ms")] public ulong TsMs { get; set; }
        /// <summary>Log severity level: "INFO", "WARN", "ERROR", "DEBUG", "TRACE".</summary>
        [JsonPropertyName("level")] public string Level { get; set; } = "INFO";
        /// <summary>Log message text.</summary>
        [JsonPropertyName("message")] public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Operating system permission audit status item returned inside SetupHealthSnapshotModel.
    /// </summary>
    internal sealed class PermissionStatusModel
    {
        /// <summary>Canonical permission identifier (e.g., "firewall", "network_profile", "camera_privacy", "smb_server", "admin_elevation").</summary>
        [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;
        /// <summary>Human-readable permission title.</summary>
        [JsonPropertyName("title")] public string Title { get; set; } = string.Empty;
        /// <summary>Explanation of why Integrator uses this permission.</summary>
        [JsonPropertyName("description")] public string Description { get; set; } = string.Empty;
        /// <summary>True if permission or prerequisite is currently satisfied.</summary>
        [JsonPropertyName("granted")] public bool Granted { get; set; }
        /// <summary>True if missing this permission triggers the launch Setup Assistant prompt.</summary>
        [JsonPropertyName("required")] public bool Required { get; set; }
        /// <summary>True if Integrator can trigger an automated or UAC-elevated fix directly.</summary>
        [JsonPropertyName("can_request_directly")] public bool CanRequestDirectly { get; set; }
        /// <summary>Optional Windows Settings (ms-settings:) deep-link URI.</summary>
        [JsonPropertyName("settings_url")] public string? SettingsUrl { get; set; }
        /// <summary>Diagnostic status detail string.</summary>
        [JsonPropertyName("detail")] public string Detail { get; set; } = string.Empty;
    }

    /// <summary>
    /// Companion streaming tool or driver dependency status item returned inside SetupHealthSnapshotModel.
    /// </summary>
    internal sealed class DependencyStatusModel
    {
        /// <summary>Canonical dependency identifier ("sunshine", "moonlight", "vdd", "usb_ncm", "vcam").</summary>
        [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;
        /// <summary>Human-readable dependency name.</summary>
        [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
        /// <summary>Explanation of which subsystem relies on this tool or driver.</summary>
        [JsonPropertyName("description")] public string Description { get; set; } = string.Empty;
        /// <summary>True if detected as installed on the local machine.</summary>
        [JsonPropertyName("installed")] public bool Installed { get; set; }
        /// <summary>Optional runtime flag indicating whether the service or process is currently active.</summary>
        [JsonPropertyName("running")] public bool? Running { get; set; }
        /// <summary>True if required for core streaming functionality.</summary>
        [JsonPropertyName("required")] public bool Required { get; set; }
        /// <summary>Detected binary, DLL, or PnP device path if found.</summary>
        [JsonPropertyName("detected_path")] public string? DetectedPath { get; set; }
        /// <summary>Primary installation method label (e.g., "WinGet", "Elevated PowerShell Installer").</summary>
        [JsonPropertyName("install_method")] public string InstallMethod { get; set; } = string.Empty;
        /// <summary>Copyable CLI installation command.</summary>
        [JsonPropertyName("install_command")] public string InstallCommand { get; set; } = string.Empty;
        /// <summary>Official fallback download or guide URL.</summary>
        [JsonPropertyName("download_url")] public string DownloadUrl { get; set; } = string.Empty;
        /// <summary>True if 1-click guided installation is supported.</summary>
        [JsonPropertyName("can_auto_install")] public bool CanAutoInstall { get; set; }
    }

    /// <summary>
    /// Aggregate cross-platform OS permissions and companion dependencies health snapshot.
    /// </summary>
    internal sealed class SetupHealthSnapshotModel
    {
        /// <summary>Operating system identifier ("windows", "macos").</summary>
        [JsonPropertyName("os")] public string Os { get; set; } = string.Empty;
        /// <summary>True if process holds Administrator privileges.</summary>
        [JsonPropertyName("is_elevated")] public bool IsElevated { get; set; }
        /// <summary>True if at least one required permission or required dependency is missing.</summary>
        [JsonPropertyName("needs_attention")] public bool NeedsAttention { get; set; }
        /// <summary>Number of missing required OS permissions.</summary>
        [JsonPropertyName("missing_required_permissions")] public int MissingRequiredPermissions { get; set; }
        /// <summary>Number of missing required companion dependencies.</summary>
        [JsonPropertyName("missing_required_dependencies")] public int MissingRequiredDependencies { get; set; }
        /// <summary>User-persisted flag suppressing automatic Setup dialog presentation on launch.</summary>
        [JsonPropertyName("suppress_launch_prompt")] public bool SuppressLaunchPrompt { get; set; }
        /// <summary>Audited OS permissions list.</summary>
        [JsonPropertyName("permissions")] public List<PermissionStatusModel> Permissions { get; set; } = new();
        /// <summary>Audited companion dependencies list.</summary>
        [JsonPropertyName("dependencies")] public List<DependencyStatusModel> Dependencies { get; set; } = new();
    }

    /// <summary>
    /// Results of an active live network throughput benchmark test.
    /// </summary>
    internal sealed class SpeedTestResultModel
    {
        /// <summary>True if benchmark completed successfully.</summary>
        [JsonPropertyName("success")] public bool Success { get; set; }
        /// <summary>Peak combined link throughput in Gbps.</summary>
        [JsonPropertyName("max_gbps")] public double MaxGbps { get; set; }
        /// <summary>Measured upload bandwidth in Gbps.</summary>
        [JsonPropertyName("upload_gbps")] public double UploadGbps { get; set; }
        /// <summary>Measured upload throughput in MB/s.</summary>
        [JsonPropertyName("upload_mb_s")] public double UploadMbS { get; set; }
        /// <summary>Measured download bandwidth in Gbps.</summary>
        [JsonPropertyName("download_gbps")] public double DownloadGbps { get; set; }
        /// <summary>Measured download throughput in MB/s.</summary>
        [JsonPropertyName("download_mb_s")] public double DownloadMbS { get; set; }
        /// <summary>Measured round-trip ping time in milliseconds.</summary>
        [JsonPropertyName("latency_ms")] public double LatencyMs { get; set; }
        /// <summary>Target peer IP benchmarked.</summary>
        [JsonPropertyName("peer_ip")] public string PeerIp { get; set; } = string.Empty;
        /// <summary>Formatted summary string.</summary>
        [JsonPropertyName("summary")] public string Summary { get; set; } = string.Empty;
    }

    /// <summary>
    /// Real-time hardware telemetry polled from a graphics processing unit.
    /// </summary>
    internal sealed class GpuTelemetryModel
    {
        /// <summary>GPU adapter model name.</summary>
        [JsonPropertyName("gpu_name")] public string GpuName { get; set; } = string.Empty;
        /// <summary>Core temperature in degrees Celsius.</summary>
        [JsonPropertyName("temperature_c")] public uint TemperatureC { get; set; }
        /// <summary>Real-time power consumption in watts.</summary>
        [JsonPropertyName("power_usage_watts")] public float PowerUsageWatts { get; set; }
        /// <summary>GPU core utilization percentage (0-100%).</summary>
        [JsonPropertyName("gpu_utilization_percent")] public uint GpuUtilizationPercent { get; set; }
        /// <summary>Video memory controller load percentage (0-100%).</summary>
        [JsonPropertyName("memory_utilization_percent")] public uint MemoryUtilizationPercent { get; set; }
        /// <summary>Allocated VRAM in megabytes.</summary>
        [JsonPropertyName("memory_used_mb")] public ulong MemoryUsedMb { get; set; }
        /// <summary>Total dedicated VRAM in megabytes.</summary>
        [JsonPropertyName("memory_total_mb")] public ulong MemoryTotalMb { get; set; }
        /// <summary>GPU core clock frequency in MHz.</summary>
        [JsonPropertyName("core_clock_mhz")] public uint CoreClockMhz { get; set; }
        /// <summary>All detected physical GPUs installed in the machine.</summary>
        [JsonPropertyName("all_gpus")] public List<string> AllGpus { get; set; } = new List<string>();
    }

    /// <summary>
    /// Aggregate workstation status model returned by the get_bridge_status RPC endpoint.
    /// </summary>
    internal sealed class BridgeStatusModel
    {
        /// <summary>Cryptographic device identifier of the local workstation.</summary>
        [JsonPropertyName("device_id")] public string DeviceId { get; set; } = string.Empty;
        /// <summary>Workstation hostname.</summary>
        [JsonPropertyName("hostname")] public string Hostname { get; set; } = string.Empty;
        /// <summary>Operating system string.</summary>
        [JsonPropertyName("os")] public string Os { get; set; } = string.Empty;
        /// <summary>Local OS identifier.</summary>
        [JsonPropertyName("local_os")] public string LocalOs { get; set; } = string.Empty;
        /// <summary>Hardware system model description.</summary>
        [JsonPropertyName("hardware_model")] public string HardwareModel { get; set; } = string.Empty;
        /// <summary>Local hardware chassis form factor ("laptop", "desktop", or "unknown").</summary>
        [JsonPropertyName("form_factor")] public string? FormFactor { get; set; }
        /// <summary>Processor brand string.</summary>
        [JsonPropertyName("cpu_brand")] public string CpuBrand { get; set; } = string.Empty;
        /// <summary>Primary display configuration.</summary>
        [JsonPropertyName("primary_display")] public PrimaryDisplayInfo PrimaryDisplay { get; set; } = new();
        /// <summary>List of local graphics adapters.</summary>
        [JsonPropertyName("local_gpus")] public List<GpuDeviceInfo> LocalGpus { get; set; } = new();
        /// <summary>List of local shared storage share names.</summary>
        [JsonPropertyName("local_share_names")] public List<string> LocalShareNames { get; set; } = new();
        /// <summary>True if machine features an Apple Touch Bar.</summary>
        [JsonPropertyName("has_touch_bar")] public bool HasTouchBar { get; set; }

        /// <summary>True if a remote peer is actively connected.</summary>
        [JsonPropertyName("peer_connected")] public bool PeerConnected { get; set; }
        /// <summary>True if connected peer has completed cryptographic pairing.</summary>
        [JsonPropertyName("peer_trusted")] public bool PeerTrusted { get; set; }
        /// <summary>Device identifier of connected peer.</summary>
        [JsonPropertyName("peer_device_id")] public string? PeerDeviceId { get; set; }
        /// <summary>IP address of connected peer.</summary>
        [JsonPropertyName("peer_ip")] public string? PeerIp { get; set; }
        /// <summary>Operating system of connected peer.</summary>
        [JsonPropertyName("peer_os")] public string? PeerOs { get; set; }
        /// <summary>Hostname of connected peer.</summary>
        [JsonPropertyName("peer_name")] public string? PeerName { get; set; }
        /// <summary>Hardware model of connected peer.</summary>
        [JsonPropertyName("peer_hardware_model")] public string? PeerHardwareModel { get; set; }
        /// <summary>Hardware chassis form factor of connected peer ("laptop", "desktop", or "unknown").</summary>
        [JsonPropertyName("peer_form_factor")] public string? PeerFormFactor { get; set; }
        /// <summary>Primary display geometry of connected peer.</summary>
        [JsonPropertyName("peer_display")] public DisplayGeometryModel? PeerDisplay { get; set; }
        /// <summary>List of GPU names detected on connected peer.</summary>
        [JsonPropertyName("peer_gpus")] public List<string> PeerGpus { get; set; } = new();
        /// <summary>Shared storage volume name published by peer.</summary>
        [JsonPropertyName("peer_share_name")] public string? PeerShareName { get; set; }
        /// <summary>Local IP address used to communicate with peer.</summary>
        [JsonPropertyName("peer_local_ip_used")] public string? PeerLocalIpUsed { get; set; }
        /// <summary>Physical transport label (e.g., "Thunderbolt 4 Direct Cable").</summary>
        [JsonPropertyName("transport_label")] public string TransportLabel { get; set; } = string.Empty;
        /// <summary>True if direct point-to-point cable connection.</summary>
        [JsonPropertyName("is_direct_cable")] public bool IsDirectCable { get; set; }
        /// <summary>Negotiated link speed in Mbps.</summary>
        [JsonPropertyName("link_speed_mbps")] public uint? LinkSpeedMbps { get; set; }
        /// <summary>Link topology description.</summary>
        [JsonPropertyName("link_description")] public string LinkDescription { get; set; } = string.Empty;
        /// <summary>Measured round-trip ping time in milliseconds.</summary>
        [JsonPropertyName("rtt_ms")] public double? RttMs { get; set; }
        /// <summary>Formatted link speed string.</summary>
        [JsonPropertyName("link_speed")] public string LinkSpeed { get; set; } = string.Empty;
        /// <summary>Link transport category.</summary>
        [JsonPropertyName("link_type")] public string LinkType { get; set; } = string.Empty;

        /// <summary>True if display streaming session is active.</summary>
        [JsonPropertyName("display_active")] public bool DisplayActive { get; set; }
        /// <summary>Active display streaming mode (e.g., "Mac -> PC", "PC -> Mac").</summary>
        [JsonPropertyName("active_mode")] public string? ActiveMode { get; set; }
        /// <summary>True if Windows machine is the streaming master.</summary>
        [JsonPropertyName("is_windows_master")] public bool IsWindowsMaster { get; set; }
        /// <summary>Preferred GPU adapter tag for video encoding.</summary>
        [JsonPropertyName("encode_gpu")] public string EncodeGpu { get; set; } = string.Empty;
        /// <summary>Preferred GPU adapter tag for video decoding.</summary>
        [JsonPropertyName("decode_gpu")] public string DecodeGpu { get; set; } = string.Empty;
        /// <summary>True if platform supports manual GPU selection controls.</summary>
        [JsonPropertyName("gpu_controls_supported")] public bool GpuControlsSupported { get; set; }
        /// <summary>True if Touch Bar telemetry strip is active.</summary>
        [JsonPropertyName("touchbar_active")] public bool TouchbarActive { get; set; }

        /// <summary>True if ambient light sensor hardware is supported.</summary>
        [JsonPropertyName("ambient_supported")] public bool AmbientSupported { get; set; }
        /// <summary>Ambient light illuminance reading in lux.</summary>
        [JsonPropertyName("ambient_lux")] public float? AmbientLux { get; set; }
        /// <summary>Ambient Correlated Color Temperature reading in Kelvin.</summary>
        [JsonPropertyName("ambient_cct")] public uint? AmbientCct { get; set; }

        /// <summary>True if shared storage volume is mounted.</summary>
        [JsonPropertyName("storage_mounted")] public bool StorageMounted { get; set; }
        /// <summary>Shared storage mount telemetry.</summary>
        [JsonPropertyName("storage_status")] public StorageStatusModel StorageStatus { get; set; } = new();
        /// <summary>User-configured preferred peer share name override.</summary>
        [JsonPropertyName("preferred_peer_share")] public string? PreferredPeerShare { get; set; }
        /// <summary>User-configured local shared directory path.</summary>
        [JsonPropertyName("local_shared_folder")] public string? LocalSharedFolder { get; set; }
        /// <summary>True if SMB share should automatically mount upon peer detection.</summary>
        [JsonPropertyName("auto_mount_storage")] public bool AutoMountStorage { get; set; }

        /// <summary>Spatial audio routing status.</summary>
        [JsonPropertyName("audio_status")] public AudioRoutingStatusModel AudioStatus { get; set; } = new();
        /// <summary>Shared virtual camera streaming status.</summary>
        [JsonPropertyName("camera_status")] public CameraStatusModel CameraStatus { get; set; } = new();
        /// <summary>Feature flag toggles.</summary>
        [JsonPropertyName("feature_flags")] public FeatureFlagsModel FeatureFlags { get; set; } = new();
        /// <summary>Universal input KVM status.</summary>
        [JsonPropertyName("kvm")] public KvmStatusSnapshotModel Kvm { get; set; } = new();

        /// <summary>List of local network interfaces.</summary>
        [JsonPropertyName("local_interfaces")] public List<LocalInterfaceInfo> LocalInterfaces { get; set; } = new();
        /// <summary>List of manually configured peer IP addresses.</summary>
        [JsonPropertyName("manual_peer_ips")] public List<string> ManualPeerIps { get; set; } = new();
        /// <summary>List of discovered peer nodes.</summary>
        [JsonPropertyName("discovered_peers")] public List<DiscoveredPeerInfo> DiscoveredPeers { get; set; } = new();
        /// <summary>Active discovery mode ("all", "udp", "bonjour", "ble").</summary>
        [JsonPropertyName("discovery_mode")] public string? DiscoveryMode { get; set; }
        /// <summary>True if Bonjour / mDNS (_integrator._tcp.local.) discovery is active.</summary>
        [JsonPropertyName("bonjour_active")] public bool? BonjourActive { get; set; }
        /// <summary>True if Bluetooth LE magic-packet proximity discovery is active.</summary>
        [JsonPropertyName("ble_active")] public bool? BleActive { get; set; }
        /// <summary>Cryptographic trust snapshot.</summary>
        [JsonPropertyName("trust")] public TrustSnapshotInfo Trust { get; set; } = new();

        /// <summary>True if configured to launch automatically at Windows logon.</summary>
        [JsonPropertyName("autostart_enabled")] public bool AutostartEnabled { get; set; }
        /// <summary>Cross-platform OS permissions and companion dependencies setup health snapshot.</summary>
        [JsonPropertyName("setup_status")] public SetupHealthSnapshotModel? SetupStatus { get; set; }
        /// <summary>Recent log entries emitted by the core.</summary>
        [JsonPropertyName("recent_logs")] public List<LogEntryModel> RecentLogs { get; set; } = new();
    }
}
