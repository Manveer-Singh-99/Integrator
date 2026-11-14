using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace IntegratorUI
{
    internal static class CoreNative
    {
        private const string DllName = "integrator_core.dll";

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate void UiEventCallback(IntPtr eventNameUtf8, IntPtr payloadJsonUtf8);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool integrator_core_try_focus_existing();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int integrator_core_run_cli(int argc, IntPtr[] argv);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void integrator_core_set_ui_callback(UiEventCallback? cb);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int integrator_core_init(UiEventCallback? cb);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr integrator_core_invoke(IntPtr methodUtf8, IntPtr paramsJsonUtf8);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void integrator_core_free_string(IntPtr ptr);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void integrator_core_tray_action(IntPtr actionUtf8);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void integrator_core_shutdown();
    }

    internal static class CoreBridge
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        // Hold delegate strongly so GC never collects the native callback trampoline.
        private static CoreNative.UiEventCallback? _nativeCallback;
        public static event Action<string, string>? UiEventReceived;

        private static IntPtr AllocUtf8(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value + "\0");
            IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            return ptr;
        }

        private static string ReadUtf8(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return string.Empty;
            int len = 0;
            while (Marshal.ReadByte(ptr, len) != 0) len++;
            if (len == 0) return string.Empty;
            byte[] buf = new byte[len];
            Marshal.Copy(ptr, buf, 0, len);
            return Encoding.UTF8.GetString(buf);
        }

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

        public static bool TryFocusExisting()
        {
            return CoreNative.integrator_core_try_focus_existing();
        }

        public static bool Initialize()
        {
            _nativeCallback = OnNativeUiEvent;
            return CoreNative.integrator_core_init(_nativeCallback) == 0;
        }

        private static void OnNativeUiEvent(IntPtr eventPtr, IntPtr payloadPtr)
        {
            string evt = ReadUtf8(eventPtr);
            string payload = ReadUtf8(payloadPtr);
            UiEventReceived?.Invoke(evt, payload);
        }

        public static RpcResult<T> Invoke<T>(string method, object? parameters = null)
        {
            string paramsJson = parameters switch
            {
                null => "{}",
                string s => s,
                _ => JsonSerializer.Serialize(parameters, JsonOptions)
            };

            IntPtr mPtr = AllocUtf8(method);
            IntPtr pPtr = AllocUtf8(paramsJson);
            IntPtr resPtr = IntPtr.Zero;
            try
            {
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
                Marshal.FreeHGlobal(mPtr);
                Marshal.FreeHGlobal(pPtr);
            }
        }

        public static void TrayAction(string action)
        {
            IntPtr aPtr = AllocUtf8(action);
            try
            {
                CoreNative.integrator_core_tray_action(aPtr);
            }
            finally
            {
                Marshal.FreeHGlobal(aPtr);
            }
        }

        public static void Shutdown()
        {
            CoreNative.integrator_core_set_ui_callback(null);
            CoreNative.integrator_core_shutdown();
        }
    }

    internal sealed class RpcEnvelope<T>
    {
        [JsonPropertyName("ok")] public bool Ok { get; set; }
        [JsonPropertyName("data")] public T? Data { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
    }

    internal readonly record struct RpcResult<T>(bool Ok, T? Data, string? Error);

    internal sealed class UiToastPayload
    {
        [JsonPropertyName("message")] public string? Message { get; set; }
        [JsonPropertyName("kind")] public string? Kind { get; set; }
    }

    internal sealed class PrimaryDisplayInfo
    {
        [JsonPropertyName("width")] public uint Width { get; set; }
        [JsonPropertyName("height")] public uint Height { get; set; }
        [JsonPropertyName("fps")] public uint Fps { get; set; } = 60;
        [JsonPropertyName("scale_factor")] public double ScaleFactor { get; set; } = 1.0;
    }

    internal sealed class GpuDeviceInfo
    {
        [JsonPropertyName("index")] public uint Index { get; set; }
        [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
        [JsonPropertyName("vendor")] public string Vendor { get; set; } = string.Empty;
        [JsonPropertyName("is_discrete")] public bool IsDiscrete { get; set; }
        [JsonPropertyName("vram_mb")] public ulong? VramMb { get; set; }
    }

    internal sealed class DisplayGeometryModel
    {
        [JsonPropertyName("width")] public uint Width { get; set; }
        [JsonPropertyName("height")] public uint Height { get; set; }
        [JsonPropertyName("fps")] public uint Fps { get; set; }
    }

    internal sealed class LocalInterfaceInfo
    {
        [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
        [JsonPropertyName("friendly_name")] public string? FriendlyName { get; set; }
        [JsonPropertyName("ip")] public string Ip { get; set; } = string.Empty;
        [JsonPropertyName("netmask")] public string? Netmask { get; set; }
        [JsonPropertyName("broadcast")] public string? Broadcast { get; set; }
        [JsonPropertyName("cidr_prefix")] public byte? CidrPrefix { get; set; }
        [JsonPropertyName("transport")] public string? Transport { get; set; }
        [JsonPropertyName("link_speed_mbps")] public uint? LinkSpeedMbps { get; set; }
        [JsonPropertyName("description")] public string? Description { get; set; }
    }

    internal sealed class PendingPeerInfo
    {
        [JsonPropertyName("device_id")] public string DeviceId { get; set; } = string.Empty;
        [JsonPropertyName("hostname")] public string Hostname { get; set; } = string.Empty;
        [JsonPropertyName("ip")] public string Ip { get; set; } = string.Empty;
        [JsonPropertyName("is_direct_cable")] public bool IsDirectCable { get; set; }
        [JsonPropertyName("trusted")] public bool Trusted { get; set; }
        [JsonPropertyName("blocked")] public bool Blocked { get; set; }
    }

    internal sealed class TrustedPeerRecord
    {
        [JsonPropertyName("device_id")] public string DeviceId { get; set; } = string.Empty;
        [JsonPropertyName("hostname")] public string Hostname { get; set; } = string.Empty;
        [JsonPropertyName("last_ip")] public string LastIp { get; set; } = string.Empty;
        [JsonPropertyName("paired_at_epoch")] public ulong? PairedAtEpoch { get; set; }
        [JsonPropertyName("via_direct_cable")] public bool ViaDirectCable { get; set; }
        [JsonPropertyName("ed25519_pubkey_hex")] public string? Ed25519PubkeyHex { get; set; }
        [JsonPropertyName("key_id_hex")] public string? KeyIdHex { get; set; }
    }

    internal sealed class DiscoveredPeerInfo
    {
        [JsonPropertyName("device_id")] public string DeviceId { get; set; } = string.Empty;
        [JsonPropertyName("hostname")] public string Hostname { get; set; } = string.Empty;
        [JsonPropertyName("os")] public string Os { get; set; } = string.Empty;
        [JsonPropertyName("hardware_model")] public string HardwareModel { get; set; } = string.Empty;
        [JsonPropertyName("ip")] public string Ip { get; set; } = string.Empty;
        [JsonPropertyName("local_ip_used")] public string? LocalIpUsed { get; set; }
        [JsonPropertyName("transport_label")] public string TransportLabel { get; set; } = string.Empty;
        [JsonPropertyName("is_direct_cable")] public bool IsDirectCable { get; set; }
        [JsonPropertyName("link_speed_mbps")] public uint? LinkSpeedMbps { get; set; }
        [JsonPropertyName("link_description")] public string LinkDescription { get; set; } = string.Empty;
        [JsonPropertyName("rtt_ms")] public double? RttMs { get; set; }
        [JsonPropertyName("display")] public DisplayGeometryModel Display { get; set; } = new();
        [JsonPropertyName("gpus")] public List<string> Gpus { get; set; } = new();
        [JsonPropertyName("share_name")] public string? ShareName { get; set; }
        [JsonPropertyName("trusted")] public bool Trusted { get; set; }
        [JsonPropertyName("blocked")] public bool Blocked { get; set; }
    }

    internal sealed class TrustSnapshotInfo
    {
        [JsonPropertyName("pairing_pin")] public string PairingPin { get; set; } = string.Empty;
        [JsonPropertyName("auto_trust_direct_cable")] public bool AutoTrustDirectCable { get; set; }
        [JsonPropertyName("require_pairing_on_lan")] public bool RequirePairingOnLan { get; set; }
        [JsonPropertyName("pending_peers")] public List<PendingPeerInfo> PendingPeers { get; set; } = new();
        [JsonPropertyName("trusted_peers")] public List<TrustedPeerRecord> TrustedPeers { get; set; } = new();
        [JsonPropertyName("blocked_device_ids")] public List<string> BlockedDeviceIds { get; set; } = new();
    }

    internal sealed class StorageStatusModel
    {
        [JsonPropertyName("is_mounted")] public bool IsMounted { get; set; }
        [JsonPropertyName("mount_path")] public string MountPath { get; set; } = string.Empty;
        [JsonPropertyName("remote_ip")] public string RemoteIp { get; set; } = string.Empty;
        [JsonPropertyName("remote_share")] public string RemoteShare { get; set; } = string.Empty;
        [JsonPropertyName("message")] public string Message { get; set; } = string.Empty;
    }

    internal sealed class AudioRoutingStatusModel
    {
        [JsonPropertyName("topology")] public string Topology { get; set; } = string.Empty;
        [JsonPropertyName("latency_ms")] public float LatencyMs { get; set; }
        [JsonPropertyName("sample_rate")] public uint SampleRate { get; set; }
        [JsonPropertyName("bit_depth")] public byte BitDepth { get; set; }
        [JsonPropertyName("is_active")] public bool IsActive { get; set; }
    }

    internal sealed class FeatureFlagsModel
    {
        [JsonPropertyName("display")] public bool Display { get; set; } = true;
        [JsonPropertyName("input_kvm")] public bool InputKvm { get; set; } = true;
        [JsonPropertyName("clipboard")] public bool Clipboard { get; set; } = true;
        [JsonPropertyName("dragdrop")] public bool Dragdrop { get; set; } = true;
        [JsonPropertyName("truetone")] public bool Truetone { get; set; } = true;
        [JsonPropertyName("touchbar")] public bool Touchbar { get; set; } = true;
        [JsonPropertyName("storage")] public bool Storage { get; set; } = true;
        [JsonPropertyName("audio")] public bool Audio { get; set; } = true;
    }

    internal sealed class KvmLayoutConfigModel
    {
        [JsonPropertyName("peer_edge")] public string PeerEdge { get; set; } = "right";
        [JsonPropertyName("alignment_offset")] public float AlignmentOffset { get; set; }
        [JsonPropertyName("hop_delay_ms")] public uint HopDelayMs { get; set; } = 35;
        [JsonPropertyName("dead_corners")] public bool DeadCorners { get; set; } = true;
        [JsonPropertyName("modifier_translation")] public bool ModifierTranslation { get; set; } = true;
        [JsonPropertyName("precision_touchpad")] public bool PrecisionTouchpad { get; set; } = true;
        [JsonPropertyName("ghost_thumbnail")] public bool GhostThumbnail { get; set; } = true;
        [JsonPropertyName("qos_clamp")] public bool QosClamp { get; set; } = true;
        [JsonPropertyName("drop_folder")] public string DropFolder { get; set; } = "downloads";
        [JsonPropertyName("updated_at_ms")] public ulong UpdatedAtMs { get; set; }
    }

    internal sealed class KvmStatusSnapshotModel
    {
        [JsonPropertyName("enabled")] public bool Enabled { get; set; }
        [JsonPropertyName("dragdrop_enabled")] public bool DragdropEnabled { get; set; }
        [JsonPropertyName("hook_active")] public bool? HookActive { get; set; } = true;
        [JsonPropertyName("role")] public string Role { get; set; } = "idle";
        [JsonPropertyName("connected_peer_ip")] public string? ConnectedPeerIp { get; set; }
        [JsonPropertyName("peer_os")] public string? PeerOs { get; set; }
        [JsonPropertyName("peer_width")] public uint PeerWidth { get; set; }
        [JsonPropertyName("peer_height")] public uint PeerHeight { get; set; }
        [JsonPropertyName("active_drag_label")] public string? ActiveDragLabel { get; set; }
        [JsonPropertyName("layout")] public KvmLayoutConfigModel Layout { get; set; } = new();
    }

    internal sealed class LogEntryModel
    {
        [JsonPropertyName("ts_ms")] public ulong TsMs { get; set; }
        [JsonPropertyName("level")] public string Level { get; set; } = "INFO";
        [JsonPropertyName("message")] public string Message { get; set; } = string.Empty;
    }

    internal sealed class SpeedTestResultModel
    {
        [JsonPropertyName("success")] public bool Success { get; set; }
        [JsonPropertyName("max_gbps")] public double MaxGbps { get; set; }
        [JsonPropertyName("upload_gbps")] public double UploadGbps { get; set; }
        [JsonPropertyName("upload_mb_s")] public double UploadMbS { get; set; }
        [JsonPropertyName("download_gbps")] public double DownloadGbps { get; set; }
        [JsonPropertyName("download_mb_s")] public double DownloadMbS { get; set; }
        [JsonPropertyName("latency_ms")] public double LatencyMs { get; set; }
        [JsonPropertyName("peer_ip")] public string PeerIp { get; set; } = string.Empty;
        [JsonPropertyName("summary")] public string Summary { get; set; } = string.Empty;
    }

    internal sealed class GpuTelemetryModel
    {
        [JsonPropertyName("gpu_name")] public string GpuName { get; set; } = string.Empty;
        [JsonPropertyName("temperature_c")] public uint TemperatureC { get; set; }
        [JsonPropertyName("power_usage_watts")] public float PowerUsageWatts { get; set; }
        [JsonPropertyName("gpu_utilization_percent")] public uint GpuUtilizationPercent { get; set; }
        [JsonPropertyName("memory_utilization_percent")] public uint MemoryUtilizationPercent { get; set; }
        [JsonPropertyName("memory_used_mb")] public ulong MemoryUsedMb { get; set; }
        [JsonPropertyName("memory_total_mb")] public ulong MemoryTotalMb { get; set; }
        [JsonPropertyName("core_clock_mhz")] public uint CoreClockMhz { get; set; }
    }

    internal sealed class BridgeStatusModel
    {
        [JsonPropertyName("device_id")] public string DeviceId { get; set; } = string.Empty;
        [JsonPropertyName("hostname")] public string Hostname { get; set; } = string.Empty;
        [JsonPropertyName("os")] public string Os { get; set; } = string.Empty;
        [JsonPropertyName("local_os")] public string LocalOs { get; set; } = string.Empty;
        [JsonPropertyName("hardware_model")] public string HardwareModel { get; set; } = string.Empty;
        [JsonPropertyName("cpu_brand")] public string CpuBrand { get; set; } = string.Empty;
        [JsonPropertyName("primary_display")] public PrimaryDisplayInfo PrimaryDisplay { get; set; } = new();
        [JsonPropertyName("local_gpus")] public List<GpuDeviceInfo> LocalGpus { get; set; } = new();
        [JsonPropertyName("local_share_names")] public List<string> LocalShareNames { get; set; } = new();
        [JsonPropertyName("has_touch_bar")] public bool HasTouchBar { get; set; }

        [JsonPropertyName("peer_connected")] public bool PeerConnected { get; set; }
        [JsonPropertyName("peer_trusted")] public bool PeerTrusted { get; set; }
        [JsonPropertyName("peer_device_id")] public string? PeerDeviceId { get; set; }
        [JsonPropertyName("peer_ip")] public string? PeerIp { get; set; }
        [JsonPropertyName("peer_os")] public string? PeerOs { get; set; }
        [JsonPropertyName("peer_name")] public string? PeerName { get; set; }
        [JsonPropertyName("peer_hardware_model")] public string? PeerHardwareModel { get; set; }
        [JsonPropertyName("peer_display")] public DisplayGeometryModel? PeerDisplay { get; set; }
        [JsonPropertyName("peer_gpus")] public List<string> PeerGpus { get; set; } = new();
        [JsonPropertyName("peer_share_name")] public string? PeerShareName { get; set; }
        [JsonPropertyName("peer_local_ip_used")] public string? PeerLocalIpUsed { get; set; }
        [JsonPropertyName("transport_label")] public string TransportLabel { get; set; } = string.Empty;
        [JsonPropertyName("is_direct_cable")] public bool IsDirectCable { get; set; }
        [JsonPropertyName("link_speed_mbps")] public uint? LinkSpeedMbps { get; set; }
        [JsonPropertyName("link_description")] public string LinkDescription { get; set; } = string.Empty;
        [JsonPropertyName("rtt_ms")] public double? RttMs { get; set; }
        [JsonPropertyName("link_speed")] public string LinkSpeed { get; set; } = string.Empty;
        [JsonPropertyName("link_type")] public string LinkType { get; set; } = string.Empty;

        [JsonPropertyName("display_active")] public bool DisplayActive { get; set; }
        [JsonPropertyName("active_mode")] public string? ActiveMode { get; set; }
        [JsonPropertyName("is_windows_master")] public bool IsWindowsMaster { get; set; }
        [JsonPropertyName("encode_gpu")] public string EncodeGpu { get; set; } = string.Empty;
        [JsonPropertyName("decode_gpu")] public string DecodeGpu { get; set; } = string.Empty;
        [JsonPropertyName("gpu_controls_supported")] public bool GpuControlsSupported { get; set; }
        [JsonPropertyName("touchbar_active")] public bool TouchbarActive { get; set; }

        [JsonPropertyName("ambient_supported")] public bool AmbientSupported { get; set; }
        [JsonPropertyName("ambient_lux")] public float? AmbientLux { get; set; }
        [JsonPropertyName("ambient_cct")] public uint? AmbientCct { get; set; }

        [JsonPropertyName("storage_mounted")] public bool StorageMounted { get; set; }
        [JsonPropertyName("storage_status")] public StorageStatusModel StorageStatus { get; set; } = new();
        [JsonPropertyName("preferred_peer_share")] public string? PreferredPeerShare { get; set; }

        [JsonPropertyName("audio_status")] public AudioRoutingStatusModel AudioStatus { get; set; } = new();
        [JsonPropertyName("feature_flags")] public FeatureFlagsModel FeatureFlags { get; set; } = new();
        [JsonPropertyName("kvm")] public KvmStatusSnapshotModel Kvm { get; set; } = new();

        [JsonPropertyName("local_interfaces")] public List<LocalInterfaceInfo> LocalInterfaces { get; set; } = new();
        [JsonPropertyName("manual_peer_ips")] public List<string> ManualPeerIps { get; set; } = new();
        [JsonPropertyName("discovered_peers")] public List<DiscoveredPeerInfo> DiscoveredPeers { get; set; } = new();
        [JsonPropertyName("trust")] public TrustSnapshotInfo Trust { get; set; } = new();

        [JsonPropertyName("autostart_enabled")] public bool AutostartEnabled { get; set; }
        [JsonPropertyName("recent_logs")] public List<LogEntryModel> RecentLogs { get; set; } = new();
    }
}
