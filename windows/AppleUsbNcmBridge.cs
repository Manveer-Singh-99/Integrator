/*
 * ============================================================================
 * Integrator USB-C CDC-NCM WinTun Bridge Service (windows/AppleUsbNcmBridge.cs)
 * ============================================================================
 *
 * 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
 * ----------------------------------------------------------------------------
 * Bridges Apple Silicon / Intel Mac USB-C CDC-NCM gadget Ethernet interfaces
 * (WinUSB) directly to a Windows Layer-3 WinTun virtual network adapter,
 * providing zero-polling point-to-point connectivity and automatic macOS
 * Internet Sharing gateway/DNS management.
 *
 * 2. CONFIGURATION & COMPATIBILITY
 * ----------------------------------------------------------------------------
 * - Compiled with .NET Framework 4.x `csc.exe` (C# 5 language level).
 * - Runtime parameters are loaded via `BridgeConfig` from `bridge.conf`
 *   (key=value format) with optional environment variable (`APPLE_USB_NCM_*`)
 *   and CLI (`--key=value`) overrides, falling back to safe defaults.
 * - Virtual MAC and WinTun adapter GUID are derived deterministically per
 *   workstation unless explicitly overridden in configuration.
 * - Secondary DNS is opt-in (empty by default); no third-party public resolver
 *   is forced when macOS Internet Sharing is active.
 *
 * 3. THREADING & SAFETY INVARIANTS
 * ----------------------------------------------------------------------------
 * - Main loop listens for PnP USB interface arrivals via `CM_Register_Notification`.
 * - Dedicated RX, TX, ARP gateway monitor, and netsh apply threads separate
 *   packet forwarding from blocking OS configuration calls.
 * - DLL search order is restricted to System32 prior to loading `wintun.dll`
 *   by absolute path.
 * ============================================================================
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace AppleUsbNcmBridge {
    /// <summary>
    /// Immutable runtime configuration loaded from bridge.conf, environment variables, and CLI arguments.
    /// </summary>
    struct BridgeConfig {
        /// <summary>Base directory containing bridge.conf, wintun.dll, and bridge.log.</summary>
        public string DataDir;
        /// <summary>Full filesystem path to the active key=value configuration file.</summary>
        public string ConfigFilePath;
        /// <summary>Full filesystem path to the rotating diagnostic log file.</summary>
        public string LogFilePath;
        /// <summary>WinTun network adapter friendly name.</summary>
        public string AdapterName;
        /// <summary>WinTun tunnel type descriptor passed to WintunCreateAdapter.</summary>
        public string TunnelType;
        /// <summary>Windows Defender Firewall rule name scoped to the USB-C link subnets.</summary>
        public string FirewallRuleName;
        /// <summary>Windows static IPv4 address for the direct USB-C link.</summary>
        public string WinDirectIp;
        /// <summary>Four-byte IPv4 representation of WinDirectIp.</summary>
        public byte[] WinDirectIpBytes;
        /// <summary>IPv4 subnet mask for the direct USB-C link.</summary>
        public string DirectNetmask;
        /// <summary>Four-byte IPv4 representation of DirectNetmask.</summary>
        public byte[] DirectNetmaskBytes;
        /// <summary>CIDR subnet prefix for the direct USB-C link used in firewall rules.</summary>
        public string DirectCidr;
        /// <summary>Windows static IPv4 address for the macOS Internet Sharing subnet.</summary>
        public string WinSharingIp;
        /// <summary>Four-byte IPv4 representation of WinSharingIp.</summary>
        public byte[] WinSharingIpBytes;
        /// <summary>IPv4 subnet mask for the macOS Internet Sharing subnet.</summary>
        public string SharingNetmask;
        /// <summary>Four-byte IPv4 representation of SharingNetmask.</summary>
        public byte[] SharingNetmaskBytes;
        /// <summary>macOS Internet Sharing gateway IPv4 address.</summary>
        public string SharingGwIp;
        /// <summary>Four-byte IPv4 representation of SharingGwIp.</summary>
        public byte[] SharingGwIpBytes;
        /// <summary>CIDR subnet prefix for macOS Internet Sharing used in firewall rules.</summary>
        public string SharingCidr;
        /// <summary>UDP destination port accepting ON/OFF sharing hints from the macOS watchdog.</summary>
        public int HintPort;
        /// <summary>Optional secondary DNS server IPv4 address (empty disables secondary DNS injection).</summary>
        public string SecondaryDns;
        /// <summary>Locally administered unicast 6-byte virtual MAC advertised by Windows over CDC-NCM.</summary>
        public byte[] VirtualMac;
        /// <summary>Persistent WinTun adapter GUID derived deterministically or overridden by config.</summary>
        public Guid AdapterGuid;

        private const string DefaultAppFolderName = "AppleUsbNcm";
        private const string DefaultConfigFileName = "bridge.conf";
        private const string DefaultLogFileName = "bridge.log";
        private const string DefaultAdapterName = "Apple USB-C NCM";
        private const string DefaultTunnelType = "USB-C Direct";
        private const string DefaultFirewallRuleName = "Apple USB-C NCM Allow All";
        private const string DefaultWinDirectIp = "10.99.99.1";
        private const string DefaultDirectNetmask = "255.255.255.0";
        private const string DefaultDirectCidr = "10.99.99.0/24";
        private const string DefaultWinSharingIp = "192.168.2.2";
        private const string DefaultSharingNetmask = "255.255.255.0";
        private const string DefaultSharingGwIp = "192.168.2.1";
        private const string DefaultSharingCidr = "192.168.2.0/24";
        private const int DefaultHintPort = 47901;

        /// <summary>
        /// Parses a strict dotted-quad IPv4 string into canonical string and 4-byte representations.
        /// </summary>
        public static bool TryParseIpv4(string raw, out string normalized, out byte[] bytes) {
            normalized = null;
            bytes = null;
            if (string.IsNullOrEmpty(raw)) return false;
            string trimmed = raw.Trim();
            string[] parts = trimmed.Split('.');
            if (parts.Length != 4) return false;
            for (int i = 0; i < 4; i++) {
                int octet;
                if (!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out octet) || octet < 0 || octet > 255) {
                    return false;
                }
            }
            IPAddress ip;
            if (!IPAddress.TryParse(trimmed, out ip) || ip.AddressFamily != AddressFamily.InterNetwork) {
                return false;
            }
            byte[] rawBytes = ip.GetAddressBytes();
            if (rawBytes == null || rawBytes.Length != 4) return false;
            normalized = ip.ToString();
            bytes = rawBytes;
            return true;
        }

        /// <summary>
        /// Validates an IPv4 CIDR string (e.g. 10.99.99.0/24) and returns its canonical form.
        /// </summary>
        public static bool TryParseCidr(string raw, out string normalized) {
            normalized = null;
            if (string.IsNullOrEmpty(raw)) return false;
            string trimmed = raw.Trim();
            int slash = trimmed.IndexOf('/');
            if (slash <= 0 || slash >= trimmed.Length - 1) return false;
            string ipPart = trimmed.Substring(0, slash);
            string prefixPart = trimmed.Substring(slash + 1);
            string ipNorm;
            byte[] ipBytes;
            int prefix;
            if (!TryParseIpv4(ipPart, out ipNorm, out ipBytes)) return false;
            if (!int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out prefix) || prefix < 0 || prefix > 32) {
                return false;
            }
            normalized = ipNorm + "/" + prefix.ToString(CultureInfo.InvariantCulture);
            return true;
        }

        /// <summary>
        /// Parses a 6-byte unicast Ethernet MAC address separated by ':' or '-'.
        /// </summary>
        public static bool TryParseMac(string raw, out byte[] mac) {
            mac = null;
            if (string.IsNullOrEmpty(raw)) return false;
            string trimmed = raw.Trim();
            string[] parts = trimmed.Split(new char[] { ':', '-' });
            if (parts.Length != 6) return false;
            byte[] parsed = new byte[6];
            for (int i = 0; i < 6; i++) {
                byte b;
                if (parts[i].Length != 2 || !byte.TryParse(parts[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out b)) {
                    return false;
                }
                parsed[i] = b;
            }
            // Reject multicast/broadcast MAC addresses (LSB of first octet must be 0).
            if ((parsed[0] & 0x01) != 0) return false;
            mac = parsed;
            return true;
        }

        /// <summary>
        /// Derives a deterministic RFC 4122 GUID from the local machine name so each host gets a stable adapter identity.
        /// </summary>
        public static Guid DeriveDeterministicGuid(string machineName) {
            string seed = "Integrator:AppleUsbNcmBridge:AdapterGuid:" + (machineName != null ? machineName : "workstation");
            using (SHA256 sha = SHA256.Create()) {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(seed));
                byte[] guidBytes = new byte[16];
                Buffer.BlockCopy(hash, 0, guidBytes, 0, 16);
                // Set version 5 (name-based SHA) and RFC 4122 variant bits.
                guidBytes[7] = (byte)((guidBytes[7] & 0x0F) | 0x50);
                guidBytes[8] = (byte)((guidBytes[8] & 0x3F) | 0x80);
                return new Guid(guidBytes);
            }
        }

        /// <summary>
        /// Derives a deterministic locally administered unicast MAC (0x02:...) from the machine name and adapter GUID.
        /// </summary>
        public static byte[] DeriveDeterministicMac(string machineName, Guid adapterGuid) {
            string seed = "Integrator:AppleUsbNcmBridge:VirtualMac:" + (machineName != null ? machineName : "workstation") + ":" + adapterGuid.ToString("N");
            using (SHA256 sha = SHA256.Create()) {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(seed));
                byte[] mac = new byte[6];
                Buffer.BlockCopy(hash, 0, mac, 0, 6);
                // Enforce locally administered (bit 1 = 1) and unicast (bit 0 = 0).
                mac[0] = (byte)((mac[0] & 0xFE) | 0x02);
                return mac;
            }
        }

        /// <summary>
        /// Formats a 6-byte Ethernet MAC address as colon-delimited uppercase hex.
        /// </summary>
        public static string FormatMac(byte[] mac) {
            if (mac == null || mac.Length != 6) return "00:00:00:00:00:00";
            return string.Format(
                CultureInfo.InvariantCulture,
                "{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }

        private static string SanitizeSafeLabel(string raw, string fallback) {
            if (string.IsNullOrEmpty(raw)) return fallback;
            string trimmed = raw.Trim();
            if (trimmed.Length == 0 || trimmed.IndexOf('"') >= 0 || trimmed.IndexOf('\r') >= 0 || trimmed.IndexOf('\n') >= 0 || trimmed.IndexOf('\0') >= 0) {
                return fallback;
            }
            return trimmed;
        }

        private static void LoadConfFile(string confPath, Dictionary<string, string> values) {
            if (string.IsNullOrEmpty(confPath) || !File.Exists(confPath)) return;
            try {
                string[] lines = File.ReadAllLines(confPath, Encoding.UTF8);
                for (int i = 0; i < lines.Length; i++) {
                    string line = lines[i].Trim();
                    if (line.Length == 0 || line[0] == '#' || line[0] == ';') continue;
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    string key = line.Substring(0, eq).Trim();
                    string val = line.Substring(eq + 1).Trim();
                    if (val.Length >= 2 && ((val[0] == '"' && val[val.Length - 1] == '"') || (val[0] == '\'' && val[val.Length - 1] == '\''))) {
                        val = val.Substring(1, val.Length - 2);
                    }
                    if (key.Length > 0) {
                        values[key] = val;
                    }
                }
            } catch {}
        }

        private static Dictionary<string, string> ParseCliOverrides(string[] args) {
            Dictionary<string, string> cli = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (args == null) return cli;
            for (int i = 0; i < args.Length; i++) {
                string arg = args[i];
                if (string.IsNullOrEmpty(arg) || !arg.StartsWith("--")) continue;
                string body = arg.Substring(2);
                int eq = body.IndexOf('=');
                if (eq > 0) {
                    string k = NormalizeKey(body.Substring(0, eq));
                    string v = body.Substring(eq + 1);
                    cli[k] = v;
                } else if (i + 1 < args.Length && !args[i + 1].StartsWith("--")) {
                    string k = NormalizeKey(body);
                    cli[k] = args[++i];
                }
            }
            return cli;
        }

        private static string NormalizeKey(string key) {
            if (string.IsNullOrEmpty(key)) return "";
            return key.Replace("-", "").Replace("_", "").Trim();
        }

        private static string GetValue(Dictionary<string, string> conf, Dictionary<string, string> cli, string key, string envName) {
            string normKey = NormalizeKey(key);
            string val;
            if (cli.TryGetValue(normKey, out val) && val != null) return val;
            if (!string.IsNullOrEmpty(envName)) {
                string envVal = Environment.GetEnvironmentVariable(envName);
                if (envVal != null) return envVal;
            }
            if (conf.TryGetValue(normKey, out val) && val != null) return val;
            return null;
        }

        /// <summary>
        /// Loads BridgeConfig from bridge.conf with environment variable and CLI overrides.
        /// Precedence (highest to lowest): CLI args -> APPLE_USB_NCM_* env vars -> bridge.conf -> defaults.
        /// </summary>
        public static BridgeConfig Load(string[] args) {
            Dictionary<string, string> cli = ParseCliOverrides(args);
            string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string defaultDataDir = Path.Combine(commonAppData, DefaultAppFolderName);
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            string initialDataDir = defaultDataDir;
            if (!string.IsNullOrEmpty(baseDir) && File.Exists(Path.Combine(baseDir, DefaultConfigFileName))) {
                initialDataDir = baseDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
            string envDataDir = Environment.GetEnvironmentVariable("APPLE_USB_NCM_DATA_DIR");
            if (!string.IsNullOrEmpty(envDataDir)) initialDataDir = envDataDir.Trim();
            string cliDataDir;
            if (cli.TryGetValue("DataDir", out cliDataDir) && !string.IsNullOrEmpty(cliDataDir)) {
                initialDataDir = cliDataDir.Trim();
            }

            string confPath = Path.Combine(initialDataDir, DefaultConfigFileName);
            string envConf = Environment.GetEnvironmentVariable("APPLE_USB_NCM_CONFIG");
            if (!string.IsNullOrEmpty(envConf)) confPath = envConf.Trim();
            string cliConf;
            if (cli.TryGetValue("Config", out cliConf) && !string.IsNullOrEmpty(cliConf)) {
                confPath = cliConf.Trim();
            }

            Dictionary<string, string> rawConf = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            LoadConfFile(confPath, rawConf);
            Dictionary<string, string> conf = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, string> kv in rawConf) {
                conf[NormalizeKey(kv.Key)] = kv.Value;
            }

            BridgeConfig cfg = new BridgeConfig();
            string resolvedDataDir = GetValue(conf, cli, "DataDir", "APPLE_USB_NCM_DATA_DIR");
            if (string.IsNullOrEmpty(resolvedDataDir)) {
                string confDir = Path.GetDirectoryName(confPath);
                resolvedDataDir = !string.IsNullOrEmpty(confDir) ? confDir : initialDataDir;
            }
            cfg.DataDir = resolvedDataDir.Trim();
            cfg.ConfigFilePath = confPath;
            string customLogPath = GetValue(conf, cli, "LogFilePath", "APPLE_USB_NCM_LOG_FILE");
            cfg.LogFilePath = !string.IsNullOrEmpty(customLogPath) ? customLogPath.Trim() : Path.Combine(cfg.DataDir, DefaultLogFileName);

            cfg.AdapterName = SanitizeSafeLabel(GetValue(conf, cli, "AdapterName", "APPLE_USB_NCM_ADAPTER_NAME"), DefaultAdapterName);
            cfg.TunnelType = SanitizeSafeLabel(GetValue(conf, cli, "TunnelType", "APPLE_USB_NCM_TUNNEL_TYPE"), DefaultTunnelType);
            cfg.FirewallRuleName = SanitizeSafeLabel(GetValue(conf, cli, "FirewallRuleName", "APPLE_USB_NCM_FIREWALL_RULE_NAME"), DefaultFirewallRuleName);

            string parsedIp;
            byte[] parsedBytes;

            if (!TryParseIpv4(GetValue(conf, cli, "WinDirectIp", "APPLE_USB_NCM_WIN_DIRECT_IP"), out parsedIp, out parsedBytes)) {
                TryParseIpv4(DefaultWinDirectIp, out parsedIp, out parsedBytes);
            }
            cfg.WinDirectIp = parsedIp;
            cfg.WinDirectIpBytes = parsedBytes;

            if (!TryParseIpv4(GetValue(conf, cli, "DirectNetmask", "APPLE_USB_NCM_DIRECT_NETMASK"), out parsedIp, out parsedBytes)) {
                TryParseIpv4(DefaultDirectNetmask, out parsedIp, out parsedBytes);
            }
            cfg.DirectNetmask = parsedIp;
            cfg.DirectNetmaskBytes = parsedBytes;

            string parsedCidr;
            if (!TryParseCidr(GetValue(conf, cli, "DirectCidr", "APPLE_USB_NCM_DIRECT_CIDR"), out parsedCidr)) {
                parsedCidr = DefaultDirectCidr;
            }
            cfg.DirectCidr = parsedCidr;

            if (!TryParseIpv4(GetValue(conf, cli, "WinSharingIp", "APPLE_USB_NCM_WIN_SHARING_IP"), out parsedIp, out parsedBytes)) {
                TryParseIpv4(DefaultWinSharingIp, out parsedIp, out parsedBytes);
            }
            cfg.WinSharingIp = parsedIp;
            cfg.WinSharingIpBytes = parsedBytes;

            if (!TryParseIpv4(GetValue(conf, cli, "SharingNetmask", "APPLE_USB_NCM_SHARING_NETMASK"), out parsedIp, out parsedBytes)) {
                TryParseIpv4(DefaultSharingNetmask, out parsedIp, out parsedBytes);
            }
            cfg.SharingNetmask = parsedIp;
            cfg.SharingNetmaskBytes = parsedBytes;

            if (!TryParseIpv4(GetValue(conf, cli, "SharingGwIp", "APPLE_USB_NCM_SHARING_GW_IP"), out parsedIp, out parsedBytes)) {
                TryParseIpv4(DefaultSharingGwIp, out parsedIp, out parsedBytes);
            }
            cfg.SharingGwIp = parsedIp;
            cfg.SharingGwIpBytes = parsedBytes;

            if (!TryParseCidr(GetValue(conf, cli, "SharingCidr", "APPLE_USB_NCM_SHARING_CIDR"), out parsedCidr)) {
                parsedCidr = DefaultSharingCidr;
            }
            cfg.SharingCidr = parsedCidr;

            int parsedPort;
            string portStr = GetValue(conf, cli, "HintPort", "APPLE_USB_NCM_HINT_PORT");
            if (!string.IsNullOrEmpty(portStr) && int.TryParse(portStr.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out parsedPort) && parsedPort >= 1 && parsedPort <= 65535) {
                cfg.HintPort = parsedPort;
            } else {
                cfg.HintPort = DefaultHintPort;
            }

            // Secondary DNS is opt-in; empty string disables configuring any secondary resolver.
            string rawSecondaryDns = GetValue(conf, cli, "SecondaryDns", "APPLE_USB_NCM_SECONDARY_DNS");
            if (!string.IsNullOrEmpty(rawSecondaryDns) && TryParseIpv4(rawSecondaryDns, out parsedIp, out parsedBytes)) {
                cfg.SecondaryDns = parsedIp;
            } else {
                cfg.SecondaryDns = "";
            }

            Guid parsedGuid;
            string rawGuid = GetValue(conf, cli, "AdapterGuid", "APPLE_USB_NCM_ADAPTER_GUID");
            if (!string.IsNullOrEmpty(rawGuid) && Guid.TryParse(rawGuid.Trim(), out parsedGuid) && parsedGuid != Guid.Empty) {
                cfg.AdapterGuid = parsedGuid;
            } else {
                cfg.AdapterGuid = DeriveDeterministicGuid(Environment.MachineName);
            }

            byte[] parsedMac;
            string rawMac = GetValue(conf, cli, "VirtualMac", "APPLE_USB_NCM_VIRTUAL_MAC");
            if (!string.IsNullOrEmpty(rawMac) && TryParseMac(rawMac, out parsedMac)) {
                cfg.VirtualMac = parsedMac;
            } else {
                cfg.VirtualMac = DeriveDeterministicMac(Environment.MachineName, cfg.AdapterGuid);
            }

            return cfg;
        }
    }

    class Program {
        [StructLayout(LayoutKind.Sequential)]
        public struct WINUSB_SETUP_PACKET {
            public byte RequestType;
            public byte Request;
            public ushort Value;
            public ushort Index;
            public ushort Length;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SP_DEVICE_INTERFACE_DATA {
            public uint cbSize;
            public Guid InterfaceClassGuid;
            public uint Flags;
            public IntPtr Reserved;
        }

        private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;
        private const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008;

        /// <summary>Standard Microsoft GUID_DEVINTERFACE_USB_DEVICE interface class GUID.</summary>
        private static readonly Guid UsbDeviceInterfaceClassGuid = new Guid("a5dcbf10-6530-11d2-901f-00c04fb951ed");

        /// <summary>Default Apple USB-C CDC-NCM gadget hardware identifier substring.</summary>
        private const string DefaultAppleNcmHwid = "vid_05ac&pid_1902";

        /// <summary>RFC 3927 IPv4 link-local first octet (169.254.0.0/16).</summary>
        private const byte LinkLocalOctet0 = 169;

        /// <summary>RFC 3927 IPv4 link-local second octet (169.254.0.0/16).</summary>
        private const byte LinkLocalOctet1 = 254;

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, string Enumerator, IntPtr hwndParent, uint Flags);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiEnumDeviceInterfaces(IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref Guid InterfaceClassGuid, uint MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr DeviceInfoSet, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData, IntPtr DeviceInterfaceDetailData, uint DeviceInterfaceDetailDataSize, out uint RequiredSize, IntPtr DeviceInfoData);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetEvent(IntPtr hEvent);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CancelIoEx(SafeFileHandle hFile, IntPtr lpOverlapped);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetDefaultDllDirectories(uint DirectoryFlags);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryExW(string lpLibFileName, IntPtr hFile, uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct CM_NOTIFY_FILTER {
            public uint cbSize;
            public uint Flags;
            public uint FilterType;
            public uint Reserved;
            public Guid ClassGuid;
            public fixed byte Padding[384];
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint CM_NOTIFY_CALLBACK(IntPtr hNotify, IntPtr Context, int Action, IntPtr EventData, int EventDataSize);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("cfgmgr32.dll")]
        public static extern int CM_Register_Notification(ref CM_NOTIFY_FILTER pFilter, IntPtr pContext, CM_NOTIFY_CALLBACK pCallback, out IntPtr pNotifyContext);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("cfgmgr32.dll")]
        public static extern int CM_Unregister_Notification(IntPtr NotifyContext);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_Initialize(SafeFileHandle DeviceHandle, out IntPtr InterfaceHandle);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_Free(IntPtr InterfaceHandle);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_GetAssociatedInterface(IntPtr InterfaceHandle, byte AssociatedInterfaceIndex, out IntPtr AssociatedInterfaceHandle);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_SetCurrentAlternateSetting(IntPtr InterfaceHandle, byte SettingNumber);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_ControlTransfer(IntPtr InterfaceHandle, WINUSB_SETUP_PACKET SetupPacket, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_ReadPipe(IntPtr InterfaceHandle, byte PipeID, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_WritePipe(IntPtr InterfaceHandle, byte PipeID, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_AbortPipe(IntPtr InterfaceHandle, byte PipeID);

        [DllImport("wintun.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunCreateAdapter(string Name, string TunnelType, ref Guid RequestedGUID);

        [DllImport("wintun.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunOpenAdapter(string Name);

        [DllImport("wintun.dll", SetLastError = true)]
        public static extern void WintunCloseAdapter(IntPtr Adapter);

        [DllImport("wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunStartSession(IntPtr Adapter, uint Capacity);

        [DllImport("wintun.dll", SetLastError = true)]
        public static extern void WintunEndSession(IntPtr Session);

        [DllImport("wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunGetReadWaitEvent(IntPtr Session);

        [DllImport("wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunReceivePacket(IntPtr Session, out uint PacketSize);

        [DllImport("wintun.dll", SetLastError = true)]
        public static extern void WintunReleaseReceivePacket(IntPtr Session, IntPtr Packet);

        [DllImport("wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunAllocateSendPacket(IntPtr Session, uint PacketSize);

        [DllImport("wintun.dll", SetLastError = true)]
        public static extern void WintunSendPacket(IntPtr Session, IntPtr Packet);

        static BridgeConfig Config;
        static volatile bool running = false;
        static volatile bool serviceStop = false;
        // Initialized to Ethernet broadcast until the connected Mac's unicast MAC is learned from incoming frames
        const long BroadcastMacPacked = 0x0000FFFFFFFFFFFFL;
        static long peerMacPacked = BroadcastMacPacked;
        static ushort txSeq = 0;
        static readonly object txLock = new object();
        static readonly object logLock = new object();
        static readonly byte[] singleTxBuf = new byte[2048];
        const long MaxLogBytes = 2 * 1024 * 1024;

        // macOS Internet Sharing gateway tracking.
        // The default route + DNS via the Mac are only installed while the Mac is proven to be sharing,
        // so Wi-Fi stays the default route whenever Internet Sharing is off.
        const int ProbeIntervalMs = 5000;      // ARP probe interval, only while the cable link is up
        const int GatewayTimeoutSec = 12;      // no sign of sharing gateway for this long => sharing is off
        static long gwLastSeenTicks = 0;
        static volatile bool gwDesired = false;
        static volatile bool gwApplied = false;
        static volatile bool gwAppliedKnown = false;
        static volatile int linkGen = 0;
        static readonly AutoResetEvent gwApplyEvent = new AutoResetEvent(false);
        static readonly AutoResetEvent gwProbeWake = new AutoResetEvent(false);

        static bool IpEquals(byte[] buf, int off, byte[] expected) {
            if (buf == null || expected == null || off < 0 || off + 4 > buf.Length || expected.Length != 4) return false;
            return buf[off] == expected[0]
                && buf[off + 1] == expected[1]
                && buf[off + 2] == expected[2]
                && buf[off + 3] == expected[3];
        }

        static bool IsInSubnet(byte[] buf, int off, byte[] netIp, byte[] netmask) {
            if (buf == null || netIp == null || netmask == null || off < 0 || off + 4 > buf.Length) return false;
            for (int i = 0; i < 4; i++) {
                if ((buf[off + i] & netmask[i]) != (netIp[i] & netmask[i])) return false;
            }
            return true;
        }

        static bool IsLinkLocalIpv4(byte[] buf, int off) {
            if (buf == null || off < 0 || off + 4 > buf.Length) return false;
            return buf[off] == LinkLocalOctet0 && buf[off + 1] == LinkLocalOctet1;
        }

        static void SetPeerMac(byte[] buf, int off) {
            if (buf == null || off < 0 || off + 6 > buf.Length) return;
            // Ignore multicast/broadcast source MACs
            if ((buf[off] & 0x01) != 0) return;
            long packed = ((long)buf[off])
                | ((long)buf[off + 1] << 8)
                | ((long)buf[off + 2] << 16)
                | ((long)buf[off + 3] << 24)
                | ((long)buf[off + 4] << 32)
                | ((long)buf[off + 5] << 40);
            Interlocked.Exchange(ref peerMacPacked, packed);
        }

        static void WritePeerMac(byte[] dst, int off) {
            long packed = Interlocked.Read(ref peerMacPacked);
            dst[off]     = (byte)(packed & 0xFF);
            dst[off + 1] = (byte)((packed >> 8) & 0xFF);
            dst[off + 2] = (byte)((packed >> 16) & 0xFF);
            dst[off + 3] = (byte)((packed >> 24) & 0xFF);
            dst[off + 4] = (byte)((packed >> 32) & 0xFF);
            dst[off + 5] = (byte)((packed >> 40) & 0xFF);
        }

        static void ResetPeerMac() {
            Interlocked.Exchange(ref peerMacPacked, BroadcastMacPacked);
        }

        static void Log(string msg) {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + " " + msg;
            Console.WriteLine(line);
            string logPath = Config.LogFilePath;
            if (string.IsNullOrEmpty(logPath)) return;
            lock (logLock) {
                try {
                    string logDir = Path.GetDirectoryName(logPath);
                    if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir)) {
                        Directory.CreateDirectory(logDir);
                    }
                    FileInfo fi = new FileInfo(logPath);
                    if (fi.Exists && fi.Length > MaxLogBytes) {
                        string rotated = logPath + ".1";
                        if (File.Exists(rotated)) File.Delete(rotated);
                        File.Move(logPath, rotated);
                    }
                    File.AppendAllText(logPath, line + "\r\n");
                } catch {}
            }
        }

        static string FindAppleUsbPath() {
            Guid guid = UsbDeviceInterfaceClassGuid;
            IntPtr devs = SetupDiGetClassDevs(ref guid, null, IntPtr.Zero, 0x00000002 | 0x00000010);
            if (devs == IntPtr.Zero || devs == new IntPtr(-1)) return null;
            try {
                uint idx = 0;
                SP_DEVICE_INTERFACE_DATA ifData = new SP_DEVICE_INTERFACE_DATA();
                ifData.cbSize = (uint)Marshal.SizeOf(ifData);
                while (SetupDiEnumDeviceInterfaces(devs, IntPtr.Zero, ref guid, idx, ref ifData)) {
                    idx++;
                    uint reqSize = 0;
                    SetupDiGetDeviceInterfaceDetail(devs, ref ifData, IntPtr.Zero, 0, out reqSize, IntPtr.Zero);
                    if (reqSize > 0) {
                        IntPtr detail = Marshal.AllocHGlobal((int)reqSize);
                        try {
                            Marshal.WriteInt32(detail, IntPtr.Size == 8 ? 8 : 6);
                            if (SetupDiGetDeviceInterfaceDetail(devs, ref ifData, detail, reqSize, out reqSize, IntPtr.Zero)) {
                                string path = Marshal.PtrToStringUni(new IntPtr(detail.ToInt64() + 4));
                                string customHwid = Environment.GetEnvironmentVariable("APPLE_USB_NCM_HWID");
                                string lower = path != null ? path.ToLowerInvariant() : "";
                                if (lower.Contains(DefaultAppleNcmHwid)
                                    || (!string.IsNullOrEmpty(customHwid) && lower.Contains(customHwid.ToLowerInvariant()))) {
                                    return path;
                                }
                            }
                        } finally {
                            Marshal.FreeHGlobal(detail);
                        }
                    }
                }
            } finally {
                SetupDiDestroyDeviceInfoList(devs);
            }
            return null;
        }

        static void SendSingleEthernetFrame(IntPtr hIntf1, byte[] frame, int frameLen) {
            if (frame == null || frameLen < 14 || frameLen > 1536 || frameLen > frame.Length) return;
            lock (txLock) {
                int totalLen = 28 + frameLen;
                if (totalLen < 64) totalLen = 64;
                if ((totalLen % 512) == 0) totalLen += 4;
                if (totalLen > singleTxBuf.Length) return;

                byte[] buf = singleTxBuf;
                // NTH16: "NCMH" (0x4E, 0x43, 0x4D, 0x48)
                buf[0] = 0x4E; buf[1] = 0x43; buf[2] = 0x4D; buf[3] = 0x48;
                buf[4] = 12; buf[5] = 0;
                buf[6] = (byte)(txSeq & 0xFF); buf[7] = (byte)((txSeq >> 8) & 0xFF);
                txSeq++;
                buf[8] = (byte)(totalLen & 0xFF); buf[9] = (byte)((totalLen >> 8) & 0xFF);
                buf[10] = 12; buf[11] = 0;

                // NDP16: "NCM0" (0x4E, 0x43, 0x4D, 0x30)
                buf[12] = 0x4E; buf[13] = 0x43; buf[14] = 0x4D; buf[15] = 0x30;
                buf[16] = 16; buf[17] = 0;
                buf[18] = 0; buf[19] = 0;
                buf[20] = 28; buf[21] = 0;
                buf[22] = (byte)(frameLen & 0xFF); buf[23] = (byte)((frameLen >> 8) & 0xFF);
                // Explicit NDP16 zero terminator entry
                buf[24] = 0; buf[25] = 0; buf[26] = 0; buf[27] = 0;

                Buffer.BlockCopy(frame, 0, buf, 28, frameLen);
                int padBytes = totalLen - (28 + frameLen);
                if (padBytes > 0) {
                    Array.Clear(buf, 28 + frameLen, padBytes);
                }
                uint written = 0;
                WinUsb_WritePipe(hIntf1, 0x01, buf, (uint)totalLen, out written, IntPtr.Zero);
            }
        }

        static void MarkGatewaySeen() {
            Interlocked.Exchange(ref gwLastSeenTicks, DateTime.UtcNow.Ticks);
            if (!gwDesired) {
                gwDesired = true;
                gwApplyEvent.Set();
            }
        }

        // Consumes UDP hints from the macOS daemon ("ON" = sharing started, "OFF" = sharing stopped).
        static bool HandleControlHint(byte[] b, int ip, int ipLen) {
            if (b == null || ip < 0 || ipLen < 28 || ipLen > b.Length - ip) return false;
            if ((b[ip] >> 4) != 4 || b[ip + 9] != 17) return false;
            // Only accept control hints from configured USB-C link subnets or RFC 3927 link-local addresses
            bool validSrc = IsInSubnet(b, ip + 12, Config.WinDirectIpBytes, Config.DirectNetmaskBytes)
                || IsInSubnet(b, ip + 12, Config.WinSharingIpBytes, Config.SharingNetmaskBytes)
                || IsLinkLocalIpv4(b, ip + 12);
            if (!validSrc) return false;
            int ihl = (b[ip] & 0x0F) * 4;
            if (ihl < 20 || ihl + 8 > ipLen) return false;
            int udp = ip + ihl;
            if (udp + 8 > b.Length) return false;
            int dport = (b[udp + 2] << 8) | b[udp + 3];
            if (dport != Config.HintPort) return false;
            int ulen = (b[udp + 4] << 8) | b[udp + 5];
            if (ulen < 8) return false;
            int maxAvail = Math.Min(ipLen - ihl - 8, b.Length - (udp + 8));
            int plen = Math.Max(0, Math.Min(ulen - 8, maxAvail));
            string msg = plen > 0 ? Encoding.ASCII.GetString(b, udp + 8, Math.Min(plen, 16)).Trim() : "";
            if (msg == "ON") {
                gwProbeWake.Set(); // probe sharing gateway right away; the ARP reply confirms sharing
            } else if (msg == "OFF") {
                Interlocked.Exchange(ref gwLastSeenTicks, 0);
                gwDesired = false;
                gwApplyEvent.Set();
            }
            return true;
        }

        static void HandleArpRequest(IntPtr hIntf1, byte[] rxBuf, int offset, int len) {
            if (len < 42) return;
            // Any ARP (request, reply or gratuitous) sent from the sharing gateway means macOS Internet Sharing is on
            if (IpEquals(rxBuf, offset + 28, Config.SharingGwIpBytes)) {
                MarkGatewaySeen();
            }
            ushort oper = (ushort)((rxBuf[offset + 20] << 8) | rxBuf[offset + 21]);
            if (oper != 1) return; // ARP Request

            // Respond to ARP for the configured Direct Link IP or macOS Internet Sharing IP
            bool matchDirect = IpEquals(rxBuf, offset + 38, Config.WinDirectIpBytes);
            bool matchSharing = IpEquals(rxBuf, offset + 38, Config.WinSharingIpBytes);

            if (matchDirect || matchSharing) {
                byte[] reply = new byte[42];
                Buffer.BlockCopy(rxBuf, offset + 6, reply, 0, 6);        // Destination MAC (requester)
                Buffer.BlockCopy(Config.VirtualMac, 0, reply, 6, 6);     // Source MAC (Windows virtual MAC)
                reply[12] = 0x08; reply[13] = 0x06;                      // EtherType ARP
                reply[14] = 0x00; reply[15] = 0x01;                      // Hardware type: Ethernet (1)
                reply[16] = 0x08; reply[17] = 0x00;                      // Protocol type: IPv4 (0x0800)
                reply[18] = 6;    reply[19] = 4;                         // HW size 6, Proto size 4
                reply[20] = 0x00; reply[21] = 0x02;                      // Opcode: ARP Reply (2)
                Buffer.BlockCopy(Config.VirtualMac, 0, reply, 22, 6);    // Sender MAC
                Buffer.BlockCopy(rxBuf, offset + 38, reply, 28, 4);      // Sender IP (requested target)
                Buffer.BlockCopy(rxBuf, offset + 22, reply, 32, 10);     // Target MAC + Target IP (from request)

                SendSingleEthernetFrame(hIntf1, reply, 42);
            }
        }

        static void UsbRxLoop(IntPtr hIntf1, IntPtr session, uint maxIn) {
            byte[] rxBuf = new byte[maxIn];
            while (running) {
                uint transferred = 0;
                if (!WinUsb_ReadPipe(hIntf1, 0x81, rxBuf, maxIn, out transferred, IntPtr.Zero)) {
                    int err = Marshal.GetLastWin32Error();
                    Log("WinUsb_ReadPipe ended err=" + err);
                    running = false;
                    IntPtr waitEvt = WintunGetReadWaitEvent(session);
                    if (waitEvt != IntPtr.Zero) SetEvent(waitEvt);
                    break;
                }
                if (transferred < 12 || transferred > rxBuf.Length) continue;
                if (rxBuf[0] != 0x4E || rxBuf[1] != 0x43 || rxBuf[2] != 0x4D || rxBuf[3] != 0x48) continue;

                ushort ndpIdx = BitConverter.ToUInt16(rxBuf, 10);
                int safety = 0;
                while (ndpIdx >= 12 && ndpIdx + 8 <= transferred && safety++ < 64) {
                    if (rxBuf[ndpIdx] != 0x4E || rxBuf[ndpIdx + 1] != 0x43 || rxBuf[ndpIdx + 2] != 0x4D) break;
                    ushort ndpLen = BitConverter.ToUInt16(rxBuf, ndpIdx + 4);
                    ushort nextNdp = BitConverter.ToUInt16(rxBuf, ndpIdx + 6);
                    int pos = ndpIdx + 8;
                    int endPos = Math.Min((int)transferred, ndpIdx + ndpLen);
                    while (pos + 4 <= endPos) {
                        ushort dgIdx = BitConverter.ToUInt16(rxBuf, pos);
                        ushort dgLen = BitConverter.ToUInt16(rxBuf, pos + 2);
                        pos += 4;
                        if (dgIdx == 0 || dgLen == 0) break;
                        if (dgIdx <= transferred && dgLen <= transferred - dgIdx && dgLen >= 14) {
                            SetPeerMac(rxBuf, dgIdx + 6);
                            ushort etherType = (ushort)((rxBuf[dgIdx + 12] << 8) | rxBuf[dgIdx + 13]);
                            if (etherType == 0x0806) {
                                HandleArpRequest(hIntf1, rxBuf, dgIdx, dgLen);
                            } else if ((etherType == 0x0800 || etherType == 0x86DD) && dgLen > 14) {
                                if (etherType == 0x0800 && dgLen >= 34) {
                                    int ip4 = dgIdx + 14;
                                    // Consume UDP OFF/ON control hints BEFORE marking gateway seen so an OFF hint does not re-arm the timer.
                                    if (HandleControlHint(rxBuf, ip4, dgLen - 14)) continue;
                                    if (IpEquals(rxBuf, ip4 + 12, Config.SharingGwIpBytes)) {
                                        MarkGatewaySeen();
                                    }
                                }
                                uint ipLen = (uint)(dgLen - 14);
                                IntPtr pkt = WintunAllocateSendPacket(session, ipLen);
                                if (pkt != IntPtr.Zero) {
                                    Marshal.Copy(rxBuf, dgIdx + 14, pkt, (int)ipLen);
                                    WintunSendPacket(session, pkt);
                                }
                            }
                        }
                    }
                    ndpIdx = nextNdp;
                }
            }
        }

        static void UsbTxLoop(IntPtr hIntf1, IntPtr session) {
            IntPtr waitEvent = WintunGetReadWaitEvent(session);
            byte[][] batchFrames = new byte[32][];
            int[] batchLens = new int[32];
            for (int i = 0; i < 32; i++) batchFrames[i] = new byte[1536];
            byte[] txBuf = new byte[32764];

            while (running) {
                int count = 0;
                int payloadBytes = 0;
                while (running && count < 30 && payloadBytes < 14000) {
                    uint pktSize = 0;
                    IntPtr pkt = WintunReceivePacket(session, out pktSize);
                    if (pkt == IntPtr.Zero) break;
                    try {
                        if (pktSize > 0 && pktSize <= 1500) {
                            byte ver = Marshal.ReadByte(pkt);
                            int ipVer = (ver >> 4) & 0x0F;
                            if (ipVer == 4 || ipVer == 6) {
                                byte[] frame = batchFrames[count];
                                WritePeerMac(frame, 0);
                                Buffer.BlockCopy(Config.VirtualMac, 0, frame, 6, 6);
                                if (ipVer == 4) { frame[12] = 0x08; frame[13] = 0x00; }
                                else { frame[12] = 0x86; frame[13] = 0xDD; }
                                Marshal.Copy(pkt, frame, 14, (int)pktSize);
                                batchLens[count] = (int)pktSize + 14;
                                payloadBytes += batchLens[count] + 4;
                                count++;
                            }
                        }
                    } finally {
                        WintunReleaseReceivePacket(session, pkt);
                    }
                }

                if (!running) break;

                if (count == 0) {
                    if (waitEvent != IntPtr.Zero) WaitForSingleObject(waitEvent, 0xFFFFFFFF);
                    else Thread.Sleep(10);
                    continue;
                }

                if (count == 1) {
                    SendSingleEthernetFrame(hIntf1, batchFrames[0], batchLens[0]);
                } else {
                    lock (txLock) {
                        int ndpLen = 8 + (count + 1) * 4;
                        int dataStart = 12 + ndpLen;
                        if ((dataStart % 4) != 0) dataStart += 4 - (dataStart % 4);
                        if (dataStart > 12 + ndpLen) {
                            Array.Clear(txBuf, 12 + ndpLen, dataStart - (12 + ndpLen));
                        }

                        int curOffset = dataStart;
                        txBuf[0] = 0x4E; txBuf[1] = 0x43; txBuf[2] = 0x4D; txBuf[3] = 0x48;
                        txBuf[4] = 12; txBuf[5] = 0;
                        txBuf[6] = (byte)(txSeq & 0xFF); txBuf[7] = (byte)((txSeq >> 8) & 0xFF);
                        txSeq++;
                        txBuf[10] = 12; txBuf[11] = 0;

                        txBuf[12] = 0x4E; txBuf[13] = 0x43; txBuf[14] = 0x4D; txBuf[15] = 0x30;
                        txBuf[16] = (byte)(ndpLen & 0xFF); txBuf[17] = (byte)((ndpLen >> 8) & 0xFF);
                        txBuf[18] = 0; txBuf[19] = 0;

                        int ndpPos = 20;
                        for (int i = 0; i < count; i++) {
                            if ((curOffset % 4) != 0) {
                                int pad = 4 - (curOffset % 4);
                                for (int p = 0; p < pad; p++) txBuf[curOffset++] = 0;
                            }
                            int flen = batchLens[i];
                            if (curOffset + flen + 4 > txBuf.Length) break;
                            txBuf[ndpPos] = (byte)(curOffset & 0xFF);
                            txBuf[ndpPos + 1] = (byte)((curOffset >> 8) & 0xFF);
                            txBuf[ndpPos + 2] = (byte)(flen & 0xFF);
                            txBuf[ndpPos + 3] = (byte)((flen >> 8) & 0xFF);
                            ndpPos += 4;
                            Buffer.BlockCopy(batchFrames[i], 0, txBuf, curOffset, flen);
                            curOffset += flen;
                        }
                        txBuf[ndpPos] = 0; txBuf[ndpPos + 1] = 0; txBuf[ndpPos + 2] = 0; txBuf[ndpPos + 3] = 0;

                        int totalLen = curOffset;
                        if ((totalLen % 512) == 0 && totalLen + 4 <= txBuf.Length) {
                            txBuf[totalLen] = 0; txBuf[totalLen + 1] = 0; txBuf[totalLen + 2] = 0; txBuf[totalLen + 3] = 0;
                            totalLen += 4;
                        }
                        txBuf[8] = (byte)(totalLen & 0xFF); txBuf[9] = (byte)((totalLen >> 8) & 0xFF);
                        uint written = 0;
                        if (!WinUsb_WritePipe(hIntf1, 0x01, txBuf, (uint)totalLen, out written, IntPtr.Zero)) {
                            running = false;
                            break;
                        }
                    }
                }
            }
        }

        static void Netsh(string args) {
            try {
                string netshPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");
                ProcessStartInfo psi = new ProcessStartInfo(netshPath, args);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process p = Process.Start(psi)) {
                    if (p != null && !p.WaitForExit(5000)) {
                        try { p.Kill(); } catch {}
                    }
                }
            } catch {}
        }

        static void RemoveShareGateway() {
            string a = "\"" + Config.AdapterName + "\"";
            Netsh("interface ipv4 delete route prefix=0.0.0.0/0 interface=" + a + " nexthop=" + Config.SharingGwIp + " store=active");
            Netsh("interface ipv4 delete route prefix=0.0.0.0/0 interface=" + a + " nexthop=" + Config.SharingGwIp + " store=persistent");
            Netsh("interface ipv4 set dnsservers name=" + a + " source=static address=none register=none validate=no");
        }

        static void ConfigureAdapterIp() {
            string a = "\"" + Config.AdapterName + "\"";
            string fw = "\"" + Config.FirewallRuleName + "\"";
            // Static IPs only, no gateway: direct link IP + macOS Internet Sharing subnet IP
            Netsh("interface ip set address name=" + a + " static " + Config.WinDirectIp + " " + Config.DirectNetmask + " none");
            Thread.Sleep(500);
            Netsh("interface ip add address name=" + a + " " + Config.WinSharingIp + " " + Config.SharingNetmask);
            Thread.Sleep(100);
            Netsh("interface ipv4 set interface interface=" + a + " metric=10");

            // Gateway + DNS are only installed while macOS Internet Sharing is detected (see GatewayApplyLoop)
            RemoveShareGateway();
            gwApplied = false;
            gwAppliedKnown = true;

            // Exactly one firewall rule scoped to the local USB-C adapter IPs and subnets
            Netsh("advfirewall firewall delete rule name=" + fw);
            Netsh("advfirewall firewall add rule name=" + fw
                + " dir=in action=allow localip=" + Config.WinDirectIp + "," + Config.WinSharingIp
                + " remoteip=" + Config.DirectCidr + "," + Config.SharingCidr);
        }

        // Applies gateway/DNS changes off the packet path (netsh can take a few hundred ms).
        static void GatewayApplyLoop() {
            string a = "\"" + Config.AdapterName + "\"";
            while (true) {
                gwApplyEvent.WaitOne();
                Thread.Sleep(300); // coalesce bursts
                bool want = gwDesired;
                if (gwAppliedKnown && want == gwApplied) continue;
                if (want) {
                    Netsh("interface ipv4 add route prefix=0.0.0.0/0 interface=" + a + " nexthop=" + Config.SharingGwIp + " metric=5 store=active");
                    Netsh("interface ipv4 set dnsservers name=" + a + " source=static address=" + Config.SharingGwIp + " register=none validate=no");
                    if (!string.IsNullOrEmpty(Config.SecondaryDns)) {
                        Netsh("interface ipv4 add dnsservers name=" + a + " address=" + Config.SecondaryDns + " index=2 validate=no");
                    }
                    Log("macOS Internet Sharing ON: default route + DNS via " + Config.SharingGwIp + " enabled");
                } else {
                    RemoveShareGateway();
                    Log("macOS Internet Sharing OFF: default route + DNS via " + Config.SharingGwIp + " removed (Wi-Fi is default)");
                }
                gwApplied = want;
                gwAppliedKnown = true;
            }
        }

        // ARP-probes the configured sharing gateway while the cable link is up; turns sharing off after GatewayTimeoutSec of silence.
        static void GatewayMonitorLoop(IntPtr hIntf1, int gen) {
            byte[] req = new byte[42];
            for (int i = 0; i < 6; i++) req[i] = 0xFF;                 // broadcast
            Buffer.BlockCopy(Config.VirtualMac, 0, req, 6, 6);
            req[12] = 0x08; req[13] = 0x06;                              // ARP
            req[14] = 0x00; req[15] = 0x01; req[16] = 0x08; req[17] = 0x00;
            req[18] = 6; req[19] = 4; req[20] = 0x00; req[21] = 0x01;    // request
            Buffer.BlockCopy(Config.VirtualMac, 0, req, 22, 6);
            Buffer.BlockCopy(Config.WinSharingIpBytes, 0, req, 28, 4);
            Buffer.BlockCopy(Config.SharingGwIpBytes, 0, req, 38, 4);

            while (running && gen == linkGen) {
                SendSingleEthernetFrame(hIntf1, req, 42);
                gwProbeWake.WaitOne(ProbeIntervalMs);
                if (!running || gen != linkGen) break;
                long last = Interlocked.Read(ref gwLastSeenTicks);
                bool alive = last != 0 && (DateTime.UtcNow.Ticks - last) < TimeSpan.FromSeconds(GatewayTimeoutSec).Ticks;
                if (alive != gwDesired) {
                    gwDesired = alive;
                    gwApplyEvent.Set();
                }
            }
        }

        static void Main(string[] args) {
            Config = BridgeConfig.Load(args);
            try {
                // Restrict implicit DLL resolution to System32 first, then explicitly load wintun.dll by full path.
                SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string wintunPath = (!string.IsNullOrEmpty(baseDir) && File.Exists(Path.Combine(baseDir, "wintun.dll")))
                    ? Path.Combine(baseDir, "wintun.dll")
                    : Path.Combine(Config.DataDir, "wintun.dll");
                if (!File.Exists(wintunPath) || LoadLibraryExW(wintunPath, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH) == IntPtr.Zero) {
                    Log("Failed to load wintun.dll safely from " + wintunPath + " err=" + Marshal.GetLastWin32Error());
                    return;
                }
            } catch (Exception ex) {
                Log("DLL search initialization failed: " + ex.Message);
                return;
            }
            try {
                Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High;
                Thread.CurrentThread.Priority = ThreadPriority.Highest;
            } catch {}
            Log("Starting AppleUsbNcmBridge service (High Priority, Hardened, MAC=" + BridgeConfig.FormatMac(Config.VirtualMac) + ")...");
            Guid adapterGuid = Config.AdapterGuid;
            IntPtr adapter = WintunOpenAdapter(Config.AdapterName);
            if (adapter == IntPtr.Zero) {
                adapter = WintunCreateAdapter(Config.AdapterName, Config.TunnelType, ref adapterGuid);
            }
            if (adapter == IntPtr.Zero) {
                Log("Failed to create WinTun adapter: " + Marshal.GetLastWin32Error());
                return;
            }
            IntPtr session = WintunStartSession(adapter, 0x400000);
            if (session == IntPtr.Zero) {
                Log("Failed to start WinTun session: " + Marshal.GetLastWin32Error());
                WintunCloseAdapter(adapter);
                return;
            }
            ConfigureAdapterIp();
            Log("WinTun adapter '" + Config.AdapterName + "' configured at " + Config.WinDirectIp
                + " (" + Config.DirectCidr + ") + " + Config.WinSharingIp
                + " (" + Config.SharingCidr + "), hint UDP :" + Config.HintPort
                + " (gateway " + Config.SharingGwIp + " active only while Mac shares Internet)");

            Thread gwApplyThread = new Thread(GatewayApplyLoop);
            gwApplyThread.IsBackground = true;
            gwApplyThread.Start();

            IntPtr hPlugEvent = CreateEvent(IntPtr.Zero, false, false, null);
            CM_NOTIFY_FILTER filter = new CM_NOTIFY_FILTER();
            filter.cbSize = (uint)Marshal.SizeOf(typeof(CM_NOTIFY_FILTER));
            filter.Flags = 2; // CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES
            filter.FilterType = 0; // CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE
            CM_NOTIFY_CALLBACK cb = (hN, ctx, act, ed, eds) => {
                if (act == 0 && hPlugEvent != IntPtr.Zero) SetEvent(hPlugEvent);
                return 0;
            };
            GCHandle cbHandle = GCHandle.Alloc(cb);
            IntPtr hNotify = IntPtr.Zero;
            CM_Register_Notification(ref filter, IntPtr.Zero, cb, out hNotify);
            Console.CancelKeyPress += (s, e) => {
                e.Cancel = true;
                serviceStop = true;
                running = false;
                if (hPlugEvent != IntPtr.Zero) SetEvent(hPlugEvent);
            };
            bool loggedSleep = false;

            try {
                while (!serviceStop) {
                try {
                    string devPath = FindAppleUsbPath();
                    if (devPath == null) {
                        if (!loggedSleep) {
                            Log("Cable unplugged. Waiting for USB-C connection...");
                            loggedSleep = true;
                        }
                        if (hPlugEvent != IntPtr.Zero) WaitForSingleObject(hPlugEvent, 3000);
                        else Thread.Sleep(3000);
                        continue;
                    }
                    loggedSleep = false;
                    Log("Found Apple USB-C device: " + devPath);
                    using (SafeFileHandle hDev = CreateFile(devPath, 0xC0000000, 3, IntPtr.Zero, 3, 0x40000000, IntPtr.Zero)) {
                        if (hDev.IsInvalid) {
                            Thread.Sleep(1000);
                            continue;
                        }
                        IntPtr hIntf0 = IntPtr.Zero;
                        IntPtr hIntf1 = IntPtr.Zero;
                        Thread rxThread = null;
                        Thread gwMonThread = null;
                        try {
                            if (!WinUsb_Initialize(hDev, out hIntf0)) {
                                Thread.Sleep(1000);
                                continue;
                            }
                            WINUSB_SETUP_PACKET pkt = new WINUSB_SETUP_PACKET { RequestType = 0xA1, Request = 0x80, Value = 0, Index = 0, Length = 28 };
                            byte[] ntbParams = new byte[28];
                            uint transferred = 0;
                            WinUsb_ControlTransfer(hIntf0, pkt, ntbParams, 28, out transferred, IntPtr.Zero);
                            uint maxIn = BitConverter.ToUInt32(ntbParams, 4);
                            if (maxIn < 2048 || maxIn > 65536) maxIn = 32764;

                            if (!WinUsb_GetAssociatedInterface(hIntf0, 0, out hIntf1) || hIntf1 == IntPtr.Zero) {
                                Thread.Sleep(1000);
                                continue;
                            }
                            WinUsb_SetCurrentAlternateSetting(hIntf1, 0);

                            WINUSB_SETUP_PACKET setIn = new WINUSB_SETUP_PACKET { RequestType = 0x21, Request = 0x86, Value = 0, Index = 0, Length = 4 };
                            byte[] inSizeBuf = BitConverter.GetBytes(maxIn);
                            WinUsb_ControlTransfer(hIntf0, setIn, inSizeBuf, 4, out transferred, IntPtr.Zero);

                            if (!WinUsb_SetCurrentAlternateSetting(hIntf1, 1)) {
                                Thread.Sleep(1000);
                                continue;
                            }
                            WINUSB_SETUP_PACKET filt = new WINUSB_SETUP_PACKET { RequestType = 0x21, Request = 0x43, Value = 0x000F, Index = 0, Length = 0 };
                            WinUsb_ControlTransfer(hIntf0, filt, null, 0, out transferred, IntPtr.Zero);

                            Log("CDC-NCM link active (maxIn=" + maxIn + "). Starting RX/TX threads...");
                            running = true;
                            IntPtr hIntf1Copy = hIntf1;
                            rxThread = new Thread(() => UsbRxLoop(hIntf1Copy, session, maxIn));
                            rxThread.IsBackground = true;
                            rxThread.Priority = ThreadPriority.Highest;
                            rxThread.Start();

                            int gen = linkGen;
                            gwMonThread = new Thread(() => GatewayMonitorLoop(hIntf1Copy, gen));
                            gwMonThread.IsBackground = true;
                            gwMonThread.Start();

                            UsbTxLoop(hIntf1, session);
                        } finally {
                            // Signal shutdown and abort blocked WinUSB I/O BEFORE joining threads and freeing WinUSB handles.
                            running = false;
                            ResetPeerMac();
                            linkGen++;
                            gwProbeWake.Set();
                            IntPtr waitEvt = WintunGetReadWaitEvent(session);
                            if (waitEvt != IntPtr.Zero) SetEvent(waitEvt);
                            if (hIntf1 != IntPtr.Zero) {
                                WinUsb_AbortPipe(hIntf1, 0x81);
                                WinUsb_AbortPipe(hIntf1, 0x01);
                            }
                            if (!hDev.IsInvalid && !hDev.IsClosed) {
                                CancelIoEx(hDev, IntPtr.Zero);
                            }
                            if (rxThread != null && rxThread.IsAlive) rxThread.Join(5000);
                            if (gwMonThread != null && gwMonThread.IsAlive) gwMonThread.Join(2000);
                            Interlocked.Exchange(ref gwLastSeenTicks, 0);
                            if (gwDesired || gwApplied) {
                                gwDesired = false;
                                gwApplyEvent.Set();
                            }
                            if (hIntf1 != IntPtr.Zero) WinUsb_Free(hIntf1);
                            if (hIntf0 != IntPtr.Zero) WinUsb_Free(hIntf0);
                        }
                    }
                } catch (Exception ex) {
                    Log("Loop exception: " + ex.Message);
                }
                if (!serviceStop) Thread.Sleep(1000);
            }
            } finally {
                running = false;
                if (hNotify != IntPtr.Zero) CM_Unregister_Notification(hNotify);
                if (cbHandle.IsAllocated) cbHandle.Free();
                if (hPlugEvent != IntPtr.Zero) CloseHandle(hPlugEvent);
                WintunEndSession(session);
                WintunCloseAdapter(adapter);
            }
        }
    }
}
