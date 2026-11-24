/*
 * ============================================================================
 * Integrator USB-C CDC-NCM WinTun Bridge Service (windows/AppleUsbNcmBridge.cs)
 * ============================================================================
 *
 * 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
 * ----------------------------------------------------------------------------
 * Bridges Apple Silicon Mac USB-C CDC-NCM gadget Ethernet interfaces (exposed
 * via WinUSB as USB\VID_05AC&PID_1902) directly to a Windows Layer-3 WinTun
 * virtual network adapter. Because Windows lacks a built-in CDC-NCM class
 * driver compatible with Apple's point-to-point USB-C gadget configuration,
 * this userspace daemon encapsulates/decapsulates 16-bit NCM Transfer Blocks
 * (NTB16: NTH16 + NDP16), synthesizes Layer-2 Ethernet headers and ARP replies
 * for the Layer-3 WinTun tunnel, and dynamically manages Windows default route
 * and DNS settings when macOS Internet Sharing is active.
 *
 * 2. ARCHITECTURAL LINKAGES & DEPENDENCIES
 * ----------------------------------------------------------------------------
 * - Upstream Callers:
 *   - Compiled to `AppleUsbNcmBridge.exe` using the inbox .NET Framework 4.x
 *     `csc.exe` compiler (C# 5 language level) and registered as the
 *     `AppleUsbNcmBridge` scheduled task under `NT AUTHORITY\SYSTEM` by
 *     `windows/Install-AppleUsbNcm.ps1`.
 *   - Monitored by `app/src/setup.rs` and `app/src/config.rs` for health and
 *     readiness checks on Windows 11.
 * - Downstream Callees:
 *   - `setupapi.dll` & `cfgmgr32.dll`: Zero-polling PnP USB interface discovery
 *     and hotplug arrival notifications (`CM_Register_Notification`).
 *   - `winusb.dll`: Direct USB control transfers (`GET_NTB_PARAMETERS`,
 *     `SET_NTB_INPUT_SIZE`, `SET_ETHERNET_PACKET_FILTER`) and bulk pipe I/O
 *     (Pipe `0x81` Bulk IN, Pipe `0x01` Bulk OUT).
 *   - `wintun.dll`: High-throughput Layer-3 shared-memory ring buffer session.
 *   - `netsh.exe`: Out-of-band static IPv4, route metric, DNS, and scoped
 *     Windows Defender Firewall configuration.
 * - Cross-Platform / Cross-Device Flow:
 *   - Exchanges CDC-NCM NTB16 frames with macOS (`10.99.99.2/24` direct link
 *     and `192.168.2.1/24` macOS `bootpd`/NAT Internet Sharing gateway).
 *   - Consumes out-of-band UDP control hints (`"ON"` / `"OFF"`) on `HintPort`
 *     (default UDP 47901) sent by the macOS USB-C watchdog daemon to trigger
 *     immediate ARP gateway probing or route teardown.
 *
 * 3. THREADING & CONCURRENCY MODEL
 * ----------------------------------------------------------------------------
 * - Main Thread: Registers `CM_Register_Notification` for USB PnP arrivals,
 *   opens and configures the WinUSB device, and executes `UsbTxLoop` at
 *   `ThreadPriority.Highest` while the USB-C link is active.
 * - `UsbRxLoop` Thread: Dedicated background thread (`ThreadPriority.Highest`)
 *   blocking on synchronous `WinUsb_ReadPipe` (Pipe `0x81`), unpacking NTB16
 *   datagrams, answering ARP requests, and injecting IPv4/IPv6 packets into
 *   the WinTun send ring.
 * - `GatewayMonitorLoop` Thread: Periodic background thread sending broadcast
 *   ARP probes for `SharingGwIp` every `ProbeIntervalMs` (5,000 ms) while the
 *   cable is attached, expiring the route after `GatewayTimeoutSec` (12 s).
 * - `GatewayApplyLoop` Thread: Background worker coalescing `netsh.exe` route
 *   and DNS updates off the packet forwarding path.
 * - Synchronization:
 *   - `peerMacPacked` and `gwLastSeenTicks` use lock-free `Interlocked` 64-bit
 *     operations across RX, TX, and monitor threads.
 *   - `txLock` serializes USB Bulk OUT writes (`WinUsb_WritePipe` on Pipe `0x01`)
 *     and `txSeq` sequence numbering between `UsbTxLoop`, ARP replies, and
 *     ARP gateway probes.
 *   - `logLock` serializes diagnostic log writes and 2 MiB file rotation.
 *
 * 4. SECURITY & SAFETY INVARIANTS
 * ----------------------------------------------------------------------------
 * - DLL Hijacking Prevention: Calls `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`
 *   at process entry and loads `wintun.dll` via `LoadLibraryExW` using an
 *   explicit absolute path from the ACL-locked `%ProgramData%\AppleUsbNcm`
 *   directory.
 * - Command Injection Prevention: All IPv4 addresses, CIDR blocks, and adapter
 *   or firewall rule labels are strictly parsed or sanitized (`SanitizeSafeLabel`
 *   rejects quotes, CR/LF, and NUL) before constructing `netsh.exe` arguments.
 * - Control-Plane Spoofing Protection: `HandleControlHint` only accepts UDP
 *   control hints originating from the configured USB-C direct subnet, the
 *   Internet Sharing subnet, or RFC 3927 IPv4 link-local addresses (`169.254.0.0/16`).
 * - Teardown & Memory Safety: All unmanaged handles (`SetupDi` lists, `GCHandle`,
 *   Win32 event handles, WinUSB handles, and WinTun session/adapter handles)
 *   are deterministically released in `finally` blocks; `WinUsb_AbortPipe` and
 *   `CancelIoEx` unblock synchronous I/O prior to `Thread.Join` and `WinUsb_Free`.
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

        /// <summary>Default folder name under %ProgramData% storing bridge config, logs, and binaries.</summary>
        private const string DefaultAppFolderName = "AppleUsbNcm";
        /// <summary>Default configuration filename inside the data directory.</summary>
        private const string DefaultConfigFileName = "bridge.conf";
        /// <summary>Default diagnostic log filename inside the data directory.</summary>
        private const string DefaultLogFileName = "bridge.log";
        /// <summary>Default WinTun network adapter display name in Windows Network Connections.</summary>
        private const string DefaultAdapterName = "Apple USB-C NCM";
        /// <summary>Default WinTun tunnel type identifier passed to WintunCreateAdapter.</summary>
        private const string DefaultTunnelType = "USB-C Direct";
        /// <summary>Default Windows Defender Firewall inbound allow rule display name.</summary>
        private const string DefaultFirewallRuleName = "Apple USB-C NCM Allow All";
        /// <summary>Default Windows static IPv4 address on the point-to-point USB-C direct subnet.</summary>
        private const string DefaultWinDirectIp = "10.99.99.1";
        /// <summary>Default IPv4 subnet mask (/24) for the point-to-point USB-C direct subnet.</summary>
        private const string DefaultDirectNetmask = "255.255.255.0";
        /// <summary>Default CIDR block for the point-to-point USB-C direct subnet.</summary>
        private const string DefaultDirectCidr = "10.99.99.0/24";
        /// <summary>Default Windows static IPv4 address on the macOS Internet Sharing NAT subnet.</summary>
        private const string DefaultWinSharingIp = "192.168.2.2";
        /// <summary>Default IPv4 subnet mask (/24) for the macOS Internet Sharing NAT subnet.</summary>
        private const string DefaultSharingNetmask = "255.255.255.0";
        /// <summary>Default macOS Internet Sharing gateway IPv4 address.</summary>
        private const string DefaultSharingGwIp = "192.168.2.1";
        /// <summary>Default CIDR block for the macOS Internet Sharing NAT subnet.</summary>
        private const string DefaultSharingCidr = "192.168.2.0/24";
        /// <summary>Default UDP port number receiving ON/OFF sharing state hints from macOS.</summary>
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

        /// <summary>
        /// Sanitizes an adapter name, tunnel type, or firewall rule label so it cannot inject quotes
        /// or control characters into netsh.exe command lines. Returns <paramref name="fallback"/> if invalid.
        /// </summary>
        private static string SanitizeSafeLabel(string raw, string fallback) {
            if (string.IsNullOrEmpty(raw)) return fallback;
            string trimmed = raw.Trim();
            if (trimmed.Length == 0 || trimmed.IndexOf('"') >= 0 || trimmed.IndexOf('\r') >= 0 || trimmed.IndexOf('\n') >= 0 || trimmed.IndexOf('\0') >= 0) {
                return fallback;
            }
            return trimmed;
        }

        /// <summary>
        /// Parses a UTF-8 key=value configuration file, ignoring blank lines and '#' or ';' comments,
        /// stripping optional surrounding single or double quotes from values.
        /// </summary>
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

        /// <summary>
        /// Parses command-line overrides in either <c>--key=value</c> or <c>--key value</c> syntax
        /// into a normalized case-insensitive dictionary.
        /// </summary>
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

        /// <summary>
        /// Normalizes configuration keys by stripping hyphens, underscores, and surrounding whitespace
        /// so <c>--win-direct-ip</c>, <c>win_direct_ip</c>, and <c>WinDirectIp</c> map to the same key.
        /// </summary>
        private static string NormalizeKey(string key) {
            if (string.IsNullOrEmpty(key)) return "";
            return key.Replace("-", "").Replace("_", "").Trim();
        }

        /// <summary>
        /// Resolves a configuration setting according to strict precedence:
        /// 1. CLI arguments (<paramref name="cli"/>),
        /// 2. Process environment variable (<paramref name="envName"/>),
        /// 3. Configuration file dictionary (<paramref name="conf"/>).
        /// </summary>
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

    /// <summary>
    /// Entry-point service class managing WinUSB CDC-NCM device lifecycle, WinTun Layer-3 ring buffer I/O,
    /// synthetic Layer-2 Ethernet/ARP framing, and macOS Internet Sharing gateway/DNS synchronization.
    /// </summary>
    class Program {
        /// <summary>
        /// 8-byte USB control transfer setup packet layout matching Win32 <c>WINUSB_SETUP_PACKET</c>.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct WINUSB_SETUP_PACKET {
            /// <summary>bmRequestType bitmask (direction, type, and recipient; e.g. 0xA1 class-specific interface IN, 0x21 class-specific interface OUT).</summary>
            public byte RequestType;
            /// <summary>bRequest code (e.g. 0x80 GET_NTB_PARAMETERS, 0x86 SET_NTB_INPUT_SIZE, 0x43 SET_ETHERNET_PACKET_FILTER).</summary>
            public byte Request;
            /// <summary>wValue 16-bit parameter word in little-endian host byte order (e.g. packet filter bitmask 0x000F).</summary>
            public ushort Value;
            /// <summary>wIndex 16-bit USB interface index (0 for CDC control interface).</summary>
            public ushort Index;
            /// <summary>wLength 16-bit data stage transfer size in bytes.</summary>
            public ushort Length;
        }

        /// <summary>
        /// SetupAPI <c>SP_DEVICE_INTERFACE_DATA</c> structure identifying an enumerated PnP device interface.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct SP_DEVICE_INTERFACE_DATA {
            /// <summary>Size of this structure in bytes (28 bytes on x86, 32 bytes on x64/ARM64).</summary>
            public uint cbSize;
            /// <summary>Device interface class GUID (GUID_DEVINTERFACE_USB_DEVICE).</summary>
            public Guid InterfaceClassGuid;
            /// <summary>Interface state flags (SPINT_ACTIVE, SPINT_DEFAULT, SPINT_REMOVED).</summary>
            public uint Flags;
            /// <summary>Opaque internal SetupAPI pointer reserved for system use.</summary>
            public IntPtr Reserved;
        }

        /// <summary>Win32 SetDefaultDllDirectories flag restricting implicit DLL search to %SystemRoot%\System32.</summary>
        private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;
        /// <summary>Win32 LoadLibraryExW flag resolving dependent DLLs relative to the target binary's directory.</summary>
        private const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008;

        /// <summary>Standard Microsoft GUID_DEVINTERFACE_USB_DEVICE interface class GUID ({A5DCBF10-6530-11D2-901F-00C04FB951ED}).</summary>
        private static readonly Guid UsbDeviceInterfaceClassGuid = new Guid("a5dcbf10-6530-11d2-901f-00c04fb951ed");

        /// <summary>Default Apple USB-C CDC-NCM gadget hardware identifier substring (Vendor 0x05AC Apple, Product 0x1902 USB-C NCM).</summary>
        private const string DefaultAppleNcmHwid = "vid_05ac&pid_1902";

        /// <summary>RFC 3927 IPv4 link-local first octet (169.254.0.0/16).</summary>
        private const byte LinkLocalOctet0 = 169;

        /// <summary>RFC 3927 IPv4 link-local second octet (169.254.0.0/16).</summary>
        private const byte LinkLocalOctet1 = 254;

        /// <summary>SetupAPI P/Invoke: returns a handle to a device information set for matching device interfaces.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, string Enumerator, IntPtr hwndParent, uint Flags);

        /// <summary>SetupAPI P/Invoke: enumerates device interfaces within a device information set at <paramref name="MemberIndex"/>.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiEnumDeviceInterfaces(IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref Guid InterfaceClassGuid, uint MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

        /// <summary>SetupAPI P/Invoke: retrieves the Win32 SymbolicLink device path for an enumerated device interface.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr DeviceInfoSet, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData, IntPtr DeviceInterfaceDetailData, uint DeviceInterfaceDetailDataSize, out uint RequiredSize, IntPtr DeviceInfoData);

        /// <summary>SetupAPI P/Invoke: frees a device information set allocated by <see cref="SetupDiGetClassDevs"/>.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        /// <summary>Kernel32 P/Invoke: opens a Win32 file/device handle to the USB device symbolic path.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        /// <summary>Kernel32 P/Invoke: waits up to <paramref name="dwMilliseconds"/> ms for a kernel synchronization object to be signaled.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        /// <summary>Kernel32 P/Invoke: creates an unnamed or named Win32 event synchronization object.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        /// <summary>Kernel32 P/Invoke: sets the specified Win32 event object to the signaled state.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetEvent(IntPtr hEvent);

        /// <summary>Kernel32 P/Invoke: closes an open Win32 kernel object handle.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        /// <summary>Kernel32 P/Invoke: cancels pending synchronous or overlapped I/O operations on <paramref name="hFile"/> across all threads.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CancelIoEx(SafeFileHandle hFile, IntPtr lpOverlapped);

        /// <summary>Kernel32 P/Invoke: restricts process-wide implicit DLL search directories to mitigate DLL planting attacks.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetDefaultDllDirectories(uint DirectoryFlags);

        /// <summary>Kernel32 P/Invoke: loads a dynamic-link library by absolute path with explicit search flags.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryExW(string lpLibFileName, IntPtr hFile, uint dwFlags);

        /// <summary>
        /// Configuration Manager <c>CM_NOTIFY_FILTER</c> structure (416 bytes total) specifying PnP interface arrival filter criteria.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct CM_NOTIFY_FILTER {
            /// <summary>Total size of this structure in bytes (416 bytes).</summary>
            public uint cbSize;
            /// <summary>Filter flags (0x00000002 = CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES).</summary>
            public uint Flags;
            /// <summary>Filter type (0 = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE).</summary>
            public uint FilterType;
            /// <summary>Reserved alignment word; must be 0.</summary>
            public uint Reserved;
            /// <summary>Device interface class GUID when filtering a single class (unused when Flags == 2).</summary>
            public Guid ClassGuid;
            /// <summary>Union padding matching MAX_DEVICE_ID_LEN (200 WCHARs = 400 bytes minus 16-byte Guid = 384 bytes).</summary>
            public fixed byte Padding[384];
        }

        /// <summary>
        /// Configuration Manager PnP event callback invoked on a system thread-pool thread when a device interface arrives or departs.
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint CM_NOTIFY_CALLBACK(IntPtr hNotify, IntPtr Context, int Action, IntPtr EventData, int EventDataSize);

        /// <summary>CfgMgr32 P/Invoke: registers an asynchronous callback for PnP device interface arrival/removal events.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("cfgmgr32.dll")]
        public static extern int CM_Register_Notification(ref CM_NOTIFY_FILTER pFilter, IntPtr pContext, CM_NOTIFY_CALLBACK pCallback, out IntPtr pNotifyContext);

        /// <summary>CfgMgr32 P/Invoke: unregisters a PnP notification context handle allocated by <see cref="CM_Register_Notification"/>.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("cfgmgr32.dll")]
        public static extern int CM_Unregister_Notification(IntPtr NotifyContext);

        /// <summary>WinUSB P/Invoke: initializes WinUSB on an open device file handle and returns Interface 0 (CDC Control).</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_Initialize(SafeFileHandle DeviceHandle, out IntPtr InterfaceHandle);

        /// <summary>WinUSB P/Invoke: releases a WinUSB interface handle returned by <see cref="WinUsb_Initialize"/> or <see cref="WinUsb_GetAssociatedInterface"/>.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_Free(IntPtr InterfaceHandle);

        /// <summary>WinUSB P/Invoke: opens an associated USB interface by zero-based index (0 = USB Interface 1, CDC Data).</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_GetAssociatedInterface(IntPtr InterfaceHandle, byte AssociatedInterfaceIndex, out IntPtr AssociatedInterfaceHandle);

        /// <summary>WinUSB P/Invoke: switches a USB interface's active alternate setting (Alt 0 = idle/reset, Alt 1 = active bulk data pipes).</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_SetCurrentAlternateSetting(IntPtr InterfaceHandle, byte SettingNumber);

        /// <summary>WinUSB P/Invoke: performs a synchronous USB control transfer on Endpoint 0.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_ControlTransfer(IntPtr InterfaceHandle, WINUSB_SETUP_PACKET SetupPacket, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        /// <summary>WinUSB P/Invoke: reads raw NTB16 transfer blocks from a Bulk IN pipe (Pipe 0x81).</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_ReadPipe(IntPtr InterfaceHandle, byte PipeID, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        /// <summary>WinUSB P/Invoke: writes raw NTB16 transfer blocks to a Bulk OUT pipe (Pipe 0x01).</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_WritePipe(IntPtr InterfaceHandle, byte PipeID, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        /// <summary>WinUSB P/Invoke: aborts all pending transfers on the specified pipe so blocked reader/writer threads wake immediately.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_AbortPipe(IntPtr InterfaceHandle, byte PipeID);

        /// <summary>WinTun P/Invoke: creates a new Layer-3 WinTun virtual network adapter with a requested GUID.</summary>
        [DllImport("wintun.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunCreateAdapter(string Name, string TunnelType, ref Guid RequestedGUID);

        /// <summary>WinTun P/Invoke: opens an existing Layer-3 WinTun virtual network adapter by friendly name.</summary>
        [DllImport("wintun.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunOpenAdapter(string Name);

        /// <summary>WinTun P/Invoke: closes a WinTun adapter handle.</summary>
        [DllImport("wintun.dll", SetLastError = true)]
        public static extern void WintunCloseAdapter(IntPtr Adapter);

        /// <summary>WinTun P/Invoke: starts a packet ring-buffer session with <paramref name="Capacity"/> bytes (must be power of two between 0x20000 and 0x4000000).</summary>
        [DllImport("wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunStartSession(IntPtr Adapter, uint Capacity);

        /// <summary>WinTun P/Invoke: terminates an active WinTun ring-buffer session.</summary>
        [DllImport("wintun.dll", SetLastError = true)]
        public static extern void WintunEndSession(IntPtr Session);

        /// <summary>WinTun P/Invoke: returns the kernel wait event signaled when outgoing Layer-3 packets arrive in the WinTun ring.</summary>
        [DllImport("wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunGetReadWaitEvent(IntPtr Session);

        /// <summary>WinTun P/Invoke: dequeues the next outgoing Layer-3 IPv4/IPv6 packet from Windows (returns IntPtr.Zero when ring is empty).</summary>
        [DllImport("wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunReceivePacket(IntPtr Session, out uint PacketSize);

        /// <summary>WinTun P/Invoke: releases the ring-buffer slot for a packet previously returned by <see cref="WintunReceivePacket"/>.</summary>
        [DllImport("wintun.dll", SetLastError = true)]
        public static extern void WintunReleaseReceivePacket(IntPtr Session, IntPtr Packet);

        /// <summary>WinTun P/Invoke: allocates a slot of <paramref name="PacketSize"/> bytes in the WinTun receive ring for injecting an incoming Layer-3 packet.</summary>
        [DllImport("wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunAllocateSendPacket(IntPtr Session, uint PacketSize);

        /// <summary>WinTun P/Invoke: commits and dispatches an allocated incoming Layer-3 packet to the Windows TCP/IP stack.</summary>
        [DllImport("wintun.dll", SetLastError = true)]
        public static extern void WintunSendPacket(IntPtr Session, IntPtr Packet);

        /// <summary>Active immutable bridge configuration loaded at startup.</summary>
        static BridgeConfig Config;
        /// <summary>Volatile flag indicating that an active USB-C CDC-NCM session is running RX/TX forwarding loops.</summary>
        static volatile bool running = false;
        /// <summary>Volatile flag set on Ctrl+C / process shutdown to exit the outer PnP connection loop cleanly.</summary>
        static volatile bool serviceStop = false;
        /// <summary>48-bit Ethernet broadcast MAC (FF:FF:FF:FF:FF:FF) packed into the low 6 bytes of a 64-bit integer.</summary>
        const long BroadcastMacPacked = 0x0000FFFFFFFFFFFFL;
        /// <summary>Atomically updated 48-bit unicast MAC address learned from incoming Mac Ethernet frames (defaults to broadcast).</summary>
        static long peerMacPacked = BroadcastMacPacked;
        /// <summary>Monotonically wrapping 16-bit NTH16 sequence counter (wSequence), guarded by <see cref="txLock"/>.</summary>
        static ushort txSeq = 0;
        /// <summary>Mutex serializing USB Bulk OUT pipe writes (Pipe 0x01), <see cref="txSeq"/> increments, and <see cref="singleTxBuf"/> access.</summary>
        static readonly object txLock = new object();
        /// <summary>Mutex serializing diagnostic file writes and log rotation on <see cref="BridgeConfig.LogFilePath"/>.</summary>
        static readonly object logLock = new object();
        /// <summary>Pre-allocated 2,048-byte NTB16 staging buffer for single-frame USB writes (ARP replies, ARP probes, single IP packets), guarded by <see cref="txLock"/>.</summary>
        static readonly byte[] singleTxBuf = new byte[2048];
        /// <summary>Maximum size in bytes (2 MiB) of bridge.log before rotating to bridge.log.1.</summary>
        const long MaxLogBytes = 2 * 1024 * 1024;

        // macOS Internet Sharing gateway tracking.
        // The default route + DNS via the Mac are only installed while the Mac is proven to be sharing,
        // so Wi-Fi stays the default route whenever Internet Sharing is off.
        /// <summary>Interval in milliseconds (5,000 ms) between ARP gateway reachability probes while the USB-C cable is connected.</summary>
        const int ProbeIntervalMs = 5000;
        /// <summary>Timeout in seconds (12 s) without any ARP or IPv4 traffic from SharingGwIp before tearing down the sharing default route.</summary>
        const int GatewayTimeoutSec = 12;
        /// <summary>UTC timestamp in 100-nanosecond ticks (<see cref="DateTime.Ticks"/>) when traffic from <see cref="BridgeConfig.SharingGwIp"/> was last observed (0 = never/expired).</summary>
        static long gwLastSeenTicks = 0;
        /// <summary>Desired macOS Internet Sharing gateway state (true = install default route + DNS, false = remove).</summary>
        static volatile bool gwDesired = false;
        /// <summary>Last state applied to the OS routing table by <see cref="GatewayApplyLoop"/>.</summary>
        static volatile bool gwApplied = false;
        /// <summary>True once <see cref="ConfigureAdapterIp"/> or <see cref="GatewayApplyLoop"/> has synchronized OS route state at least once.</summary>
        static volatile bool gwAppliedKnown = false;
        /// <summary>Monotonically incremented generation counter identifying the current USB-C cable attachment session.</summary>
        static volatile int linkGen = 0;
        /// <summary>Signaled whenever <see cref="gwDesired"/> changes so <see cref="GatewayApplyLoop"/> reconciles netsh routes out-of-band.</summary>
        static readonly AutoResetEvent gwApplyEvent = new AutoResetEvent(false);
        /// <summary>Signaled on UDP "ON" hints or link teardown to wake <see cref="GatewayMonitorLoop"/> immediately.</summary>
        static readonly AutoResetEvent gwProbeWake = new AutoResetEvent(false);

        /// <summary>
        /// Compares a 4-byte IPv4 address at <paramref name="buf"/>[<paramref name="off"/>..+4] against <paramref name="expected"/>.
        /// </summary>
        static bool IpEquals(byte[] buf, int off, byte[] expected) {
            if (buf == null || expected == null || off < 0 || off + 4 > buf.Length || expected.Length != 4) return false;
            return buf[off] == expected[0]
                && buf[off + 1] == expected[1]
                && buf[off + 2] == expected[2]
                && buf[off + 3] == expected[3];
        }

        /// <summary>
        /// Returns true if the 4-byte IPv4 address at <paramref name="buf"/>[<paramref name="off"/>..+4] belongs to
        /// the subnet defined by (<paramref name="netIp"/> &amp; <paramref name="netmask"/>).
        /// </summary>
        static bool IsInSubnet(byte[] buf, int off, byte[] netIp, byte[] netmask) {
            if (buf == null || netIp == null || netmask == null || netIp.Length < 4 || netmask.Length < 4 || off < 0 || off + 4 > buf.Length) return false;
            for (int i = 0; i < 4; i++) {
                if ((buf[off + i] & netmask[i]) != (netIp[i] & netmask[i])) return false;
            }
            return true;
        }

        /// <summary>
        /// Returns true if the 4-byte IPv4 address at <paramref name="buf"/>[<paramref name="off"/>..+4] is in RFC 3927 link-local space (169.254.0.0/16).
        /// </summary>
        static bool IsLinkLocalIpv4(byte[] buf, int off) {
            if (buf == null || off < 0 || off + 4 > buf.Length) return false;
            return buf[off] == LinkLocalOctet0 && buf[off + 1] == LinkLocalOctet1;
        }

        /// <summary>
        /// Atomically learns the connected Mac's 6-byte unicast Ethernet MAC address from an incoming frame header.
        /// Ignores multicast/broadcast source MACs (I/G bit 0 of first octet set).
        /// </summary>
        static void SetPeerMac(byte[] buf, int off) {
            if (buf == null || off < 0 || off + 6 > buf.Length) return;
            // Ignore multicast/broadcast source MACs (LSB of first octet == 1)
            if ((buf[off] & 0x01) != 0) return;
            long packed = ((long)buf[off])
                | ((long)buf[off + 1] << 8)
                | ((long)buf[off + 2] << 16)
                | ((long)buf[off + 3] << 24)
                | ((long)buf[off + 4] << 32)
                | ((long)buf[off + 5] << 40);
            Interlocked.Exchange(ref peerMacPacked, packed);
        }

        /// <summary>
        /// Atomically reads the learned Mac peer MAC address (or broadcast fallback) and writes its 6 octets into <paramref name="dst"/>[<paramref name="off"/>..+6].
        /// </summary>
        static void WritePeerMac(byte[] dst, int off) {
            if (dst == null || off < 0 || off + 6 > dst.Length) return;
            long packed = Interlocked.Read(ref peerMacPacked);
            dst[off]     = (byte)(packed & 0xFF);
            dst[off + 1] = (byte)((packed >> 8) & 0xFF);
            dst[off + 2] = (byte)((packed >> 16) & 0xFF);
            dst[off + 3] = (byte)((packed >> 24) & 0xFF);
            dst[off + 4] = (byte)((packed >> 32) & 0xFF);
            dst[off + 5] = (byte)((packed >> 40) & 0xFF);
        }

        /// <summary>
        /// Resets the learned peer MAC address back to Ethernet broadcast (FF:FF:FF:FF:FF:FF) on link disconnect.
        /// </summary>
        static void ResetPeerMac() {
            Interlocked.Exchange(ref peerMacPacked, BroadcastMacPacked);
        }

        /// <summary>
        /// Writes a timestamped diagnostic message to standard output and appends it to <see cref="BridgeConfig.LogFilePath"/>,
        /// rotating the log file at <see cref="MaxLogBytes"/> (2 MiB).
        /// </summary>
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

        /// <summary>
        /// Enumerates active Win32 USB device interfaces via SetupAPI and returns the symbolic device path
        /// matching Apple's USB-C CDC-NCM gadget (<c>VID_05AC&amp;PID_1902</c> or <c>APPLE_USB_NCM_HWID</c>), or null if unplugged.
        /// </summary>
        static string FindAppleUsbPath() {
            Guid guid = UsbDeviceInterfaceClassGuid;
            // DIGCF_PRESENT (0x02) | DIGCF_DEVICEINTERFACE (0x10)
            IntPtr devs = SetupDiGetClassDevs(ref guid, null, IntPtr.Zero, 0x00000002 | 0x00000010);
            if (devs == IntPtr.Zero || devs == new IntPtr(-1)) return null;
            string customHwid = Environment.GetEnvironmentVariable("APPLE_USB_NCM_HWID");
            string customHwidLower = !string.IsNullOrEmpty(customHwid) ? customHwid.Trim().ToLowerInvariant() : null;
            try {
                uint idx = 0;
                SP_DEVICE_INTERFACE_DATA ifData = new SP_DEVICE_INTERFACE_DATA();
                ifData.cbSize = (uint)Marshal.SizeOf(ifData);
                while (SetupDiEnumDeviceInterfaces(devs, IntPtr.Zero, ref guid, idx, ref ifData)) {
                    idx++;
                    uint reqSize = 0;
                    SetupDiGetDeviceInterfaceDetail(devs, ref ifData, IntPtr.Zero, 0, out reqSize, IntPtr.Zero);
                    // SP_DEVICE_INTERFACE_DETAIL_DATA_W requires at least 6 bytes (4-byte cbSize + 1 WCHAR) and bounded allocation
                    if (reqSize >= 8 && reqSize <= 65536) {
                        IntPtr detail = Marshal.AllocHGlobal((int)reqSize);
                        try {
                            // SP_DEVICE_INTERFACE_DETAIL_DATA_W.cbSize is 8 on 64-bit Windows (4-byte uint + 2-byte WCHAR + 2-byte alignment) and 6 on 32-bit
                            Marshal.WriteInt32(detail, IntPtr.Size == 8 ? 8 : 6);
                            if (SetupDiGetDeviceInterfaceDetail(devs, ref ifData, detail, reqSize, out reqSize, IntPtr.Zero)) {
                                // DevicePath UTF-16LE string starts at byte offset 4 immediately after cbSize
                                string path = Marshal.PtrToStringUni(new IntPtr(detail.ToInt64() + 4));
                                string lower = path != null ? path.ToLowerInvariant() : "";
                                if (lower.Contains(DefaultAppleNcmHwid)
                                    || (!string.IsNullOrEmpty(customHwidLower) && lower.Contains(customHwidLower))) {
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

        /// <summary>
        /// Wraps a single Layer-2 Ethernet frame (14..1536 bytes) in a USB CDC-NCM NTB16 container
        /// (12-byte NTH16 + 16-byte NDP16 + payload) and writes it synchronously to Bulk OUT Pipe 0x01.
        /// Pads exact 512-byte USB High/SuperSpeed packet multiples by 4 bytes to avoid needing a USB Zero-Length Packet (ZLP).
        /// </summary>
        static void SendSingleEthernetFrame(IntPtr hIntf1, byte[] frame, int frameLen) {
            if (frame == null || frameLen < 14 || frameLen > 1536 || frameLen > frame.Length) return;
            lock (txLock) {
                int totalLen = 28 + frameLen;
                if (totalLen < 64) totalLen = 64;
                // Avoid exact 512-byte bulk max-packet boundary so macOS AppleUSBCDC driver commits the NTB without waiting for a ZLP
                if ((totalLen % 512) == 0) totalLen += 4;
                if (totalLen > singleTxBuf.Length) return;

                byte[] buf = singleTxBuf;
                // 12-byte NTH16 header: dwSignature = "NCMH" (0x484D434E little-endian)
                buf[0] = 0x4E; buf[1] = 0x43; buf[2] = 0x4D; buf[3] = 0x48;
                // wHeaderLength = 12 bytes
                buf[4] = 12; buf[5] = 0;
                // wSequence = monotonically incrementing 16-bit NTB sequence counter
                buf[6] = (byte)(txSeq & 0xFF); buf[7] = (byte)((txSeq >> 8) & 0xFF);
                txSeq++;
                // wBlockLength = total NTB16 size in bytes
                buf[8] = (byte)(totalLen & 0xFF); buf[9] = (byte)((totalLen >> 8) & 0xFF);
                // wNdpIndex = byte offset of first NDP16 (immediately after 12-byte NTH16)
                buf[10] = 12; buf[11] = 0;

                // 16-byte NDP16 header: dwSignature = "NCM0" (0x304D434E, no CRC32 appended)
                buf[12] = 0x4E; buf[13] = 0x43; buf[14] = 0x4D; buf[15] = 0x30;
                // wLength = 16 bytes (8-byte NDP16 header + one 4-byte datagram pointer + one 4-byte NULL terminator)
                buf[16] = 16; buf[17] = 0;
                // wNextNdpIndex = 0 (end of NDP chain)
                buf[18] = 0; buf[19] = 0;
                // Datagram[0]: wDatagramIndex = 28, wDatagramLength = frameLen
                buf[20] = 28; buf[21] = 0;
                buf[22] = (byte)(frameLen & 0xFF); buf[23] = (byte)((frameLen >> 8) & 0xFF);
                // Datagram[1]: explicit 4-byte NDP16 zero terminator entry (wDatagramIndex = 0, wDatagramLength = 0)
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

        /// <summary>
        /// Records that traffic from the macOS Internet Sharing gateway (<see cref="BridgeConfig.SharingGwIp"/>)
        /// was just observed, waking <see cref="GatewayApplyLoop"/> if the default route is not yet enabled.
        /// </summary>
        static void MarkGatewaySeen() {
            Interlocked.Exchange(ref gwLastSeenTicks, DateTime.UtcNow.Ticks);
            if (!gwDesired) {
                gwDesired = true;
                gwApplyEvent.Set();
            }
        }

        /// <summary>
        /// Inspects an incoming IPv4 packet at <paramref name="b"/>[<paramref name="ip"/>..+<paramref name="ipLen"/>]
        /// for a UDP control hint sent to <see cref="BridgeConfig.HintPort"/> from a local USB-C subnet or link-local peer.
        /// Returns true if the packet was consumed as an "ON"/"OFF" control hint (and therefore should not be injected into WinTun).
        /// </summary>
        static bool HandleControlHint(byte[] b, int ip, int ipLen) {
            if (b == null || ip < 0 || ipLen < 28 || ipLen > b.Length - ip) return false;
            // Verify IPv4 (version == 4) and Protocol == 17 (UDP)
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

        /// <summary>
        /// Processes an incoming Ethernet ARP frame (EtherType 0x0806) of length <paramref name="len"/> bytes at <paramref name="offset"/>.
        /// Because WinTun is a Layer-3 tunnel that does not process ARP, this method synthesizes Layer-2 ARP replies
        /// for <see cref="BridgeConfig.WinDirectIp"/> and <see cref="BridgeConfig.WinSharingIp"/> on behalf of Windows.
        /// </summary>
        static void HandleArpRequest(IntPtr hIntf1, byte[] rxBuf, int offset, int len) {
            if (rxBuf == null || offset < 0 || len < 42 || offset + 42 > rxBuf.Length) return;
            // Validate Ethernet (HTYPE=0x0001, HLEN=6) + IPv4 (PTYPE=0x0800, PLEN=4) before reading fixed offsets
            if (rxBuf[offset + 14] != 0x00 || rxBuf[offset + 15] != 0x01
                || rxBuf[offset + 16] != 0x08 || rxBuf[offset + 17] != 0x00
                || rxBuf[offset + 18] != 6 || rxBuf[offset + 19] != 4) {
                return;
            }
            // Any ARP (request, reply or gratuitous) sent from the sharing gateway means macOS Internet Sharing is on
            if (IpEquals(rxBuf, offset + 28, Config.SharingGwIpBytes)) {
                MarkGatewaySeen();
            }
            ushort oper = (ushort)((rxBuf[offset + 20] << 8) | rxBuf[offset + 21]);
            if (oper != 1) return; // Only reply to ARP Request (Opcode 1)

            // Respond to ARP for the configured Direct Link IP or macOS Internet Sharing IP
            bool matchDirect = IpEquals(rxBuf, offset + 38, Config.WinDirectIpBytes);
            bool matchSharing = IpEquals(rxBuf, offset + 38, Config.WinSharingIpBytes);

            if (matchDirect || matchSharing) {
                byte[] reply = new byte[42];
                Buffer.BlockCopy(rxBuf, offset + 6, reply, 0, 6);        // Destination MAC (requester)
                Buffer.BlockCopy(Config.VirtualMac, 0, reply, 6, 6);     // Source MAC (Windows virtual MAC)
                reply[12] = 0x08; reply[13] = 0x06;                      // EtherType ARP (0x0806)
                reply[14] = 0x00; reply[15] = 0x01;                      // Hardware type: Ethernet (1)
                reply[16] = 0x08; reply[17] = 0x00;                      // Protocol type: IPv4 (0x0800)
                reply[18] = 6;    reply[19] = 4;                         // HW size 6 bytes, Proto size 4 bytes
                reply[20] = 0x00; reply[21] = 0x02;                      // Opcode: ARP Reply (2)
                Buffer.BlockCopy(Config.VirtualMac, 0, reply, 22, 6);    // Sender MAC
                Buffer.BlockCopy(rxBuf, offset + 38, reply, 28, 4);      // Sender IP (requested target)
                Buffer.BlockCopy(rxBuf, offset + 22, reply, 32, 10);     // Target MAC (6B) + Target IP (4B) from request

                SendSingleEthernetFrame(hIntf1, reply, 42);
            }
        }

        /// <summary>
        /// Dedicated high-priority USB Bulk IN reader loop (Pipe 0x81).
        /// Parses incoming NTB16 transfer blocks (NTH16 + chained NDP16 tables), learns the Mac's source MAC,
        /// intercepts ARP frames and UDP control hints, and injects decapsulated IPv4/IPv6 payloads into WinTun.
        /// </summary>
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
                // Minimum NTB16 size is 12-byte NTH16 header
                if (transferred < 12 || transferred > rxBuf.Length) continue;
                // Validate NTH16 dwSignature == "NCMH" (0x4E, 0x43, 0x4D, 0x48)
                if (rxBuf[0] != 0x4E || rxBuf[1] != 0x43 || rxBuf[2] != 0x4D || rxBuf[3] != 0x48) continue;

                ushort ndpIdx = BitConverter.ToUInt16(rxBuf, 10);
                int safety = 0;
                // Walk chained NDP16 blocks (capped at 64 blocks per NTB to prevent malformed cycle DoS)
                while (ndpIdx >= 12 && ndpIdx + 8 <= transferred && safety++ < 64) {
                    // Validate NDP16 dwSignature == "NCM0" (no CRC) or "NCM1" (with CRC)
                    if (rxBuf[ndpIdx] != 0x4E || rxBuf[ndpIdx + 1] != 0x43 || rxBuf[ndpIdx + 2] != 0x4D
                        || (rxBuf[ndpIdx + 3] != 0x30 && rxBuf[ndpIdx + 3] != 0x31)) {
                        break;
                    }
                    ushort ndpLen = BitConverter.ToUInt16(rxBuf, ndpIdx + 4);
                    if (ndpLen < 12) break; // NDP16 must hold at least 8-byte header + 4-byte terminator
                    ushort nextNdp = BitConverter.ToUInt16(rxBuf, ndpIdx + 6);
                    int pos = ndpIdx + 8;
                    int endPos = Math.Min((int)transferred, ndpIdx + ndpLen);
                    while (pos + 4 <= endPos) {
                        ushort dgIdx = BitConverter.ToUInt16(rxBuf, pos);
                        ushort dgLen = BitConverter.ToUInt16(rxBuf, pos + 2);
                        pos += 4;
                        if (dgIdx == 0 || dgLen == 0) break; // Zero entry terminates the NDP16 datagram list
                        if (dgIdx >= 12 && dgIdx <= transferred && dgLen <= transferred - dgIdx && dgLen >= 14) {
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
                    if (nextNdp == 0 || nextNdp == ndpIdx) break;
                    ndpIdx = nextNdp;
                }
            }
        }

        /// <summary>
        /// High-priority TX loop draining outgoing Layer-3 IPv4/IPv6 packets from the WinTun ring buffer,
        /// prepending 14-byte Layer-2 Ethernet headers, batching up to 30 frames (or 14,000 bytes) into a single
        /// multi-datagram NTB16 block, and writing them to USB Bulk OUT Pipe 0x01.
        /// </summary>
        static void UsbTxLoop(IntPtr hIntf1, IntPtr session) {
            IntPtr waitEvent = WintunGetReadWaitEvent(session);
            byte[][] batchFrames = new byte[32][];
            int[] batchLens = new int[32];
            for (int i = 0; i < 32; i++) batchFrames[i] = new byte[1536];
            byte[] txBuf = new byte[32764];

            while (running) {
                int count = 0;
                int payloadBytes = 0;
                // Drain up to 30 queued packets (or 14 KB) per NTB16 batch for high throughput without starving latency
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
                                // Set EtherType: 0x0800 for IPv4, 0x86DD for IPv6
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
                    // Wait up to 250 ms per cycle on WinTun's kernel event so shutdown/disconnect cannot deadlock
                    if (waitEvent != IntPtr.Zero) WaitForSingleObject(waitEvent, 250);
                    else Thread.Sleep(10);
                    continue;
                }

                if (count == 1) {
                    SendSingleEthernetFrame(hIntf1, batchFrames[0], batchLens[0]);
                } else {
                    lock (txLock) {
                        // NDP16 length = 8-byte header + (count + 1) * 4-byte datagram descriptors (including zero terminator)
                        int ndpLen = 8 + (count + 1) * 4;
                        int dataStart = 12 + ndpLen;
                        // Align payload section to a 4-byte boundary per CDC-NCM alignment rules
                        if ((dataStart % 4) != 0) dataStart += 4 - (dataStart % 4);
                        if (dataStart > 12 + ndpLen) {
                            Array.Clear(txBuf, 12 + ndpLen, dataStart - (12 + ndpLen));
                        }

                        int curOffset = dataStart;
                        // Populate 12-byte NTH16 header ("NCMH")
                        txBuf[0] = 0x4E; txBuf[1] = 0x43; txBuf[2] = 0x4D; txBuf[3] = 0x48;
                        txBuf[4] = 12; txBuf[5] = 0;
                        txBuf[6] = (byte)(txSeq & 0xFF); txBuf[7] = (byte)((txSeq >> 8) & 0xFF);
                        txSeq++;
                        txBuf[10] = 12; txBuf[11] = 0;

                        // Populate 8-byte NDP16 header ("NCM0")
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
                        // Write 4-byte zero terminator entry at end of NDP16 datagram pointer table
                        txBuf[ndpPos] = 0; txBuf[ndpPos + 1] = 0; txBuf[ndpPos + 2] = 0; txBuf[ndpPos + 3] = 0;

                        int totalLen = curOffset;
                        // Pad exact 512-byte multiples by 4 bytes so bulk transfer finishes with a short packet
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

        /// <summary>
        /// Executes <c>%SystemRoot%\System32\netsh.exe</c> hidden with a 5,000 ms timeout, terminating the child process if it hangs.
        /// </summary>
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

        /// <summary>
        /// Removes the default route (<c>0.0.0.0/0</c> via <see cref="BridgeConfig.SharingGwIp"/>) and clears static DNS
        /// on the WinTun adapter so Windows falls back to its primary Wi-Fi/Ethernet gateway when macOS Internet Sharing is off.
        /// </summary>
        static void RemoveShareGateway() {
            string a = "\"" + Config.AdapterName + "\"";
            Netsh("interface ipv4 delete route prefix=0.0.0.0/0 interface=" + a + " nexthop=" + Config.SharingGwIp + " store=active");
            Netsh("interface ipv4 delete route prefix=0.0.0.0/0 interface=" + a + " nexthop=" + Config.SharingGwIp + " store=persistent");
            Netsh("interface ipv4 set dnsservers name=" + a + " source=static address=none register=none validate=no");
        }

        /// <summary>
        /// Assigns the dual static IPv4 addresses (<see cref="BridgeConfig.WinDirectIp"/> and <see cref="BridgeConfig.WinSharingIp"/>),
        /// interface metric 10, and scoped Windows Defender Firewall rule to the WinTun adapter on service startup.
        /// </summary>
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

        /// <summary>
        /// Background worker thread that applies or removes the macOS Internet Sharing default route (metric 5)
        /// and DNS resolvers via <c>netsh.exe</c> out-of-band so packet forwarding threads never block on OS route updates.
        /// </summary>
        static void GatewayApplyLoop() {
            string a = "\"" + Config.AdapterName + "\"";
            while (true) {
                gwApplyEvent.WaitOne();
                Thread.Sleep(300); // coalesce rapid state transitions
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

        /// <summary>
        /// Per-connection background thread that transmits an ARP Who-Has probe for <see cref="BridgeConfig.SharingGwIp"/>
        /// every <see cref="ProbeIntervalMs"/> (5,000 ms) while link generation <paramref name="gen"/> is active,
        /// disabling the sharing default route after <see cref="GatewayTimeoutSec"/> (12 s) of silence.
        /// </summary>
        static void GatewayMonitorLoop(IntPtr hIntf1, int gen) {
            byte[] req = new byte[42];
            for (int i = 0; i < 6; i++) req[i] = 0xFF;                 // Destination MAC: Ethernet broadcast
            Buffer.BlockCopy(Config.VirtualMac, 0, req, 6, 6);         // Source MAC: Windows virtual MAC
            req[12] = 0x08; req[13] = 0x06;                              // EtherType: ARP (0x0806)
            req[14] = 0x00; req[15] = 0x01; req[16] = 0x08; req[17] = 0x00; // HTYPE=1 (Ethernet), PTYPE=0x0800 (IPv4)
            req[18] = 6; req[19] = 4; req[20] = 0x00; req[21] = 0x01;    // HLEN=6, PLEN=4, OPER=1 (ARP Request)
            Buffer.BlockCopy(Config.VirtualMac, 0, req, 22, 6);        // Sender Hardware Address (SHA)
            Buffer.BlockCopy(Config.WinSharingIpBytes, 0, req, 28, 4); // Sender Protocol Address (SPA)
            Buffer.BlockCopy(Config.SharingGwIpBytes, 0, req, 38, 4);  // Target Protocol Address (TPA)

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

        /// <summary>
        /// Process entry point: loads configuration, locks DLL search order to System32, initializes the WinTun
        /// Layer-3 adapter and 4 MiB ring buffer, registers PnP arrival notifications, and manages the USB-C NCM link lifecycle.
        /// </summary>
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
            // Start WinTun ring buffer session with 4 MiB (0x400000 bytes) capacity
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
                // CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL == 0
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
                gwProbeWake.Set();
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
                    // GENERIC_READ | GENERIC_WRITE (0xC0000000), FILE_SHARE_READ | FILE_SHARE_WRITE (3), OPEN_EXISTING (3), FILE_FLAG_OVERLAPPED (0x40000000)
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
                            // CDC-NCM class request 0x80 (GET_NTB_PARAMETERS, bmRequestType 0xA1 = Device-to-Host | Class | Interface)
                            WINUSB_SETUP_PACKET pkt = new WINUSB_SETUP_PACKET { RequestType = 0xA1, Request = 0x80, Value = 0, Index = 0, Length = 28 };
                            byte[] ntbParams = new byte[28];
                            uint transferred = 0;
                            bool gotNtbParams = WinUsb_ControlTransfer(hIntf0, pkt, ntbParams, 28, out transferred, IntPtr.Zero);
                            // dwNtbInMaxSize is a 32-bit little-endian integer at byte offset 4 of NTB_PARAMETER_STRUCTURE
                            uint maxIn = (gotNtbParams && transferred >= 8) ? BitConverter.ToUInt32(ntbParams, 4) : 32764;
                            if (maxIn < 2048 || maxIn > 65536) maxIn = 32764;

                            // Open Associated Interface 0 (USB Interface 1 = CDC Data Class interface with Bulk IN 0x81 and Bulk OUT 0x01)
                            if (!WinUsb_GetAssociatedInterface(hIntf0, 0, out hIntf1) || hIntf1 == IntPtr.Zero) {
                                Thread.Sleep(1000);
                                continue;
                            }
                            // Reset CDC Data interface to Alternate Setting 0 (zero-bandwidth idle state) before configuring NTB parameters
                            WinUsb_SetCurrentAlternateSetting(hIntf1, 0);

                            // CDC-NCM class request 0x86 (SET_NTB_INPUT_SIZE, bmRequestType 0x21 = Host-to-Device | Class | Interface)
                            WINUSB_SETUP_PACKET setIn = new WINUSB_SETUP_PACKET { RequestType = 0x21, Request = 0x86, Value = 0, Index = 0, Length = 4 };
                            byte[] inSizeBuf = BitConverter.GetBytes(maxIn);
                            WinUsb_ControlTransfer(hIntf0, setIn, inSizeBuf, 4, out transferred, IntPtr.Zero);

                            // Activate Alternate Setting 1 on CDC Data interface to enable Bulk IN (0x81) and Bulk OUT (0x01) endpoints
                            if (!WinUsb_SetCurrentAlternateSetting(hIntf1, 1)) {
                                Thread.Sleep(1000);
                                continue;
                            }
                            // CDC-ECM/NCM class request 0x43 (SET_ETHERNET_PACKET_FILTER, wValue = 0x000F: Promiscuous | AllMulticast | Directed | Broadcast)
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
