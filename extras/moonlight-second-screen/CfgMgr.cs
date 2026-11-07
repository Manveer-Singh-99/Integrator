using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32;

public class CfgMgr
{
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern int CM_Locate_DevNodeW(out uint pdnDevInst, string pDeviceID, int ulFlags);

    [DllImport("cfgmgr32.dll")]
    public static extern int CM_Get_DevNode_Status(out uint pulStatus, out uint pulProblemNumber, uint dnDevInst, int ulFlags);

    [StructLayout(LayoutKind.Sequential)]
    public struct DEVPROPKEY
    {
        public Guid fmtid;
        public uint pid;
    }

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    public static extern int CM_Get_DevNode_PropertyW(
        uint dnDevInst,
        ref DEVPROPKEY PropertyKey,
        out uint PropertyType,
        byte[] PropertyBuffer,
        ref uint PropertyBufferSize,
        uint ulFlags);

    public static bool IsDeviceStarted(string instanceId)
    {
        uint devInst;
        if (CM_Locate_DevNodeW(out devInst, instanceId, 0) != 0)
            return false;
        uint status, problem;
        if (CM_Get_DevNode_Status(out status, out problem, devInst, 0) != 0)
            return false;
        return (status & 0x08) != 0; // DN_STARTED
    }

    public static string GetBusReportedDeviceDesc(string instanceId)
    {
        uint devInst;
        if (CM_Locate_DevNodeW(out devInst, instanceId, 0) != 0)
            return "";
        DEVPROPKEY key = new DEVPROPKEY();
        key.fmtid = new Guid("540b947e-8b40-45bc-a8a2-6a0b894cbda2");
        key.pid = 4; // DEVPKEY_Device_BusReportedDeviceDesc
        uint propType = 0;
        byte[] buf = new byte[512];
        uint size = (uint)buf.Length;
        if (CM_Get_DevNode_PropertyW(devInst, ref key, out propType, buf, ref size, 0) == 0 && size > 2)
        {
            return Encoding.Unicode.GetString(buf, 0, (int)size).TrimEnd('\0');
        }
        return "";
    }

    public static bool IsAppleUsbNcmStarted()
    {
        try
        {
            using (RegistryKey k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB\VID_05AC&PID_1902"))
            {
                if (k == null) return false;
                foreach (string sub in k.GetSubKeyNames())
                {
                    if (IsDeviceStarted(@"USB\VID_05AC&PID_1902\" + sub))
                        return true;
                }
            }
        }
        catch { }
        return false;
    }

    public static bool IsAppleIpadUsbConnected()
    {
        try
        {
            using (RegistryKey usbKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB"))
            {
                if (usbKey == null) return false;
                foreach (string sub in usbKey.GetSubKeyNames())
                {
                    if (!sub.StartsWith("VID_05AC&PID_", StringComparison.OrdinalIgnoreCase))
                        continue;
                    // Skip Mac USB-C NCM (1902), USB-C Headphone Adapter (110A), and Apple HID (0421)
                    if (sub.IndexOf("PID_1902", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        sub.IndexOf("PID_110A", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        sub.IndexOf("PID_0421", StringComparison.OrdinalIgnoreCase) >= 0)
                        continue;

                    using (RegistryKey pidKey = usbKey.OpenSubKey(sub))
                    {
                        if (pidKey == null) continue;
                        foreach (string inst in pidKey.GetSubKeyNames())
                        {
                            string fullId = @"USB\" + sub + @"\" + inst;
                            if (!IsDeviceStarted(fullId)) continue;

                            // Dedicated iPad USB-C Product IDs
                            if (sub.IndexOf("PID_12AB", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                sub.IndexOf("PID_12AF", StringComparison.OrdinalIgnoreCase) >= 0)
                                return true;

                            string busDesc = GetBusReportedDeviceDesc(fullId);
                            if (busDesc.IndexOf("iPad", StringComparison.OrdinalIgnoreCase) >= 0)
                                return true;

                            using (RegistryKey instKey = pidKey.OpenSubKey(inst))
                            {
                                if (instKey != null)
                                {
                                    string fn = Convert.ToString(instKey.GetValue("FriendlyName") ?? "");
                                    string dd = Convert.ToString(instKey.GetValue("DeviceDesc") ?? "");
                                    if (fn.IndexOf("iPad", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                        dd.IndexOf("iPad", StringComparison.OrdinalIgnoreCase) >= 0)
                                        return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        catch { }
        return false;
    }

    public static bool TestTcpPort(string ip, int port, int timeoutMs)
    {
        if (string.IsNullOrEmpty(ip)) return false;
        try
        {
            using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                IAsyncResult ar = sock.BeginConnect(ip, port, null, null);
                if (ar.AsyncWaitHandle.WaitOne(timeoutMs))
                {
                    sock.EndConnect(ar);
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    public static bool ProbeHostAlive(string ip, int port, int timeoutMs)
    {
        if (string.IsNullOrEmpty(ip)) return false;
        try
        {
            using (Ping p = new Ping())
            {
                PingReply r = p.Send(ip, timeoutMs);
                if (r != null && r.Status == IPStatus.Success)
                    return true;
            }
        }
        catch { }

        // Even if ICMP is ignored, an awake iPad/Mac immediately replies with SYN-ACK or RST (ConnectionRefused)
        try
        {
            using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                IAsyncResult ar = sock.BeginConnect(ip, port, null, null);
                if (ar.AsyncWaitHandle.WaitOne(timeoutMs))
                {
                    try
                    {
                        sock.EndConnect(ar);
                        return true;
                    }
                    catch (SocketException se)
                    {
                        if (se.SocketErrorCode == SocketError.ConnectionRefused)
                            return true;
                    }
                }
            }
        }
        catch { }
        return false;
    }

    public static string GetLocalIpForRemote(string remoteIp)
    {
        try
        {
            using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                s.Connect(remoteIp, 9);
                IPEndPoint ep = s.LocalEndPoint as IPEndPoint;
                if (ep != null) return ep.Address.ToString();
            }
        }
        catch { }
        return "";
    }

    public static string GetSunshinePeerExcluding(string[] excludeIps)
    {
        try
        {
            HashSet<string> excl = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            excl.Add("127.0.0.1");
            excl.Add("0.0.0.0");
            if (excludeIps != null)
            {
                foreach (string e in excludeIps)
                {
                    if (!string.IsNullOrEmpty(e)) excl.Add(e);
                }
            }

            IPGlobalProperties props = IPGlobalProperties.GetIPGlobalProperties();
            TcpConnectionInformation[] conns = props.GetActiveTcpConnections();
            HashSet<string> candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (TcpConnectionInformation c in conns)
            {
                int lp = c.LocalEndPoint.Port;
                if (lp == 47984 || lp == 47989 || lp == 47990 || lp == 48010)
                {
                    if (c.RemoteEndPoint.AddressFamily == AddressFamily.InterNetwork)
                    {
                        string rip = c.RemoteEndPoint.Address.ToString();
                        if (!excl.Contains(rip))
                            candidates.Add(rip);
                    }
                }
            }

            foreach (string cand in candidates)
            {
                if (ProbeHostAlive(cand, 62078, 90))
                    return cand;
            }
        }
        catch { }
        return "";
    }

    public static string QueryMdnsHosts(string[] hostnames, int timeoutMs)
    {
        try
        {
            IPEndPoint mcast = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
            List<byte[]> queries = new List<byte[]>();
            foreach (string hostname in hostnames)
            {
                string clean = hostname.TrimEnd('.');
                string[] labels = clean.Split('.');
                List<byte> pkt = new List<byte>();
                pkt.AddRange(new byte[] { 0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                foreach (string lbl in labels)
                {
                    byte[] lb = Encoding.ASCII.GetBytes(lbl);
                    pkt.Add((byte)lb.Length);
                    pkt.AddRange(lb);
                }
                pkt.Add(0x00);
                pkt.AddRange(new byte[] { 0x00, 0x01, 0x80, 0x01 });
                queries.Add(pkt.ToArray());
            }

            List<Socket> sockets = new List<Socket>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;
                    foreach (UnicastIPAddressInformation ua in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        try
                        {
                            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                            s.Bind(new IPEndPoint(ua.Address, 0));
                            foreach (byte[] q in queries)
                                s.SendTo(q, mcast);
                            sockets.Add(s);
                        }
                        catch { }
                    }
                }

                Stopwatch sw = Stopwatch.StartNew();
                byte[] buf = new byte[1024];
                while (sw.ElapsedMilliseconds < timeoutMs && sockets.Count > 0)
                {
                    List<Socket> readList = new List<Socket>(sockets);
                    int remainUs = (int)Math.Max(5000, (timeoutMs - sw.ElapsedMilliseconds) * 1000);
                    Socket.Select(readList, null, null, remainUs);
                    foreach (Socket rs in readList)
                    {
                        int n = rs.Receive(buf);
                        if (n >= 16)
                        {
                            for (int i = 12; i <= n - 14; i++)
                            {
                                if (buf[i] == 0x00 && buf[i + 1] == 0x01 &&
                                    (buf[i + 2] == 0x80 || buf[i + 2] == 0x00) && buf[i + 3] == 0x01 &&
                                    buf[i + 8] == 0x00 && buf[i + 9] == 0x04)
                                {
                                    string ip = string.Format("{0}.{1}.{2}.{3}", buf[i + 10], buf[i + 11], buf[i + 12], buf[i + 13]);
                                    if (!ip.StartsWith("127.") && !ip.StartsWith("169.254."))
                                        return ip;
                                }
                            }
                        }
                    }
                }
            }
            finally
            {
                foreach (Socket s in sockets)
                {
                    try { s.Close(); } catch { }
                }
            }
        }
        catch { }
        return "";
    }

    public static string QueryMdnsHost(string hostname, int timeoutMs)
    {
        return QueryMdnsHosts(new string[] { hostname }, timeoutMs);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
        public uint remoteAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] remotePort;
        public uint owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);

    public static bool IsLocalPortListening(int port)
    {
        try
        {
            IPGlobalProperties props = IPGlobalProperties.GetIPGlobalProperties();
            foreach (IPEndPoint ep in props.GetActiveTcpListeners())
            {
                if (ep.Port == port) return true;
            }
        }
        catch { }
        return false;
    }

    public static void StopProcessOnPort(int localPort)
    {
        int bufLen = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufLen, false, 2, 3, 0); // AF_INET=2, TCP_TABLE_OWNER_PID_LISTENER=3
        if (bufLen <= 0) return;
        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufLen);
        try
        {
            if (GetExtendedTcpTable(tcpTablePtr, ref bufLen, false, 2, 3, 0) == 0)
            {
                int numEntries = Marshal.ReadInt32(tcpTablePtr);
                IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
                int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                for (int i = 0; i < numEntries; i++)
                {
                    MIB_TCPROW_OWNER_PID row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                    int p = (row.localPort[0] << 8) | row.localPort[1];
                    if (p == localPort && row.owningPid > 0)
                    {
                        try
                        {
                            Process proc = Process.GetProcessById((int)row.owningPid);
                            proc.Kill();
                        }
                        catch { }
                    }
                    rowPtr = (IntPtr)((long)rowPtr + rowSize);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tcpTablePtr);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DISPLAY_DEVICEW
    {
        public int cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
        public int StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DEVMODEW
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
        public short dmSpecVersion;
        public short dmDriverVersion;
        public short dmSize;
        public short dmDriverExtra;
        public int dmFields;
        public int dmPositionX;
        public int dmPositionY;
        public int dmDisplayOrientation;
        public int dmDisplayFixedOutput;
        public short dmColor;
        public short dmDuplex;
        public short dmYResolution;
        public short dmTTOption;
        public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
        public short dmLogPixels;
        public int dmBitsPerPel;
        public int dmPelsWidth;
        public int dmPelsHeight;
        public int dmDisplayFlags;
        public int dmDisplayFrequency;
        public int dmICMMethod;
        public int dmICMIntent;
        public int dmMediaType;
        public int dmDitherType;
        public int dmReserved1;
        public int dmReserved2;
        public int dmPanningWidth;
        public int dmPanningHeight;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern bool EnumDisplayDevicesW(string lpDevice, uint iDevNum, ref DISPLAY_DEVICEW lpDisplayDevice, uint dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern bool EnumDisplaySettingsExW(string lpszDeviceName, int iModeNum, ref DEVMODEW lpDevMode, int dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int ChangeDisplaySettingsExW(string lpszDeviceName, ref DEVMODEW lpDevMode, IntPtr hwnd, uint dwFlags, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int ChangeDisplaySettingsExW(string lpszDeviceName, IntPtr lpDevMode, IntPtr hwnd, uint dwFlags, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int SetDisplayConfig(uint numPathArrayElements, IntPtr pathArray, uint numModeInfoArrayElements, IntPtr modeInfoArray, uint flags);

    public static string ConfigureVirtualDisplays(int expectedCount, int w1, int h1, int w2, int h2)
    {
        List<string> vdds = new List<string>();
        bool needExtend = false;

        for (int attempt = 0; attempt < 25; attempt++)
        {
            vdds.Clear();
            needExtend = false;
            uint idx = 0;
            while (true)
            {
                DISPLAY_DEVICEW dd = new DISPLAY_DEVICEW();
                dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICEW));
                if (!EnumDisplayDevicesW(null, idx, ref dd, 0)) break;
                idx++;
                if (dd.DeviceString != null && dd.DeviceString.IndexOf("Virtual Display Driver", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if ((dd.StateFlags & 1) == 0)
                        needExtend = true;
                    vdds.Add(dd.DeviceName);
                }
            }
            if (vdds.Count >= expectedCount)
                break;
            Thread.Sleep(80);
        }

        if (needExtend)
        {
            SetDisplayConfig(0, IntPtr.Zero, 0, IntPtr.Zero, 0x00000004 | 0x00000080); // SDC_TOPOLOGY_EXTEND | SDC_APPLY
            Thread.Sleep(250);
        }

        vdds.Sort((a, b) =>
        {
            int na = 0, nb = 0;
            int.TryParse(a.Replace(@"\\.\DISPLAY", ""), out na);
            int.TryParse(b.Replace(@"\\.\DISPLAY", ""), out nb);
            return na.CompareTo(nb);
        });

        int curX = 1920;
        for (int i = 0; i < vdds.Count && i < expectedCount; i++)
        {
            int targetW = (i == 0) ? w1 : w2;
            int targetH = (i == 0) ? h1 : h2;
            if (targetW <= 0 || targetH <= 0) break;

            DEVMODEW dm = new DEVMODEW();
            dm.dmSize = (short)Marshal.SizeOf(typeof(DEVMODEW));
            if (EnumDisplaySettingsExW(vdds[i], -1, ref dm, 0))
            {
                dm.dmPelsWidth = targetW;
                dm.dmPelsHeight = targetH;
                dm.dmDisplayFrequency = 60;
                dm.dmPositionX = curX;
                dm.dmPositionY = 0;
                dm.dmFields = 0x00000020 | 0x00080000 | 0x00100000 | 0x00400000;
                ChangeDisplaySettingsExW(vdds[i], ref dm, IntPtr.Zero, 0x00000001 | 0x10000000, IntPtr.Zero);
                curX += targetW;
            }
        }
        ChangeDisplaySettingsExW(null, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero);
        return string.Join(",", vdds.ToArray());
    }
}
