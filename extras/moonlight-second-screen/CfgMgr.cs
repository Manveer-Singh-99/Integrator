using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
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

    public static bool HasActiveNonUsbStream(int basePort)
    {
        try
        {
            int httpsPort = basePort - 5;
            int rtspPort = basePort + 21;
            IPGlobalProperties props = IPGlobalProperties.GetIPGlobalProperties();
            TcpConnectionInformation[] conns = props.GetActiveTcpConnections();
            foreach (TcpConnectionInformation c in conns)
            {
                int lp = c.LocalEndPoint.Port;
                if (lp == basePort || lp == httpsPort || lp == rtspPort)
                {
                    string lip = c.LocalEndPoint.Address.ToString();
                    if (!lip.StartsWith("10.99.99.") && !lip.StartsWith("192.168.2.") && !lip.StartsWith("127."))
                        return true;
                }
            }
        }
        catch { }
        return false;
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

    public static int GetAttachedVirtualDisplayCount()
    {
        int count = 0;
        uint idx = 0;
        while (true)
        {
            DISPLAY_DEVICEW dd = new DISPLAY_DEVICEW();
            dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICEW));
            if (!EnumDisplayDevicesW(null, idx, ref dd, 0)) break;
            idx++;
            if (dd.DeviceString != null && dd.DeviceString.IndexOf("Virtual Display Driver", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                if ((dd.StateFlags & 1) != 0)
                    count++;
            }
        }
        return count;
    }

    private static void GetVirtualDisplayInfo(out List<DISPLAY_DEVICEW> vdds, out int primaryWidth)
    {
        vdds = new List<DISPLAY_DEVICEW>();
        primaryWidth = 1920;
        uint idx = 0;
        while (true)
        {
            DISPLAY_DEVICEW dd = new DISPLAY_DEVICEW();
            dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICEW));
            if (!EnumDisplayDevicesW(null, idx, ref dd, 0)) break;
            idx++;
            if ((dd.StateFlags & 4) != 0) // DISPLAY_DEVICE_PRIMARY_DEVICE
            {
                DEVMODEW pdm = new DEVMODEW();
                pdm.dmSize = (short)Marshal.SizeOf(typeof(DEVMODEW));
                if (EnumDisplaySettingsExW(dd.DeviceName, -1, ref pdm, 0) && pdm.dmPelsWidth > 0)
                    primaryWidth = pdm.dmPelsWidth;
            }
            if (dd.DeviceString != null && dd.DeviceString.IndexOf("Virtual Display Driver", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                vdds.Add(dd);
            }
        }
        vdds.Sort((a, b) =>
        {
            int na = 0, nb = 0;
            int.TryParse(a.DeviceName.Replace(@"\\.\DISPLAY", ""), out na);
            int.TryParse(b.DeviceName.Replace(@"\\.\DISPLAY", ""), out nb);
            return na.CompareTo(nb);
        });
    }

    private static void StageDetachDisplay(string devName)
    {
        DEVMODEW dm = new DEVMODEW();
        dm.dmSize = (short)Marshal.SizeOf(typeof(DEVMODEW));
        dm.dmPelsWidth = 0;
        dm.dmPelsHeight = 0;
        dm.dmFields = 0x00000020 | 0x00080000 | 0x00100000; // DM_POSITION | DM_PELSWIDTH | DM_PELSHEIGHT
        ChangeDisplaySettingsExW(devName, ref dm, IntPtr.Zero, 0x00000001 | 0x10000000, IntPtr.Zero);
    }

    private static void StageAttachDisplay(string devName, int posX, int posY, int width, int height, int hz)
    {
        DEVMODEW dm = new DEVMODEW();
        dm.dmSize = (short)Marshal.SizeOf(typeof(DEVMODEW));
        if (!EnumDisplaySettingsExW(devName, -1, ref dm, 0))
        {
            EnumDisplaySettingsExW(devName, 0, ref dm, 0);
        }
        dm.dmPositionX = posX;
        dm.dmPositionY = posY;
        dm.dmPelsWidth = width;
        dm.dmPelsHeight = height;
        dm.dmBitsPerPel = 32;
        dm.dmDisplayFrequency = hz;
        dm.dmFields = 0x00000020 | 0x00040000 | 0x00080000 | 0x00100000 | 0x00400000;
        ChangeDisplaySettingsExW(devName, ref dm, IntPtr.Zero, 0x00000001 | 0x10000000, IntPtr.Zero);
    }

    // Dynamic per-slot display allocator:
    //   - Slot 0 (vdds[0], {5eb52002-...}): iPad 2360x1640 @ 60Hz (Primary Sunshine :47989)
    //   - Slot 1 (vdds[1], {456a3c17-...}): Mac  2560x1600 @ 60Hz (Secondary Sunshine :48989)
    public static string SyncVirtualDisplays(bool slot0Active, bool slot1Active)
    {
        bool locked = false;
        Mutex mtx = null;
        try
        {
            mtx = new Mutex(false, @"Local\VddSyncDisplayMutex");
            try { locked = mtx.WaitOne(3000); } catch (AbandonedMutexException) { locked = true; }

            List<DISPLAY_DEVICEW> vdds;
            int primaryW;
            GetVirtualDisplayInfo(out vdds, out primaryW);

            if ((slot0Active || slot1Active) && vdds.Count < 2 && IsDeviceStarted(@"ROOT\DISPLAY\0001"))
            {
                for (int attempt = 0; attempt < 25; attempt++)
                {
                    Thread.Sleep(80);
                    GetVirtualDisplayInfo(out vdds, out primaryW);
                    if (vdds.Count >= 2) break;
                }
            }

            if (vdds.Count == 0)
                return "none";

            if (vdds.Count == 1)
            {
                bool want = slot0Active || slot1Active;
                int tw = slot1Active ? 2560 : 2360;
                int th = slot1Active ? 1600 : 1640;
                bool att = (vdds[0].StateFlags & 1) != 0;
                DEVMODEW c0 = new DEVMODEW();
                c0.dmSize = (short)Marshal.SizeOf(typeof(DEVMODEW));
                bool ok0 = att && EnumDisplaySettingsExW(vdds[0].DeviceName, -1, ref c0, 0);
                if (!want && !att) return "noop";
                if (want && ok0 && c0.dmPelsWidth == tw && c0.dmPelsHeight == th && c0.dmPositionX == primaryW && c0.dmPositionY == 0)
                    return "noop";
                if (want) StageAttachDisplay(vdds[0].DeviceName, primaryW, 0, tw, th, 60);
                else StageDetachDisplay(vdds[0].DeviceName);
                ChangeDisplaySettingsExW(null, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero);
                return vdds[0].DeviceName;
            }

            bool att0 = (vdds[0].StateFlags & 1) != 0;
            bool att1 = (vdds[1].StateFlags & 1) != 0;

            DEVMODEW dm0 = new DEVMODEW();
            dm0.dmSize = (short)Marshal.SizeOf(typeof(DEVMODEW));
            bool okCur0 = att0 && EnumDisplaySettingsExW(vdds[0].DeviceName, -1, ref dm0, 0);

            DEVMODEW dm1 = new DEVMODEW();
            dm1.dmSize = (short)Marshal.SizeOf(typeof(DEVMODEW));
            bool okCur1 = att1 && EnumDisplaySettingsExW(vdds[1].DeviceName, -1, ref dm1, 0);

            int targetX0 = primaryW;
            int targetX1 = primaryW;

            if (slot0Active && slot1Active)
            {
                // Preserve (primaryW, 0) for whichever display is already positioned at primaryW so active windows never jump
                if (okCur1 && dm1.dmPositionX == primaryW && (!okCur0 || dm0.dmPositionX != primaryW))
                {
                    targetX1 = primaryW;
                    targetX0 = primaryW + 2560;
                }
                else
                {
                    targetX0 = primaryW;
                    targetX1 = primaryW + 2360;
                }
            }

            bool need0 = (slot0Active != att0) || (slot0Active && (!okCur0 || dm0.dmPelsWidth != 2360 || dm0.dmPelsHeight != 1640 || dm0.dmPositionX != targetX0 || dm0.dmPositionY != 0));
            bool need1 = (slot1Active != att1) || (slot1Active && (!okCur1 || dm1.dmPelsWidth != 2560 || dm1.dmPelsHeight != 1600 || dm1.dmPositionX != targetX1 || dm1.dmPositionY != 0));

            if (!need0 && !need1)
                return "noop";

            if (!slot0Active && att0)
                StageDetachDisplay(vdds[0].DeviceName);
            if (!slot1Active && att1)
                StageDetachDisplay(vdds[1].DeviceName);

            if (slot0Active)
                StageAttachDisplay(vdds[0].DeviceName, targetX0, 0, 2360, 1640, 60);
            if (slot1Active)
                StageAttachDisplay(vdds[1].DeviceName, targetX1, 0, 2560, 1600, 60);

            ChangeDisplaySettingsExW(null, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero);

            // Verify attachment; if a brand-new virtual connector has never been in CCD topology, extend once and re-stage
            GetVirtualDisplayInfo(out vdds, out primaryW);
            if (vdds.Count >= 2)
            {
                bool nowAtt0 = (vdds[0].StateFlags & 1) != 0;
                bool nowAtt1 = (vdds[1].StateFlags & 1) != 0;
                if ((slot0Active && !nowAtt0) || (slot1Active && !nowAtt1))
                {
                    SetDisplayConfig(0, IntPtr.Zero, 0, IntPtr.Zero, 0x00000004 | 0x00000080); // SDC_TOPOLOGY_EXTEND | SDC_APPLY
                    Thread.Sleep(200);
                    if (!slot0Active) StageDetachDisplay(vdds[0].DeviceName);
                    else StageAttachDisplay(vdds[0].DeviceName, targetX0, 0, 2360, 1640, 60);
                    if (!slot1Active) StageDetachDisplay(vdds[1].DeviceName);
                    else StageAttachDisplay(vdds[1].DeviceName, targetX1, 0, 2560, 1600, 60);
                    ChangeDisplaySettingsExW(null, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero);
                }
            }

            return string.Format("slot0={0}@{1},slot1={2}@{3}", slot0Active, targetX0, slot1Active, targetX1);
        }
        finally
        {
            if (locked && mtx != null)
            {
                try { mtx.ReleaseMutex(); } catch { }
            }
            if (mtx != null)
            {
                try { mtx.Dispose(); } catch { }
            }
        }
    }

    public static string ConfigureVirtualDisplays(int expectedCount, int w1, int h1, int w2, int h2)
    {
        if (expectedCount >= 2 && w1 > 0 && w2 > 0)
            return SyncVirtualDisplays(true, true);
        if (expectedCount == 1 && w1 == 2560)
            return SyncVirtualDisplays(false, true);
        if (expectedCount == 1 && w1 == 2360)
            return SyncVirtualDisplays(true, false);
        return SyncVirtualDisplays(false, false);
    }

    private static DateTime ParseSunshineLogTimestamp(string line)
    {
        // Format: [2026-11-08 03:30:19.535]: ...
        if (line != null && line.Length >= 25 && line[0] == '[' && line[24] == ']')
        {
            DateTime dt;
            if (DateTime.TryParseExact(line.Substring(1, 23), "yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out dt))
                return dt;
        }
        return DateTime.MinValue;
    }

    private static long[] _lastLogLen = new long[] { -1, -1 };
    private static DateTime[] _lastLogWriteUtc = new DateTime[] { DateTime.MinValue, DateTime.MinValue };
    private static bool[] _lastSlotResult = new bool[] { false, false };

    public static bool IsSlotStreaming(int slot)
    {
        int idx = (slot == 0) ? 0 : 1;
        int port = (idx == 0) ? 47989 : 48989;
        string logPath = (idx == 0)
            ? @"C:\Program Files\Sunshine\config\sunshine.log"
            : @"C:\Program Files\Sunshine\config\sunshine_mac2.log";
        string stampFile = (idx == 0)
            ? @"C:\VirtualDisplayDriver\slot0_join.stamp"
            : @"C:\VirtualDisplayDriver\slot1_join.stamp";

        if (!IsLocalPortListening(port))
        {
            _lastLogLen[idx] = -1;
            _lastSlotResult[idx] = false;
            return false;
        }

        DateTime stampLocalTime = DateTime.MinValue;
        bool hasFreshStamp = false;
        try
        {
            if (File.Exists(stampFile))
            {
                stampLocalTime = File.GetLastWriteTime(stampFile);
                double ageSec = (DateTime.Now - stampLocalTime).TotalSeconds;
                if (ageSec >= 0 && ageSec < 18.0)
                    hasFreshStamp = true;
                else
                    File.Delete(stampFile);
            }
        }
        catch { }

        try
        {
            FileInfo fi = new FileInfo(logPath);
            if (!fi.Exists)
                return hasFreshStamp;

            if (!hasFreshStamp && _lastLogLen[idx] == fi.Length && _lastLogWriteUtc[idx] == fi.LastWriteTimeUtc)
                return _lastSlotResult[idx];

            string content = "";
            using (FileStream fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
            {
                content = sr.ReadToEnd();
            }

            int startIdx = content.LastIndexOf("Info: Sunshine version:", StringComparison.Ordinal);
            if (startIdx > 0)
            {
                int lineStart = content.LastIndexOf('\n', startIdx);
                startIdx = (lineStart >= 0) ? lineStart + 1 : 0;
                content = content.Substring(startIdx);
            }

            int state = 0; // 0 = disconnected, 1 = launching, 2 = connected
            DateTime lastLaunchTime = DateTime.MinValue;
            DateTime lastDisconnectTime = DateTime.MinValue;

            string[] lines = content.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string line in lines)
            {
                if (line.IndexOf("Scheduling display device configuration:", StringComparison.Ordinal) >= 0 ||
                    line.IndexOf("Display device configuration applied successfully.", StringComparison.Ordinal) >= 0 ||
                    line.IndexOf("Executing [Desktop]", StringComparison.Ordinal) >= 0 ||
                    line.IndexOf("Executing Do Cmd:", StringComparison.Ordinal) >= 0)
                {
                    if (state != 2)
                        state = 1;
                    DateTime ts = ParseSunshineLogTimestamp(line);
                    if (ts != DateTime.MinValue)
                        lastLaunchTime = ts;
                }
                else if (line.IndexOf("Info: CLIENT CONNECTED", StringComparison.Ordinal) >= 0)
                {
                    state = 2;
                }
                else if (line.IndexOf("Info: CLIENT DISCONNECTED", StringComparison.Ordinal) >= 0 ||
                         line.IndexOf("Info: Process terminated", StringComparison.Ordinal) >= 0 ||
                         line.IndexOf("Failed to initialize video capture", StringComparison.Ordinal) >= 0 ||
                         line.IndexOf("Failed to start the specified application", StringComparison.Ordinal) >= 0)
                {
                    state = 0;
                    DateTime ts = ParseSunshineLogTimestamp(line);
                    if (ts != DateTime.MinValue)
                        lastDisconnectTime = ts;
                }
            }

            bool res = false;
            if (state == 2)
            {
                res = true;
            }
            else if (state == 1)
            {
                if (lastLaunchTime != DateTime.MinValue && Math.Abs((DateTime.Now - lastLaunchTime).TotalSeconds) < 20.0)
                    res = true;
                else if (hasFreshStamp)
                    res = true;
            }
            else if (state == 0 && hasFreshStamp)
            {
                if (lastDisconnectTime != DateTime.MinValue && lastDisconnectTime >= stampLocalTime.AddMilliseconds(-200))
                {
                    try { File.Delete(stampFile); } catch { }
                    res = false;
                }
                else
                {
                    res = true;
                }
            }

            if (state != 1 && !hasFreshStamp)
            {
                _lastLogLen[idx] = fi.Length;
                _lastLogWriteUtc[idx] = fi.LastWriteTimeUtc;
                _lastSlotResult[idx] = res;
            }
            return res;
        }
        catch { }

        return false;
    }

    public static void PostSunshineApi(int webPort, string path)
    {
        try
        {
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(string.Format("https://localhost:{0}{1}", webPort, path));
            req.Method = "POST";
            req.ContentType = "application/json";
            req.Timeout = 1200;
            req.ReadWriteTimeout = 1200;
            string auth = Convert.ToBase64String(Encoding.ASCII.GetBytes("admin:alpine"));
            req.Headers["Authorization"] = "Basic " + auth;
            using (Stream s = req.GetRequestStream())
            {
                byte[] body = Encoding.UTF8.GetBytes("{}");
                s.Write(body, 0, body.Length);
            }
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse()) { }
        }
        catch { }
    }

    public static void ResetSunshinePersistence(int webPort)
    {
        PostSunshineApi(webPort, "/api/reset-display-device-persistence");
    }

    public static void CloseSunshineApp(int webPort)
    {
        PostSunshineApi(webPort, "/api/apps/close");
    }

    public static void WriteJoinStamp(int slot)
    {
        string stampFile = (slot == 0)
            ? @"C:\VirtualDisplayDriver\slot0_join.stamp"
            : @"C:\VirtualDisplayDriver\slot1_join.stamp";
        try
        {
            File.WriteAllText(stampFile, DateTime.UtcNow.Ticks.ToString());
        }
        catch { }
    }

    public static void DeleteJoinStamp(int slot)
    {
        string stampFile = (slot == 0)
            ? @"C:\VirtualDisplayDriver\slot0_join.stamp"
            : @"C:\VirtualDisplayDriver\slot1_join.stamp";
        try
        {
            if (File.Exists(stampFile))
                File.Delete(stampFile);
        }
        catch { }
    }

    public static void RunSchtasks(string args)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe", args);
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            using (Process p = Process.Start(psi))
            {
                if (p != null) p.WaitForExit(3000);
            }
        }
        catch { }
    }

    public static void EnsureSecondarySunshineReady()
    {
        try
        {
            string logPath = @"C:\Program Files\Sunshine\config\sunshine_mac2.log";
            bool listening = IsLocalPortListening(48989);
            bool hasEnsureActive = false;
            if (listening && File.Exists(logPath))
            {
                using (FileStream fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                {
                    string txt = sr.ReadToEnd();
                    int idx = txt.LastIndexOf("Info: Sunshine version:", StringComparison.Ordinal);
                    if (idx >= 0) txt = txt.Substring(idx);
                    if (txt.IndexOf("'dd_configuration_option' = ensure_active", StringComparison.Ordinal) >= 0)
                        hasEnsureActive = true;
                }
            }

            if (!listening || !hasEnsureActive)
            {
                if (listening)
                {
                    RunSchtasks("/End /TN \"SunshineSecondary\"");
                    StopProcessOnPort(48989);
                    StopProcessOnPort(48990);
                    Thread.Sleep(300);
                }
                RunSchtasks("/Run /TN \"SunshineSecondary\"");
            }
        }
        catch { }
    }

    private static void LaunchMacStreamOverSsh(string pcIp, string macIp)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = @"C:\Windows\System32\OpenSSH\ssh.exe";
            psi.Arguments = string.Format("-i \"C:\\Users\\Manveer Singh\\.ssh\\id_ed25519\" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no manveersingh@{0} \"/usr/local/bin/stream-pc-screen.sh {1} 48989\"", macIp, pcIp);
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            Process.Start(psi);
        }
        catch { }
    }

    public static void RunDaemon()
    {
        bool createdNew = false;
        using (Mutex daemonMtx = new Mutex(true, @"Local\VddDynamicWatcherMutex", out createdNew))
        {
            if (!createdNew)
                return;

            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            AutoResetEvent wakeEvent = new AutoResetEvent(false);
            FileSystemWatcher fsw = null;
            FileSystemWatcher fswStamp = null;
            try
            {
                string cfgDir = @"C:\Program Files\Sunshine\config";
                if (Directory.Exists(cfgDir))
                {
                    fsw = new FileSystemWatcher(cfgDir, "sunshine*.log");
                    fsw.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName;
                    FileSystemEventHandler onFs = delegate { try { wakeEvent.Set(); } catch { } };
                    fsw.Changed += onFs;
                    fsw.Created += onFs;
                    fsw.EnableRaisingEvents = true;
                }
                string vddDir = @"C:\VirtualDisplayDriver";
                if (Directory.Exists(vddDir))
                {
                    fswStamp = new FileSystemWatcher(vddDir, "*.stamp");
                    fswStamp.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName;
                    FileSystemEventHandler onSt = delegate { try { wakeEvent.Set(); } catch { } };
                    fswStamp.Changed += onSt;
                    fswStamp.Created += onSt;
                    fswStamp.Deleted += onSt;
                    fswStamp.EnableRaisingEvents = true;
                }
            }
            catch { }

            NetworkAddressChangedEventHandler onNet = delegate { try { wakeEvent.Set(); } catch { } };
            NetworkChange.NetworkAddressChanged += onNet;

            try
            {
                bool prevS0 = IsSlotStreaming(0);
                bool prevS1 = IsSlotStreaming(1);
                bool prevUsbNcm = IsAppleUsbNcmStarted();

                SyncVirtualDisplays(prevS0, prevS1);

                while (IsDeviceStarted(@"ROOT\DISPLAY\0001"))
                {
                    bool signaled = wakeEvent.WaitOne(2500);
                    if (!IsDeviceStarted(@"ROOT\DISPLAY\0001"))
                        break;

                    bool curUsbNcm = IsAppleUsbNcmStarted();
                    if (prevUsbNcm && !curUsbNcm)
                    {
                        // Physical USB-C cable unplugged from Mac
                        prevUsbNcm = false;
                        if (prevS1 && !HasActiveNonUsbStream(48989))
                        {
                            DeleteJoinStamp(1);
                            ResetSunshinePersistence(48990);
                            CloseSunshineApp(48990);
                            prevS1 = false;
                            SyncVirtualDisplays(IsSlotStreaming(0), false);
                            EnsureSecondarySunshineReady();
                        }
                    }
                    else if (!prevUsbNcm && curUsbNcm)
                    {
                        // Physical USB-C cable plugged into Mac -> dynamically allocate Mac display & launch Moonlight
                        prevUsbNcm = true;
                        string pcUsbIp = "";
                        string macUsbIp = "";
                        for (int retry = 0; retry < 16; retry++)
                        {
                            if (!IsAppleUsbNcmStarted()) break;
                            if (ProbeHostAlive("10.99.99.2", 22, 120))
                            {
                                pcUsbIp = "10.99.99.1";
                                macUsbIp = "10.99.99.2";
                                break;
                            }
                            if (ProbeHostAlive("192.168.2.1", 22, 120))
                            {
                                pcUsbIp = "192.168.2.2";
                                macUsbIp = "192.168.2.1";
                                break;
                            }
                            Thread.Sleep(250);
                        }
                        if (!string.IsNullOrEmpty(macUsbIp))
                        {
                            EnsureSecondarySunshineReady();
                            WriteJoinStamp(1);
                            prevS1 = true;
                            SyncVirtualDisplays(IsSlotStreaming(0), true);
                            LaunchMacStreamOverSsh(pcUsbIp, macUsbIp);
                        }
                    }

                    bool curS0 = IsSlotStreaming(0);
                    if (!prevS0 && curS0)
                    {
                        prevS0 = true;
                        ResetSunshinePersistence(47990);
                        SyncVirtualDisplays(true, IsSlotStreaming(1));
                    }
                    else if (prevS0 && !curS0)
                    {
                        Thread.Sleep(400);
                        curS0 = IsSlotStreaming(0);
                        if (!curS0)
                        {
                            prevS0 = false;
                            DeleteJoinStamp(0);
                            ResetSunshinePersistence(47990);
                            CloseSunshineApp(47990);
                            SyncVirtualDisplays(false, IsSlotStreaming(1));
                        }
                    }

                    bool curS1 = IsSlotStreaming(1);
                    if (!prevS1 && curS1)
                    {
                        prevS1 = true;
                        ResetSunshinePersistence(48990);
                        SyncVirtualDisplays(IsSlotStreaming(0), true);
                    }
                    else if (prevS1 && !curS1)
                    {
                        Thread.Sleep(400);
                        curS1 = IsSlotStreaming(1);
                        if (!curS1)
                        {
                            prevS1 = false;
                            DeleteJoinStamp(1);
                            ResetSunshinePersistence(48990);
                            CloseSunshineApp(48990);
                            SyncVirtualDisplays(IsSlotStreaming(0), false);
                            EnsureSecondarySunshineReady();
                        }
                    }

                    if (!prevS1 && !IsLocalPortListening(48989))
                    {
                        EnsureSecondarySunshineReady();
                    }

                    if (signaled)
                    {
                        SyncVirtualDisplays(prevS0, prevS1);
                    }
                }
            }
            finally
            {
                NetworkChange.NetworkAddressChanged -= onNet;
                if (fsw != null)
                {
                    try { fsw.Dispose(); } catch { }
                }
                if (fswStamp != null)
                {
                    try { fswStamp.Dispose(); } catch { }
                }
            }
        }
    }

    public static void Main(string[] args)
    {
        if (args == null || args.Length == 0)
            return;

        string cmd = args[0].ToLowerInvariant();
        if (cmd == "join" && args.Length >= 2)
        {
            int slot = (args[1] == "1") ? 1 : 0;
            WriteJoinStamp(slot);
            if (slot == 0)
            {
                SyncVirtualDisplays(true, IsSlotStreaming(1));
            }
            else
            {
                SyncVirtualDisplays(IsSlotStreaming(0), true);
            }
        }
        else if (cmd == "leave" && args.Length >= 2)
        {
            int slot = (args[1] == "1") ? 1 : 0;
            DeleteJoinStamp(slot);
            if (slot == 0)
            {
                ResetSunshinePersistence(47990);
                SyncVirtualDisplays(false, IsSlotStreaming(1));
            }
            else
            {
                ResetSunshinePersistence(48990);
                SyncVirtualDisplays(IsSlotStreaming(0), false);
            }
        }
        else if (cmd == "sync")
        {
            SyncVirtualDisplays(IsSlotStreaming(0), IsSlotStreaming(1));
        }
        else if (cmd == "detach-all")
        {
            DeleteJoinStamp(0);
            DeleteJoinStamp(1);
            SyncVirtualDisplays(false, false);
        }
        else if (cmd == "daemon")
        {
            RunDaemon();
        }
    }
}
