
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AppleUsbNcmBridge {
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

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, string Enumerator, IntPtr hwndParent, uint Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiEnumDeviceInterfaces(IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref Guid InterfaceClassGuid, uint MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr DeviceInfoSet, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData, IntPtr DeviceInterfaceDetailData, uint DeviceInterfaceDetailDataSize, out uint RequiredSize, IntPtr DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetEvent(IntPtr hEvent);

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

        [DllImport("cfgmgr32.dll")]
        public static extern int CM_Register_Notification(ref CM_NOTIFY_FILTER pFilter, IntPtr pContext, CM_NOTIFY_CALLBACK pCallback, out IntPtr pNotifyContext);

        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_Initialize(SafeFileHandle DeviceHandle, out IntPtr InterfaceHandle);

        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_Free(IntPtr InterfaceHandle);

        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_GetAssociatedInterface(IntPtr InterfaceHandle, byte AssociatedInterfaceIndex, out IntPtr AssociatedInterfaceHandle);

        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_SetCurrentAlternateSetting(IntPtr InterfaceHandle, byte SettingNumber);

        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_ControlTransfer(IntPtr InterfaceHandle, WINUSB_SETUP_PACKET SetupPacket, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_ReadPipe(IntPtr InterfaceHandle, byte PipeID, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_WritePipe(IntPtr InterfaceHandle, byte PipeID, byte[] Buffer, uint BufferLength, out uint LengthTransferred, IntPtr Overlapped);

        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_SetPipePolicy(IntPtr InterfaceHandle, byte PipeID, uint PolicyType, uint ValueLength, ref byte Value);

        [DllImport("winusb.dll", SetLastError = true)]
        public static extern bool WinUsb_ResetPipe(IntPtr InterfaceHandle, byte PipeID);

        [DllImport("C:\\ProgramData\\AppleUsbNcm\\wintun.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunCreateAdapter(string Name, string TunnelType, ref Guid RequestedGUID);

        [DllImport("C:\\ProgramData\\AppleUsbNcm\\wintun.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr WintunOpenAdapter(string Name);

        [DllImport("C:\\ProgramData\\AppleUsbNcm\\wintun.dll", SetLastError = true)]
        public static extern void WintunCloseAdapter(IntPtr Adapter);

        [DllImport("C:\\ProgramData\\AppleUsbNcm\\wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunStartSession(IntPtr Adapter, uint Capacity);

        [DllImport("C:\\ProgramData\\AppleUsbNcm\\wintun.dll", SetLastError = true)]
        public static extern void WintunEndSession(IntPtr Session);

        [DllImport("C:\\ProgramData\\AppleUsbNcm\\wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunGetReadWaitEvent(IntPtr Session);

        [DllImport("C:\\ProgramData\\AppleUsbNcm\\wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunReceivePacket(IntPtr Session, out uint PacketSize);

        [DllImport("C:\\ProgramData\\AppleUsbNcm\\wintun.dll", SetLastError = true)]
        public static extern void WintunReleaseReceivePacket(IntPtr Session, IntPtr Packet);

        [DllImport("C:\\ProgramData\\AppleUsbNcm\\wintun.dll", SetLastError = true)]
        public static extern IntPtr WintunAllocateSendPacket(IntPtr Session, uint PacketSize);

        [DllImport("C:\\ProgramData\\AppleUsbNcm\\wintun.dll", SetLastError = true)]
        public static extern void WintunSendPacket(IntPtr Session, IntPtr Packet);

        static volatile bool running = false;
        static byte[] macPeerAddr = new byte[] { 0x62, 0xD6, 0x7D, 0x44, 0x48, 0x0F };
        static readonly byte[] winVirtualMac = new byte[] { 0x02, 0x00, 0x5E, 0x99, 0x99, 0x01 };
        static ushort txSeq = 0;
        static readonly object txLock = new object();
        static readonly byte[] singleTxBuf = new byte[2048];

        // macOS Internet Sharing gateway tracking (Mac = 192.168.2.1, PC = 192.168.2.2).
        // The default route + DNS via the Mac are only installed while the Mac is proven to be sharing,
        // so Wi-Fi stays the default route whenever Internet Sharing is off.
        const string AdapterName = "Apple USB-C NCM";
        const int HintPort = 47901;            // UDP "ON"/"OFF" hints sent by the macOS helper daemon
        const int ProbeIntervalMs = 5000;      // ARP probe interval, only while the cable link is up
        const int GatewayTimeoutSec = 12;      // no sign of 192.168.2.1 for this long => sharing is off
        static readonly byte[] ShareGw = { 192, 168, 2, 1 };
        static readonly byte[] SharePc = { 192, 168, 2, 2 };
        static long gwLastSeenTicks = 0;
        static volatile bool gwDesired = false;
        static bool gwApplied = false;
        static bool gwAppliedKnown = false;
        static volatile int linkGen = 0;
        static readonly AutoResetEvent gwApplyEvent = new AutoResetEvent(false);
        static readonly AutoResetEvent gwProbeWake = new AutoResetEvent(false);

        static void Log(string msg) {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + " " + msg;
            Console.WriteLine(line);
            try { File.AppendAllText("C:\\ProgramData\\AppleUsbNcm\\bridge.log", line + "\r\n"); } catch {}
        }

        static string FindAppleUsbPath() {
            Guid guid = new Guid("a5dcbf10-6530-11d2-901f-00c04fb951ed");
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
                            Marshal.WriteInt32(detail, 8);
                            if (SetupDiGetDeviceInterfaceDetail(devs, ref ifData, detail, reqSize, out reqSize, IntPtr.Zero)) {
                                string path = Marshal.PtrToStringUni(new IntPtr(detail.ToInt64() + 4));
                                if (path != null && path.ToLowerInvariant().Contains("vid_05ac&pid_1902")) {
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
            lock (txLock) {
                int totalLen = 28 + frameLen;
                if (totalLen < 64) totalLen = 64;
                if ((totalLen % 512) == 0) totalLen += 4;

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

                Buffer.BlockCopy(frame, 0, buf, 28, frameLen);
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
            if (ipLen < 28 || b[ip + 9] != 17) return false;
            int ihl = (b[ip] & 0x0F) * 4;
            if (ihl < 20 || ihl + 8 > ipLen) return false;
            int udp = ip + ihl;
            int dport = (b[udp + 2] << 8) | b[udp + 3];
            if (dport != HintPort) return false;
            int ulen = (b[udp + 4] << 8) | b[udp + 5];
            int plen = Math.Min(ulen - 8, ipLen - ihl - 8);
            string msg = plen > 0 ? Encoding.ASCII.GetString(b, udp + 8, Math.Min(plen, 16)).Trim() : "";
            if (msg == "ON") {
                gwProbeWake.Set(); // probe 192.168.2.1 right away; the ARP reply confirms sharing
            } else if (msg == "OFF") {
                Interlocked.Exchange(ref gwLastSeenTicks, 0);
                gwDesired = false;
                gwApplyEvent.Set();
            }
            return true;
        }

        static void HandleArpRequest(IntPtr hIntf1, byte[] rxBuf, int offset, int len) {
            if (len < 42) return;
            // Any ARP (request, reply or gratuitous) sent from 192.168.2.1 means macOS Internet Sharing is on
            if (rxBuf[offset + 28] == 192 && rxBuf[offset + 29] == 168 && rxBuf[offset + 30] == 2 && rxBuf[offset + 31] == 1) {
                MarkGatewaySeen();
            }
            ushort oper = (ushort)((rxBuf[offset + 20] << 8) | rxBuf[offset + 21]);
            if (oper != 1) return; // ARP Request

            byte t0 = rxBuf[offset + 38];
            byte t1 = rxBuf[offset + 39];
            byte t2 = rxBuf[offset + 40];
            byte t3 = rxBuf[offset + 41];

            // Respond to ARP for 10.99.99.1 (Direct Link) or 192.168.2.2 (macOS Internet Sharing)
            bool match1099 = (t0 == 10 && t1 == 99 && t2 == 99 && t3 == 1);
            bool match1922 = (t0 == 192 && t1 == 168 && t2 == 2 && t3 == 2);

            if (match1099 || match1922) {
                byte[] reply = new byte[42];
                Buffer.BlockCopy(rxBuf, offset + 6, reply, 0, 6); // Destination MAC (requester)
                Buffer.BlockCopy(winVirtualMac, 0, reply, 6, 6);   // Source MAC (Windows virtual MAC)
                reply[12] = 0x08; reply[13] = 0x06;               // EtherType ARP
                reply[14] = 0x00; reply[15] = 0x01;               // Hardware type: Ethernet (1)
                reply[16] = 0x08; reply[17] = 0x00;               // Protocol type: IPv4 (0x0800)
                reply[18] = 6;    reply[19] = 4;                  // HW size 6, Proto size 4
                reply[20] = 0x00; reply[21] = 0x02;               // Opcode: ARP Reply (2)
                Buffer.BlockCopy(winVirtualMac, 0, reply, 22, 6);  // Sender MAC
                reply[28] = t0; reply[29] = t1; reply[30] = t2; reply[31] = t3; // Sender IP (requested target)
                Buffer.BlockCopy(rxBuf, offset + 22, reply, 32, 10); // Target MAC + Target IP (from request)

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
                    SetEvent(WintunGetReadWaitEvent(session));
                    break;
                }
                if (transferred < 12) continue;
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
                        if (dgIdx + dgLen <= transferred && dgLen >= 14) {
                            Buffer.BlockCopy(rxBuf, dgIdx + 6, macPeerAddr, 0, 6);
                            ushort etherType = (ushort)((rxBuf[dgIdx + 12] << 8) | rxBuf[dgIdx + 13]);
                            if (etherType == 0x0806) {
                                HandleArpRequest(hIntf1, rxBuf, dgIdx, dgLen);
                            } else if ((etherType == 0x0800 || etherType == 0x86DD) && dgLen > 14) {
                                if (etherType == 0x0800 && dgLen >= 34) {
                                    int ip4 = dgIdx + 14;
                                    if (rxBuf[ip4 + 12] == 192 && rxBuf[ip4 + 13] == 168 && rxBuf[ip4 + 14] == 2 && rxBuf[ip4 + 15] == 1) {
                                        MarkGatewaySeen();
                                    }
                                    if (HandleControlHint(rxBuf, ip4, dgLen - 14)) continue;
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
                while (count < 30 && payloadBytes < 14000) {
                    uint pktSize = 0;
                    IntPtr pkt = WintunReceivePacket(session, out pktSize);
                    if (pkt == IntPtr.Zero) break;
                    if (pktSize > 0 && pktSize <= 1500) {
                        byte ver = Marshal.ReadByte(pkt);
                        int ipVer = (ver >> 4) & 0x0F;
                        if (ipVer == 4 || ipVer == 6) {
                            byte[] frame = batchFrames[count];
                            Buffer.BlockCopy(macPeerAddr, 0, frame, 0, 6);
                            Buffer.BlockCopy(winVirtualMac, 0, frame, 6, 6);
                            if (ipVer == 4) { frame[12] = 0x08; frame[13] = 0x00; }
                            else { frame[12] = 0x86; frame[13] = 0xDD; }
                            Marshal.Copy(pkt, frame, 14, (int)pktSize);
                            batchLens[count] = (int)pktSize + 14;
                            payloadBytes += batchLens[count] + 4;
                            count++;
                        }
                    }
                    WintunReleaseReceivePacket(session, pkt);
                }

                if (count == 0) {
                    WaitForSingleObject(waitEvent, 0xFFFFFFFF);
                    continue;
                }

                if (count == 1) {
                    SendSingleEthernetFrame(hIntf1, batchFrames[0], batchLens[0]);
                } else {
                    lock (txLock) {
                        int ndpLen = 8 + (count + 1) * 4;
                        int dataStart = 12 + ndpLen;
                        if ((dataStart % 4) != 0) dataStart += 4 - (dataStart % 4);

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
                        if ((totalLen % 512) == 0) {
                            txBuf[totalLen] = 0; txBuf[totalLen+1] = 0; txBuf[totalLen+2] = 0; txBuf[totalLen+3] = 0;
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
                ProcessStartInfo psi = new ProcessStartInfo("netsh.exe", args);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                Process p = Process.Start(psi);
                if (p != null) p.WaitForExit(5000);
            } catch {}
        }

        static void RemoveShareGateway() {
            string a = "\"" + AdapterName + "\"";
            Netsh("interface ipv4 delete route prefix=0.0.0.0/0 interface=" + a + " nexthop=192.168.2.1 store=active");
            Netsh("interface ipv4 delete route prefix=0.0.0.0/0 interface=" + a + " nexthop=192.168.2.1 store=persistent");
            Netsh("interface ipv4 set dnsservers name=" + a + " source=static address=none register=none validate=no");
        }

        static void ConfigureAdapterIp() {
            string a = "\"" + AdapterName + "\"";
            // Static IPs only, no gateway: 10.99.99.1 (direct link) + 192.168.2.2 (macOS Internet Sharing subnet)
            Netsh("interface ip set address name=" + a + " static 10.99.99.1 255.255.255.0 none");
            Thread.Sleep(100);
            Netsh("interface ip add address name=" + a + " 192.168.2.2 255.255.255.0");
            Thread.Sleep(50);
            Netsh("interface ipv4 set interface interface=" + a + " metric=10");

            // Gateway + DNS are only installed while macOS Internet Sharing is detected (see GatewayApplyLoop)
            RemoveShareGateway();
            gwApplied = false;
            gwAppliedKnown = true;

            // Exactly one firewall rule: delete stale duplicates from older versions, then add
            Netsh("advfirewall firewall delete rule name=\"Apple USB-C NCM Allow All\"");
            Netsh("advfirewall firewall add rule name=\"Apple USB-C NCM Allow All\" dir=in action=allow remoteip=10.99.99.0/24,192.168.2.0/24");
        }

        // Applies gateway/DNS changes off the packet path (netsh can take a few hundred ms).
        static void GatewayApplyLoop() {
            string a = "\"" + AdapterName + "\"";
            while (true) {
                gwApplyEvent.WaitOne();
                Thread.Sleep(300); // coalesce bursts
                bool want = gwDesired;
                if (gwAppliedKnown && want == gwApplied) continue;
                if (want) {
                    Netsh("interface ipv4 add route prefix=0.0.0.0/0 interface=" + a + " nexthop=192.168.2.1 metric=5 store=active");
                    Netsh("interface ipv4 set dnsservers name=" + a + " source=static address=192.168.2.1 register=none validate=no");
                    Netsh("interface ipv4 add dnsservers name=" + a + " address=1.1.1.1 index=2 validate=no");
                    Log("macOS Internet Sharing ON: default route + DNS via 192.168.2.1 enabled");
                } else {
                    RemoveShareGateway();
                    Log("macOS Internet Sharing OFF: default route + DNS via 192.168.2.1 removed (Wi-Fi is default)");
                }
                gwApplied = want;
                gwAppliedKnown = true;
            }
        }

        // ARP-probes 192.168.2.1 while the cable link is up; turns sharing off after GatewayTimeoutSec of silence.
        static void GatewayMonitorLoop(IntPtr hIntf1, int gen) {
            byte[] req = new byte[42];
            for (int i = 0; i < 6; i++) req[i] = 0xFF;                 // broadcast
            Buffer.BlockCopy(winVirtualMac, 0, req, 6, 6);
            req[12] = 0x08; req[13] = 0x06;                              // ARP
            req[14] = 0x00; req[15] = 0x01; req[16] = 0x08; req[17] = 0x00;
            req[18] = 6; req[19] = 4; req[20] = 0x00; req[21] = 0x01;    // request
            Buffer.BlockCopy(winVirtualMac, 0, req, 22, 6);
            Buffer.BlockCopy(SharePc, 0, req, 28, 4);
            Buffer.BlockCopy(ShareGw, 0, req, 38, 4);

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
            try {
                Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High;
                Thread.CurrentThread.Priority = ThreadPriority.Highest;
            } catch {}
            Log("Starting AppleUsbNcmBridge service (High Priority, Zero-Alloc)...");
            Guid adapterGuid = new Guid("62d67d44-480f-45ac-1902-109999000001");
            IntPtr adapter = WintunOpenAdapter("Apple USB-C NCM");
            if (adapter == IntPtr.Zero) {
                adapter = WintunCreateAdapter("Apple USB-C NCM", "USB-C Direct", ref adapterGuid);
            }
            if (adapter == IntPtr.Zero) {
                Log("Failed to create WinTun adapter: " + Marshal.GetLastWin32Error());
                return;
            }
            IntPtr session = WintunStartSession(adapter, 0x400000);
            if (session == IntPtr.Zero) {
                Log("Failed to start WinTun session: " + Marshal.GetLastWin32Error());
                return;
            }
            ConfigureAdapterIp();
            Log("WinTun adapter 'Apple USB-C NCM' configured at 10.99.99.1/24 + 192.168.2.2/24 (gateway only while Mac shares Internet)");

            Thread gwApplyThread = new Thread(GatewayApplyLoop);
            gwApplyThread.IsBackground = true;
            gwApplyThread.Start();

            IntPtr hPlugEvent = CreateEvent(IntPtr.Zero, false, false, null);
            CM_NOTIFY_FILTER filter = new CM_NOTIFY_FILTER();
            filter.cbSize = (uint)Marshal.SizeOf(typeof(CM_NOTIFY_FILTER));
            filter.Flags = 2; // CM_NOTIFY_FILTER_FLAG_ALL_INTERFACE_CLASSES
            filter.FilterType = 0; // CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE
            CM_NOTIFY_CALLBACK cb = (hN, ctx, act, ed, eds) => {
                if (act == 0) SetEvent(hPlugEvent);
                return 0;
            };
            GCHandle cbHandle = GCHandle.Alloc(cb);
            IntPtr hNotify;
            CM_Register_Notification(ref filter, IntPtr.Zero, cb, out hNotify);
            bool loggedSleep = false;

            while (true) {
                try {
                    string devPath = FindAppleUsbPath();
                    if (devPath == null) {
                        if (!loggedSleep) {
                            Log("Cable unplugged. Waiting for USB-C connection...");
                            loggedSleep = true;
                        }
                        WaitForSingleObject(hPlugEvent, 3000);
                        continue;
                    }
                    loggedSleep = false;
                    Log("Found Apple USB-C device: " + devPath);
                    SafeFileHandle hDev = CreateFile(devPath, 0xC0000000, 3, IntPtr.Zero, 3, 0x40000000, IntPtr.Zero);
                    if (hDev.IsInvalid) {
                        Thread.Sleep(1000);
                        continue;
                    }
                    IntPtr hIntf0 = IntPtr.Zero;
                    IntPtr hIntf1 = IntPtr.Zero;
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
                        if (maxIn == 0) maxIn = 32764;

                        WinUsb_GetAssociatedInterface(hIntf0, 0, out hIntf1);
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
                        Thread rxThread = new Thread(() => UsbRxLoop(hIntf1, session, maxIn));
                        rxThread.IsBackground = true;
                        rxThread.Priority = ThreadPriority.Highest;
                        rxThread.Start();

                        int gen = linkGen;
                        IntPtr hIntf1Copy = hIntf1;
                        Thread gwMonThread = new Thread(() => GatewayMonitorLoop(hIntf1Copy, gen));
                        gwMonThread.IsBackground = true;
                        gwMonThread.Start();

                        UsbTxLoop(hIntf1, session);
                        rxThread.Join(2000);

                        // Link is down: stop probing and drop any gateway via the Mac
                        running = false;
                        linkGen++;
                        gwProbeWake.Set();
                        gwMonThread.Join(1000);
                        Interlocked.Exchange(ref gwLastSeenTicks, 0);
                        if (gwDesired || gwApplied) {
                            gwDesired = false;
                            gwApplyEvent.Set();
                        }
                    } finally {
                        if (hIntf1 != IntPtr.Zero) WinUsb_Free(hIntf1);
                        if (hIntf0 != IntPtr.Zero) WinUsb_Free(hIntf0);
                        hDev.Close();
                    }
                } catch (Exception ex) {
                    Log("Loop exception: " + ex.Message);
                }
                Thread.Sleep(1000);
            }
        }
    }
}
