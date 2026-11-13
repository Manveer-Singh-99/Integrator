#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the signed WinUSB driver for Apple Silicon Mac USB-C CDC-NCM (VID_05AC&PID_1902)
    and deploys the zero-polling AppleUsbNcmBridge WinTun service (10.99.99.1/24).
    Works with Windows 11 Secure Boot ON and requires zero reboots.
#>
$ErrorActionPreference = "Stop"
$dir = "C:\ProgramData\AppleUsbNcm"
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

Write-Host "[1/5] Generating AppleWinUsb.inf for USB\VID_05AC&PID_1902..." -ForegroundColor Cyan
$infContent = @"
[Version]
Signature   = "`$Windows NT`$"
Class       = USBDevice
ClassGUID   = {88BAE032-5A81-49f0-BC3D-A4FF138216D6}
Provider    = %ProviderName%
CatalogFile = AppleWinUsb.cat
DriverVer   = 11/04/2026,1.0.0.0
PnpLockdown = 1

[Manufacturer]
%MfgName% = AppleModels,NTamd64,NTarm64

[AppleModels.NTamd64]
%DeviceDesc% = AppleWinUsb_Install, USB\VID_05AC&PID_1902

[AppleModels.NTarm64]
%DeviceDesc% = AppleWinUsb_Install, USB\VID_05AC&PID_1902

[AppleWinUsb_Install.NT]
Include = winusb.inf
Needs   = WINUSB.NT

[AppleWinUsb_Install.NT.Services]
Include = winusb.inf
Needs   = WINUSB.NT.Services

[AppleWinUsb_Install.NT.HW]
AddReg = Dev_AddReg

[Dev_AddReg]
HKR,,DeviceInterfaceGUIDs,0x10000,"{a5dcbf10-6530-11d2-901f-00c04fb951ed}"

[Strings]
ProviderName = "AppleUsbNcmBridge"
MfgName      = "Apple Inc."
DeviceDesc   = "Apple MacBook USB-C NCM Direct Link (WinUSB)"
"@
$infPath = Join-Path $dir "AppleWinUsb.inf"
$catPath = Join-Path $dir "AppleWinUsb.cat"
[System.IO.File]::WriteAllText($infPath, $infContent, [System.Text.Encoding]::ASCII)

Write-Host "[2/5] Generating Windows 11 v2 Security Catalog (AppleWinUsb.cat) and signing..." -ForegroundColor Cyan
if (-not ("CatGenWinUsb" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;

public class CatGenWinUsb {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CRYPTCATATTRIBUTE {
        public uint cbStruct;
        public string pwszReferenceTag;
        public uint dwAttrTypeAndAction;
        public uint cbValue;
        public IntPtr pbValue;
        public uint dwReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPTOAPI_BLOB {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CRYPTCATMEMBER {
        public uint cbStruct;
        public string pwszReferenceTag;
        public string pwszFileName;
        public Guid gSubjectType;
        public uint fdwMemberFlags;
        public IntPtr pIndirectData;
        public uint dwCertVersion;
        public uint dwReserved;
        public IntPtr hReserved;
        public CRYPTOAPI_BLOB sEncodedIndirectData;
        public CRYPTOAPI_BLOB sEncodedMemberInfo;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATOpen(string pwszFileName, uint fdwOpenFlags, IntPtr hProv, uint dwPublicVersion, uint dwEncodingType);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATClose(IntPtr hCatalog);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATPutCatAttrInfo(IntPtr hCatalog, string pwszReferenceTag, uint dwAttrTypeAndAction, uint cbData, byte[] pbData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATPutMemberInfo(IntPtr hCatalog, string pwszFileName, string pwszReferenceTag, ref Guid pgSubjectType, uint dwCertVersion, uint cbSIPIndirectData, IntPtr pbSIPIndirectData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATPutAttrInfo(IntPtr hCatalog, IntPtr pCatMember, string pwszReferenceTag, uint dwAttrTypeAndAction, uint cbData, byte[] pbData);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATPersistStore(IntPtr hCatalog);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

    public static void BuildCat(string infPath, string catPath) {
        if (File.Exists(catPath)) File.Delete(catPath);
        Guid drvVerify = new Guid("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
        IntPtr hdrv = Marshal.AllocHGlobal(16);
        Marshal.StructureToPtr(drvVerify, hdrv, false);

        IntPtr hAdmin256, hAdmin1;
        CryptCATAdminAcquireContext2(out hAdmin256, hdrv, "SHA256", IntPtr.Zero, 0);
        CryptCATAdminAcquireContext2(out hAdmin1, hdrv, "SHA1", IntPtr.Zero, 0);
        Marshal.FreeHGlobal(hdrv);

        byte[] hash256, hash1;
        using (FileStream fs = File.OpenRead(infPath)) {
            uint len256 = 64; byte[] tmp256 = new byte[64];
            CryptCATAdminCalcHashFromFileHandle2(hAdmin256, fs.SafeFileHandle.DangerousGetHandle(), ref len256, tmp256, 0);
            hash256 = new byte[len256]; Array.Copy(tmp256, hash256, len256);

            fs.Position = 0;
            uint len1 = 64; byte[] tmp1 = new byte[64];
            CryptCATAdminCalcHashFromFileHandle2(hAdmin1, fs.SafeFileHandle.DangerousGetHandle(), ref len1, tmp1, 0);
            hash1 = new byte[len1]; Array.Copy(tmp1, hash1, len1);
        }
        CryptCATAdminReleaseContext(hAdmin256, 0);
        CryptCATAdminReleaseContext(hAdmin1, 0);

        string tag256 = BitConverter.ToString(hash256).Replace("-", "");
        string tag1 = BitConverter.ToString(hash1).Replace("-", "");

        IntPtr hCat = CryptCATOpen(catPath, 2, IntPtr.Zero, 0x200, 0x00010001);
        uint attrFlags = 0x10010001;
        CryptCATPutCatAttrInfo(hCat, "OS", attrFlags, 10, System.Text.Encoding.Unicode.GetBytes("10X64\0"));
        CryptCATPutCatAttrInfo(hCat, "OSAttr", attrFlags, 22, System.Text.Encoding.Unicode.GetBytes("2:10.0,2:6.4\0"));

        Guid infGuid = new Guid("DE351A42-8E59-11D0-8C47-00C04FC295EE");
        byte[] dummy = new byte[4];
        IntPtr pDummy = Marshal.AllocHGlobal(4);
        Marshal.Copy(dummy, 0, pDummy, 4);

        byte[] memberInfoDer = new byte[] {
            0x30, 0x45, 0x13, 0x43,
            0x00, 0x7B, 0x00, 0x44, 0x00, 0x45, 0x00, 0x33, 0x00, 0x35, 0x00, 0x31, 0x00, 0x41, 0x00, 0x34,
            0x00, 0x32, 0x00, 0x2D, 0x00, 0x38, 0x00, 0x45, 0x00, 0x35, 0x00, 0x39, 0x00, 0x2D, 0x00, 0x31,
            0x00, 0x31, 0x00, 0x44, 0x00, 0x30, 0x00, 0x2D, 0x00, 0x38, 0x00, 0x43, 0x00, 0x34, 0x00, 0x37,
            0x00, 0x2D, 0x00, 0x30, 0x00, 0x30, 0x00, 0x43, 0x00, 0x30, 0x00, 0x34, 0x00, 0x46, 0x00, 0x43,
            0x00, 0x32, 0x00, 0x39, 0x00, 0x35, 0x00, 0x45, 0x00, 0x45, 0x00, 0x7D, 0x02, 0x02, 0x02, 0x00
        };
        IntPtr pMemInfo = Marshal.AllocHGlobal(memberInfoDer.Length);
        Marshal.Copy(memberInfoDer, 0, pMemInfo, memberInfoDer.Length);

        byte[] indirect256 = new byte[71];
        byte[] hdr256 = new byte[] {
            0x30, 0x45, 0x30, 0x10, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x19,
            0x02, 0x02, 0x82, 0x00, 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
        };
        Array.Copy(hdr256, 0, indirect256, 0, hdr256.Length);
        Array.Copy(hash256, 0, indirect256, hdr256.Length, 32);
        IntPtr pInd256 = Marshal.AllocHGlobal(indirect256.Length);
        Marshal.Copy(indirect256, 0, pInd256, indirect256.Length);

        IntPtr pMem256 = CryptCATPutMemberInfo(hCat, null, tag256, ref infGuid, 0x200, 4, pDummy);
        CRYPTCATMEMBER m256 = (CRYPTCATMEMBER)Marshal.PtrToStructure(pMem256, typeof(CRYPTCATMEMBER));
        m256.sEncodedIndirectData.cbData = (uint)indirect256.Length;
        m256.sEncodedIndirectData.pbData = pInd256;
        m256.sEncodedMemberInfo.cbData = (uint)memberInfoDer.Length;
        m256.sEncodedMemberInfo.pbData = pMemInfo;
        Marshal.StructureToPtr(m256, pMem256, false);

        string fnLower = Path.GetFileName(infPath).ToLowerInvariant();
        CryptCATPutAttrInfo(hCat, pMem256, "File", attrFlags, (uint)((fnLower.Length + 1) * 2), System.Text.Encoding.Unicode.GetBytes(fnLower + "\0"));

        byte[] indirect1 = new byte[55];
        byte[] hdr1 = new byte[] {
            0x30, 0x35, 0x30, 0x10, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x19,
            0x02, 0x02, 0x82, 0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05,
            0x00, 0x04, 0x14
        };
        Array.Copy(hdr1, 0, indirect1, 0, hdr1.Length);
        Array.Copy(hash1, 0, indirect1, hdr1.Length, 20);
        IntPtr pInd1 = Marshal.AllocHGlobal(indirect1.Length);
        Marshal.Copy(indirect1, 0, pInd1, indirect1.Length);

        IntPtr pMem1 = CryptCATPutMemberInfo(hCat, null, tag1, ref infGuid, 0x200, 4, pDummy);
        CRYPTCATMEMBER m1 = (CRYPTCATMEMBER)Marshal.PtrToStructure(pMem1, typeof(CRYPTCATMEMBER));
        m1.sEncodedIndirectData.cbData = (uint)indirect1.Length;
        m1.sEncodedIndirectData.pbData = pInd1;
        m1.sEncodedMemberInfo.cbData = (uint)memberInfoDer.Length;
        m1.sEncodedMemberInfo.pbData = pMemInfo;
        Marshal.StructureToPtr(m1, pMem1, false);
        CryptCATPutAttrInfo(hCat, pMem1, "File", attrFlags, (uint)((fnLower.Length + 1) * 2), System.Text.Encoding.Unicode.GetBytes(fnLower + "\0"));

        CryptCATPersistStore(hCat);
        CryptCATClose(hCat);
    }
}
"@
}

[CatGenWinUsb]::BuildCat($infPath, $catPath)

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=AppleUsbNcmDriverCert" } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=AppleUsbNcmDriverCert" -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(10)
    $cerPath = Join-Path $dir "AppleUsbNcmDriverCert.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
    Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
}
Set-AuthenticodeSignature -FilePath $catPath -Certificate $cert -HashAlgorithm SHA256 | Out-Null

Write-Host "[3/5] Installing signed WinUSB driver via pnputil..." -ForegroundColor Cyan
& pnputil.exe /add-driver $infPath /install

Write-Host "[4/5] Downloading WHQL-signed Wintun v0.14.1..." -ForegroundColor Cyan
$wintunDll = Join-Path $dir "wintun.dll"
if (-not (Test-Path $wintunDll)) {
    $zipPath = Join-Path $dir "wintun.zip"
    Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $zipPath -UseBasicParsing
    Expand-Archive -Path $zipPath -DestinationPath (Join-Path $dir "wintun_extracted") -Force
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "x86" }
    Copy-Item (Join-Path $dir "wintun_extracted\wintun\bin\$arch\wintun.dll") $wintunDll -Force
}

Write-Host "[5/5] Compiling AppleUsbNcmBridge.exe and registering background service..." -ForegroundColor Cyan
$csSource = Join-Path $PSScriptRoot "AppleUsbNcmBridge.cs"
$csDest = Join-Path $dir "AppleUsbNcmBridge.cs"
$exeDest = Join-Path $dir "AppleUsbNcmBridge.exe"
Copy-Item $csSource $csDest -Force

Stop-ScheduledTask -TaskName "AppleUsbNcmBridge" -ErrorAction SilentlyContinue
Stop-Process -Name "AppleUsbNcmBridge" -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /unsafe /optimize+ /platform:x64 /out:$exeDest $csDest

$action = New-ScheduledTaskAction -Execute $exeDest -WorkingDirectory $dir
$trigger1 = New-ScheduledTaskTrigger -AtStartup
$trigger2 = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "AppleUsbNcmBridge" -Action $action -Trigger @($trigger1, $trigger2) -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "AppleUsbNcmBridge"

if (-not (Get-NetFirewallRule -DisplayName "Apple USB-C Direct Link" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "Apple USB-C Direct Link" -Direction Inbound -Action Allow -RemoteAddress 10.99.99.0/24,192.168.2.0/24 -Profile Any | Out-Null
}

Start-Sleep -Seconds 3
Get-Content (Join-Path $dir "bridge.log") -ErrorAction SilentlyContinue
Write-Host "`nInstallation complete! Windows USB-C IP is 10.99.99.1/24 (Direct Link) and 192.168.2.2/24 (macOS Internet Sharing)." -ForegroundColor Green
