#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the signed WinUSB driver for Apple Silicon Mac USB-C CDC-NCM (VID_05AC&PID_1902)
    and deploys the zero-polling AppleUsbNcmBridge WinTun service (10.99.99.1/24).
    Works with Windows 10/11 Secure Boot ON and requires zero reboots.
#>
$ErrorActionPreference = "Stop"
$dir = "C:\ProgramData\AppleUsbNcm"
if (-not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# Restrict directory ACLs to SYSTEM and BUILTIN\Administrators before placing binaries or DLLs
# (prevents non-admin DLL planting / LPE against the SYSTEM scheduled task).
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
$adminSid  = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
$inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$prop    = [System.Security.AccessControl.PropagationFlags]::None
$full    = [System.Security.AccessControl.FileSystemRights]::FullControl
$allow   = [System.Security.AccessControl.AccessControlType]::Allow
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, $full, $inherit, $prop, $allow)))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, $full, $inherit, $prop, $allow)))
Set-Acl -Path $dir -AclObject $acl

Write-Host "[1/5] Generating AppleWinUsb.inf for USB\VID_05AC&PID_1902..." -ForegroundColor Cyan
$infContent = @"
[Version]
Signature   = "`$Windows NT`$"
Class       = USBDevice
ClassGUID   = {88BAE032-5A81-49f0-BC3D-A4FF138216D6}
Provider    = %ProviderName%
CatalogFile = AppleWinUsb.cat
DriverVer   = 11/15/2026,1.0.0.0
PnpLockdown = 1

[Manufacturer]
%MfgName% = AppleModels,NTamd64,NTarm64,NTx86

[AppleModels.NTamd64]
%DeviceDesc% = AppleWinUsb_Install, USB\VID_05AC&PID_1902

[AppleModels.NTarm64]
%DeviceDesc% = AppleWinUsb_Install, USB\VID_05AC&PID_1902

[AppleModels.NTx86]
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
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

public class CatGenWinUsb {
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

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATOpen(string pwszFileName, uint fdwOpenFlags, IntPtr hProv, uint dwPublicVersion, uint dwEncodingType);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATClose(IntPtr hCatalog);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATPutCatAttrInfo(IntPtr hCatalog, string pwszReferenceTag, uint dwAttrTypeAndAction, uint cbData, byte[] pbData);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATPutMemberInfo(IntPtr hCatalog, string pwszFileName, string pwszReferenceTag, ref Guid pgSubjectType, uint dwCertVersion, uint cbSIPIndirectData, IntPtr pbSIPIndirectData);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CryptCATPutAttrInfo(IntPtr hCatalog, IntPtr pCatMember, string pwszReferenceTag, uint dwAttrTypeAndAction, uint cbData, byte[] pbData);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATPersistStore(IntPtr hCatalog);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

    public static void BuildCat(string infPath, string catPath, bool isArm64) {
        if (File.Exists(catPath)) File.Delete(catPath);
        Guid drvVerify = new Guid("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
        IntPtr hdrv = IntPtr.Zero;
        IntPtr hAdmin256 = IntPtr.Zero;
        IntPtr hAdmin1 = IntPtr.Zero;
        IntPtr hCat = new IntPtr(-1);
        IntPtr pDummy = IntPtr.Zero;
        IntPtr pMemInfo = IntPtr.Zero;
        IntPtr pInd256 = IntPtr.Zero;
        IntPtr pInd1 = IntPtr.Zero;

        try {
            hdrv = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(drvVerify, hdrv, false);

            if (!CryptCATAdminAcquireContext2(out hAdmin256, hdrv, "SHA256", IntPtr.Zero, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATAdminAcquireContext2 SHA256 failed");
            if (!CryptCATAdminAcquireContext2(out hAdmin1, hdrv, "SHA1", IntPtr.Zero, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATAdminAcquireContext2 SHA1 failed");

            byte[] hash256, hash1;
            using (FileStream fs = File.OpenRead(infPath)) {
                uint len256 = 64; byte[] tmp256 = new byte[64];
                if (!CryptCATAdminCalcHashFromFileHandle2(hAdmin256, fs.SafeFileHandle.DangerousGetHandle(), ref len256, tmp256, 0) || len256 < 32)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATAdminCalcHashFromFileHandle2 SHA256 failed");
                hash256 = new byte[len256]; Array.Copy(tmp256, hash256, len256);

                fs.Position = 0;
                uint len1 = 64; byte[] tmp1 = new byte[64];
                if (!CryptCATAdminCalcHashFromFileHandle2(hAdmin1, fs.SafeFileHandle.DangerousGetHandle(), ref len1, tmp1, 0) || len1 < 20)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATAdminCalcHashFromFileHandle2 SHA1 failed");
                hash1 = new byte[len1]; Array.Copy(tmp1, hash1, len1);
            }

            string tag256 = BitConverter.ToString(hash256).Replace("-", "");
            string tag1 = BitConverter.ToString(hash1).Replace("-", "");

            hCat = CryptCATOpen(catPath, 2, IntPtr.Zero, 0x200, 0x00010001);
            if (hCat == IntPtr.Zero || hCat == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATOpen failed");

            uint attrFlags = 0x10010001;
            string osToken = isArm64 ? "10ARM64\0" : "10X64\0";
            byte[] osBytes = System.Text.Encoding.Unicode.GetBytes(osToken);
            byte[] osAttrBytes = System.Text.Encoding.Unicode.GetBytes("2:10.0,2:6.4\0");
            if (CryptCATPutCatAttrInfo(hCat, "OS", attrFlags, (uint)osBytes.Length, osBytes) == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATPutCatAttrInfo OS failed");
            if (CryptCATPutCatAttrInfo(hCat, "OSAttr", attrFlags, (uint)osAttrBytes.Length, osAttrBytes) == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATPutCatAttrInfo OSAttr failed");

            Guid infGuid = new Guid("DE351A42-8E59-11D0-8C47-00C04FC295EE");
            pDummy = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(pDummy, 0);

            byte[] memberInfoDer = new byte[] {
                0x30, 0x45, 0x13, 0x43,
                0x00, 0x7B, 0x00, 0x44, 0x00, 0x45, 0x00, 0x33, 0x00, 0x35, 0x00, 0x31, 0x00, 0x41, 0x00, 0x34,
                0x00, 0x32, 0x00, 0x2D, 0x00, 0x38, 0x00, 0x45, 0x00, 0x35, 0x00, 0x39, 0x00, 0x2D, 0x00, 0x31,
                0x00, 0x31, 0x00, 0x44, 0x00, 0x30, 0x00, 0x2D, 0x00, 0x38, 0x00, 0x43, 0x00, 0x34, 0x00, 0x37,
                0x00, 0x2D, 0x00, 0x30, 0x00, 0x30, 0x00, 0x43, 0x00, 0x30, 0x00, 0x34, 0x00, 0x46, 0x00, 0x43,
                0x00, 0x32, 0x00, 0x39, 0x00, 0x35, 0x00, 0x45, 0x00, 0x45, 0x00, 0x7D, 0x02, 0x02, 0x02, 0x00
            };
            pMemInfo = Marshal.AllocHGlobal(memberInfoDer.Length);
            Marshal.Copy(memberInfoDer, 0, pMemInfo, memberInfoDer.Length);

            byte[] indirect256 = new byte[71];
            byte[] hdr256 = new byte[] {
                0x30, 0x45, 0x30, 0x10, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x19,
                0x02, 0x02, 0x82, 0x00, 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
            };
            Array.Copy(hdr256, 0, indirect256, 0, hdr256.Length);
            Array.Copy(hash256, 0, indirect256, hdr256.Length, 32);
            pInd256 = Marshal.AllocHGlobal(indirect256.Length);
            Marshal.Copy(indirect256, 0, pInd256, indirect256.Length);

            IntPtr pMem256 = CryptCATPutMemberInfo(hCat, null, tag256, ref infGuid, 0x200, 4, pDummy);
            if (pMem256 == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATPutMemberInfo SHA256 failed");
            CRYPTCATMEMBER m256 = (CRYPTCATMEMBER)Marshal.PtrToStructure(pMem256, typeof(CRYPTCATMEMBER));
            m256.sEncodedIndirectData.cbData = (uint)indirect256.Length;
            m256.sEncodedIndirectData.pbData = pInd256;
            m256.sEncodedMemberInfo.cbData = (uint)memberInfoDer.Length;
            m256.sEncodedMemberInfo.pbData = pMemInfo;
            Marshal.StructureToPtr(m256, pMem256, false);

            string fnLower = Path.GetFileName(infPath).ToLowerInvariant();
            byte[] fileBytes = System.Text.Encoding.Unicode.GetBytes(fnLower + "\0");
            if (CryptCATPutAttrInfo(hCat, pMem256, "File", attrFlags, (uint)fileBytes.Length, fileBytes) == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATPutAttrInfo SHA256 File failed");

            byte[] indirect1 = new byte[55];
            byte[] hdr1 = new byte[] {
                0x30, 0x35, 0x30, 0x10, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x19,
                0x02, 0x02, 0x82, 0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05,
                0x00, 0x04, 0x14
            };
            Array.Copy(hdr1, 0, indirect1, 0, hdr1.Length);
            Array.Copy(hash1, 0, indirect1, hdr1.Length, 20);
            pInd1 = Marshal.AllocHGlobal(indirect1.Length);
            Marshal.Copy(indirect1, 0, pInd1, indirect1.Length);

            IntPtr pMem1 = CryptCATPutMemberInfo(hCat, null, tag1, ref infGuid, 0x200, 4, pDummy);
            if (pMem1 == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATPutMemberInfo SHA1 failed");
            CRYPTCATMEMBER m1 = (CRYPTCATMEMBER)Marshal.PtrToStructure(pMem1, typeof(CRYPTCATMEMBER));
            m1.sEncodedIndirectData.cbData = (uint)indirect1.Length;
            m1.sEncodedIndirectData.pbData = pInd1;
            m1.sEncodedMemberInfo.cbData = (uint)memberInfoDer.Length;
            m1.sEncodedMemberInfo.pbData = pMemInfo;
            Marshal.StructureToPtr(m1, pMem1, false);
            if (CryptCATPutAttrInfo(hCat, pMem1, "File", attrFlags, (uint)fileBytes.Length, fileBytes) == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATPutAttrInfo SHA1 File failed");

            if (!CryptCATPersistStore(hCat))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CryptCATPersistStore failed");
        } finally {
            if (hCat != IntPtr.Zero && hCat != new IntPtr(-1)) CryptCATClose(hCat);
            if (hAdmin256 != IntPtr.Zero) CryptCATAdminReleaseContext(hAdmin256, 0);
            if (hAdmin1 != IntPtr.Zero) CryptCATAdminReleaseContext(hAdmin1, 0);
            if (hdrv != IntPtr.Zero) Marshal.FreeHGlobal(hdrv);
            if (pDummy != IntPtr.Zero) Marshal.FreeHGlobal(pDummy);
            if (pMemInfo != IntPtr.Zero) Marshal.FreeHGlobal(pMemInfo);
            if (pInd256 != IntPtr.Zero) Marshal.FreeHGlobal(pInd256);
            if (pInd1 != IntPtr.Zero) Marshal.FreeHGlobal(pInd1);
        }
    }
}
"@
}

$isArm64 = ($env:PROCESSOR_ARCHITECTURE -eq "ARM64")
[CatGenWinUsb]::BuildCat($infPath, $catPath, $isArm64)

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=AppleUsbNcmDriverCert" -and $_.NotAfter -gt (Get-Date) } | Select-Object -First 1
$cerPath = Join-Path $dir "AppleUsbNcmDriverCert.cer"
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=AppleUsbNcmDriverCert" -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(10)
}
Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
if (-not (Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
    Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
}
if (-not (Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
    Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
}
$sigResult = Set-AuthenticodeSignature -FilePath $catPath -Certificate $cert -HashAlgorithm SHA256
if ($sigResult.Status -ne "Valid") {
    throw "Catalog Authenticode signing failed with status: $($sigResult.Status) ($($sigResult.StatusMessage))"
}

Write-Host "[3/5] Installing signed WinUSB driver via pnputil..." -ForegroundColor Cyan
$pnputil = Join-Path $env:SystemRoot "System32\pnputil.exe"
& $pnputil /add-driver $infPath /install
# 0 = success, 259 = already installed / no matching attached device, 3010 = reboot requested
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 259 -and $LASTEXITCODE -ne 3010) {
    throw "pnputil.exe exited with unexpected code $LASTEXITCODE"
}

Write-Host "[4/5] Verifying / Installing WHQL-signed Wintun v0.14.1..." -ForegroundColor Cyan
$wintunDll = Join-Path $dir "wintun.dll"
$needWintunDownload = $true
if (Test-Path $wintunDll) {
    $existingSig = Get-AuthenticodeSignature -FilePath $wintunDll -ErrorAction SilentlyContinue
    if ($existingSig -and $existingSig.Status -eq "Valid") {
        $needWintunDownload = $false
    } else {
        Write-Warning "Existing wintun.dll failed Authenticode verification; re-downloading..."
        Remove-Item $wintunDll -Force -ErrorAction SilentlyContinue
    }
}
if ($needWintunDownload) {
    $zipPath = Join-Path $dir "wintun.zip"
    $extractDir = Join-Path $dir "wintun_extracted"
    try {
        Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $zipPath -UseBasicParsing
        $expectedSha256 = "07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51"
        $actualSha256 = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actualSha256 -ne $expectedSha256) {
            throw "Wintun archive SHA-256 verification failed (expected $expectedSha256, got $actualSha256)."
        }
        if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
        $arch = if ($isArm64) { "arm64" } elseif ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "x86" }
        $candidateDll = Join-Path $extractDir "wintun\bin\$arch\wintun.dll"
        $dlSig = Get-AuthenticodeSignature -FilePath $candidateDll
        if ($dlSig.Status -ne "Valid") {
            throw "Extracted wintun.dll Authenticode signature invalid: $($dlSig.Status)"
        }
        Copy-Item $candidateDll $wintunDll -Force
    } finally {
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[5/5] Compiling AppleUsbNcmBridge.exe and registering background service..." -ForegroundColor Cyan
$csSource = Join-Path $PSScriptRoot "AppleUsbNcmBridge.cs"
$csDest   = Join-Path $dir "AppleUsbNcmBridge.cs"
$exeDest  = Join-Path $dir "AppleUsbNcmBridge.exe"
Copy-Item $csSource $csDest -Force

Stop-ScheduledTask -TaskName "AppleUsbNcmBridge" -ErrorAction SilentlyContinue
$runningProcs = Get-Process -Name "AppleUsbNcmBridge" -ErrorAction SilentlyContinue
if ($runningProcs) {
    $runningProcs | Stop-Process -Force -ErrorAction SilentlyContinue
    $runningProcs | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue
}

$cscPath = Get-ChildItem "$env:WINDIR\Microsoft.NET\Framework64\v4.0*\csc.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if (-not $cscPath) {
    $cscPath = Get-ChildItem "$env:WINDIR\Microsoft.NET\Framework\v4.0*\csc.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $cscPath) {
    throw "Could not find .NET Framework csc.exe compiler under $env:WINDIR\Microsoft.NET"
}
$platformFlag = if ($isArm64) { "/platform:arm64" } elseif ([Environment]::Is64BitOperatingSystem) { "/platform:x64" } else { "/platform:x86" }
& $cscPath /nologo /unsafe /optimize+ $platformFlag /out:$exeDest $csDest
if ($LASTEXITCODE -ne 0) {
    throw "csc.exe compilation of AppleUsbNcmBridge.cs failed with exit code $LASTEXITCODE"
}

$action    = New-ScheduledTaskAction -Execute $exeDest -WorkingDirectory $dir
$trigger1  = New-ScheduledTaskTrigger -AtStartup
$trigger2  = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "AppleUsbNcmBridge" -Action $action -Trigger @($trigger1, $trigger2) -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "AppleUsbNcmBridge"

# Remove overly broad legacy firewall rule if present and enforce program-free / scoped rule
$fwRuleName = "Apple USB-C Direct Link"
if (Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue) {
    Remove-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
}
New-NetFirewallRule -DisplayName $fwRuleName -Direction Inbound -Action Allow -LocalAddress 10.99.99.1,192.168.2.2 -RemoteAddress 10.99.99.0/24,192.168.2.0/24 -Profile Any | Out-Null

Start-Sleep -Seconds 3
Get-Content (Join-Path $dir "bridge.log") -Tail 20 -ErrorAction SilentlyContinue
Write-Host "`nInstallation complete! Windows USB-C IP is 10.99.99.1/24 (Direct Link) and 192.168.2.2/24 (macOS Internet Sharing)." -ForegroundColor Green
