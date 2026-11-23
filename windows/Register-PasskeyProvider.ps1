# ==============================================================================================
# Integrator Windows 11 Sparse MSIX Passkey Provider Installer (`windows/Register-PasskeyProvider.ps1`)
#
# 1. Module Purpose & System Scope:
#    - Builds, signs, and installs the `Integrator.PasskeyProvider` sparse MSIX package granting
#      Windows 11 Package Identity and Packaged COM activation (`windows.comServer`) to the
#      non-elevated Medium-IL `IntegratorPasskeyHost.exe` passkey server.
#    - Registers CLSID `{4b2c1f30-8a1e-4509-913a-96696ef07bc3}` (`IPluginAuthenticator`) so Windows
#      Security and browsers (Chrome, Edge, Brave) activate `IntegratorPasskeyHost.exe -PluginActivated`
#      on-demand and route WebAuthn ceremonies to macOS Touch ID.
#
# 2. Architectural Linkages & Dependencies:
#    - External Content Root: `%LOCALAPPDATA%\Integrator` (contains `IntegratorPasskeyHost.exe` and
#      `integrator_cli.exe`).
#    - Windows SDK Tools: `makeappx.exe` and `signtool.exe` under Windows Kits 10 (`10.0.26100.0`).
#    - Code-Signing Certificate: Self-signed `CN=Integrator` in `Cert:\LocalMachine\My` &
#      `Cert:\LocalMachine\TrustedPeople`.
#
# 3. Execution & Concurrency Model:
#    - Executed synchronously as Administrator during deployment/setup; invokes
#      `IntegratorPasskeyHost.exe --register` and `--self-test` in the interactive user session
#      (Medium IL) so Windows WebAuthn binds the plugin to the interactive user's package context.
#
# 4. Security & Safety Invariants:
#    - Never grants Administrator privileges to `IntegratorPasskeyHost.exe`; COM activation runs
#      strictly at Medium IL (`asInvoker`).
#    - Replaces any stale `Integrator.PasskeyProvider` sparse registration cleanly before
#      re-registering with `Add-AppxPackage -ExternalLocation`.
# ==============================================================================================

param(
    [string]$ExternalLocation = (Join-Path $env:LOCALAPPDATA "Integrator"),
    [string]$PackageWorkDir = "C:\ProgramData\Integrator\PasskeyPackage",
    [string]$PublisherSubject = "CN=Integrator",
    [string]$PackageName = "Integrator.PasskeyProvider",
    [string]$PluginClsid = "4b2c1f30-8a1e-4509-913a-96696ef07bc3"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Named Constants
$AppId = "IntegratorPasskeyHost"
$HostExeName = "IntegratorPasskeyHost.exe"
$PluginDisplayName = "Integrator Touch ID"
$MinTargetWinVer = "10.0.22635.4515"
$MaxTargetWinVer = "10.0.26100.0"
$CertValidityYears = 3

# 1. Verify ExternalLocation & Host Binary
$HostExePath = Join-Path $ExternalLocation $HostExeName
if (-not (Test-Path $HostExePath)) {
    throw "Missing packaged COM host executable at '$HostExePath'. Publish PasskeyHost first."
}

# 2. Locate Windows SDK makeappx.exe and signtool.exe
$KitBinRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
$MakeAppx = (Get-ChildItem $KitBinRoot -Recurse -Filter "makeappx.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "\\x64\\" } | Sort-Object FullName | Select-Object -Last 1).FullName
$SignTool = (Get-ChildItem $KitBinRoot -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "\\x64\\" } | Sort-Object FullName | Select-Object -Last 1).FullName

if (-not $MakeAppx -or -not $SignTool) {
    throw "Windows SDK makeappx.exe / signtool.exe (x64) not found under '$KitBinRoot'."
}

# 3. Prepare Manifest Layout Directory & Assets
$ManifestDir = Join-Path $PackageWorkDir "Layout"
$AssetsDir = Join-Path $ManifestDir "Assets"
New-Item -ItemType Directory -Path $AssetsDir -Force | Out-Null

$LogoDest = Join-Path $AssetsDir "Logo.png"
$ScriptRepoRoot = Split-Path -Parent $PSScriptRoot
$LogoCandidates = @(
    (Join-Path $ScriptRepoRoot "app\icons\Square150x150Logo.png"),
    "C:\ProgramData\Integrator\SparseTest\Manifest\Assets\Logo.png",
    "C:\Program Files\WindowsApps\Integrator.PasskeyProvider_1.0.0.0_x64__wjatwpqxn16dt\Assets\Logo.png"
)
$CopiedLogo = $false
foreach ($cand in $LogoCandidates) {
    if (Test-Path $cand) {
        Copy-Item -Path $cand -Destination $LogoDest -Force
        $CopiedLogo = $true
        break
    }
}
if (-not $CopiedLogo) {
    Add-Type -AssemblyName System.Drawing
    $bmp = New-Object System.Drawing.Bitmap 150, 150
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.Clear([System.Drawing.Color]::FromArgb(255, 13, 110, 253))
    $bmp.Save($LogoDest, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
}

# 4. Write AppxManifest.xml with windows.comServer Extension + AllowExternalContent
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
$ManifestXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Package
    xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
    xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
    xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
    xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
    xmlns:com="http://schemas.microsoft.com/appx/manifest/com/windows10"
    IgnorableNamespaces="uap uap10 rescap com">
  <Identity
      Name="$PackageName"
      Publisher="$PublisherSubject"
      Version="1.0.0.0"
      ProcessorArchitecture="$Arch" />
  <Properties>
    <DisplayName>$PluginDisplayName</DisplayName>
    <PublisherDisplayName>Integrator</PublisherDisplayName>
    <Logo>Assets\Logo.png</Logo>
    <uap10:AllowExternalContent>true</uap10:AllowExternalContent>
  </Properties>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="$MinTargetWinVer" MaxVersionTested="$MaxTargetWinVer" />
  </Dependencies>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
  <Applications>
    <Application Id="$AppId" Executable="$HostExeName" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements
          DisplayName="$PluginDisplayName"
          Description="Passkey Provider for $PluginDisplayName"
          BackgroundColor="transparent"
          Square150x150Logo="Assets\Logo.png"
          Square44x44Logo="Assets\Logo.png" />
      <Extensions>
        <com:Extension Category="windows.comServer">
          <com:ComServer>
            <com:ExeServer Executable="$HostExeName" Arguments="-PluginActivated" DisplayName="$PluginDisplayName">
              <com:Class Id="$PluginClsid" DisplayName="$PluginDisplayName" />
            </com:ExeServer>
          </com:ComServer>
        </com:Extension>
      </Extensions>
    </Application>
  </Applications>
</Package>
"@

$ManifestPath = Join-Path $ManifestDir "AppxManifest.xml"
[System.IO.File]::WriteAllText($ManifestPath, $ManifestXml, [System.Text.UTF8Encoding]::new($false))

# 5. Pack Sparse MSIX
$MsixPath = Join-Path $PackageWorkDir "IntegratorPasskeyProvider.msix"
if (Test-Path $MsixPath) { Remove-Item -Path $MsixPath -Force }
& $MakeAppx pack /d $ManifestDir /p $MsixPath /nv /o
if ($LASTEXITCODE -ne 0) { throw "makeappx pack failed with exit code $LASTEXITCODE" }

# 6. Locate or Create Trusted Local Signing Certificate
$Cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq $PublisherSubject -and $_.HasPrivateKey } |
    Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $Cert) {
    $Cert = New-SelfSignedCertificate -Type Custom -Subject $PublisherSubject `
        -KeyUsage DigitalSignature -FriendlyName "Integrator Passkey Provider" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}") `
        -NotAfter (Get-Date).AddYears($CertValidityYears)
}

# Ensure certificate is trusted in LocalMachine\TrustedPeople
$Trusted = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
if (-not $Trusted) {
    $CerPath = Join-Path $PackageWorkDir "IntegratorCert.cer"
    Export-Certificate -Cert $Cert -FilePath $CerPath -Force | Out-Null
    Import-Certificate -FilePath $CerPath -CertStoreLocation "Cert:\LocalMachine\TrustedPeople" | Out-Null
}

# 7. Sign the Sparse MSIX
& $SignTool sign /fd SHA256 /sm /sha1 $Cert.Thumbprint $MsixPath
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed with exit code $LASTEXITCODE" }

# 8. Replace Existing Package & Register Sparse MSIX pointing to ExternalLocation
Get-Process IntegratorPasskeyHost -ErrorAction SilentlyContinue | Stop-Process -Force
$Existing = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
if ($Existing) {
    Remove-AppxPackage -Package $Existing.PackageFullName
}
Add-AppxPackage -Path $MsixPath -ExternalLocation $ExternalLocation

$Installed = Get-AppxPackage -Name $PackageName
Write-Host "REGISTERED_PACKAGE=$($Installed.PackageFullName)"
Write-Host "INSTALL_LOCATION=$($Installed.InstallLocation)"
Write-Host "EXTERNAL_LOCATION=$ExternalLocation"
