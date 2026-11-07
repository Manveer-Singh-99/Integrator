Add-Type -AssemblyName System.Windows.Forms

# Zero-CIM Ultra-Fast Multi-Device Detection (Mac + iPad across USB-C, Hotspot, and Wi-Fi)
. "C:\VirtualDisplayDriver\detect_connection.ps1" | Out-Null

$deviceId = "ROOT\DISPLAY\0001"
$vddXmlPath = "C:\VirtualDisplayDriver\vdd_settings.xml"
$isRunning = [CfgMgr]::IsDeviceStarted($deviceId)

$activeCount = 1
if ([System.IO.File]::Exists($vddXmlPath)) {
    $xmlTxt = [System.IO.File]::ReadAllText($vddXmlPath)
    if ($xmlTxt -match "<count>(\d+)</count>") {
        $activeCount = [int]$matches[1]
    }
}
$desiredCount = if ($global:MacPresent -and $global:IpadPresent) { 2 } else { 1 }
$upgradeToDual = ($isRunning -and $activeCount -eq 1 -and $desiredCount -eq 2)

function Set-VddMonitorCount([int]$count) {
    $desiredXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<IddSampleDriverConfig>
  <monitors>
    <count>$count</count>
    <monitor>
      <friendlyname>Intel(R) Arc(TM) 140T GPU (16GB)</friendlyname>
      <modes>
        <mode>
          <width>2560</width>
          <height>1600</height>
          <refresh_rate>60</refresh_rate>
        </mode>
        <mode>
          <width>2360</width>
          <height>1640</height>
          <refresh_rate>60</refresh_rate>
        </mode>
      </modes>
    </monitor>
  </monitors>
</IddSampleDriverConfig>
"@
    $currentXml = if ([System.IO.File]::Exists($vddXmlPath)) { [System.IO.File]::ReadAllText($vddXmlPath) } else { "" }
    if ($currentXml -notmatch "<count>$count</count>") {
        [System.IO.File]::WriteAllText($vddXmlPath, $desiredXml)
    }
}

function Stop-SecondarySunshine {
    if ([CfgMgr]::IsLocalPortListening(48989) -or [CfgMgr]::IsLocalPortListening(48990)) {
        & curl.exe -k -s --max-time 1 -u "admin:alpine" -X POST "https://localhost:48990/api/apps/close" -H "Content-Type: application/json" | Out-Null
    }
    & schtasks.exe /End /TN "SunshineSecondary" 2>$null | Out-Null
    [CfgMgr]::StopProcessOnPort(48989)
    [CfgMgr]::StopProcessOnPort(48990)
}

if ($isRunning -and -not $upgradeToDual) {
    # 1. Terminate active stream on Primary Sunshine (47990) & Secondary Sunshine (48990)
    & curl.exe -k -s --max-time 1 -u "admin:alpine" -X POST "https://localhost:47990/api/apps/close" -H "Content-Type: application/json" | Out-Null
    Stop-SecondarySunshine

    # 2. Disable Virtual Display via pnputil (~80ms, eliminates hidden desktop & stops GPU duplication)
    & pnputil.exe /disable-device $deviceId | Out-Null

    # 3. Close Moonlight (and any pending stream-pc-screen wait loop) on Mac if reachable (non-blocking)
    if ($global:MacPresent -or $global:MacIp) {
        Start-Process -FilePath "C:\Windows\System32\OpenSSH\ssh.exe" -ArgumentList "-i `"C:\Users\Manveer Singh\.ssh\id_ed25519`" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no manveersingh@$($global:MacIp) `"pkill -f stream-pc-screen 2>/dev/null; killall Moonlight 2>/dev/null || true`"" -WindowStyle Hidden
    }

    [System.Windows.Forms.MessageBox]::Show("All virtual extended displays DISABLED.", "Second Screen", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
} else {
    if ($upgradeToDual) {
        # Upgrading live from 1 virtual display -> 2 independent extended displays
        & curl.exe -k -s --max-time 1 -u "admin:alpine" -X POST "https://localhost:47990/api/apps/close" -H "Content-Type: application/json" | Out-Null
        & pnputil.exe /disable-device $deviceId | Out-Null
        Start-Sleep -Milliseconds 350
    }
    # Ensure Primary SunshineService is running (sc.exe start is a 2ms no-op if already running)
    & sc.exe start SunshineService 2>$null | Out-Null

    if ($global:MacPresent -and $global:IpadPresent) {
        # =========================================================================
        # CASE 1: BOTH MAC + IPAD CONNECTED (Triple Display: PC + iPad + Mac)
        #   - Virtual Monitor 1 ({5eb52002-...}): 2360x1640 @ 60Hz -> Primary Sunshine (:47989) for iPad
        #   - Virtual Monitor 2 ({456a3c17-...}): 2560x1600 @ 60Hz -> Secondary Sunshine (:48989) for Mac
        # =========================================================================
        Set-VddMonitorCount 2
        & pnputil.exe /enable-device $deviceId | Out-Null

        if (-not [CfgMgr]::IsLocalPortListening(48989)) {
            & schtasks.exe /Run /TN "SunshineSecondary" 2>$null | Out-Null
        }

        [CfgMgr]::ConfigureVirtualDisplays(2, 2360, 1640, 2560, 1600) | Out-Null

        Start-Process -FilePath "C:\Windows\System32\OpenSSH\ssh.exe" -ArgumentList "-i `"C:\Users\Manveer Singh\.ssh\id_ed25519`" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no manveersingh@$($global:MacIp) `"/usr/local/bin/stream-pc-screen.sh $($global:PcIp) 48989`"" -WindowStyle Hidden

        [System.Windows.Forms.MessageBox]::Show(
            "Dual Extended Displays ENABLED:`n`n" +
            "1. iPad (2360x1640 @ 60Hz) via $($global:IpadMode) [Primary Sunshine :47989]`n" +
            "2. Mac (2560x1600 @ 60Hz) via $($global:MacMode) ($($global:PcIp):48989)",
            "Second Screen (Mac + iPad)",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null

    } elseif ($global:MacPresent) {
        # =========================================================================
        # CASE 2: MAC ONLY CONNECTED (Dual Display: PC + Mac 2560x1600 @ 60Hz)
        # =========================================================================
        Stop-SecondarySunshine
        Set-VddMonitorCount 1
        & pnputil.exe /enable-device $deviceId | Out-Null

        [CfgMgr]::ConfigureVirtualDisplays(1, 2560, 1600, 0, 0) | Out-Null

        Start-Process -FilePath "C:\Windows\System32\OpenSSH\ssh.exe" -ArgumentList "-i `"C:\Users\Manveer Singh\.ssh\id_ed25519`" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no manveersingh@$($global:MacIp) `"/usr/local/bin/stream-pc-screen.sh $($global:PcIp) 47989`"" -WindowStyle Hidden

        [System.Windows.Forms.MessageBox]::Show(
            "Mac Extended Display ENABLED (2560x1600 @ 60Hz) via $($global:MacMode) ($($global:PcIp)).",
            "Second Screen (Mac)",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null

    } else {
        # =========================================================================
        # CASE 3: IPAD ONLY CONNECTED (Dual Display: PC + iPad 2360x1640 @ 60Hz)
        # =========================================================================
        Stop-SecondarySunshine
        Set-VddMonitorCount 1
        & pnputil.exe /enable-device $deviceId | Out-Null

        [CfgMgr]::ConfigureVirtualDisplays(1, 2360, 1640, 0, 0) | Out-Null

        $ipadTransport = if ($global:IpadMode) { $global:IpadMode } else { "Wi-Fi / USB-C" }
        [System.Windows.Forms.MessageBox]::Show(
            "iPad Extended Display ENABLED (2360x1640 @ 60Hz) via $ipadTransport.`nOpen Moonlight on iPad and tap Desktop.",
            "Second Screen (iPad)",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }
}
