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
$upgradeToDual = ($isRunning -and $activeCount -lt 2)

function Ensure-DualVddConfig {
    $desiredXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<IddSampleDriverConfig>
  <monitors>
    <count>2</count>
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
    if ($currentXml -notmatch "<count>2</count>") {
        [System.IO.File]::WriteAllText($vddXmlPath, $desiredXml)
    }
}

function Stop-DynamicWatcher {
    & schtasks.exe /End /TN "VddDynamicWatcher" 2>$null | Out-Null
    Get-Process -Name "VddCtl" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Stop-SecondarySunshine {
    if ([CfgMgr]::IsLocalPortListening(48989) -or [CfgMgr]::IsLocalPortListening(48990)) {
        [CfgMgr]::ResetSunshinePersistence(48990)
        [CfgMgr]::CloseSunshineApp(48990)
    }
    & schtasks.exe /End /TN "SunshineSecondary" 2>$null | Out-Null
    [CfgMgr]::StopProcessOnPort(48989)
    [CfgMgr]::StopProcessOnPort(48990)
}

if ($isRunning -and -not $upgradeToDual) {
    # 1. Stop dynamic display watcher first so it doesn't fight shutdown
    Stop-DynamicWatcher

    # 2. Close active streams & clear persistence on Primary (:47990) and Secondary (:48990)
    [CfgMgr]::DeleteJoinStamp(0)
    [CfgMgr]::DeleteJoinStamp(1)
    if ([CfgMgr]::IsLocalPortListening(47990)) {
        [CfgMgr]::ResetSunshinePersistence(47990)
        [CfgMgr]::CloseSunshineApp(47990)
    }
    Stop-SecondarySunshine

    # 3. Detach both virtual connectors cleanly in registry, then disable ROOT\DISPLAY\0001
    [CfgMgr]::SyncVirtualDisplays($false, $false) | Out-Null
    & pnputil.exe /disable-device $deviceId | Out-Null

    # 4. Close Moonlight on Mac if reachable (non-blocking)
    if ($global:MacPresent -or $global:MacIp) {
        Start-Process -FilePath "C:\Windows\System32\OpenSSH\ssh.exe" -ArgumentList "-i `"C:\Users\Manveer Singh\.ssh\id_ed25519`" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no manveersingh@$($global:MacIp) `"pkill -f stream-pc-screen 2>/dev/null; killall Moonlight 2>/dev/null || true`"" -WindowStyle Hidden
    }

    [System.Windows.Forms.MessageBox]::Show("All virtual extended displays DISABLED.", "Second Screen", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
} else {
    if ($upgradeToDual) {
        Stop-DynamicWatcher
        if ([CfgMgr]::IsLocalPortListening(47990)) {
            [CfgMgr]::ResetSunshinePersistence(47990)
            [CfgMgr]::CloseSunshineApp(47990)
        }
        & pnputil.exe /disable-device $deviceId | Out-Null
        Start-Sleep -Milliseconds 350
    }

    # 1. Always prepare 2 independent virtual slots (both detached until actively streaming):
    #    - Slot 0 ({5eb52002-...}): iPad 2360x1640 @ 60Hz on Primary Sunshine (:47989, HP-Omen)
    #    - Slot 1 ({456a3c17-...}): Mac  2560x1600 @ 60Hz on Secondary Sunshine (:48989, HP-Omen-Mac2)
    Ensure-DualVddConfig
    & pnputil.exe /enable-device $deviceId | Out-Null

    # 2. Ensure both Sunshine instances are running
    & sc.exe start SunshineService 2>$null | Out-Null
    [CfgMgr]::EnsureSecondarySunshineReady()

    $s0 = [CfgMgr]::IsSlotStreaming(0)

    if ($global:MacPresent) {
        # Attach Mac display immediately & launch Moonlight on Mac; iPad slot stays detached unless/until iPad streams
        [CfgMgr]::WriteJoinStamp(1)
        [CfgMgr]::SyncVirtualDisplays($s0, $true) | Out-Null

        Start-Process -FilePath "C:\Windows\System32\OpenSSH\ssh.exe" -ArgumentList "-i `"C:\Users\Manveer Singh\.ssh\id_ed25519`" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no manveersingh@$($global:MacIp) `"/usr/local/bin/stream-pc-screen.sh $($global:PcIp) 48989`"" -WindowStyle Hidden

        & schtasks.exe /Run /TN "VddDynamicWatcher" 2>$null | Out-Null

        $ipadNote = if ($s0) {
            "iPad (2360x1640 @ 60Hz): Active"
        } else {
            "iPad (2360x1640 @ 60Hz): Ready — auto-attaches when you tap Desktop in Moonlight on iPad, and auto-detaches on exit"
        }

        [System.Windows.Forms.MessageBox]::Show(
            "Dynamic Extended Display ENABLED:`n`n" +
            "- Mac (2560x1600 @ 60Hz): Connecting via $($global:MacMode) ($($global:PcIp):48989)`n" +
            "- $ipadNote",
            "Second Screen (Dynamic)",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    } else {
        # Keep unstreamed slots detached until a client connects so there is never a phantom display
        [CfgMgr]::SyncVirtualDisplays($s0, $false) | Out-Null
        & schtasks.exe /Run /TN "VddDynamicWatcher" 2>$null | Out-Null

        $ipadTransport = if ($global:IpadMode) { " via $($global:IpadMode)" } else { "" }
        [System.Windows.Forms.MessageBox]::Show(
            "Dynamic Extended Display READY$ipadTransport.`n`n" +
            "- Tap Desktop on iPad Moonlight (HP-Omen) -> 2360x1640 display auto-attaches`n" +
            "- Plug in or connect Mac (HP-Omen-Mac2) -> 2560x1600 display auto-attaches`n" +
            "- Exiting any stream automatically detaches that display.",
            "Second Screen (Dynamic)",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }
}
