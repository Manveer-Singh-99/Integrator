# Zero-CIM, Zero-Module Precompiled Multi-Device Detection (Mac + iPad across USB-C, Hotspot, & Wi-Fi)
if (-not ("CfgMgr" -as [type]) -or -not ([CfgMgr].GetMethod("ConfigureVirtualDisplays"))) {
    Add-Type -Path "C:\VirtualDisplayDriver\CfgMgr.dll"
}

$global:MacPresent = $false
$global:MacMode = ""
$global:ConnMode = "Wi-Fi"
$global:PcIp = "192.168.137.1"
$global:MacIp = "192.168.137.58"

$global:IpadPresent = $false
$global:IpadMode = ""
$global:IpadIp = ""

# ---------------------------------------------------------------------------
# 1. Detect Mac Wired (Apple USB-C NCM VID_05AC&PID_1902: 10.99.99.x or 192.168.2.x)
# ---------------------------------------------------------------------------
if ([CfgMgr]::IsAppleUsbNcmStarted()) {
    if ([CfgMgr]::ProbeHostAlive("10.99.99.2", 22, 70)) {
        $global:MacPresent = $true
        $global:MacMode = "USB-C"
        $global:ConnMode = "USB-C"
        $global:PcIp = "10.99.99.1"
        $global:MacIp = "10.99.99.2"
    } elseif ([CfgMgr]::ProbeHostAlive("192.168.2.1", 22, 70)) {
        $global:MacPresent = $true
        $global:MacMode = "USB-C"
        $global:ConnMode = "USB-C"
        $global:PcIp = "192.168.2.2"
        $global:MacIp = "192.168.2.1"
    }
}

# ---------------------------------------------------------------------------
# 2. Parse ARP Table Once for Hotspot (192.168.137.x), Bridge (192.168.2.x), & Mac Wi-Fi MAC
# ---------------------------------------------------------------------------
$hotspotNeighbors = New-Object System.Collections.Generic.List[string]
$bridgeNeighbors = New-Object System.Collections.Generic.List[string]
$arpMacWifiIp = ""

$arpOut = & arp.exe -a
foreach ($line in $arpOut) {
    # Note: Windows 11 Mobile Hotspot (icssvc) registers connected DHCP clients as 'static' in arp -a
    if ($line -match "^\s*(192\.168\.137\.(?!1\b|255\b)\d+)\s+(?!ff-ff-ff-ff-ff-ff)([0-9a-f]{2}-){5}[0-9a-f]{2}\s+(?:dynamic|static)") {
        $hotspotNeighbors.Add($matches[1])
    } elseif ($line -match "^\s*(192\.168\.2\.(?!1\b|2\b|255\b)\d+)\s+(?!ff-ff-ff-ff-ff-ff)([0-9a-f]{2}-){5}[0-9a-f]{2}\s+(?:dynamic|static)") {
        $bridgeNeighbors.Add($matches[1])
    }
    if ($line -match "^\s*(\d+\.\d+\.\d+\.\d+)\s+a0-78-17-5c-6b-93\s+") {
        $arpMacWifiIp = $matches[1]
    }
}

# ---------------------------------------------------------------------------
# 3. Detect Mac Wireless (Mobile Hotspot 192.168.137.x or Shared Wi-Fi LAN)
# ---------------------------------------------------------------------------
if (-not $global:MacPresent) {
    foreach ($hip in $hotspotNeighbors) {
        if ([CfgMgr]::TestTcpPort($hip, 22, 90)) {
            $global:MacPresent = $true
            $global:MacMode = "Wi-Fi (Hotspot)"
            $global:ConnMode = "Wi-Fi"
            $global:PcIp = "192.168.137.1"
            $global:MacIp = $hip
            break
        }
    }
}

if (-not $global:MacPresent) {
    $candMac = $arpMacWifiIp
    if (-not $candMac) {
        $candMac = [CfgMgr]::QueryMdnsHost("Manveers-M1-MacBook-Pro.local", 90)
    }
    if ($candMac -and -not $candMac.StartsWith("10.99.99.") -and -not $candMac.StartsWith("192.168.2.")) {
        if ([CfgMgr]::TestTcpPort($candMac, 22, 90)) {
            $localPc = [CfgMgr]::GetLocalIpForRemote($candMac)
            if ($localPc) {
                $global:MacPresent = $true
                $global:MacMode = "Wi-Fi"
                $global:ConnMode = "Wi-Fi"
                $global:PcIp = $localPc
                $global:MacIp = $candMac
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 4. Detect iPad (Wired USB-C, Bridged USB-C, Hotspot, or Wi-Fi LAN)
# ---------------------------------------------------------------------------
# 4a. Direct USB-C connection to PC (Apple iPad USB device or 172.20.10.1 USB tether)
if ([CfgMgr]::IsAppleIpadUsbConnected()) {
    $global:IpadPresent = $true
    $global:IpadMode = "USB-C"
} elseif (-not [string]::IsNullOrEmpty([CfgMgr]::GetLocalIpForRemote("172.20.10.1")) -and ([CfgMgr]::GetLocalIpForRemote("172.20.10.1")).StartsWith("172.20.10.")) {
    if ([CfgMgr]::ProbeHostAlive("172.20.10.1", 62078, 60) -and -not [CfgMgr]::TestTcpPort("172.20.10.1", 22, 40)) {
        $global:IpadPresent = $true
        $global:IpadMode = "USB-C"
        $global:IpadIp = "172.20.10.1"
    }
}

# 4b. Bridged USB-C via macOS Internet Sharing (192.168.2.x neighbor other than .1 Mac and .2 PC)
if (-not $global:IpadPresent) {
    foreach ($bip in $bridgeNeighbors) {
        if ([CfgMgr]::ProbeHostAlive($bip, 62078, 70)) {
            $global:IpadPresent = $true
            $global:IpadMode = "USB-C (Bridge)"
            $global:IpadIp = $bip
            break
        }
    }
}

# 4c. Active/Recent Moonlight iPad session or serverinfo poll on Sunshine ports (47984/47989)
if (-not $global:IpadPresent) {
    $peerIp = [CfgMgr]::GetSunshinePeerExcluding([string[]]@($global:MacIp, "10.99.99.2", "192.168.2.1"))
    if ($peerIp) {
        $global:IpadPresent = $true
        $global:IpadIp = $peerIp
        if ($peerIp.StartsWith("192.168.137.")) {
            $global:IpadMode = "Wi-Fi (Hotspot)"
        } elseif ($peerIp.StartsWith("172.20.10.") -or $peerIp.StartsWith("192.168.2.")) {
            $global:IpadMode = "USB-C"
        } else {
            $global:IpadMode = "Wi-Fi"
        }
    }
}

# 4d. Windows Mobile Hotspot (192.168.137.x neighbor that is alive and is NOT the Mac)
if (-not $global:IpadPresent) {
    foreach ($hip in $hotspotNeighbors) {
        if ($hip -ne $global:MacIp -and [CfgMgr]::ProbeHostAlive($hip, 62078, 120)) {
            $global:IpadPresent = $true
            $global:IpadMode = "Wi-Fi (Hotspot)"
            $global:IpadIp = $hip
            break
        }
    }
}

# 4e. mDNS resolution on local Wi-Fi (iPad.local + Manveers-iPad.local in single query window)
if (-not $global:IpadPresent) {
    $mip = [CfgMgr]::QueryMdnsHosts([string[]]@("iPad.local", "Manveers-iPad.local"), 85)
    if ($mip -and $mip -ne $global:MacIp -and [CfgMgr]::ProbeHostAlive($mip, 62078, 75)) {
        $global:IpadPresent = $true
        $global:IpadMode = "Wi-Fi"
        $global:IpadIp = $mip
    }
}

# 4f. Cached Last-Known iPad IP fallback
$lastIpadFile = "C:\VirtualDisplayDriver\last_ipad_ip.txt"
if (-not $global:IpadPresent -and [System.IO.File]::Exists($lastIpadFile)) {
    $cachedIp = ([System.IO.File]::ReadAllText($lastIpadFile)).Trim()
    if ($cachedIp -and $cachedIp -ne $global:MacIp -and [CfgMgr]::ProbeHostAlive($cachedIp, 62078, 70)) {
        if (-not [CfgMgr]::TestTcpPort($cachedIp, 22, 45)) {
            $global:IpadPresent = $true
            $global:IpadIp = $cachedIp
            $global:IpadMode = if ($cachedIp.StartsWith("192.168.137.")) { "Wi-Fi (Hotspot)" } else { "Wi-Fi" }
        }
    }
}

if ($global:IpadIp) {
    [System.IO.File]::WriteAllText($lastIpadFile, $global:IpadIp)
}

# ---------------------------------------------------------------------------
# 5. Update Windows Moonlight Client Host Entries via .NET Registry (0.2ms, zero PSDrive load)
# ---------------------------------------------------------------------------
$rk1 = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Moonlight Game Streaming Project\Moonlight\hosts\1", $true)
if ($rk1) {
    $rk1.SetValue("localaddress", $global:PcIp)
    $rk1.SetValue("manualaddress", "192.168.137.1")
    $rk1.Close()
}
$rk2 = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Moonlight Game Streaming Project\Moonlight\hosts\2", $true)
if ($rk2) {
    $rk2.SetValue("localaddress", $global:MacIp)
    $rk2.SetValue("manualaddress", $global:MacIp)
    $rk2.Close()
}

$iniPath = "$env:USERPROFILE\Moonlight\Moonlight Game Streaming Project\Moonlight.ini"
if ([System.IO.File]::Exists($iniPath)) {
    $iniContent = [System.IO.File]::ReadAllText($iniPath)
    $iniContent = [regex]::Replace($iniContent, '(?m)^1\\localaddress=.*$', "1\localaddress=$($global:PcIp)")
    $iniContent = [regex]::Replace($iniContent, '(?m)^1\\manualaddress=.*$', "1\manualaddress=192.168.137.1")
    $iniContent = [regex]::Replace($iniContent, '(?m)^2\\localaddress=.*$', "2\localaddress=$($global:MacIp)")
    $iniContent = [regex]::Replace($iniContent, '(?m)^2\\manualaddress=.*$', "2\manualaddress=$($global:MacIp)")
    [System.IO.File]::WriteAllText($iniPath, $iniContent)
}

Write-Output "Mac=$global:MacPresent($global:MacMode)|iPad=$global:IpadPresent($global:IpadMode)|PcIp=$global:PcIp|MacIp=$global:MacIp|IpadIp=$global:IpadIp"
