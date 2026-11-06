# Zero-CIM Precompiled Mutual Detection (~35ms)
if (-not ("CfgMgr" -as [type])) {
    Add-Type -Path "C:\VirtualDisplayDriver\CfgMgr.dll"
}

$global:ConnMode = "Wi-Fi"
$global:PcIp = "192.168.137.1"
$global:MacIp = "192.168.137.58"

# Check if any Apple USB-C NCM device (VID 05AC, PID 1902) is connected and started
$appleConnected = $false
foreach ($k in (Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Enum\USB\VID_05AC&PID_1902" -ErrorAction SilentlyContinue)) {
    if ([CfgMgr]::IsDeviceStarted("USB\VID_05AC&PID_1902\" + $k.PSChildName)) {
        $appleConnected = $true
        break
    }
}

$usbcAlive = $false
if ($appleConnected) {
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        # 1. Probe direct link-local 10.99.99.2 (60ms timeout)
        $reply = $ping.Send("10.99.99.2", 60)
        if ($reply.Status -eq "Success") {
            $usbcAlive = $true
            $global:ConnMode = "USB-C"
            $global:PcIp = "10.99.99.1"
            $global:MacIp = "10.99.99.2"
        } else {
            # 2. Probe macOS Internet Sharing link 192.168.2.1 (60ms timeout)
            $reply2 = $ping.Send("192.168.2.1", 60)
            if ($reply2.Status -eq "Success") {
                $usbcAlive = $true
                $global:ConnMode = "USB-C"
                $global:PcIp = "192.168.2.2"
                $global:MacIp = "192.168.2.1"
            }
        }
    } catch {}
    $ping.Dispose()
}

# 3. Fall back to Wi-Fi if USB-C is not alive
if (-not $usbcAlive) {
    $arpOut = & arp.exe -a
    foreach ($line in $arpOut) {
        if ($line -match "^\s*(192\.168\.137\.(?!1\b|255\b)\d+)\s+([0-9a-f]{2}-){5}[0-9a-f]{2}\s+dynamic") {
            $global:MacIp = $matches[1]
            break
        }
    }
}

$regHost1 = "HKCU:\Software\Moonlight Game Streaming Project\Moonlight\hosts\1"
if (Test-Path $regHost1) {
    Set-ItemProperty -Path $regHost1 -Name "localaddress" -Value $global:PcIp -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $regHost1 -Name "manualaddress" -Value "192.168.137.1" -ErrorAction SilentlyContinue
}
$regHost2 = "HKCU:\Software\Moonlight Game Streaming Project\Moonlight\hosts\2"
if (Test-Path $regHost2) {
    Set-ItemProperty -Path $regHost2 -Name "localaddress" -Value $global:MacIp -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $regHost2 -Name "manualaddress" -Value $global:MacIp -ErrorAction SilentlyContinue
}

$iniPath = "$env:USERPROFILE\Moonlight\Moonlight Game Streaming Project\Moonlight.ini"
if (Test-Path $iniPath) {
    $iniContent = [System.IO.File]::ReadAllText($iniPath)
    $iniContent = [regex]::Replace($iniContent, '(?m)^1\\localaddress=.*$', "1\localaddress=$($global:PcIp)")
    $iniContent = [regex]::Replace($iniContent, '(?m)^1\\manualaddress=.*$', "1\manualaddress=192.168.137.1")
    $iniContent = [regex]::Replace($iniContent, '(?m)^2\\localaddress=.*$', "2\localaddress=$($global:MacIp)")
    $iniContent = [regex]::Replace($iniContent, '(?m)^2\\manualaddress=.*$', "2\manualaddress=$($global:MacIp)")
    [System.IO.File]::WriteAllText($iniPath, $iniContent)
}

Write-Output "$($global:ConnMode)|$($global:PcIp)|$($global:MacIp)"
