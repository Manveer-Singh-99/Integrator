# Zero-CIM Precompiled Mutual Detection (~35ms)
if (-not ("CfgMgr" -as [type])) {
    Add-Type -Path "C:\VirtualDisplayDriver\CfgMgr.dll"
}

$global:ConnMode = "Wi-Fi"
$global:PcIp = "192.168.137.1"
$global:MacIp = "192.168.137.58"

$usbcAlive = $false
if ([CfgMgr]::IsDeviceStarted("USB\VID_05AC&PID_1902\FVFDX9HXQ05D")) {
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        $reply = $ping.Send("10.99.99.2", 80)
        if ($reply.Status -eq "Success") { $usbcAlive = $true }
    } catch {}
}

if ($usbcAlive) {
    $global:ConnMode = "USB-C"
    $global:PcIp = "10.99.99.1"
    $global:MacIp = "10.99.99.2"
} else {
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
    Set-ItemProperty -Path $regHost2 -Name "manualaddress" -Value "10.99.99.2" -ErrorAction SilentlyContinue
}

$iniPath = "C:\Users\Manveer Singh\Moonlight\Moonlight Game Streaming Project\Moonlight.ini"
if (Test-Path $iniPath) {
    $iniContent = [System.IO.File]::ReadAllText($iniPath)
    $iniContent = [regex]::Replace($iniContent, '(?m)^1\\localaddress=.*$', "1\localaddress=$($global:PcIp)")
    $iniContent = [regex]::Replace($iniContent, '(?m)^1\\manualaddress=.*$', "1\manualaddress=192.168.137.1")
    $iniContent = [regex]::Replace($iniContent, '(?m)^2\\localaddress=.*$', "2\localaddress=$($global:MacIp)")
    $iniContent = [regex]::Replace($iniContent, '(?m)^2\\manualaddress=.*$', "2\manualaddress=10.99.99.2")
    [System.IO.File]::WriteAllText($iniPath, $iniContent)
}

Write-Output "$($global:ConnMode)|$($global:PcIp)|$($global:MacIp)"
