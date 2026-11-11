# Find Moonlight executable
$moonlightExe = "C:\Program Files\Moonlight Game Streaming\Moonlight.exe"
if (-not (Test-Path $moonlightExe)) {
    $found = Get-ChildItem -Path @("C:\Program Files", "$env:LOCALAPPDATA") -Filter "Moonlight.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $moonlightExe = $found.FullName }
}
# Determine Mac IP
$macIp = $args[0]
if (-not $macIp) {
    if (Test-Path "C:\VirtualDisplayDriver\detect_connection.ps1") {
        . "C:\VirtualDisplayDriver\detect_connection.ps1" | Out-Null
        $macIp = $global:MacIp
    }
}
if (-not $macIp) { $macIp = "10.99.99.2" }
# Update Moonlight host 2 registry entry with current Mac IP
$regPath = "HKCU:\Software\Moonlight Game Streaming Project\Moonlight\hosts\2"
if (Test-Path $regPath) {
    Set-ItemProperty $regPath -Name "localaddress" -Value $macIp -ErrorAction SilentlyContinue
    Set-ItemProperty $regPath -Name "manualaddress" -Value $macIp -ErrorAction SilentlyContinue
}
# Wait up to 6 seconds for Sunshine on Mac (port 47989) to be ready
for ($i = 0; $i -lt 30; $i++) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $tcp.BeginConnect($macIp, 47989, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne(200)) {
            $tcp.EndConnect($ar)
            $tcp.Close()
            break
        }
    } catch { }
    finally { $tcp.Dispose() }
    Start-Sleep -Milliseconds 200
}
# Kill any existing Moonlight instance cleanly
Stop-Process -Name Moonlight -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
# Launch Moonlight in fullscreen 1920x1200 @ 165Hz with host audio
Start-Process -FilePath $moonlightExe -ArgumentList "stream `"$macIp`" Desktop --resolution 1920x1200 --fps 165 --bitrate 100000 --audio-on-host --display-mode fullscreen"
