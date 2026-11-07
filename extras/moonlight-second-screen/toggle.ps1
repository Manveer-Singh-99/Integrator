Add-Type -AssemblyName System.Windows.Forms

# Zero-CIM Ultra-Fast Detection (~50ms)
. "C:\VirtualDisplayDriver\detect_connection.ps1" | Out-Null

$deviceId = "ROOT\DISPLAY\0001"
$isRunning = [CfgMgr]::IsDeviceStarted($deviceId)

if ($isRunning) {
    # 1. Terminate active Sunshine stream (disconnects iPad, Mac, or any client immediately & stops GPU encoder)
    & curl.exe -k -s -u "admin:alpine" -X POST "https://localhost:47990/api/apps/close" -H "Content-Type: application/json" | Out-Null

    # 2. Disable Virtual Display via pnputil (~80ms instead of 5000ms WMI Disable-PnpDevice)
    & pnputil.exe /disable-device $deviceId | Out-Null

    # 3. Close Moonlight on Mac if running (non-blocking)
    Start-Process -FilePath "C:\Windows\System32\OpenSSH\ssh.exe" -ArgumentList "-i `"C:\Users\Manveer Singh\.ssh\id_ed25519`" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no manveersingh@$($global:MacIp) `"killall Moonlight 2>/dev/null || true`"" -WindowStyle Hidden

    [System.Windows.Forms.MessageBox]::Show("Virtual display DISABLED ($($global:ConnMode)).", "Second Screen", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
} else {
    # 1. Enable Virtual Display via pnputil (~80ms instead of 5000ms WMI Enable-PnpDevice)
    & pnputil.exe /enable-device $deviceId | Out-Null

    # 2. Ensure SunshineService is running
    $svc = Get-Service -Name SunshineService -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne "Running") {
        Start-Service -Name SunshineService -ErrorAction SilentlyContinue
    }

    # 3. Wait brief 400ms for Windows DXGI display topology to attach the new monitor
    Start-Sleep -Milliseconds 400

    # 4. Launch Moonlight on Mac if connected to Mac (non-blocking)
    Start-Process -FilePath "C:\Windows\System32\OpenSSH\ssh.exe" -ArgumentList "-i `"C:\Users\Manveer Singh\.ssh\id_ed25519`" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no manveersingh@$($global:MacIp) `"/usr/local/bin/stream-pc-screen.sh $($global:PcIp)`"" -WindowStyle Hidden

    [System.Windows.Forms.MessageBox]::Show("Virtual display ENABLED via $($global:ConnMode) ($($global:PcIp)).`nDisplay active.", "Second Screen", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}
