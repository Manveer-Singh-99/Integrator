Add-Type -AssemblyName System.Windows.Forms

# Zero-CIM Ultra-Fast Detection (~50ms)
. "C:\VirtualDisplayDriver\detect_connection.ps1" | Out-Null

$deviceId = "ROOT\DISPLAY\0001"
$isRunning = [CfgMgr]::IsDeviceStarted($deviceId)

if ($isRunning) {
    # Disable Virtual Display via pnputil (~80ms instead of 5000ms WMI Disable-PnpDevice)
    & pnputil.exe /disable-device $deviceId | Out-Null
    # Close Moonlight on Mac immediately in background
    Start-Process -FilePath "C:\Windows\System32\OpenSSH\ssh.exe" -ArgumentList "-i `"C:\Users\Manveer Singh\.ssh\id_ed25519`" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no manveersingh@$($global:MacIp) `"killall Moonlight 2>/dev/null || true`"" -WindowStyle Hidden
    [System.Windows.Forms.MessageBox]::Show("Virtual display DISABLED ($($global:ConnMode)).", "Second Screen", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
} else {
    # Enable Virtual Display via pnputil (~80ms instead of 5000ms WMI Enable-PnpDevice)
    & pnputil.exe /enable-device $deviceId | Out-Null

    # Ensure SunshineService is running (without killing/restarting it if already running, saving 5 seconds of QSV encoder probing!)
    $svc = Get-Service -Name SunshineService -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne "Running") {
        Start-Service -Name SunshineService -ErrorAction SilentlyContinue
    }

    # Wait brief 400ms for Windows DXGI display topology to attach the new monitor
    Start-Sleep -Milliseconds 400

    # Launch Moonlight on Mac immediately in background (non-blocking)
    Start-Process -FilePath "C:\Windows\System32\OpenSSH\ssh.exe" -ArgumentList "-i `"C:\Users\Manveer Singh\.ssh\id_ed25519`" -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no manveersingh@$($global:MacIp) `"/usr/local/bin/stream-pc-screen.sh $($global:PcIp)`"" -WindowStyle Hidden

    [System.Windows.Forms.MessageBox]::Show("Virtual display ENABLED via $($global:ConnMode) ($($global:PcIp)).`nMac Moonlight launched.", "Second Screen", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}
