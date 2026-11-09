$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $desktopPath "Toggle Second Screen.lnk"

if (Test-Path $shortcutPath) { Remove-Item $shortcutPath -Force }

$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($shortcutPath)
$Shortcut.TargetPath = "C:\VirtualDisplayDriver\VddCtl.exe"
$Shortcut.Arguments = "toggle"
$Shortcut.WorkingDirectory = "C:\VirtualDisplayDriver"
$Shortcut.WindowStyle = 7
$Shortcut.Description = "Toggle Virtual Second Screen (2560x1600 @ 60Hz)"

# DisplaySwitch.exe has a clean monitor/display icon on all Windows versions
$Shortcut.IconLocation = "C:\Windows\System32\DisplaySwitch.exe,0"
$Shortcut.Save()

Write-Host "Created shortcut pointing to VddCtl.exe toggle (GUI-subsystem, zero console windows)."
