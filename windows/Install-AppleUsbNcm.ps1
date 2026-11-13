# Backwards compatibility forwarding wrapper
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$TargetScript = Join-Path $ScriptDir "..\Legacy\windows\Install-AppleUsbNcm.ps1"

if (Test-Path $TargetScript) {
    & $TargetScript @args
} else {
    Write-Error "Error: Legacy script not found at $TargetScript"
    exit 1
}
