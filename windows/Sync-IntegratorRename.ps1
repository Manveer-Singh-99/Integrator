# Sync-IntegratorRename.ps1
# Automates the migration and synchronization of the Windows PC (HP OMEN) to Integrator.
# Run this script when reconnecting the PC.

$ErrorActionPreference = "Stop"
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Integrator Windows PC Migration & Sync Assistant  " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$CurrentDir = Get-Item -Path $PSScriptRoot\..
$CurrentDirName = $CurrentDir.Name
$ParentPath = $CurrentDir.Parent.FullName
$TargetDir = Join-Path -Path $ParentPath -ChildPath "Integrator"

Write-Host "[*] Current repository path: $($CurrentDir.FullName)" -ForegroundColor Yellow

# Step 1: Update Git Remote Origin
Set-Location $CurrentDir.FullName
$CurrentRemote = git remote get-url origin 2>$null
Write-Host "[*] Current Git origin: $CurrentRemote" -ForegroundColor Gray

$NewRemote = "https://github.com/Manveer-Singh-99/Integrator.git"
if ($CurrentRemote -ne $NewRemote) {
    Write-Host "[+] Updating Git remote origin to $NewRemote..." -ForegroundColor Green
    git remote set-url origin $NewRemote
} else {
    Write-Host "[✓] Git remote origin already up-to-date." -ForegroundColor Green
}

# Step 2: Fetch and pull latest main
Write-Host "[*] Pulling latest commits from origin/main..." -ForegroundColor Yellow
git fetch origin
git pull origin main

# Step 3: Folder rename if running under old name
if ($CurrentDirName -ne "Integrator") {
    Write-Host "[!] Repository directory is currently named '$CurrentDirName'." -ForegroundColor Yellow
    if (Test-Path $TargetDir) {
        Write-Host "[!] Destination '$TargetDir' already exists. Skipping folder move." -ForegroundColor Gray
    } else {
        Set-Location $ParentPath
        Write-Host "[+] Renaming folder '$CurrentDirName' -> 'Integrator'..." -ForegroundColor Green
        Rename-Item -Path $CurrentDir.FullName -NewName "Integrator"
        
        # Create directory junction for backwards compatibility
        $JunctionPath = Join-Path -Path $ParentPath -ChildPath "mac-windows-usbc-bridge"
        if (-not (Test-Path $JunctionPath)) {
            Write-Host "[+] Creating directory junction for backwards compatibility: $JunctionPath -> Integrator" -ForegroundColor Green
            cmd.exe /c "mklink /J `"$JunctionPath`" `"$TargetDir`""
        }
        Set-Location $TargetDir
    }
} else {
    Write-Host "[✓] Folder already named 'Integrator'." -ForegroundColor Green
    $JunctionPath = Join-Path -Path $ParentPath -ChildPath "mac-windows-usbc-bridge"
    if (-not (Test-Path $JunctionPath)) {
        Write-Host "[+] Creating backwards compatibility junction: mac-windows-usbc-bridge -> Integrator" -ForegroundColor Green
        cmd.exe /c "mklink /J `"$JunctionPath`" `"$TargetDir`""
    }
}

# Step 4: Build Windows Release Binary
$AppDir = Join-Path -Path (Get-Location) -ChildPath "app"
if (Test-Path $AppDir) {
    Set-Location $AppDir
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        Write-Host "[*] Building release binary with updated embedded icon and autostart..." -ForegroundColor Yellow
        cargo build --release
        Write-Host "[✓] Release build completed successfully: target\release\Integrator.exe" -ForegroundColor Green
    } else {
        Write-Host "[!] Cargo not found in PATH. Skipping compilation." -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Migration & Sync Complete! Workstation is Ready.  " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
