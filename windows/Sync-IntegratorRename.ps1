# Sync-IntegratorRename.ps1
# Automates the migration and synchronization of the Windows PC to Integrator.
# Run this script when reconnecting the PC.

param(
    [string]$NewRemote = "https://github.com/Manveer-Singh-99/Integrator.git",
    [string]$LegacyDirName = "mac-windows-usbc-bridge"
)

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
        $JunctionPath = Join-Path -Path $ParentPath -ChildPath $LegacyDirName
        if (-not (Test-Path $JunctionPath)) {
            Write-Host "[+] Creating directory junction for backwards compatibility: $JunctionPath -> Integrator" -ForegroundColor Green
            cmd.exe /c "mklink /J `"$JunctionPath`" `"$TargetDir`""
        }
        Set-Location $TargetDir
    }
} else {
    Write-Host "[✓] Folder already named 'Integrator'." -ForegroundColor Green
    $JunctionPath = Join-Path -Path $ParentPath -ChildPath $LegacyDirName
    if (-not (Test-Path $JunctionPath)) {
        Write-Host "[+] Creating backwards compatibility junction: $LegacyDirName -> Integrator" -ForegroundColor Green
        cmd.exe /c "mklink /J `"$JunctionPath`" `"$TargetDir`""
    }
}

# Step 4: Build Windows Release Binaries
$AppDir = Join-Path -Path (Get-Location) -ChildPath "app"
if (Test-Path $AppDir) {
    Set-Location $AppDir
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        Write-Host "[*] Building release core & CLI binaries (cargo build --release)..." -ForegroundColor Yellow
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed" }
        Write-Host "[✓] Rust core build completed: target\release\integrator.exe & integrator_core.dll" -ForegroundColor Green
    } else {
        Write-Host "[!] Cargo not found in PATH. Skipping Rust compilation." -ForegroundColor Gray
    }

    $UiProj = Join-Path -Path $AppDir -ChildPath "ui-windows\IntegratorUI.csproj"
    if ((Test-Path $UiProj) -and (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        $ArchPlat = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "ARM64" } else { "x64" }
        Write-Host "[*] Building native WinUI 3 GUI (IntegratorUI.csproj, Platform=$ArchPlat)..." -ForegroundColor Yellow
        dotnet build $UiProj -c Release -p:Platform=$ArchPlat
        if ($LASTEXITCODE -ne 0) { throw "dotnet build IntegratorUI.csproj failed" }
        Write-Host "[✓] WinUI 3 build completed." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Migration & Sync Complete! Workstation is Ready.  " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
