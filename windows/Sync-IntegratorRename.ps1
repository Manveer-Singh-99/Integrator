<#
==============================================================================================
Integrator Windows PC Migration & Synchronization Assistant (windows/Sync-IntegratorRename.ps1)
==============================================================================================

1. MODULE PURPOSE & ARCHITECTURAL SCOPE
----------------------------------------------------------------------------------------------
Automates the git origin migration, branch synchronization, directory rename, backwards-
compatible NTFS directory junction creation, and release binary compilation on Windows 10/11
workstations reconnecting to the Integrator codebase. Ensures the local repository directory
is migrated from the legacy project name (`mac-windows-usbc-bridge`) to `Integrator`, preserves
external tooling paths via an NTFS directory junction (`mklink /J`), and optionally compiles
the Rust core/CLI release binaries (`integrator.exe` and `integrator_core.dll`) and native WinUI 3
GUI (`IntegratorUI.csproj`) when dev toolchains are present.

2. ARCHITECTURAL LINKAGES & DEPENDENCIES
----------------------------------------------------------------------------------------------
- Upstream Callers:
  - Invoked manually by developers or administrators when reconnecting a Windows PC or
    syncing after repository rename.
- Downstream Callees:
  - `git.exe`: Updates remote origin, fetches, and pulls latest commits from origin/main.
  - Windows Command Shell (`cmd.exe /c mklink /J`): Creates NTFS directory junction for backwards compatibility.
  - Rust Toolchain (`cargo.exe`): Compiles release binaries (`cargo build --release`).
  - .NET SDK (`dotnet.exe`): Compiles the native WinUI 3 desktop application (`ui-windows\IntegratorUI.csproj`).
- Cross-Platform / Cross-Device Flow:
  - Synchronizes the Windows workstation's build artifacts and repository configuration with the
    macOS counterpart.

3. EXECUTION & CONCURRENCY MODEL
----------------------------------------------------------------------------------------------
- Executed synchronously from PowerShell in the local repository working copy.
- Performs sequential atomic operations: git remote update -> git pull -> folder rename & junction ->
  toolchain compilation.

4. SECURITY & SAFETY INVARIANTS
----------------------------------------------------------------------------------------------
- Strict Error Handling: `$ErrorActionPreference = "Stop"` and explicit `$LASTEXITCODE`
  verification after every external process execution (`git`, `cmd.exe mklink`, `cargo`, `dotnet`).
- Path Quoting & Validation: All paths passed to cmd.exe or shell utilities are explicitly quoted
  to prevent command injection or whitespace truncation.
- Idempotent Junction Creation: Checks for existing destination directory and legacy junction
  before creating or modifying filesystem links.
==============================================================================================

.SYNOPSIS
    Automates the migration, git synchronization, and build of the Integrator Windows repository.

.DESCRIPTION
    Validates git origin, pulls origin/main, renames legacy folder to Integrator with NTFS junction,
    and builds Rust and WinUI 3 binaries.

.PARAMETER NewRemote
    Target git remote URL for the Integrator repository (default: https://github.com/Manveer-Singh-99/Integrator.git).

.PARAMETER LegacyDirName
    Legacy repository directory name used for NTFS junction compatibility (default: mac-windows-usbc-bridge).

.EXAMPLE
    .\Sync-IntegratorRename.ps1
#>

param(
    [ValidateNotNullOrEmpty()]
    [string]$NewRemote = "https://github.com/Manveer-Singh-99/Integrator.git",
    [ValidateNotNullOrEmpty()]
    [string]$LegacyDirName = "mac-windows-usbc-bridge"
)

$ErrorActionPreference = "Stop"
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Integrator Windows PC Migration & Sync Assistant  " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# Validate Git availability
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git executable was not found in PATH. Please install Git for Windows before running this script."
}

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
    if ($LASTEXITCODE -ne 0) { throw "git remote set-url origin failed with exit code $LASTEXITCODE" }
} else {
    Write-Host "[✓] Git remote origin already up-to-date." -ForegroundColor Green
}

# Step 2: Fetch and pull latest main
Write-Host "[*] Pulling latest commits from origin/main..." -ForegroundColor Yellow
git fetch origin
if ($LASTEXITCODE -ne 0) { throw "git fetch origin failed with exit code $LASTEXITCODE" }
git pull origin main
if ($LASTEXITCODE -ne 0) { throw "git pull origin main failed with exit code $LASTEXITCODE" }

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
            if ($LASTEXITCODE -ne 0) { Write-Warning "mklink /J exited with code $LASTEXITCODE" }
        }
        Set-Location $TargetDir
    }
} else {
    Write-Host "[✓] Folder already named 'Integrator'." -ForegroundColor Green
    $JunctionPath = Join-Path -Path $ParentPath -ChildPath $LegacyDirName
    if (-not (Test-Path $JunctionPath)) {
        Write-Host "[+] Creating backwards compatibility junction: $LegacyDirName -> Integrator" -ForegroundColor Green
        cmd.exe /c "mklink /J `"$JunctionPath`" `"$TargetDir`""
        if ($LASTEXITCODE -ne 0) { Write-Warning "mklink /J exited with code $LASTEXITCODE" }
    }
}

# Step 4: Build Windows Release Binaries
$AppDir = Join-Path -Path (Get-Location) -ChildPath "app"
if (Test-Path $AppDir) {
    Set-Location $AppDir
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        Write-Host "[*] Building release core & CLI binaries (cargo build --release)..." -ForegroundColor Yellow
        cargo build --release
        if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed with exit code $LASTEXITCODE" }
        Write-Host "[✓] Rust core build completed: target\release\integrator.exe & integrator_core.dll" -ForegroundColor Green
    } else {
        Write-Host "[!] Cargo not found in PATH. Skipping Rust compilation." -ForegroundColor Gray
    }

    $UiProj = Join-Path -Path $AppDir -ChildPath "ui-windows\IntegratorUI.csproj"
    if ((Test-Path $UiProj) -and (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        $ArchPlat = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "ARM64" } else { "x64" }
        Write-Host "[*] Building native WinUI 3 GUI (IntegratorUI.csproj, Platform=$ArchPlat)..." -ForegroundColor Yellow
        dotnet build $UiProj -c Release -p:Platform=$ArchPlat
        if ($LASTEXITCODE -ne 0) { throw "dotnet build IntegratorUI.csproj failed with exit code $LASTEXITCODE" }
        Write-Host "[✓] WinUI 3 build completed." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Migration & Sync Complete! Workstation is Ready.  " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
