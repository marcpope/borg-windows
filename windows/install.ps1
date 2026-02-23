# Borg Backup Windows Installer
# Run this script in the borg-portable folder.
# Requires: Python 3.11 already installed

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== Borg Backup Windows Installer ===" -ForegroundColor Cyan

# Find the wheel file
$wheel = Get-ChildItem "$scriptDir\*.whl" | Select-Object -First 1
if (-not $wheel) {
    Write-Host "ERROR: No .whl file found in $scriptDir" -ForegroundColor Red
    exit 1
}
Write-Host "Installing wheel: $($wheel.Name)"

# Install the wheel
pip install $wheel.FullName
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: pip install failed" -ForegroundColor Red
    exit 1
}

# Find where borg.exe was installed
$borgExe = (Get-Command borg -ErrorAction SilentlyContinue).Source
if (-not $borgExe) {
    Write-Host "ERROR: borg.exe not found on PATH after install" -ForegroundColor Red
    exit 1
}
$borgDir = Split-Path -Parent $borgExe
Write-Host "borg.exe installed at: $borgExe"

# Copy DLLs next to borg.exe
$dlls = Get-ChildItem "$scriptDir\*.dll"
foreach ($dll in $dlls) {
    Write-Host "  Copying $($dll.Name) -> $borgDir"
    Copy-Item $dll.FullName "$borgDir\" -Force
}

# Also copy DLLs to the site-packages borg directories (for the .pyd extensions)
$sitePackages = python -c "import site; print(site.getsitepackages()[0])"
$borgPkg = Join-Path $sitePackages "borg"
if (Test-Path $borgPkg) {
    $subDirs = @("", "algorithms", "crypto", "platform")
    foreach ($sub in $subDirs) {
        $target = Join-Path $borgPkg $sub
        if (Test-Path $target) {
            foreach ($dll in $dlls) {
                Copy-Item $dll.FullName "$target\" -Force
            }
        }
    }
    Write-Host "DLLs copied to site-packages borg directories"
}

Write-Host ""
Write-Host "=== Installation complete! ===" -ForegroundColor Green
Write-Host "Try running: borg --version"
