#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fortify - Windows 11 Hardening Tool
.DESCRIPTION
    Modular security hardening for Windows 11. Combines telemetry elimination,
    AI/Copilot removal, network hardening, and deep security configuration.
    Each module can be run independently or all at once.
.PARAMETER Modules
    Comma-separated list of modules to run. Options: telemetry, ai, network, security.
    Default: all modules.
.PARAMETER List
    Show available modules and exit.
.EXAMPLE
    .\fortify.ps1
    .\fortify.ps1 -Modules telemetry,ai
    .\fortify.ps1 -List
#>

param(
    [string[]]$Modules,
    [switch]$List
)

$ErrorActionPreference = "Continue"

. "$PSScriptRoot\modules\utils.ps1"

$available = [ordered]@{
    "telemetry" = @{ File = "telemetry.ps1"; Desc = "Disable telemetry services, registry policies, scheduled tasks" }
    "ai"        = @{ File = "ai_removal.ps1"; Desc = "Remove Copilot, Recall, and all AI integration with reinstall prevention" }
    "network"   = @{ File = "network.ps1"; Desc = "Firewall hardening, disable insecure protocols, remove unnecessary services" }
    "security"  = @{ File = "security.ps1"; Desc = "ASR rules, Defender, credential protection, TLS, PowerShell lockdown" }
}

if ($List) {
    Write-Host ""
    Write-Host "Fortify - Available Modules" -ForegroundColor Cyan
    Write-Host ""
    foreach ($key in $available.Keys) {
        Write-Host "  $key" -ForegroundColor White -NoNewline
        Write-Host " - $($available[$key].Desc)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "Usage: .\fortify.ps1 -Modules telemetry,ai" -ForegroundColor Yellow
    Write-Host "       .\fortify.ps1                         (runs all modules)" -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

if (-not (Test-FortifyAdmin)) {
    Write-Host "Fortify requires Administrator privileges. Right-click and run as Administrator." -ForegroundColor Red
    exit 1
}

# Default to all modules
if (-not $Modules -or $Modules.Count -eq 0) {
    $Modules = @($available.Keys)
}

# Validate module names
foreach ($m in $Modules) {
    if (-not $available.Contains($m)) {
        Write-Host "Unknown module: $m" -ForegroundColor Red
        Write-Host "Available: $($available.Keys -join ', ')" -ForegroundColor Yellow
        exit 1
    }
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  FORTIFY - Windows 11 Hardening Tool" -ForegroundColor Cyan
Write-Host "  Game Deity Studios LLC" -ForegroundColor DarkGray
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Modules: $($Modules -join ', ')" -ForegroundColor White
Write-Host ""

$startTime = Get-Date

foreach ($m in $Modules) {
    $script = Join-Path $PSScriptRoot "modules\$($available[$m].File)"
    . $script
}

$elapsed = (Get-Date) - $startTime

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  FORTIFY COMPLETE" -ForegroundColor Green
Write-Host "  Elapsed: $($elapsed.ToString('mm\:ss'))" -ForegroundColor DarkGray
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Reboot recommended to finalize all changes." -ForegroundColor Yellow
Write-Host ""
