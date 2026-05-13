# Fortify - Shared Utilities

function Test-FortifyAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-FortifyRegistry {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord"
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
}

function Disable-FortifyService {
    param(
        [string]$Name,
        [string]$Description
    )
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return $false }

    try {
        if ($svc.Status -eq 'Running') {
            Stop-Service -Name $Name -Force -ErrorAction Stop
        }
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
        Write-Host "  [OK] $Description" -ForegroundColor Green
        return $true
    } catch {
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name 'Start' -Value 4 -Type DWord -Force -ErrorAction Stop
            Write-Host "  [OK] $Description (via registry)" -ForegroundColor Yellow
            return $true
        } catch {
            Write-Host "  [FAIL] $Description, $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
}

function Write-FortifyBanner {
    param([string]$Phase)
    Write-Host ""
    Write-Host "=== $Phase ===" -ForegroundColor Cyan
}

function Write-FortifyResult {
    param(
        [string]$Message,
        [string]$Status = "OK"
    )
    switch ($Status) {
        "OK"   { Write-Host "  [OK] $Message" -ForegroundColor Green }
        "SKIP" { Write-Host "  [SKIP] $Message" -ForegroundColor DarkGray }
        "WARN" { Write-Host "  [WARN] $Message" -ForegroundColor Yellow }
        "FAIL" { Write-Host "  [FAIL] $Message" -ForegroundColor Red }
    }
}
