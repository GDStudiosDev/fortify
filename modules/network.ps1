# Fortify - Network Module
# Hardens firewall, disables insecure protocols, removes unnecessary services.
# Preserves: RDP, core networking, Hyper-V integration.

param([switch]$Standalone)

$ErrorActionPreference = "Continue"

if ($Standalone) {
    . "$PSScriptRoot\utils.ps1"
    if (-not (Test-FortifyAdmin)) {
        Write-Host "This module requires Administrator privileges." -ForegroundColor Red
        exit 1
    }
}

# ============================================================
# PHASE 1: FIREWALL
# ============================================================
Write-FortifyBanner "NETWORK: FIREWALL"

Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow
Write-FortifyResult "Default inbound: BLOCK (all profiles)"

$disablePatterns = @(
    "AllJoyn*",
    "Cast to Device*",
    "DIAL protocol*",
    "Feedback Hub*",
    "Game Bar*",
    "Microsoft Copilot*",
    "Microsoft Lync*",
    "Microsoft Teams*",
    "Microsoft To Do*",
    "MSN Weather*",
    "ms-resource*",
    "Network Discovery*",
    "Proximity sharing*",
    "Remote Assistance*",
    "Solitaire*",
    "Wi-Fi Direct*",
    "WFD*",
    "Windows Camera*",
    "Windows Media Player*",
    "Wireless Display*",
    "Xbox*",
    "Delivery Optimization*",
    "Connected Devices Platform*",
    "Start*",
    "Store Experience Host*",
    "Your account*",
    "Work or school account*",
    "Microsoft Store*",
    "Windows Feature Experience*",
    "App Installer*",
    "Windows Shell Experience*",
    "Windows Security*",
    "Microsoft Office Outlook*",
    "Microsoft Media Foundation*",
    "Desktop App Web Viewer*",
    "Microsoft Edge*"
)

$totalDisabled = 0
foreach ($pattern in $disablePatterns) {
    $rules = Get-NetFirewallRule -DisplayName $pattern -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq 'True' }
    if ($rules) {
        $rules | Disable-NetFirewallRule
        $count = @($rules).Count
        $totalDisabled += $count
        Write-FortifyResult "Disabled: $pattern ($count rules)"
    }
}
Write-Host "  Total inbound rules disabled: $totalDisabled" -ForegroundColor Cyan

# Verify critical rules remain
Write-Host ""
Write-Host "  Verifying critical rules remain enabled:" -ForegroundColor Yellow
$criticalPatterns = @("Remote Desktop*", "Core Networking*", "Hyper-V*")
foreach ($p in $criticalPatterns) {
    $enabled = Get-NetFirewallRule -DisplayName $p -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' }
    if ($enabled) {
        Write-FortifyResult "$p ($(@($enabled).Count) rules)"
    } else {
        Write-FortifyResult "No enabled rules for $p" -Status "WARN"
    }
}

# ============================================================
# PHASE 2: PROTOCOL HARDENING
# ============================================================
Write-FortifyBanner "NETWORK: PROTOCOL HARDENING"

# SMB1
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false -ErrorAction Stop
    Write-FortifyResult "SMB1 disabled"
} catch {
    Write-FortifyResult "SMB1: $($_.Exception.Message)" -Status "WARN"
}

# SMB signing
try {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false -ErrorAction Stop
    Write-FortifyResult "SMB signing required"
} catch {
    Write-FortifyResult "SMB signing: $($_.Exception.Message)" -Status "WARN"
}

# RDP: require NLA and force TLS security layer (SecurityLayer=0 with TLS 1.0 disabled breaks RDP)
Set-FortifyRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Set-FortifyRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2
Set-FortifyRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 3
Write-FortifyResult "RDP: NLA required, TLS security layer, high encryption"

# Remote Assistance
Set-FortifyRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
Write-FortifyResult "Remote Assistance disabled"

# AutoPlay
Set-FortifyRegistry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1
Write-FortifyResult "AutoPlay disabled"

# LLMNR
Set-FortifyRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
Write-FortifyResult "LLMNR disabled (prevents name poisoning)"

# WPAD
Set-FortifyRegistry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1
Write-FortifyResult "WPAD disabled (prevents proxy MITM)"

# NetBIOS over TCP/IP on all adapters
$adapters = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
foreach ($a in $adapters) {
    Set-ItemProperty -Path $a.PSPath -Name 'NetbiosOptions' -Value 2 -Type DWord -Force
}
Write-FortifyResult "NetBIOS over TCP/IP disabled (all adapters)"

# ============================================================
# PHASE 3: UNNECESSARY SERVICES
# ============================================================
Write-FortifyBanner "NETWORK: UNNECESSARY SERVICES"

$services = @(
    @{ Name = "Spooler";       Desc = "Print Spooler (attack surface if no printer)" },
    @{ Name = "SSDPSRV";       Desc = "SSDP Discovery (UPnP)" },
    @{ Name = "SharedAccess";  Desc = "Internet Connection Sharing" },
    @{ Name = "WebClient";     Desc = "WebDAV Client" },
    @{ Name = "WpnService";    Desc = "Windows Push Notifications" },
    @{ Name = "RmSvc";         Desc = "Radio Management Service" },
    @{ Name = "SysMain";       Desc = "SysMain/Superfetch" },
    @{ Name = "lmhosts";       Desc = "TCP/IP NetBIOS Helper" },
    @{ Name = "PcaSvc";        Desc = "Program Compatibility Assistant" }
)

foreach ($svc in $services) {
    Disable-FortifyService -Name $svc.Name -Description $svc.Desc
}

Write-Host ""
Write-Host "Network module complete." -ForegroundColor Cyan
