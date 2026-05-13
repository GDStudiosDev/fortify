# Fortify - Security Module
# ASR rules, Defender hardening, credential protection, TLS, PowerShell lockdown.

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
# PHASE 1: ATTACK SURFACE REDUCTION RULES
# ============================================================
Write-FortifyBanner "SECURITY: ATTACK SURFACE REDUCTION"

# Mode: 1 = Enabled, 6 = Warn/Audit
$asrRules = @(
    @{ Id = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"; Name = "Block executable content from email/webmail"; Mode = 1 },
    @{ Id = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"; Name = "Block Office creating child processes"; Mode = 1 },
    @{ Id = "3B576869-A4EC-4529-8536-B80A7769E899"; Name = "Block Office creating executable content"; Mode = 1 },
    @{ Id = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"; Name = "Block Office injecting into other processes"; Mode = 1 },
    @{ Id = "D3E037E1-3EB8-44C8-A917-57927947596D"; Name = "Block JS/VBS launching downloaded executables"; Mode = 1 },
    @{ Id = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"; Name = "Block obfuscated scripts"; Mode = 1 },
    @{ Id = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"; Name = "Block Win32 API from Office macros"; Mode = 1 },
    @{ Id = "01443614-cd74-433a-b99e-2ecdc07bfc25"; Name = "Block executables unless prevalent/aged/trusted"; Mode = 6 },
    @{ Id = "c1db55ab-c21a-4637-bb3f-a12568109d35"; Name = "Advanced ransomware protection"; Mode = 1 },
    @{ Id = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"; Name = "Block credential stealing from LSASS"; Mode = 1 },
    @{ Id = "d1e49aac-8f56-4280-b9ba-993a6d77406c"; Name = "Block process creations from PSExec/WMI"; Mode = 6 },
    @{ Id = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"; Name = "Block untrusted/unsigned from USB"; Mode = 1 },
    @{ Id = "26190899-1602-49e8-8b27-eb1d0a1ce869"; Name = "Block Office comms creating child processes"; Mode = 1 },
    @{ Id = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"; Name = "Block Adobe Reader creating child processes"; Mode = 1 },
    @{ Id = "e6db77e5-3df2-4cf1-b95a-636979351e5b"; Name = "Block persistence via WMI event subscription"; Mode = 1 }
)

foreach ($rule in $asrRules) {
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id -AttackSurfaceReductionRules_Actions $rule.Mode -ErrorAction Stop
        $modeStr = if ($rule.Mode -eq 1) { "ENABLED" } else { "AUDIT" }
        Write-FortifyResult "[$modeStr] $($rule.Name)"
    } catch {
        Write-FortifyResult "$($rule.Name): $($_.Exception.Message)" -Status "FAIL"
    }
}

# ============================================================
# PHASE 2: WINDOWS DEFENDER
# ============================================================
Write-FortifyBanner "SECURITY: WINDOWS DEFENDER"

$defenderSettings = @{
    "DisableRealtimeMonitoring"        = $false
    "DisableBehaviorMonitoring"        = $false
    "DisableIOAVProtection"            = $false
    "DisableScriptScanning"            = $false
    "DisableRemovableDriveScanning"    = $false
    "DisableBlockAtFirstSeen"          = $false
    "DisableArchiveScanning"           = $false
    "DisableEmailScanning"             = $false
    "DisableIntrusionPreventionSystem" = $false
    "PUAProtection"                    = 1
    "CloudBlockLevel"                  = 4
    "CloudExtendedTimeout"             = 50
    "EnableNetworkProtection"          = 1
    "EnableFileHashComputation"        = $true
    "SignatureUpdateInterval"          = 8
    "CheckForSignaturesBeforeRunningScan" = $true
    "SubmitSamplesConsent"             = 2
}

foreach ($key in $defenderSettings.Keys) {
    try {
        $params = @{ $key = $defenderSettings[$key] }
        Set-MpPreference @params -ErrorAction Stop
        Write-FortifyResult "$key = $($defenderSettings[$key])"
    } catch {
        Write-FortifyResult "$key: $($_.Exception.Message)" -Status "FAIL"
    }
}

# ============================================================
# PHASE 3: CREDENTIAL PROTECTION
# ============================================================
Write-FortifyBanner "SECURITY: CREDENTIAL PROTECTION"

$credRegistry = @(
    # Disable WDigest (prevents cleartext password storage in memory)
    @{ Path = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\Wdigest"; Name = "UseLogonCredential"; Value = 0 },
    # Disable LM hash storage
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "NoLMHash"; Value = 1 },
    # NTLMv2 only (refuse LM and NTLM)
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LmCompatibilityLevel"; Value = 5 },
    # LSA protection audit mode
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe"; Name = "AuditLevel"; Value = 8 },
    # Restrict anonymous SAM enumeration
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymous"; Value = 1 },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name = "RestrictAnonymousSAM"; Value = 1 },
    # SMB null session restriction
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"; Name = "RestrictNullSessAccess"; Value = 1 },
    # Disable password reveal button
    @{ Path = "HKLM:\Software\Policies\Microsoft\Windows\CredUI"; Name = "DisablePasswordReveal"; Value = 1 },
    # Prevent MSI privilege escalation
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "AlwaysInstallElevated"; Value = 0 }
)

foreach ($reg in $credRegistry) {
    try {
        Set-FortifyRegistry -Path $reg.Path -Name $reg.Name -Value $reg.Value
        Write-FortifyResult "$($reg.Name) = $($reg.Value)"
    } catch {
        Write-FortifyResult "$($reg.Name): $($_.Exception.Message)" -Status "FAIL"
    }
}

# SMB encryption
try {
    Set-SmbServerConfiguration -EncryptData $true -Confirm:$false -ErrorAction Stop
    Write-FortifyResult "SMB encryption enabled"
} catch {
    Write-FortifyResult "SMB encryption: $($_.Exception.Message)" -Status "WARN"
}

# ============================================================
# PHASE 4: TLS HARDENING
# ============================================================
Write-FortifyBanner "SECURITY: TLS HARDENING"

$schannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"

# Disable insecure protocols
foreach ($proto in @("SSL 2.0", "SSL 3.0", "TLS 1.0")) {
    foreach ($role in @("Server", "Client")) {
        $path = "$schannelBase\Protocols\$proto\$role"
        Set-FortifyRegistry -Path $path -Name "Enabled" -Value 0
        Set-FortifyRegistry -Path $path -Name "DisabledByDefault" -Value 1
    }
    Write-FortifyResult "Disabled: $proto"
}

# Enable secure protocols
foreach ($proto in @("TLS 1.2", "TLS 1.3")) {
    foreach ($role in @("Server", "Client")) {
        $path = "$schannelBase\Protocols\$proto\$role"
        Set-FortifyRegistry -Path $path -Name "Enabled" -Value 1
        Set-FortifyRegistry -Path $path -Name "DisabledByDefault" -Value 0
    }
    Write-FortifyResult "Enabled: $proto"
}

# DH minimum key size
$dhPath = "$schannelBase\KeyExchangeAlgorithms\Diffie-Hellman"
Set-FortifyRegistry -Path $dhPath -Name "ServerMinKeyBitLength" -Value 4096
Set-FortifyRegistry -Path $dhPath -Name "ClientMinKeyBitLength" -Value 4096
Write-FortifyResult "DH minimum key size: 4096 bit"

# .NET strong crypto (all framework versions, both bitness)
$netPaths = @(
    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
    "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
)
foreach ($path in $netPaths) {
    Set-FortifyRegistry -Path $path -Name "SchUseStrongCrypto" -Value 1
    Set-FortifyRegistry -Path $path -Name "SystemDefaultTlsVersions" -Value 1
}
Write-FortifyResult ".NET strong crypto enabled (all frameworks)"

# ============================================================
# PHASE 5: POWERSHELL HARDENING
# ============================================================
Write-FortifyBanner "SECURITY: POWERSHELL HARDENING"

# Disable PowerShell v2 engine (defense evasion vector)
try {
    $psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
    if ($psv2.State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null
        Write-FortifyResult "PowerShell v2 engine disabled"
    } else {
        Write-FortifyResult "PowerShell v2 already disabled" -Status "SKIP"
    }
} catch {
    Write-FortifyResult "PSv2 disable: $($_.Exception.Message)" -Status "WARN"
}

# Script Block Logging
$sblPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
Set-FortifyRegistry -Path $sblPath -Name "EnableScriptBlockLogging" -Value 1
Write-FortifyResult "Script Block Logging enabled"

# Transcription
$transPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
Set-FortifyRegistry -Path $transPath -Name "EnableTranscripting" -Value 1
Set-FortifyRegistry -Path $transPath -Name "EnableInvocationHeader" -Value 1

$psLogDir = "C:\PowerShellLogs"
if (-not (Test-Path $psLogDir)) { New-Item -Path $psLogDir -ItemType Directory -Force | Out-Null }
Set-FortifyRegistry -Path $transPath -Name "OutputDirectory" -Value $psLogDir -Type "String"
Write-FortifyResult "Transcription enabled (output: $psLogDir)"

# Disable WinRM Basic Auth
Set-FortifyRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0
Write-FortifyResult "WinRM Basic Auth disabled"

# ============================================================
# PHASE 6: MISCELLANEOUS
# ============================================================
Write-FortifyBanner "SECURITY: MISCELLANEOUS"

# DEP system-wide
try {
    $bcdResult = & bcdedit /set "{current}" nx OptOut 2>&1
    Write-FortifyResult "DEP set to OptOut"
} catch {
    Write-FortifyResult "DEP: $($_.Exception.Message)" -Status "WARN"
}

# SEHOP
Set-FortifyRegistry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0
Write-FortifyResult "SEHOP enabled"

# Disable Windows Script Host
Set-FortifyRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
Write-FortifyResult "Windows Script Host disabled"

# Zone information preserved on attachments
Set-FortifyRegistry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2
Write-FortifyResult "Zone info preserved on downloads"

# Disable TCP timestamps (prevents OS fingerprinting)
try {
    & netsh int tcp set global timestamps=disabled 2>&1 | Out-Null
    Write-FortifyResult "TCP timestamps disabled"
} catch {
    Write-FortifyResult "TCP timestamps: $($_.Exception.Message)" -Status "WARN"
}

Write-Host ""
Write-Host "Security module complete." -ForegroundColor Cyan
