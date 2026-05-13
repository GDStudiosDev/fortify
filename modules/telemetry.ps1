# Fortify - Telemetry Module
# Disables Microsoft telemetry services, registry hooks, and scheduled tasks.

param([switch]$Standalone)

$ErrorActionPreference = "Continue"

if ($Standalone) {
    . "$PSScriptRoot\utils.ps1"
    if (-not (Test-FortifyAdmin)) {
        Write-Host "This module requires Administrator privileges." -ForegroundColor Red
        exit 1
    }
}

Write-FortifyBanner "TELEMETRY: SERVICES"

$services = @(
    @{ Name = "DiagTrack";          Desc = "Connected User Experiences and Telemetry" },
    @{ Name = "dmwappushservice";   Desc = "WAP Push Message Routing" },
    @{ Name = "InventorySvc";       Desc = "Inventory and Compatibility Appraisal" },
    @{ Name = "lfsvc";              Desc = "Geolocation Service" },
    @{ Name = "CDPSvc";             Desc = "Connected Devices Platform" },
    @{ Name = "DPS";                Desc = "Diagnostic Policy Service" },
    @{ Name = "whesvc";             Desc = "Windows Health and Optimized Experiences" },
    @{ Name = "WSearch";            Desc = "Windows Search (cloud indexing)" }
)

foreach ($svc in $services) {
    Disable-FortifyService -Name $svc.Name -Description $svc.Desc
}

# Delivery Optimization: cannot be fully disabled without breaking Windows Update.
# Set to HTTP only (no P2P) to eliminate peer telemetry exposure.
Set-FortifyRegistry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Value 0
Write-FortifyResult "Delivery Optimization set to HTTP only (no P2P)"

Write-FortifyBanner "TELEMETRY: REGISTRY POLICIES"

$registrySettings = @(
    # Core telemetry
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name = "DoNotShowFeedbackNotifications"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "AllowTelemetry"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name = "MaxTelemetryAllowed"; Value = 0 },

    # Advertising ID
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; Name = "DisabledByGroupPolicy"; Value = 1 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name = "Enabled"; Value = 0 },

    # App compatibility telemetry
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "AITEnable"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "DisableInventory"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"; Name = "DisableUAR"; Value = 1 },

    # CEIP
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"; Name = "CEIPEnable"; Value = 0 },

    # Activity history
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableActivityFeed"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "PublishUserActivities"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "UploadUserActivities"; Value = 0 },

    # Tailored experiences and feedback
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"; Name = "TailoredExperiencesWithDiagnosticDataEnabled"; Value = 0 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"; Name = "NumberOfSIUFInPeriod"; Value = 0 },

    # Handwriting and tablet telemetry
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"; Name = "PreventHandwritingErrorReports"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; Value = 1 },

    # Cloud content and consumer features
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsConsumerFeatures"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableSoftLanding"; Value = 1 },
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableTailoredExperiencesWithDiagnosticData"; Value = 1 },

    # Location
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name = "DisableLocation"; Value = 1 },

    # OneDrive sync
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; Name = "DisableFileSyncNGSC"; Value = 1 },

    # Edge telemetry
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "DiagnosticData"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "PersonalizationReportingEnabled"; Value = 0 },

    # Office telemetry
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry"; Name = "DisableTelemetry"; Value = 1 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry"; Name = "SendTelemetry"; Value = 3 }
)

foreach ($reg in $registrySettings) {
    try {
        Set-FortifyRegistry -Path $reg.Path -Name $reg.Name -Value $reg.Value
        Write-FortifyResult "$($reg.Name) = $($reg.Value)"
    } catch {
        Write-FortifyResult "$($reg.Name): $($_.Exception.Message)" -Status "FAIL"
    }
}

Write-FortifyBanner "TELEMETRY: SCHEDULED TASKS"

$tasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing",
    "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReceiver",
    "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting",
    "\Microsoft\Windows\Flighting\FeatureConfig\GovernedFeatureUsageProcessing",
    "\Microsoft\Windows\PerformanceTrace\ShowFeedbackToast",
    "\Microsoft\Windows\Sustainability\SustainabilityTelemetry"
)

foreach ($task in $tasks) {
    try {
        Disable-ScheduledTask -TaskName $task -ErrorAction Stop | Out-Null
        Write-FortifyResult "Disabled $($task | Split-Path -Leaf)"
    } catch {
        Write-FortifyResult "$($task | Split-Path -Leaf): $($_.Exception.Message)" -Status "WARN"
    }
}

Write-Host ""
Write-Host "Telemetry module complete." -ForegroundColor Cyan
