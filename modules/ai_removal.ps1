# Fortify - AI Removal Module
# Removes Microsoft Copilot, Recall, and all AI integration from Windows.
# Includes reinstall prevention and deep policy enforcement.

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
# PHASE 1: AI SERVICES
# ============================================================
Write-FortifyBanner "AI REMOVAL: SERVICES"

$aiServices = @(
    @{ Name = "MicrosoftCopilotElevationService"; Desc = "Copilot Elevation Service" },
    @{ Name = "WSAIFabricSvc";                    Desc = "AI Fabric Service" }
)

foreach ($svc in $aiServices) {
    Disable-FortifyService -Name $svc.Name -Description $svc.Desc
}

# ============================================================
# PHASE 2: AI SCHEDULED TASKS
# ============================================================
Write-FortifyBanner "AI REMOVAL: SCHEDULED TASKS"

$aiTasks = @(
    "\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingIdle",
    "\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingLimit",
    "\Microsoft\Windows\WindowsAI\ClickToDo\ModelCachingUpdate",
    "\Microsoft\Windows\WindowsAI\Recall\InitialConfiguration",
    "\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration",
    "\Microsoft\Windows\WindowsAI\Settings\InitialConfiguration"
)

foreach ($task in $aiTasks) {
    try {
        Disable-ScheduledTask -TaskName $task -ErrorAction Stop | Out-Null
        Write-FortifyResult "Disabled $($task | Split-Path -Leaf)"
    } catch {
        Write-FortifyResult "$($task | Split-Path -Leaf): $($_.Exception.Message)" -Status "WARN"
    }
}

# ============================================================
# PHASE 3: CORE AI REGISTRY POLICIES
# ============================================================
Write-FortifyBanner "AI REMOVAL: REGISTRY POLICIES"

$aiRegistry = @(
    # Windows Copilot
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"; Name = "TurnOffWindowsCopilot"; Value = 1 },
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"; Name = "TurnOffWindowsCopilot"; Value = 1 },

    # Windows Recall
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name = "DisableAIDataAnalysis"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name = "TurnOffSaveSnapshots"; Value = 1 },
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name = "DisableAIDataAnalysis"; Value = 1 },
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name = "TurnOffSaveSnapshots"; Value = 1 },

    # ClickToDo / Smart Actions
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name = "DisableClickToDo"; Value = 1 },

    # Edge AI features
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "CopilotCDPPageContext"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "CopilotPageContext"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "HubsSidebarEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "DiscoverPageContextEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EdgeAssetDeliveryServiceEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EdgeShoppingAssistantEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EdgeCollectionsEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EdgeFollowEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "AIGenThemesEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "SearchInSidebarEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "LinkedAccountEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "BingChatNewTabPageEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "BingSidebarEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "ComposeInlineEnabled"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "QuickSearchShowMiniMenu"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "ShowRecommendationsEnabled"; Value = 0 },

    # Bing in Start menu
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name = "BingSearchEnabled"; Value = 0 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name = "CortanaConsent"; Value = 0 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "DisableWebSearch"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name = "ConnectedSearchUseWeb"; Value = 0 },

    # Copilot taskbar button
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name = "ShowCopilotButton"; Value = 0 },

    # Office AI
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common"; Name = "DisableCopilot"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeAI"; Name = "DisableOfficeAI"; Value = 1 },
    @{ Path = "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Common"; Name = "DisableCopilot"; Value = 1 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ExperimentConfigs\Ecs"; Name = "Enabled"; Value = 0 },

    # Widgets and news
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"; Name = "AllowNewsAndInterests"; Value = 0 },

    # Content delivery and suggestions
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-338393Enabled"; Value = 0 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-353694Enabled"; Value = 0 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SubscribedContent-353696Enabled"; Value = 0 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SilentInstalledAppsEnabled"; Value = 0 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SoftLandingEnabled"; Value = 0 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name = "SystemPaneSuggestionsEnabled"; Value = 0 }
)

foreach ($reg in $aiRegistry) {
    try {
        Set-FortifyRegistry -Path $reg.Path -Name $reg.Name -Value $reg.Value
        Write-FortifyResult "$($reg.Name) = $($reg.Value)"
    } catch {
        Write-FortifyResult "$($reg.Name): $($_.Exception.Message)" -Status "FAIL"
    }
}

# ============================================================
# PHASE 4: DEEP AI POLICIES (Capability Access, Agents, Paint, Notepad)
# ============================================================
Write-FortifyBanner "AI REMOVAL: DEEP POLICIES"

$deepPolicies = @(
    # Capability Access Manager: deny AI model access
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI"; Name = "Value"; Value = "Deny"; Type = "String" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels"; Name = "Value"; Value = "Deny"; Type = "String" },

    # AI agent policies
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name = "DisableAIAgentCreation"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"; Name = "DisableAIAgentAccess"; Value = 1 },

    # Copilot shell eligibility
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Shell\Copilot"; Name = "IsCopilotEligible"; Value = 0 },

    # Paint AI
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Paint"; Name = "DisableCocreator"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Paint"; Name = "DisableImageCreator"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Paint"; Name = "DisableGenerativeErase"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Paint"; Name = "DisableGenerativeFill"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Paint"; Name = "DisableGenerativeExpand"; Value = 1 },

    # Notepad AI
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Notepad"; Name = "DisableRewriteWithAI"; Value = 1 },

    # Office AI training opt out
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeAI"; Name = "DisableOfficeAITraining"; Value = 1 }
)

foreach ($reg in $deepPolicies) {
    $type = if ($reg.Type) { $reg.Type } else { "DWord" }
    try {
        Set-FortifyRegistry -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type $type
        Write-FortifyResult "$($reg.Name) = $($reg.Value)"
    } catch {
        Write-FortifyResult "$($reg.Name): $($_.Exception.Message)" -Status "FAIL"
    }
}

# ============================================================
# PHASE 5: PACKAGE REMOVAL
# ============================================================
Write-FortifyBanner "AI REMOVAL: PACKAGES"

$aiPackages = @(
    "Microsoft.Copilot",
    "Microsoft.M365Companions",
    "Microsoft.AIFabric*",
    "aimgr",
    "Microsoft.Windows.Ai.Copilot.Provider",
    "Microsoft.WindowsCopilot*",
    "Microsoft.AIXPlatformPlugin*",
    "Microsoft.Windows.AIX*",
    "MicrosoftWindows.CrossDevice*",
    "Microsoft.GameAssist*",
    "Microsoft.ActionsServer*",
    "Microsoft.WritingAssist*"
)

foreach ($pkg in $aiPackages) {
    $found = Get-AppxPackage -AllUsers -Name $pkg -ErrorAction SilentlyContinue
    if ($found) {
        foreach ($p in $found) {
            try {
                Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop
                Write-FortifyResult "Removed $($p.Name)"
            } catch {
                Write-FortifyResult "Could not remove $($p.Name), attempting deprovisioning" -Status "WARN"
                try {
                    Get-AppxProvisionedPackage -Online |
                        Where-Object { $_.DisplayName -eq $p.Name } |
                        Remove-AppxProvisionedPackage -Online -ErrorAction Stop | Out-Null
                    Write-FortifyResult "Deprovisioned $($p.Name)"
                } catch {
                    Write-FortifyResult "$($p.Name): $($_.Exception.Message)" -Status "FAIL"
                }
            }
        }
    }
}

# Remove provisioned packages to prevent reinstall on new user profiles
$provPatterns = 'Copilot|AIFabric|aimgr|M365Companions|AIX|GameAssist|ActionsServer|WritingAssist'
$provPkgs = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match $provPatterns }

foreach ($pp in $provPkgs) {
    try {
        Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null
        Write-FortifyResult "Deprovisioned $($pp.DisplayName)"
    } catch {
        Write-FortifyResult "Deprovision $($pp.DisplayName): $($_.Exception.Message)" -Status "FAIL"
    }
}

# ============================================================
# PHASE 6: REINSTALL PREVENTION
# ============================================================
Write-FortifyBanner "AI REMOVAL: REINSTALL PREVENTION"

# Mark packages as end-of-life to block Store reinstall
$eolBase = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife"
$eolTargets = @(
    "Microsoft.Copilot_8wekyb3d8bbwe",
    "Microsoft.M365Companions_8wekyb3d8bbwe",
    "Microsoft.Windows.Ai.Copilot.Provider_cw5n1h2txyewy"
)

foreach ($eol in $eolTargets) {
    $eolPath = "$eolBase\$eol"
    if (-not (Test-Path $eolPath)) { New-Item -Path $eolPath -Force | Out-Null }
    Write-FortifyResult "EOL entry: $eol"
}

# Mark as deprovisioned to prevent new-user reprovisioning
$deprovBase = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned"
foreach ($eol in $eolTargets) {
    $deprovPath = "$deprovBase\$eol"
    if (-not (Test-Path $deprovPath)) { New-Item -Path $deprovPath -Force | Out-Null }
    Write-FortifyResult "Deprovision entry: $eol"
}

# Group Policy removal policy
$removalBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx\PackageRemovalPolicies"
$removalTargets = @(
    @{ Name = "Microsoft.Copilot"; Value = 1 },
    @{ Name = "Microsoft.M365Companions"; Value = 1 }
)

foreach ($rm in $removalTargets) {
    Set-FortifyRegistry -Path $removalBase -Name $rm.Name -Value $rm.Value
    Write-FortifyResult "GP removal policy: $($rm.Name)"
}

# Remove Recall optional feature if present
try {
    $recall = Get-WindowsOptionalFeature -Online -FeatureName "Recall" -ErrorAction Stop
    if ($recall.State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName "Recall" -NoRestart -ErrorAction Stop | Out-Null
        Write-FortifyResult "Recall optional feature disabled"
    } else {
        Write-FortifyResult "Recall optional feature already disabled" -Status "SKIP"
    }
} catch {
    Write-FortifyResult "Recall feature not present on this build" -Status "SKIP"
}

Write-Host ""
Write-Host "AI removal module complete." -ForegroundColor Cyan
