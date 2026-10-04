<#
.SYNOPSIS
    Exports the tenant's SKU catalog (with friendly names and consumption) and the service plans inside every SKU.
.DESCRIPTION
    Reads /subscribedSkus once and writes two CSV files: the SKU catalog (SkuPartNumber, SkuId, FriendlyName, CapabilityStatus,
    Enabled, Consumed, Available, AppliesTo) to OutputPath and the service plan list (SkuPartNumber, ServicePlanName,
    ServicePlanId, ProvisioningStatus, AppliesTo, FriendlyPlanName) to <OutputPath base>_ServicePlans.csv. Friendly names
    come from an inline table of common SKUs and plans; anything unknown falls back to the technical name. With -Json the
    raw subscribedSkus response is also saved, which is handy as input for other scripts or for diffing tenants.
.PARAMETER OutputPath
    Path of the SKU catalog CSV. Defaults to .\Reports\SkuCatalog_<timestamp>.csv; the plan CSV uses the same base plus _ServicePlans.
.PARAMETER Json
    Also write the unmodified /subscribedSkus payload to <OutputPath base>.json.
.PARAMETER PassThru
    Also emit the SKU catalog objects to the pipeline.
.EXAMPLE
    PS> .\Export-M365SkuCatalog.ps1
    Writes SkuCatalog_<timestamp>.csv and SkuCatalog_<timestamp>_ServicePlans.csv under .\Reports and prints the SKU count.
.EXAMPLE
    PS> .\Export-M365SkuCatalog.ps1 -OutputPath C:\Temp\Skus.csv -Json -PassThru | Where-Object { $_.Available -lt 0 }
    Exports catalog, plans and JSON to C:\Temp and shows SKUs that are in overage.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Organization.Read.All (delegated); Global Reader, License Administrator or Billing Administrator.
    Category    : Licensing
    Changes     : No
    Notes       : The inline friendly-name tables cover common SKUs and plans only. The authoritative, complete mapping is
                  Microsoft's "Product names and service plan identifiers for licensing" page, which offers a downloadable CSV
                  (linked below); this script deliberately makes no internet call to fetch it.
.LINK
    https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference
.LINK
    https://learn.microsoft.com/graph/api/subscribedsku-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$Json,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-GraphIfNeeded {
    <# Connects to Microsoft Graph only when there is no usable session for the required scopes. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )
    $context = Get-MgContext
    $missingScopes = @()
    if ($null -ne $context) {
        $missingScopes = @($Scopes | Where-Object { $context.Scopes -notcontains $_ })
    }
    if ($null -eq $context -or $missingScopes.Count -gt 0) {
        Write-Verbose "Connecting to Microsoft Graph with scopes: $($Scopes -join ', ')"
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
    }
    else {
        Write-Verbose "Reusing existing Microsoft Graph session for $($context.Account)."
    }
}

function Invoke-GraphPaged {
    <# GET helper that follows @odata.nextLink and returns every item in 'value'. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Headers
    )
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $requestParams = @{ Method = 'GET'; Uri = $nextLink; OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($null -ne $Headers) { $requestParams['Headers'] = $Headers }
        $response = Invoke-MgGraphRequest @requestParams
        if ($null -ne $response.PSObject.Properties['value']) {
            foreach ($item in $response.value) { $results.Add($item) }
        }
        elseif ($null -ne $response) {
            $results.Add($response)
        }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}

# Friendly names for common SKU part numbers and service plans; unknown values fall back to the technical name.
$skuFriendlyNames = @{
    'SPE_E3' = 'Microsoft 365 E3'; 'SPE_E5' = 'Microsoft 365 E5'; 'SPE_F1' = 'Microsoft 365 F1'; 'SPE_F3' = 'Microsoft 365 F3'
    'ENTERPRISEPACK' = 'Office 365 E3'; 'ENTERPRISEPREMIUM' = 'Office 365 E5'; 'STANDARDPACK' = 'Office 365 E1'; 'DESKLESSPACK' = 'Office 365 F3'
    'EMS' = 'Enterprise Mobility + Security E3'; 'EMSPREMIUM' = 'Enterprise Mobility + Security E5'
    'AAD_PREMIUM' = 'Microsoft Entra ID P1'; 'AAD_PREMIUM_P2' = 'Microsoft Entra ID P2'
    'INTUNE_A' = 'Microsoft Intune Plan 1'; 'INTUNE_A_D' = 'Microsoft Intune Plan 1 Device'; 'Intune_Suite' = 'Microsoft Intune Suite'
    'DEFENDER_ENDPOINT_P1' = 'Microsoft Defender for Endpoint P1'; 'WIN_DEF_ATP' = 'Microsoft Defender for Endpoint P2'
    'ATP_ENTERPRISE' = 'Microsoft Defender for Office 365 (Plan 1)'; 'THREAT_INTELLIGENCE' = 'Microsoft Defender for Office 365 (Plan 2)'
    'IDENTITY_THREAT_PROTECTION' = 'Microsoft 365 E5 Security'; 'INFORMATION_PROTECTION_COMPLIANCE' = 'Microsoft 365 E5 Compliance'
    'Microsoft_365_Copilot' = 'Microsoft 365 Copilot'; 'Microsoft_Teams_Premium' = 'Microsoft Teams Premium'; 'TEAMS_ESSENTIALS_AAD' = 'Microsoft Teams Essentials'
    'O365_BUSINESS_ESSENTIALS' = 'Microsoft 365 Business Basic'; 'O365_BUSINESS_PREMIUM' = 'Microsoft 365 Business Standard'; 'SPB' = 'Microsoft 365 Business Premium'
    'EXCHANGESTANDARD' = 'Exchange Online (Plan 1)'; 'EXCHANGEENTERPRISE' = 'Exchange Online (Plan 2)'; 'EXCHANGEDESKLESS' = 'Exchange Online Kiosk'
    'MCOEV' = 'Microsoft Teams Phone Standard'; 'MCOMEETADV' = 'Microsoft 365 Audio Conferencing'
    'POWER_BI_PRO' = 'Power BI Pro'; 'POWER_BI_STANDARD' = 'Power BI (free)'; 'FLOW_FREE' = 'Power Automate Free'
    'PROJECTPREMIUM' = 'Project Plan 5'; 'PROJECTPROFESSIONAL' = 'Project Plan 3'; 'VISIOCLIENT' = 'Visio Plan 2'
    'WIN10_VDA_E3' = 'Windows 10/11 Enterprise E3'; 'WIN10_VDA_E5' = 'Windows 10/11 Enterprise E5'
    'RIGHTSMANAGEMENT' = 'Azure Information Protection Plan 1'; 'DEVELOPERPACK_E5' = 'Microsoft 365 E5 Developer'
}
$planFriendlyNames = @{
    'EXCHANGE_S_ENTERPRISE' = 'Exchange Online (Plan 2)'; 'EXCHANGE_S_STANDARD' = 'Exchange Online (Plan 1)'; 'EXCHANGE_S_DESKLESS' = 'Exchange Online Kiosk'
    'SHAREPOINTENTERPRISE' = 'SharePoint (Plan 2)'; 'SHAREPOINTSTANDARD' = 'SharePoint (Plan 1)'; 'SHAREPOINTDESKLESS' = 'SharePoint Kiosk'
    'TEAMS1' = 'Microsoft Teams'; 'MCOSTANDARD' = 'Skype for Business Online (Plan 2)'; 'MCOEV' = 'Microsoft Teams Phone Standard'
    'MCOMEETADV' = 'Microsoft 365 Audio Conferencing'; 'INTUNE_A' = 'Microsoft Intune Plan 1'; 'INTUNE_O365' = 'Mobile Device Management for Office 365'
    'AAD_PREMIUM' = 'Microsoft Entra ID P1'; 'AAD_PREMIUM_P2' = 'Microsoft Entra ID P2'; 'MFA_PREMIUM' = 'Microsoft Entra multifactor authentication'
    'RMS_S_ENTERPRISE' = 'Azure Rights Management'; 'RMS_S_PREMIUM' = 'Azure Information Protection Premium P1'; 'RMS_S_PREMIUM2' = 'Azure Information Protection Premium P2'
    'OFFICESUBSCRIPTION' = 'Microsoft 365 Apps for enterprise'; 'OFFICE_BUSINESS' = 'Microsoft 365 Apps for business'
    'WINDEFATP' = 'Microsoft Defender for Endpoint'; 'MDE_SMB' = 'Microsoft Defender for Business'; 'ATA' = 'Microsoft Defender for Identity'
    'ATP_ENTERPRISE' = 'Microsoft Defender for Office 365 (Plan 1)'; 'THREAT_INTELLIGENCE' = 'Microsoft Defender for Office 365 (Plan 2)'
    'ADALLOM_S_STANDALONE' = 'Microsoft Defender for Cloud Apps'; 'MIP_S_CLP1' = 'Information Protection for Office 365 - Standard'
    'YAMMER_ENTERPRISE' = 'Viva Engage Core'; 'PROJECTWORKMANAGEMENT' = 'Microsoft Planner'; 'SWAY' = 'Sway'; 'FORMS_PLAN_E3' = 'Microsoft Forms (Plan E3)'
    'STREAM_O365_E3' = 'Microsoft Stream for Office 365 E3'; 'FLOW_O365_P2' = 'Power Automate for Office 365'; 'POWERAPPS_O365_P2' = 'Power Apps for Office 365'
    'WHITEBOARD_PLAN2' = 'Whiteboard (Plan 2)'; 'BPOS_S_TODO_2' = 'To-Do (Plan 2)'; 'WIN10_PRO_ENT_SUB' = 'Windows 10/11 Enterprise'
    'M365_COPILOT_BUSINESS_CHAT' = 'Microsoft 365 Copilot Chat'; 'M365_COPILOT_APPS' = 'Microsoft 365 Copilot in Productivity Apps'; 'M365_COPILOT_TEAMS' = 'Microsoft 365 Copilot in Teams'
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SkuCatalog_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
# Path.Combine tolerates an empty folder (bare file name in -OutputPath) where Join-Path would throw.
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
$plansPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_ServicePlans.csv' -f $baseName))
$jsonPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}.json' -f $baseName))

try { Connect-GraphIfNeeded -Scopes @('Organization.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus') }
catch { throw "Failed to read subscribed SKUs: $($_.Exception.Message)" }

$skuRows = New-Object -TypeName System.Collections.Generic.List[object]
$planRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($sku in $skus) {
    $partNumber = [string]$sku.skuPartNumber
    $friendly = $skuFriendlyNames[$partNumber]
    if ([string]::IsNullOrEmpty($friendly)) { $friendly = $partNumber }
    $skuRows.Add([PSCustomObject]@{
            SkuPartNumber    = $partNumber
            SkuId            = $sku.skuId
            FriendlyName     = $friendly
            CapabilityStatus = $sku.capabilityStatus
            Enabled          = [int]$sku.prepaidUnits.enabled
            Consumed         = [int]$sku.consumedUnits
            Available        = ([int]$sku.prepaidUnits.enabled - [int]$sku.consumedUnits)
            AppliesTo        = $sku.appliesTo
            ServicePlanCount = @($sku.servicePlans | Where-Object { $null -ne $_ }).Count
        })
    foreach ($plan in @($sku.servicePlans | Where-Object { $null -ne $_ })) {
        $planName = [string]$plan.servicePlanName
        $friendlyPlan = $planFriendlyNames[$planName]
        if ([string]::IsNullOrEmpty($friendlyPlan)) { $friendlyPlan = $planName }
        $planRows.Add([PSCustomObject]@{
                SkuPartNumber      = $partNumber
                SkuFriendlyName    = $friendly
                ServicePlanName    = $planName
                ServicePlanId      = $plan.servicePlanId
                ProvisioningStatus = $plan.provisioningStatus
                AppliesTo          = $plan.appliesTo
                FriendlyPlanName   = $friendlyPlan
            })
    }
}
$skuOutput = @($skuRows | Sort-Object -Property FriendlyName)
$skuOutput | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$planRows | Sort-Object -Property SkuPartNumber, ServicePlanName | Export-Csv -Path $plansPath -NoTypeInformation -Encoding UTF8
if ($Json) { ConvertTo-Json -InputObject $skus -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8 }

$unknownSkus = @($skuOutput | Where-Object { $_.FriendlyName -eq $_.SkuPartNumber })
Write-Host 'SKU catalog summary' -ForegroundColor Cyan
Write-Host ('  SKUs / service plan rows  : {0} / {1}' -f $skuOutput.Count, $planRows.Count)
Write-Host ('  SKUs without friendly name: {0}' -f $unknownSkus.Count)
foreach ($unknown in $unknownSkus) { Write-Host ('    {0}' -f $unknown.SkuPartNumber) }
Write-Host ('  Catalog CSV               : {0}' -f $OutputPath)
Write-Host ('  Service plan CSV          : {0}' -f $plansPath)
if ($Json) { Write-Host ('  JSON                      : {0}' -f $jsonPath) }
if ($PassThru) { $skuOutput }
#endregion Main
