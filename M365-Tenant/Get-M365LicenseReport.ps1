<#
.SYNOPSIS
    Reports Microsoft 365 license consumption per SKU and, optionally, licensed users whose licenses could be reclaimed.
.DESCRIPTION
    Reads every subscription from /subscribedSkus and outputs one row per SKU with a friendly product name,
    enabled, warning, suspended and consumed units, the units still available and the percentage used.
    With -IncludeUsers it also lists every licensed user from /users (advanced query on assignedLicenses) with
    the friendly names of the assigned licenses and the last sign-in (interactive or non-interactive) and
    flags accounts that are disabled or inactive for -DaysInactive days but still licensed. The user list is
    written to a second CSV named <OutputPath base>_Users.csv. Prints the SKUs close to exhaustion and the
    number of potentially reclaimable licenses.
.PARAMETER IncludeUsers
    Also export licensed users with their sign-in activity and a reclaim flag (one extra paged query, not one call per user).
.PARAMETER DaysInactive
    Days without any sign-in after which an enabled, licensed user is flagged InactiveButLicensed. Default 90.
.PARAMETER OutputPath
    Path of the SKU CSV file. Defaults to .\Reports\M365Licenses_<timestamp>.csv. The user CSV uses the same base name plus _Users.
.PARAMETER PassThru
    Also emit the SKU objects (and, with -IncludeUsers, the user objects) to the pipeline.
.EXAMPLE
    PS> .\Get-M365LicenseReport.ps1
    Exports all SKUs with consumption figures and lists the ones with 5 % or 5 units (or fewer) left.
.EXAMPLE
    PS> .\Get-M365LicenseReport.ps1 -IncludeUsers -DaysInactive 60 -OutputPath C:\Temp\Licenses.csv -Verbose
    Additionally writes C:\Temp\Licenses_Users.csv with every licensed user, flagging disabled accounts and accounts without a sign-in for 60 days.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Organization.Read.All, User.Read.All (delegated). -IncludeUsers additionally requests AuditLog.Read.All
                  for signInActivity; Global Reader or License Administrator (plus Reports Reader for sign-in data) can run it.
    Category    : Licensing
    Changes     : No
    Notes       : signInActivity requires a Microsoft Entra ID P1 (or higher) license in the tenant. When the scope cannot be
                  consented or Graph rejects the property, the script retries without it and the inactivity flag is skipped.
                  Users who never signed in are flagged only when the account is older than -DaysInactive days. The friendly
                  name table covers common SKUs; unknown SKUs fall back to the SKU part number (see the licensing service plan
                  reference linked below for the full list). Available can be negative when a SKU is in overage.
.LINK
    https://learn.microsoft.com/graph/api/subscribedsku-list
.LINK
    https://learn.microsoft.com/graph/api/resources/signinactivity
.LINK
    https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeUsers,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [string]$OutputPath,

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

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; $null when empty. #>
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}

# Friendly names for common SKU part numbers; anything else falls back to the part number itself.
$skuFriendlyNames = @{
    'SPE_E3'                            = 'Microsoft 365 E3'
    'SPE_E5'                            = 'Microsoft 365 E5'
    'SPE_F1'                            = 'Microsoft 365 F1'
    'SPE_F3'                            = 'Microsoft 365 F3'
    'M365_F1'                           = 'Microsoft 365 F1'
    'ENTERPRISEPACK'                    = 'Office 365 E3'
    'ENTERPRISEPREMIUM'                 = 'Office 365 E5'
    'STANDARDPACK'                      = 'Office 365 E1'
    'DESKLESSPACK'                      = 'Office 365 F3'
    'EMS'                               = 'Enterprise Mobility + Security E3'
    'EMSPREMIUM'                        = 'Enterprise Mobility + Security E5'
    'AAD_PREMIUM'                       = 'Microsoft Entra ID P1'
    'AAD_PREMIUM_P2'                    = 'Microsoft Entra ID P2'
    'INTUNE_A'                          = 'Microsoft Intune Plan 1'
    'INTUNE_A_D'                        = 'Microsoft Intune Plan 1 Device'
    'Intune_Suite'                      = 'Microsoft Intune Suite'
    'DEFENDER_ENDPOINT_P1'              = 'Microsoft Defender for Endpoint P1'
    'WIN_DEF_ATP'                       = 'Microsoft Defender for Endpoint P2'
    'MDATP_XPLAT'                       = 'Microsoft Defender for Endpoint P2 (cross-platform)'
    'ATP_ENTERPRISE'                    = 'Microsoft Defender for Office 365 (Plan 1)'
    'THREAT_INTELLIGENCE'               = 'Microsoft Defender for Office 365 (Plan 2)'
    'IDENTITY_THREAT_PROTECTION'        = 'Microsoft 365 E5 Security'
    'INFORMATION_PROTECTION_COMPLIANCE' = 'Microsoft 365 E5 Compliance'
    'Microsoft_365_Copilot'             = 'Microsoft 365 Copilot'
    'O365_BUSINESS_ESSENTIALS'          = 'Microsoft 365 Business Basic'
    'O365_BUSINESS_PREMIUM'             = 'Microsoft 365 Business Standard'
    'SPB'                               = 'Microsoft 365 Business Premium'
    'EXCHANGESTANDARD'                  = 'Exchange Online (Plan 1)'
    'EXCHANGEENTERPRISE'                = 'Exchange Online (Plan 2)'
    'EXCHANGEDESKLESS'                  = 'Exchange Online Kiosk'
    'SHAREPOINTSTANDARD'                = 'SharePoint Online (Plan 1)'
    'SHAREPOINTENTERPRISE'              = 'SharePoint Online (Plan 2)'
    'MCOEV'                             = 'Microsoft Teams Phone Standard'
    'MCOMEETADV'                        = 'Microsoft 365 Audio Conferencing'
    'TEAMS_ESSENTIALS_AAD'              = 'Microsoft Teams Essentials'
    'Microsoft_Teams_Premium'           = 'Microsoft Teams Premium'
    'POWER_BI_PRO'                      = 'Power BI Pro'
    'POWER_BI_STANDARD'                 = 'Power BI (free)'
    'PROJECTPREMIUM'                    = 'Project Plan 5'
    'PROJECTPROFESSIONAL'               = 'Project Plan 3'
    'VISIOCLIENT'                       = 'Visio Plan 2'
    'FLOW_FREE'                         = 'Power Automate Free'
    'POWERAPPS_VIRAL'                   = 'Power Apps Plan 2 Trial'
    'WIN10_VDA_E3'                      = 'Windows 10/11 Enterprise E3'
    'WIN10_VDA_E5'                      = 'Windows 10/11 Enterprise E5'
    'WINDOWS_STORE'                     = 'Windows Store for Business'
    'RIGHTSMANAGEMENT'                  = 'Azure Information Protection Plan 1'
    'DEVELOPERPACK_E5'                  = 'Microsoft 365 E5 Developer'
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365Licenses_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
# Path.Combine tolerates an empty folder (bare file name in -OutputPath) where Join-Path would throw.
$usersOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_Users.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

$scopes = @('Organization.Read.All', 'User.Read.All')
$includeSignIn = $false
try {
    if ($IncludeUsers) {
        try {
            # AuditLog.Read.All is only needed for signInActivity; fall back gracefully when it cannot be consented.
            Connect-GraphIfNeeded -Scopes ($scopes + 'AuditLog.Read.All')
            $includeSignIn = $true
        }
        catch {
            Write-Warning "Could not connect with AuditLog.Read.All ($($_.Exception.Message)); sign-in activity will be omitted."
            Connect-GraphIfNeeded -Scopes $scopes
        }
    }
    else {
        Connect-GraphIfNeeded -Scopes $scopes
    }
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

Write-Verbose 'Reading subscribed SKUs.'
try {
    $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,capabilityStatus,appliesTo,consumedUnits,prepaidUnits')
}
catch {
    throw "Failed to read subscribed SKUs: $($_.Exception.Message)"
}

$skuRows = New-Object -TypeName System.Collections.Generic.List[object]
$skuNameById = @{}
foreach ($sku in $skus) {
    $friendlyName = $skuFriendlyNames[[string]$sku.skuPartNumber]
    if ([string]::IsNullOrWhiteSpace($friendlyName)) { $friendlyName = $sku.skuPartNumber }
    $skuNameById[[string]$sku.skuId] = $friendlyName
    $enabled = [int]$sku.prepaidUnits.enabled
    $consumed = [int]$sku.consumedUnits
    $available = $enabled - $consumed
    $percentUsed = $null
    if ($enabled -gt 0) { $percentUsed = [math]::Round(($consumed / $enabled) * 100, 1) }
    $skuRows.Add([PSCustomObject]@{
            SkuPartNumber    = $sku.skuPartNumber
            FriendlyName     = $friendlyName
            SkuId            = $sku.skuId
            CapabilityStatus = $sku.capabilityStatus
            AppliesTo        = $sku.appliesTo
            Enabled          = $enabled
            Warning          = [int]$sku.prepaidUnits.warning
            Suspended        = [int]$sku.prepaidUnits.suspended
            Consumed         = $consumed
            Available        = $available
            PercentUsed      = $percentUsed
            IsNearExhaustion = (($enabled -gt 0) -and (($available -le 5) -or (($available / $enabled) -le 0.05)))
        })
}
$skuOutput = @($skuRows | Sort-Object -Property @{ Expression = 'Consumed'; Descending = $true }, FriendlyName)
$skuOutput | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$userRows = New-Object -TypeName System.Collections.Generic.List[object]
if ($IncludeUsers) {
    $usersUriBase = 'https://graph.microsoft.com/v1.0/users?$filter=assignedLicenses/$count ne 0&$count=true&$top=999&$select='
    $userSelect = 'id,displayName,userPrincipalName,userType,accountEnabled,usageLocation,createdDateTime,assignedLicenses'
    $eventualHeaders = @{ ConsistencyLevel = 'eventual' }
    Write-Verbose 'Reading licensed users.'
    try {
        if ($includeSignIn) { $userSelect += ',signInActivity' }
        $users = @(Invoke-GraphPaged -Uri ($usersUriBase + $userSelect) -Headers $eventualHeaders)
    }
    catch {
        if (-not $includeSignIn) { throw "Failed to list licensed users: $($_.Exception.Message)" }
        # Graph answers 403/400 for signInActivity without Entra ID P1 or the AuditLog scope; retry without the property.
        Write-Warning "Sign-in activity is not available ($($_.Exception.Message)); retrying without it."
        $includeSignIn = $false
        $userSelect = $userSelect.Replace(',signInActivity', '')
        try {
            $users = @(Invoke-GraphPaged -Uri ($usersUriBase + $userSelect) -Headers $eventualHeaders)
        }
        catch {
            throw "Failed to list licensed users: $($_.Exception.Message)"
        }
    }
    Write-Verbose "Shaping $($users.Count) licensed users."

    $nowUtc = [datetime]::UtcNow
    $counter = 0
    foreach ($user in $users) {
        $counter++
        if ($counter % 100 -eq 0) { Write-Progress -Activity 'Shaping licensed users' -Status "$counter of $($users.Count)" -PercentComplete ([int](($counter / $users.Count) * 100)) }

        $licenseNames = New-Object -TypeName System.Collections.Generic.List[string]
        foreach ($assigned in @($user.assignedLicenses | Where-Object { $null -ne $_ })) {
            $skuKey = [string]$assigned.skuId
            if ($skuNameById.ContainsKey($skuKey)) { $licenseNames.Add($skuNameById[$skuKey]) } else { $licenseNames.Add($skuKey) }
        }

        $lastSignIn = $null
        if ($includeSignIn -and $null -ne $user.signInActivity) {
            $signInDates = @(
                (ConvertTo-UtcDateTime -Value $user.signInActivity.lastSignInDateTime),
                (ConvertTo-UtcDateTime -Value $user.signInActivity.lastNonInteractiveSignInDateTime)
            ) | Where-Object { $null -ne $_ } | Sort-Object -Descending
            $lastSignIn = $signInDates | Select-Object -First 1
        }
        $daysSinceLastSignIn = $null
        if ($null -ne $lastSignIn) { $daysSinceLastSignIn = [int](($nowUtc - $lastSignIn).TotalDays) }
        $created = ConvertTo-UtcDateTime -Value $user.createdDateTime
        $accountAgeDays = $null
        if ($null -ne $created) { $accountAgeDays = [int](($nowUtc - $created).TotalDays) }

        # Never signed in: judge by account age so brand-new accounts are not flagged.
        $idleDays = $daysSinceLastSignIn
        if ($null -eq $idleDays) { $idleDays = $accountAgeDays }
        $flag = 'Ok'
        if (-not $user.accountEnabled) { $flag = 'DisabledButLicensed' }
        elseif ($includeSignIn -and $null -ne $idleDays -and $idleDays -ge $DaysInactive) { $flag = 'InactiveButLicensed' }

        $userRows.Add([PSCustomObject]@{
                DisplayName         = $user.displayName
                UserPrincipalName   = $user.userPrincipalName
                UserType            = $user.userType
                AccountEnabled      = [bool]$user.accountEnabled
                UsageLocation       = $user.usageLocation
                LicenseCount        = $licenseNames.Count
                Licenses            = (($licenseNames | Sort-Object) -join ';')
                LastSignInDateTime  = $lastSignIn
                DaysSinceLastSignIn = $daysSinceLastSignIn
                CreatedDateTime     = $created
                Flag                = $flag
            })
    }
    Write-Progress -Activity 'Shaping licensed users' -Completed
    if ($userRows.Count -gt 0) {
        $userRows | Sort-Object -Property Flag, DisplayName | Export-Csv -Path $usersOutputPath -NoTypeInformation -Encoding UTF8
    }
}

$nearExhaustion = @($skuOutput | Where-Object { $_.IsNearExhaustion })
$totalEnabled = ($skuOutput | Measure-Object -Property Enabled -Sum).Sum
$totalConsumed = ($skuOutput | Measure-Object -Property Consumed -Sum).Sum
Write-Host ''
Write-Host 'License summary' -ForegroundColor Cyan
Write-Host ('  SKUs                         : {0}' -f $skuOutput.Count)
Write-Host ('  Units enabled / consumed     : {0} / {1}' -f [int]$totalEnabled, [int]$totalConsumed)
Write-Host ('  SKUs near exhaustion         : {0}' -f $nearExhaustion.Count) -ForegroundColor Yellow
foreach ($sku in $nearExhaustion) {
    Write-Host ('    {0,-50} {1,6} of {2,6} left' -f $sku.FriendlyName, $sku.Available, $sku.Enabled)
}
Write-Host ('  SKU CSV                      : {0}' -f $OutputPath)
if ($IncludeUsers) {
    $disabledLicensed = @($userRows | Where-Object { $_.Flag -eq 'DisabledButLicensed' })
    $inactiveLicensed = @($userRows | Where-Object { $_.Flag -eq 'InactiveButLicensed' })
    $reclaimable = (@($disabledLicensed + $inactiveLicensed) | Measure-Object -Property LicenseCount -Sum).Sum
    if ($null -eq $reclaimable) { $reclaimable = 0 }
    Write-Host ('  Licensed users               : {0}' -f $userRows.Count)
    Write-Host ('  Disabled but licensed        : {0}' -f $disabledLicensed.Count) -ForegroundColor Yellow
    if ($includeSignIn) {
        Write-Host ('  Inactive but licensed        : {0} (no sign-in for {1}+ days)' -f $inactiveLicensed.Count, $DaysInactive) -ForegroundColor Yellow
    }
    else {
        Write-Host '  Inactive but licensed        : n/a (sign-in activity not available)'
    }
    Write-Host ('  Potentially reclaimable      : {0} license assignments' -f [int]$reclaimable) -ForegroundColor Yellow
    Write-Host ('  Users CSV                    : {0}' -f $usersOutputPath)
}

if ($PassThru) {
    $skuOutput
    if ($IncludeUsers) { $userRows }
}
#endregion Main
