<#
.SYNOPSIS
    One-screen Intune tenant health check: enrolment, compliance, policy and app counts, Autopilot, certificate/token expiry and service health.
.DESCRIPTION
    Collects the managed device overview (v1.0 /deviceManagement/managedDeviceOverview), the compliance state distribution
    (/managedDevices?$select=complianceState), counts of configuration profiles, settings catalog policies (beta), compliance
    policies, assigned apps and Autopilot identities, Apple MDM push certificate and VPP token expiry, the MDM authority
    (/organization) and the Intune service health overview with open issues. Prints a coloured dashboard, returns one object
    and optionally writes it as JSON for trend tracking.
.PARAMETER ExpiryWarningDays
    Days before an Apple push certificate or VPP token expiry at which the dashboard shows a warning. Default 30.
.PARAMETER OutputPath
    Optional JSON file to write the summary object to; the folder is created when missing.
.EXAMPLE
    PS> .\Get-IntuneTenantSummary.ps1
    Prints the tenant dashboard and returns the summary object.
.EXAMPLE
    PS> .\Get-IntuneTenantSummary.ps1 -OutputPath C:\Reports\IntuneSummary.json -ExpiryWarningDays 60 -Verbose
    Also writes the summary as JSON and warns about Apple certificates or tokens expiring within 60 days.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementApps.Read.All,
                  DeviceManagementServiceConfig.Read.All, Organization.Read.All, ServiceHealth.Read.All (delegated)
    Category    : Reporting & platform insights
    Changes     : No
    Notes       : Every section is collected independently; a failing call (missing licence, permission or feature) is reported
                  as a warning and leaves that field empty instead of aborting. Settings catalog policies exist only on the beta
                  endpoint. Device and Autopilot counts page through the collections (a few seconds in large tenants). Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddeviceoverview-get
.LINK
    https://learn.microsoft.com/graph/api/serviceannouncement-list-healthoverviews
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$ExpiryWarningDays = 30,

    [Parameter()]
    [string]$OutputPath
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

function Get-GraphItems {
    <# Pages through a collection and returns its items; on failure writes a warning for the named section and returns $null. #>
    param([string]$Uri, [string]$Section)
    try { return @(Invoke-GraphPaged -Uri $Uri) }
    catch { Write-Warning ('{0}: {1}' -f $Section, $_.Exception.Message); return $null }
}

function Get-DaysLeft {
    <# Whole days from now until a Graph expiry date; $null when the date is missing. #>
    param([object]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    return [int][Math]::Floor((([datetime]$Value).ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalDays)
}
#endregion Helpers

#region Main
$scopes = @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementApps.Read.All',
    'DeviceManagementServiceConfig.Read.All', 'Organization.Read.All', 'ServiceHealth.Read.All')
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0'
$beta = 'https://graph.microsoft.com/beta'   # beta: settings catalog policies (configurationPolicies) are not available in v1.0

Write-Progress -Activity 'Collecting Intune tenant summary' -Status 'Device overview and compliance' -PercentComplete 5
$overview = @(Get-GraphItems -Uri ($v1 + '/deviceManagement/managedDeviceOverview') -Section 'Managed device overview')[0]
$organization = @(Get-GraphItems -Uri ($v1 + '/organization?$select=displayName,mobileDeviceManagementAuthority') -Section 'Organization')[0]
$compliance = [ordered]@{ compliant = 0; noncompliant = 0; inGracePeriod = 0; conflict = 0; error = 0; configManager = 0; unknown = 0 }
$devices = Get-GraphItems -Uri ($v1 + '/deviceManagement/managedDevices?$select=id,complianceState') -Section 'Managed devices'
foreach ($device in @($devices)) {
    $state = [string]$device.complianceState; if ([string]::IsNullOrEmpty($state)) { $state = 'unknown' }
    if ($compliance.Contains($state)) { $compliance[$state]++ } else { $compliance[$state] = 1 }
}

Write-Progress -Activity 'Collecting Intune tenant summary' -Status 'Policies, apps and Autopilot' -PercentComplete 40
$counts = [ordered]@{}
$collections = @(
    [PSCustomObject]@{ Name = 'ConfigurationProfiles'; Uri = $v1 + '/deviceManagement/deviceConfigurations?$select=id' }
    [PSCustomObject]@{ Name = 'SettingsCatalogPolicies'; Uri = $beta + '/deviceManagement/configurationPolicies?$select=id' }
    [PSCustomObject]@{ Name = 'CompliancePolicies'; Uri = $v1 + '/deviceManagement/deviceCompliancePolicies?$select=id' }
    [PSCustomObject]@{ Name = 'AssignedApps'; Uri = $v1 + '/deviceAppManagement/mobileApps?$filter=isAssigned eq true&$select=id' }
    [PSCustomObject]@{ Name = 'AutopilotDevices'; Uri = $v1 + '/deviceManagement/windowsAutopilotDeviceIdentities?$select=id' }
)
foreach ($collection in $collections) {
    $items = Get-GraphItems -Uri $collection.Uri -Section $collection.Name
    $counts[$collection.Name] = $null
    if ($null -ne $items) { $counts[$collection.Name] = @($items).Count }
}

Write-Progress -Activity 'Collecting Intune tenant summary' -Status 'Apple certificate, tokens and service health' -PercentComplete 70
# APNs returns 404 when no Apple MDM push certificate was ever uploaded; that is a valid state, not an error.
$apnsExpiry = $null; $apnsState = 'Not configured'
try {
    $apns = Invoke-MgGraphRequest -Method GET -Uri ($v1 + '/deviceManagement/applePushNotificationCertificate') -OutputType PSObject -ErrorAction Stop
    $apnsExpiry = ([datetime]$apns.expirationDateTime).ToUniversalTime(); $apnsState = $apns.appleIdentifier
}
catch { Write-Verbose ('Apple push certificate not available: {0}' -f $_.Exception.Message) }
$vppTokens = @(Get-GraphItems -Uri ($v1 + '/deviceAppManagement/vppTokens?$select=id,organizationName,state,expirationDateTime') -Section 'VPP tokens' | Where-Object { $null -ne $_ })
$vppNearest = $vppTokens | ForEach-Object { $_.expirationDateTime } | Where-Object { -not [string]::IsNullOrEmpty([string]$_) } | Sort-Object | Select-Object -First 1

$health = $null; $openIssues = @()
try { $health = Invoke-MgGraphRequest -Method GET -Uri ($v1 + '/admin/serviceAnnouncement/healthOverviews/Microsoft%20Intune?$expand=issues') -OutputType PSObject -ErrorAction Stop }
catch { Write-Warning ('Service health: {0}' -f $_.Exception.Message) }
if ($null -ne $health) { $openIssues = @($health.issues | Where-Object { $_.isResolved -ne $true } | ForEach-Object { '{0} ({1})' -f $_.title, $_.id }) }
Write-Progress -Activity 'Collecting Intune tenant summary' -Completed

$summary = [PSCustomObject]@{
    Tenant                  = [string]$organization.displayName
    CollectedAt             = (Get-Date).ToUniversalTime()
    MdmAuthority            = [string]$organization.mobileDeviceManagementAuthority
    EnrolledDevices         = $overview.enrolledDeviceCount
    MdmEnrolled             = $overview.mdmEnrolledCount
    DualEnrolled            = $overview.dualEnrolledDeviceCount
    DevicesByOS             = $overview.deviceOperatingSystemSummary
    ExchangeAccess          = $overview.deviceExchangeAccessStateSummary
    Compliance              = [PSCustomObject]$compliance
    ConfigurationProfiles   = $counts['ConfigurationProfiles']
    SettingsCatalogPolicies = $counts['SettingsCatalogPolicies']
    CompliancePolicies      = $counts['CompliancePolicies']
    AssignedApps            = $counts['AssignedApps']
    AutopilotDevices        = $counts['AutopilotDevices']
    ApnsCertificate         = $apnsState
    ApnsExpiry              = $apnsExpiry
    ApnsDaysLeft            = Get-DaysLeft -Value $apnsExpiry
    VppTokens               = $vppTokens.Count
    VppNearestExpiry        = Get-DaysLeft -Value $vppNearest
    ServiceHealthStatus     = [string]$health.status
    ServiceOpenIssues       = $openIssues
}

$line = '  {0,-36} {1}'
Write-Host ('Intune tenant summary - {0} ({1:yyyy-MM-dd HH:mm} UTC)' -f $summary.Tenant, $summary.CollectedAt) -ForegroundColor Cyan
Write-Host ($line -f 'MDM authority', $summary.MdmAuthority)
Write-Host ($line -f 'Enrolled devices (MDM / dual)', ('{0} ({1} / {2})' -f $summary.EnrolledDevices, $summary.MdmEnrolled, $summary.DualEnrolled))
$os = $overview.deviceOperatingSystemSummary; $exchange = $overview.deviceExchangeAccessStateSummary
Write-Host ($line -f 'Windows / iOS / Android / macOS', ('{0} / {1} / {2} / {3}' -f $os.windowsCount, $os.iosCount, $os.androidCount, $os.macOSCount))
$total = [int](($compliance.Values | Measure-Object -Sum).Sum)
$complianceColour = 'Green'; if ($total -gt 0 -and ($compliance['noncompliant'] / $total) -gt 0.1) { $complianceColour = 'Yellow' }
Write-Host ($line -f 'Compliant / noncompliant / grace', ('{0} / {1} / {2}' -f $compliance['compliant'], $compliance['noncompliant'], $compliance['inGracePeriod'])) -ForegroundColor $complianceColour
Write-Host ($line -f 'Exchange blocked / quarantined', ('{0} / {1}' -f $exchange.blockedDeviceCount, $exchange.quarantinedDeviceCount))
Write-Host ($line -f 'Config profiles / settings catalog', ('{0} / {1}' -f $summary.ConfigurationProfiles, $summary.SettingsCatalogPolicies))
Write-Host ($line -f 'Compliance policies / assigned apps', ('{0} / {1}' -f $summary.CompliancePolicies, $summary.AssignedApps))
Write-Host ($line -f 'Autopilot identities', $summary.AutopilotDevices)
$apnsColour = 'Gray'; if ($null -ne $apnsExpiry) { $apnsColour = 'Green'; if ($summary.ApnsDaysLeft -lt $ExpiryWarningDays) { $apnsColour = 'Red' } }
Write-Host ($line -f 'Apple push certificate', ('{0} (expires in {1} days)' -f $summary.ApnsCertificate, $summary.ApnsDaysLeft)) -ForegroundColor $apnsColour
$vppColour = 'Green'; if ($null -ne $summary.VppNearestExpiry -and $summary.VppNearestExpiry -lt $ExpiryWarningDays) { $vppColour = 'Red' }
Write-Host ($line -f 'VPP tokens (nearest expiry)', ('{0} ({1} days)' -f $summary.VppTokens, $summary.VppNearestExpiry)) -ForegroundColor $vppColour
$healthColour = 'Green'; if ($summary.ServiceHealthStatus -ne 'serviceOperational') { $healthColour = 'Yellow' }
Write-Host ($line -f 'Intune service health', ('{0}; open issues: {1}' -f $summary.ServiceHealthStatus, $openIssues.Count)) -ForegroundColor $healthColour
foreach ($issue in $openIssues) { Write-Host ('    - {0}' -f $issue) -ForegroundColor Yellow }

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputFolder = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8; Write-Host ('Summary written to {0}' -f $OutputPath) -ForegroundColor Green
}
$summary
#endregion Main
