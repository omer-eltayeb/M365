<#
.SYNOPSIS
    Health check of Intune connectors and tokens: Apple push certificate, ADE and VPP tokens, Managed Google Play, NDES/certificate connectors, MTD and Autopilot sync.
.DESCRIPTION
    Queries each connector endpoint independently (v1.0 /deviceManagement/applePushNotificationCertificate; beta depOnboardingSettings,
    /deviceAppManagement/vppTokens, androidManagedStoreAccountEnterpriseSettings, ndesConnectors, mobileThreatDefenseConnectors,
    windowsAutopilotSettings and certificateConnectorDetails) and returns one row per connector or token with status, expiry, days until
    expiry, last sync and a Health verdict: OK, Warning (expires within -WarnDays or sync older than -StaleSyncDays), Expired, Error
    (failed/invalid state or unexpected API error) or NotConfigured (HTTP 404/403 or an empty collection).
.PARAMETER WarnDays
    Certificates and tokens expiring within this many days are reported as Warning. Default 30.
.PARAMETER StaleSyncDays
    A last sync, heartbeat or check-in older than this many days is reported as Warning. Default 7.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneConnectorsHealth_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneConnectorsHealth.ps1
    Checks every connector, writes the CSV and prints a colour-coded summary per health state.
.EXAMPLE
    PS> .\Get-IntuneConnectorsHealth.ps1 -WarnDays 60 -PassThru | Where-Object { $_.Health -ne 'OK' } | Format-Table Connector, Name, Status, DaysUntilExpiry, Health
    Shows only connectors that need attention, treating anything expiring within 60 days as a warning.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementServiceConfig.Read.All, DeviceManagementApps.Read.All and DeviceManagementConfiguration.Read.All
                  (delegated). Intune RBAC: Read Only Operator or Intune Administrator.
    Category    : Enrollment & Autopilot
    Changes     : No
    Notes       : All endpoints except the Apple push certificate are beta and may change without notice. A 403 is treated as
                  NotConfigured because several connector endpoints return it when the feature was never set up; verify the
                  scopes above if every row shows NotConfigured. Run this weekly or schedule it to catch token expiry early.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-applepushnotificationcertificate-get?view=graph-rest-1.0
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$WarnDays = 30,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$StaleSyncDays = 7,

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
    <# Normalises a Graph date value (string or DateTime) to a UTC [datetime]; returns $null for empty or 0001-01-01 placeholders. #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { $parsed = [datetime]$Value } catch { return $null }
    if ($parsed.Year -le 1) { return $null }
    return $parsed.ToUniversalTime()
}

function Get-ConnectorHealth {
    <# Derives OK / Warning / Expired / Error / NotConfigured from the state text, expiry date and last sync of a connector. #>
    param([string]$Status, [object]$ExpiresOn, [object]$LastSync)
    $now = (Get-Date).ToUniversalTime()
    if ($Status -match '^(notBound|notSetUp|none)\b') { return 'NotConfigured' }
    if ($null -ne $ExpiresOn -and $ExpiresOn -lt $now) { return 'Expired' }
    if ($Status -match 'fail|error|invalid|expired|unresponsive|unavailable|inactive|duplicate|externalMDM|credentialsNotValid') { return 'Error' }
    if ($null -ne $ExpiresOn -and $ExpiresOn -lt $now.AddDays($WarnDays)) { return 'Warning' }
    if ($null -ne $LastSync -and $LastSync -lt $now.AddDays(-$StaleSyncDays)) { return 'Warning' }
    if ($Status -match 'unknown|inProgress') { return 'Warning' }
    return 'OK'
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneConnectorsHealth_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementServiceConfig.Read.All', 'DeviceManagementApps.Read.All', 'DeviceManagementConfiguration.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

# beta: only the Apple push certificate is exposed on v1.0; every other connector lives on the beta endpoint.
$v1 = 'https://graph.microsoft.com/v1.0/deviceManagement'; $beta = 'https://graph.microsoft.com/beta/deviceManagement'
# Each Map scriptblock turns one API object into the common Name / Status / ExpiresOn / LastSync / Detail shape (missing keys read as $null).
$connectors = @(
    [PSCustomObject]@{ Connector = 'Apple MDM Push Certificate'; Uri = "$v1/applePushNotificationCertificate"
        Map = { param($i) @{ Name = $i.appleIdentifier; Status = 'Uploaded'; ExpiresOn = $i.expirationDateTime; Detail = ('Topic {0}' -f $i.topicIdentifier) } } }
    [PSCustomObject]@{ Connector = 'Apple ADE (DEP) Token'; Uri = "$beta/depOnboardingSettings"
        Map = { param($i) $s = 'OK'; if ([int]$i.lastSyncErrorCode -ne 0) { $s = 'Sync error {0}' -f $i.lastSyncErrorCode }
            @{ Name = $i.appleIdentifier; Status = $s; ExpiresOn = $i.tokenExpirationDateTime; LastSync = $i.lastSuccessfulSyncDateTime; Detail = ('{0} synced devices' -f $i.syncedDeviceCount) } } }
    [PSCustomObject]@{ Connector = 'Apple VPP Token'; Uri = 'https://graph.microsoft.com/beta/deviceAppManagement/vppTokens'
        Map = { param($i) @{ Name = $i.organizationName; Status = ('{0} (sync {1})' -f $i.state, $i.lastSyncStatus); ExpiresOn = $i.expirationDateTime; LastSync = $i.lastSyncDateTime } } }
    [PSCustomObject]@{ Connector = 'Managed Google Play'; Uri = "$beta/androidManagedStoreAccountEnterpriseSettings"
        Map = { param($i) @{ Name = $i.ownerUserPrincipalName; Status = ('{0} (sync {1})' -f $i.bindStatus, $i.lastAppSyncStatus); LastSync = $i.lastAppSyncDateTime; Detail = $i.enrollmentTarget } } }
    [PSCustomObject]@{ Connector = 'NDES Connector'; Uri = "$beta/ndesConnectors"
        Map = { param($i) @{ Name = $i.displayName; Status = $i.state; LastSync = $i.lastConnectionDateTime; Detail = ('{0} v{1}' -f $i.machineName, $i.connectorVersion) } } }
    [PSCustomObject]@{ Connector = 'Mobile Threat Defense'; Uri = "$beta/mobileThreatDefenseConnectors"
        Map = { param($i) $p = @(); if ($i.androidEnabled) { $p += 'Android' }; if ($i.iosEnabled) { $p += 'iOS' }; if ($i.windowsEnabled) { $p += 'Windows' }
            @{ Name = $i.id; Status = $i.partnerState; LastSync = $i.lastHeartbeatDateTime; Detail = ('Platforms: {0}' -f ($p -join ', ')) } } }
    [PSCustomObject]@{ Connector = 'Windows Autopilot Sync'; Uri = "$beta/windowsAutopilotSettings"
        Map = { param($i) @{ Name = 'Windows Autopilot'; Status = $i.syncStatus; LastSync = $i.lastSyncDateTime; Detail = ('Last manual sync {0}' -f $i.lastManualSyncTriggerDateTime) } } }
    [PSCustomObject]@{ Connector = 'Certificate Connector'; Uri = "$beta/certificateConnectorDetails"
        Map = { param($i) @{ Name = $i.connectorName; Status = ('Version {0}' -f $i.connectorVersion); LastSync = $i.lastCheckinDateTime; Detail = $i.machineName } } }
)

$rows = New-Object -TypeName System.Collections.Generic.List[object]; $now = (Get-Date).ToUniversalTime()
foreach ($connector in $connectors) {
    $items = @(); $health = $null; $detail = $null
    try { $items = @(Invoke-GraphPaged -Uri $connector.Uri) }
    catch {
        # 404 = the singleton was never created, 403 = feature not enabled for the tenant; anything else is a real error.
        if ($_.Exception.Message -match 'NotFound|Not Found|\b404\b|Forbidden|\b403\b') { $health = 'NotConfigured' }
        else { $health = 'Error'; $detail = $_.Exception.Message; Write-Warning ('{0}: {1}' -f $connector.Connector, $detail) }
    }
    if ($items.Count -eq 0) {
        if ($null -eq $health) { $health = 'NotConfigured' }
        $rows.Add([PSCustomObject]@{ Connector = $connector.Connector; Name = $null; Status = $null; ExpiresOn = $null; DaysUntilExpiry = $null; LastSync = $null; Health = $health; Detail = $detail })
        continue
    }
    foreach ($item in $items) {
        $mapped = & $connector.Map $item
        $expiresOn = ConvertTo-UtcDateTime -Value $mapped.ExpiresOn
        $lastSync = ConvertTo-UtcDateTime -Value $mapped.LastSync
        $daysUntilExpiry = $null
        if ($null -ne $expiresOn) { $daysUntilExpiry = [int][math]::Floor(($expiresOn - $now).TotalDays) }
        $rows.Add([PSCustomObject]@{
                Connector       = $connector.Connector
                Name            = $mapped.Name
                Status          = $mapped.Status
                ExpiresOn       = $expiresOn
                DaysUntilExpiry = $daysUntilExpiry
                LastSync        = $lastSync
                Health          = Get-ConnectorHealth -Status ([string]$mapped.Status) -ExpiresOn $expiresOn -LastSync $lastSync
                Detail          = $mapped.Detail
            })
    }
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
$colours = @{ OK = 'Green'; Warning = 'Yellow'; Expired = 'Red'; Error = 'Red'; NotConfigured = 'DarkGray' }
Write-Host ("`nConnector rows : {0}" -f $rows.Count) -ForegroundColor Cyan
foreach ($group in ($rows | Group-Object -Property Health | Sort-Object -Property Name)) {
    Write-Host ('  {0,-14} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colours[$group.Name]
}
foreach ($row in ($rows | Where-Object { $_.Health -in @('Warning', 'Expired', 'Error') })) {
    Write-Host ('  [{0}] {1} - {2}: {3}' -f $row.Health, $row.Connector, $row.Name, $row.Status) -ForegroundColor $colours[$row.Health]
}

if ($PassThru) { $rows }
#endregion Main
