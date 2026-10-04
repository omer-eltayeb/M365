<#
.SYNOPSIS
    Reconciles Intune-managed Windows, macOS and Linux devices against Defender for Endpoint to find devices that are not onboarded or not reporting.
.DESCRIPTION
    Reads the Intune managed devices per platform (GET v1.0 /deviceManagement/managedDevices, $filter on operatingSystem, $select of id,
    deviceName, azureADDeviceId, operatingSystem, osVersion, lastSyncDateTime, userPrincipalName) and the latest DeviceInfo record per device
    from Advanced Hunting (POST v1.0 /security/runHuntingQuery). Devices are matched on azureADDeviceId = AadDeviceId, falling back to the host
    name before the first dot, and classified as Onboarded, SensorInactive, NotOnboarded or NotInDefender. By default only gaps are exported.
.PARAMETER Days
    Advanced Hunting timespan in days (1-30, default 7). An onboarded device that has not reported within the window shows as NotInDefender.
.PARAMETER Platform
    Intune operatingSystem values to reconcile: Windows, macOS and/or Linux. Default: all three.
.PARAMETER OnlyGaps
    Exports only devices that are not Onboarded (default). Use -OnlyGaps:$false to include the healthy devices in the CSV.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderDevicesNotOnboarded_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderDevicesNotOnboarded.ps1
    Exports the Intune devices that Defender for Endpoint does not know, has not onboarded or has not heard from in 7 days.
.EXAMPLE
    PS> .\Get-DefenderDevicesNotOnboarded.ps1 -Platform Windows -Days 30 -OnlyGaps:$false -OutputPath C:\Temp\MdeCoverage.csv -PassThru | Group-Object -Property DefenderStatus
    Builds the full 30-day coverage picture for Windows and groups it per status in the pipeline.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : ThreatHunting.Read.All, DeviceManagementManagedDevices.Read.All (delegated); Security Reader or another Defender XDR role
                  with advanced hunting access, plus Intune read access (for example Intune Read Only Operator).
    Category    : Advanced hunting (Graph)
    Changes     : No
    Notes       : Advanced hunting caps results per query (10,000 rows in the portal, 100,000 through the API); -Days maps to the Timespan
                  property (P<n>D). Intune returns an all-zero azureADDeviceId for devices without an Entra record, so those match by name only.
                  Fix for gaps: Intune Defender for Endpoint connector plus an EDR onboarding policy (Endpoint security > Endpoint detection and response).
.LINK
    https://learn.microsoft.com/graph/api/security-security-runhuntingquery
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$Days = 7,

    [Parameter()]
    [ValidateSet('Windows', 'macOS', 'Linux')]
    [string[]]$Platform = @('Windows', 'macOS', 'Linux'),

    [Parameter()]
    [switch]$OnlyGaps = $true,

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

function Invoke-HuntingQuery {
    <# Runs an Advanced Hunting KQL query through Microsoft Graph and returns the result rows. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$Days = 7
    )
    $body = @{ Query = $Query; Timespan = ('P{0}D' -f $Days) }
    $response = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
    if ($null -eq $response.results) { return @() }
    return @($response.results)
}

function ConvertTo-UtcDateTime {
    <# Normalises a Graph or hunting date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [cultureinfo]::InvariantCulture, 'AdjustToUniversal')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderDevicesNotOnboarded_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('ThreatHunting.Read.All', 'DeviceManagementManagedDevices.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$intuneDevices = New-Object -TypeName System.Collections.Generic.List[object]
$select = '$select=id,deviceName,azureADDeviceId,operatingSystem,osVersion,lastSyncDateTime,userPrincipalName'
foreach ($os in $Platform) {
    Write-Progress -Activity 'Reading Intune managed devices' -Status $os
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem eq '{0}'&{1}" -f $os, $select
    try { foreach ($device in (Invoke-GraphPaged -Uri $uri)) { $intuneDevices.Add($device) } }
    catch { throw "Failed to read Intune devices for platform '$os': $($_.Exception.Message)" }
}
Write-Progress -Activity 'Reading Intune managed devices' -Completed
if ($intuneDevices.Count -eq 0) { Write-Warning 'Intune returned no devices for the selected platforms; nothing to reconcile.'; return }
$query = @"
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceName, AadDeviceId, OnboardingStatus, SensorHealthState, OSPlatform, LastSeen=Timestamp
"@
try { $defenderRows = @(Invoke-HuntingQuery -Query $query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }

# Two lookups keyed on the Entra device id and on the short host name; when several records share a key the most recent one wins.
$byAadId = @{}
$byName = @{}
foreach ($row in $defenderRows) {
    $entry = [PSCustomObject]@{ DeviceName = $row.DeviceName; OnboardingStatus = $row.OnboardingStatus; SensorHealthState = $row.SensorHealthState
        LastSeen = ConvertTo-UtcDateTime -Value $row.LastSeen }
    $aadKey = ([string]$row.AadDeviceId).ToLowerInvariant()
    $nameKey = ([string]$row.DeviceName).Split('.')[0].ToLowerInvariant()
    if ($aadKey -and (-not $byAadId.ContainsKey($aadKey) -or $byAadId[$aadKey].LastSeen -lt $entry.LastSeen)) { $byAadId[$aadKey] = $entry }
    if ($nameKey -and (-not $byName.ContainsKey($nameKey) -or $byName[$nameKey].LastSeen -lt $entry.LastSeen)) { $byName[$nameKey] = $entry }
}

$report = @(foreach ($device in $intuneDevices) {
    $aadKey = ([string]$device.azureADDeviceId).ToLowerInvariant()
    if ($aadKey -eq '00000000-0000-0000-0000-000000000000') { $aadKey = '' }
    $nameKey = ([string]$device.deviceName).Split('.')[0].ToLowerInvariant()
    $match = $null
    $matchedBy = 'None'
    if ($aadKey -and $byAadId.ContainsKey($aadKey)) { $match = $byAadId[$aadKey]; $matchedBy = 'AadDeviceId' }
    elseif ($nameKey -and $byName.ContainsKey($nameKey)) { $match = $byName[$nameKey]; $matchedBy = 'DeviceName' }
    $status = 'NotInDefender'
    if ($null -ne $match) {
        if ($match.OnboardingStatus -ne 'Onboarded') { $status = 'NotOnboarded' }
        elseif ($match.SensorHealthState -ne 'Active') { $status = 'SensorInactive' }
        else { $status = 'Onboarded' }
    }
    if ($OnlyGaps -and $status -eq 'Onboarded') { continue }
    [PSCustomObject]@{
        DeviceName = $device.deviceName; UserPrincipalName = $device.userPrincipalName; OperatingSystem = $device.operatingSystem; OsVersion = $device.osVersion
        IntuneLastSync = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime; DefenderStatus = $status; DefenderOnboardingStatus = $(if ($match) { $match.OnboardingStatus })
        DefenderSensorHealth = $(if ($match) { $match.SensorHealthState }); DefenderLastSeen = $(if ($match) { $match.LastSeen }); MatchedBy = $matchedBy
        IntuneDeviceId = $device.id; AzureAdDeviceId = $device.azureADDeviceId
    }
})
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$gaps = @($report | Where-Object { $_.DefenderStatus -ne 'Onboarded' })
Write-Host ('Defender for Endpoint coverage: {0} Intune device(s) checked against {1} Defender record(s); {2} gap(s)' -f $intuneDevices.Count,
    $defenderRows.Count, $gaps.Count) -ForegroundColor $(if ($gaps.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($group in ($gaps | Group-Object -Property DefenderStatus | Sort-Object -Property Count -Descending)) {
    $perOs = $group.Group | Group-Object -Property OperatingSystem | Sort-Object -Property Count -Descending | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }
    Write-Host ('  {0,-14}: {1,6}  ({2})' -f $group.Name, $group.Count, (@($perOs) -join ', '))
}
if ($gaps.Count -gt 0) {
    Write-Host '  Fix: enable the Defender for Endpoint connector (Intune > Endpoint security > Microsoft Defender for Endpoint) and assign an EDR onboarding policy' -ForegroundColor Cyan
    Write-Host '       (Endpoint security > Endpoint detection and response); SensorInactive devices need a local sensor health check (MDEClientAnalyzer).' -ForegroundColor Cyan
}
Write-Host ('  Report -> {0}' -f $OutputPath)
if ($PassThru) { $report }
#endregion Main
