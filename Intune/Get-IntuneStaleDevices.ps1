<#
.SYNOPSIS
    Reports Intune managed devices that have not synced for a given number of days and can optionally retire or delete them.
.DESCRIPTION
    Queries Microsoft Graph (v1.0 /deviceManagement/managedDevices) with a server-side filter on
    lastSyncDateTime to find devices that have not checked in for -DaysInactive days, optionally
    limited to one operating system. By default the script only reports (CSV plus console summary).
    With -RetireDevices it posts the 'retire' action for each stale device; with -DeleteDevices it
    deletes the device record. Both actions honour -WhatIf / -Confirm and are mutually exclusive.
.PARAMETER DaysInactive
    Number of days since the last successful sync before a device is considered stale. Default 90.
.PARAMETER OperatingSystem
    Restrict the query to one platform: Windows, iOS, Android, macOS or Linux.
.PARAMETER RetireDevices
    Retire every stale device (removes company data and management, keeps personal data). Prompts per device.
.PARAMETER DeleteDevices
    Delete every stale device record from Intune. Cannot be combined with -RetireDevices. Prompts per device.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneStaleDevices_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneStaleDevices.ps1
    Reports all devices that have not synced for 90 days or more. Nothing is changed.
.EXAMPLE
    PS> .\Get-IntuneStaleDevices.ps1 -DaysInactive 180 -OperatingSystem Windows -RetireDevices -WhatIf
    Shows which Windows devices inactive for 180+ days would be retired, without retiring anything.
.EXAMPLE
    PS> .\Get-IntuneStaleDevices.ps1 -DaysInactive 365 -DeleteDevices -Confirm:$false -OutputPath C:\Temp\deleted.csv
    Deletes every device record inactive for a year or more without prompting and logs the outcome per device.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Report only: DeviceManagementManagedDevices.Read.All (Intune Read Only Operator).
                  With -RetireDevices / -DeleteDevices: additionally DeviceManagementManagedDevices.PrivilegedOperations.All
                  and DeviceManagementManagedDevices.ReadWrite.All (Intune Administrator or equivalent custom role).
    Category    : Devices & remote actions
    Changes     : Optional (-RetireDevices / -DeleteDevices)
    Notes       : Retire is asynchronous - Intune removes the device record once the device acknowledges the
                  command or after the retention period. Delete removes the record immediately; a device that is
                  still in use will re-appear at its next check-in only if it re-enrols. Privileged scopes are
                  requested only when an action switch is supplied. All date/time values are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-retire
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-delete
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Report')]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'Linux')]
    [string]$OperatingSystem,

    [Parameter(ParameterSetName = 'Retire')]
    [switch]$RetireDevices,

    [Parameter(ParameterSetName = 'Delete')]
    [switch]$DeleteDevices,

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
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { $parsed = [datetime]$Value } catch { return $null }
    if ($parsed.Year -le 1) { return $null }
    return $parsed.ToUniversalTime()
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneStaleDevices_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$action = 'Report'
if ($RetireDevices) { $action = 'Retire' }
elseif ($DeleteDevices) { $action = 'Delete' }

$scopes = @('DeviceManagementManagedDevices.Read.All')
if ($action -ne 'Report') {
    # Privileged scopes are only requested when the caller explicitly asked for a remote action.
    $scopes += 'DeviceManagementManagedDevices.PrivilegedOperations.All', 'DeviceManagementManagedDevices.ReadWrite.All'
    $actionVerb = 'RETIRED'
    if ($action -eq 'Delete') { $actionVerb = 'DELETED' }
    Write-Warning ('Action mode: stale devices will be {0}. Use -WhatIf to preview or -Confirm:$false to suppress prompts.' -f $actionVerb)
}

try {
    Connect-GraphIfNeeded -Scopes $scopes
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$baseUri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
$now = [datetime]::UtcNow
$cutoff = $now.AddDays(-$DaysInactive)
$filter = 'lastSyncDateTime le {0}Z' -f $cutoff.ToString('s')
if (-not [string]::IsNullOrWhiteSpace($OperatingSystem)) {
    $filter += " and operatingSystem eq '$OperatingSystem'"
}
$select = 'id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,managedDeviceOwnerType,enrolledDateTime,lastSyncDateTime,serialNumber,azureADDeviceId'
$uri = '{0}?$select={1}&$filter={2}' -f $baseUri, $select, $filter

Write-Verbose "Requesting stale devices: $uri"
try {
    $devices = @(Invoke-GraphPaged -Uri $uri)
}
catch {
    throw "Failed to retrieve managed devices from Microsoft Graph: $($_.Exception.Message)"
}
Write-Verbose ('Found {0} devices with no sync since {1:yyyy-MM-dd HH:mm} UTC.' -f $devices.Count, $cutoff)

$report = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity ('Processing stale devices ({0})' -f $action) -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))

    $lastSync = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime
    $daysSinceLastSync = $null
    if ($null -ne $lastSync) { $daysSinceLastSync = [int][math]::Floor(($now - $lastSync).TotalDays) }

    $result = 'ReportOnly'
    $errorMessage = $null
    if ($action -ne 'Report') {
        $result = 'Skipped'
        $target = '{0} ({1}, last sync {2:yyyy-MM-dd}, user {3})' -f $device.deviceName, $device.operatingSystem, $lastSync, $device.userPrincipalName
        if ($PSCmdlet.ShouldProcess($target, ('{0} device' -f $action))) {
            try {
                if ($action -eq 'Retire') {
                    Invoke-MgGraphRequest -Method POST -Uri ('{0}/{1}/retire' -f $baseUri, $device.id) -ErrorAction Stop | Out-Null
                }
                else {
                    Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/{1}' -f $baseUri, $device.id) -ErrorAction Stop | Out-Null
                }
                $result = 'Requested'
            }
            catch {
                $result = 'Failed'
                $errorMessage = $_.Exception.Message
                Write-Warning ('{0} failed for {1}: {2}' -f $action, $device.deviceName, $errorMessage)
            }
            Start-Sleep -Milliseconds 200
        }
    }

    $report.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            UserPrincipalName = $device.userPrincipalName
            OperatingSystem   = $device.operatingSystem
            OSVersion         = $device.osVersion
            ComplianceState   = $device.complianceState
            OwnerType         = $device.managedDeviceOwnerType
            EnrolledDateTime  = ConvertTo-UtcDateTime -Value $device.enrolledDateTime
            LastSyncDateTime  = $lastSync
            DaysSinceLastSync = $daysSinceLastSync
            SerialNumber      = $device.serialNumber
            EntraDeviceId     = $device.azureADDeviceId
            ManagedDeviceId   = $device.id
            Action            = $action
            Result            = $result
            Error             = $errorMessage
        })
}
Write-Progress -Activity ('Processing stale devices ({0})' -f $action) -Completed

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning ('No devices have been inactive for {0} days or more; no CSV file was written.' -f $DaysInactive)
}

Write-Host ''
Write-Host ('Stale devices (no sync for {0}+ days) : {1}' -f $DaysInactive, $report.Count) -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property OperatingSystem | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-20} {1,6}' -f $group.Name, $group.Count)
}
if ($action -ne 'Report') {
    Write-Host ('{0} results:' -f $action) -ForegroundColor Cyan
    foreach ($group in ($report | Group-Object -Property Result | Sort-Object -Property Name)) {
        $colour = 'Green'
        if ($group.Name -eq 'Failed') { $colour = 'Red' }
        elseif ($group.Name -eq 'Skipped') { $colour = 'Yellow' }
        Write-Host ('  {0,-20} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
    }
}

if ($PassThru) {
    $report
}
#endregion Main
