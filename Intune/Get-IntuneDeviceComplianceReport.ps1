<#
.SYNOPSIS
    Inventory and compliance report for all Intune managed devices.
.DESCRIPTION
    Lists every Intune managed device from Microsoft Graph (v1.0 /deviceManagement/managedDevices)
    with user, platform, enrolment, encryption and compliance details. Optional server-side filters
    narrow the result to one operating system and/or one compliance state. A DaysSinceLastSync
    column is calculated, the report is exported to CSV and a console summary grouped by operating
    system and by compliance state is printed.
.PARAMETER OperatingSystem
    Restrict the report to one platform: Windows, iOS, Android, macOS or Linux (server-side $filter).
.PARAMETER ComplianceState
    Restrict the report to one compliance state: compliant, noncompliant, inGracePeriod, unknown,
    conflict, error or configManager (server-side $filter).
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneDeviceCompliance_yyyyMMdd-HHmm.csv; the folder
    is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneDeviceComplianceReport.ps1
    Exports every managed device to .\Reports\IntuneDeviceCompliance_<timestamp>.csv and prints the summary.
.EXAMPLE
    PS> .\Get-IntuneDeviceComplianceReport.ps1 -OperatingSystem Windows -ComplianceState noncompliant -PassThru |
            Sort-Object -Property DaysSinceLastSync -Descending | Select-Object -First 20
    Lists the 20 non-compliant Windows devices that have gone the longest without checking in.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Devices & remote actions
    Changes     : No
    Notes       : Uses the v1.0 endpoint only. All date/time values are reported in UTC. The compliance
                  state 'configManager' is returned for co-managed devices whose compliance workload is
                  still evaluated by Configuration Manager.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'Linux')]
    [string]$OperatingSystem,

    [Parameter()]
    [ValidateSet('compliant', 'noncompliant', 'inGracePeriod', 'unknown', 'conflict', 'error', 'configManager')]
    [string]$ComplianceState,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneDeviceCompliance_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('DeviceManagementManagedDevices.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

# managedDeviceOwnerType is the v1.0 name of the ownership property (ownerType only exists in beta).
$selectProperties = @(
    'id', 'deviceName', 'userPrincipalName', 'userDisplayName', 'operatingSystem', 'osVersion',
    'complianceState', 'managementAgent', 'managedDeviceOwnerType', 'deviceEnrollmentType',
    'enrolledDateTime', 'lastSyncDateTime', 'isEncrypted', 'serialNumber', 'model', 'manufacturer',
    'azureADDeviceId'
) -join ','

$filterClauses = @()
if (-not [string]::IsNullOrWhiteSpace($OperatingSystem)) { $filterClauses += "operatingSystem eq '$OperatingSystem'" }
if (-not [string]::IsNullOrWhiteSpace($ComplianceState)) { $filterClauses += "complianceState eq '$ComplianceState'" }

$uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=' + $selectProperties
if ($filterClauses.Count -gt 0) {
    $uri += '&$filter=' + ($filterClauses -join ' and ')
}

Write-Verbose "Requesting managed devices: $uri"
try {
    $devices = @(Invoke-GraphPaged -Uri $uri)
}
catch {
    throw "Failed to retrieve managed devices from Microsoft Graph: $($_.Exception.Message)"
}
Write-Verbose ('Retrieved {0} managed devices.' -f $devices.Count)

$now = [datetime]::UtcNow
$report = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($device in $devices) {
    $index++
    if ($index % 250 -eq 0) {
        Write-Progress -Activity 'Building device compliance report' -Status ('{0} of {1}' -f $index, $devices.Count) -PercentComplete ([int](($index / $devices.Count) * 100))
    }

    $lastSync = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime
    $daysSinceLastSync = $null
    if ($null -ne $lastSync) {
        $daysSinceLastSync = [int][math]::Floor(($now - $lastSync).TotalDays)
    }

    $report.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            UserPrincipalName = $device.userPrincipalName
            UserDisplayName   = $device.userDisplayName
            OperatingSystem   = $device.operatingSystem
            OSVersion         = $device.osVersion
            ComplianceState   = $device.complianceState
            ManagementAgent   = $device.managementAgent
            OwnerType         = $device.managedDeviceOwnerType
            EnrollmentType    = $device.deviceEnrollmentType
            EnrolledDateTime  = ConvertTo-UtcDateTime -Value $device.enrolledDateTime
            LastSyncDateTime  = $lastSync
            DaysSinceLastSync = $daysSinceLastSync
            IsEncrypted       = $device.isEncrypted
            SerialNumber      = $device.serialNumber
            Model             = $device.model
            Manufacturer      = $device.manufacturer
            EntraDeviceId     = $device.azureADDeviceId
            ManagedDeviceId   = $device.id
        })
}
Write-Progress -Activity 'Building device compliance report' -Completed

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No managed devices matched the specified criteria; no CSV file was written.'
}

Write-Host ''
Write-Host ('Managed devices in report : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host 'By operating system:' -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property OperatingSystem | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-20} {1,6}' -f $group.Name, $group.Count)
}
Write-Host 'By compliance state:' -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property ComplianceState | Sort-Object -Property Count -Descending)) {
    $colour = 'Yellow'
    if ($group.Name -eq 'compliant') { $colour = 'Green' }
    Write-Host ('  {0,-20} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

if ($PassThru) {
    $report
}
#endregion Main
