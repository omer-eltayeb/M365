<#
.SYNOPSIS
    Groups Intune managed devices by primary user and reports users who own an unusually high number of devices.
.DESCRIPTION
    Reads every managed device from Microsoft Graph v1.0 (/deviceManagement/managedDevices), groups them by the
    primary user's UPN and reports each user with -MinimumDevices or more devices, including the device names,
    platforms, ownership split, non-compliant count and the most recent sync. The console summary shows how many
    users own 1, 2, 3 or 4+ devices and how many devices have no primary user at all, which is a quick way to spot
    duplicate enrolments, leavers whose devices were never retired and licence-count problems.
.PARAMETER MinimumDevices
    Only users with at least this many devices are written to the report. Default 3; use 1 to list every user.
.PARAMETER OperatingSystem
    Restrict the analysis to one platform: Windows, iOS, Android, macOS or Linux (server-side $filter).
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneDevicesPerUser_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneDevicesPerUser.ps1
    Reports users with three or more managed devices and prints the 1/2/3/4+ distribution for the whole tenant.
.EXAMPLE
    PS> .\Get-IntuneDevicesPerUser.ps1 -MinimumDevices 5 -OperatingSystem Windows -PassThru | Sort-Object -Property DeviceCount -Descending
    Lists users with five or more Windows devices, highest count first.
.EXAMPLE
    PS> .\Get-IntuneDevicesPerUser.ps1 -MinimumDevices 1 -OutputPath C:\Temp\devices-per-user.csv
    Exports one row per primary user, regardless of how many devices they have.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All (delegated); Intune Read Only Operator or higher.
    Category    : Devices & remote actions
    Changes     : No
    Notes       : Only the Intune primary user is considered; devices enrolled without a user (Autopilot self-deploying,
                  shared iPads, kiosks, DEM enrolments) are counted separately as "no primary user". A single list call
                  is made, so the script completes in seconds even for large tenants. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$MinimumDevices = 3,

    [Parameter()]
    [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'Linux')]
    [string]$OperatingSystem,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneDevicesPerUser_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

$uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,userDisplayName,operatingSystem,managedDeviceOwnerType,complianceState,lastSyncDateTime'
if (-not [string]::IsNullOrWhiteSpace($OperatingSystem)) { $uri += "&`$filter=operatingSystem eq '$OperatingSystem'" }
try {
    $devices = @(Invoke-GraphPaged -Uri $uri)
}
catch {
    throw "Failed to retrieve managed devices from Microsoft Graph: $($_.Exception.Message)"
}
$withUser = @($devices | Where-Object { -not [string]::IsNullOrWhiteSpace($_.userPrincipalName) })
$noUserCount = $devices.Count - $withUser.Count
# Group-Object compares strings case-insensitively, so UPN casing differences between enrolments do not split a user.
$userGroups = @($withUser | Group-Object -Property userPrincipalName | Sort-Object -Property Count -Descending)
Write-Verbose ('{0} devices, {1} with a primary user, {2} distinct users.' -f $devices.Count, $withUser.Count, $userGroups.Count)

$distribution = [ordered]@{ '1' = 0; '2' = 0; '3' = 0; '4+' = 0 }
$report = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($group in $userGroups) {
    $index++
    Write-Progress -Activity 'Grouping devices per user' -Status ('{0} of {1}: {2}' -f $index, $userGroups.Count, $group.Name) -PercentComplete ([int](($index / $userGroups.Count) * 100))
    $bucket = [string]$group.Count
    if ($group.Count -ge 4) { $bucket = '4+' }
    $distribution[$bucket]++
    if ($group.Count -lt $MinimumDevices) { continue }

    $userDevices = @($group.Group | Sort-Object -Property deviceName)
    $lastSync = $null
    foreach ($userDevice in $userDevices) {
        $sync = ConvertTo-UtcDateTime -Value $userDevice.lastSyncDateTime
        if ($null -ne $sync -and ($null -eq $lastSync -or $sync -gt $lastSync)) { $lastSync = $sync }
    }
    $platformSummary = @($userDevices | Group-Object -Property operatingSystem | Sort-Object -Property Count -Descending | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })

    $report.Add([PSCustomObject]@{
            UserPrincipalName   = $group.Name
            UserDisplayName     = $userDevices[0].userDisplayName
            DeviceCount         = $group.Count
            OperatingSystems    = ($platformSummary -join '; ')
            DeviceNames         = (@($userDevices | ForEach-Object { '{0} ({1})' -f $_.deviceName, $_.operatingSystem }) -join '; ')
            CorporateDevices    = @($userDevices | Where-Object { $_.managedDeviceOwnerType -eq 'company' }).Count
            PersonalDevices     = @($userDevices | Where-Object { $_.managedDeviceOwnerType -eq 'personal' }).Count
            NonCompliantDevices = @($userDevices | Where-Object { $_.complianceState -eq 'noncompliant' }).Count
            LastSyncDateTime    = $lastSync
        })
}
Write-Progress -Activity 'Grouping devices per user' -Completed

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning ('No user has {0} or more managed devices; no CSV file was written.' -f $MinimumDevices)
}

Write-Host ''
Write-Host ('Managed devices                : {0}' -f $devices.Count) -ForegroundColor Cyan
Write-Host ('Devices without a primary user : {0}' -f $noUserCount) -ForegroundColor Yellow
Write-Host ('Distinct primary users         : {0}' -f $userGroups.Count) -ForegroundColor Cyan
Write-Host 'Users by number of devices:'
foreach ($key in $distribution.Keys) {
    Write-Host ('  {0,-3} device(s) {1,6} users' -f $key, $distribution[$key])
}
Write-Host ('Users with {0}+ devices (reported) : {1}' -f $MinimumDevices, $report.Count) -ForegroundColor Yellow

if ($PassThru) {
    $report
}
#endregion Main
