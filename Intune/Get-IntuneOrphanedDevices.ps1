<#
.SYNOPSIS
    Reports Intune managed devices whose primary user is missing, deleted from Entra ID or disabled.
.DESCRIPTION
    Reads every managed device from Microsoft Graph v1.0 (/deviceManagement/managedDevices) and checks the primary
    user of each one with GET /users/{id}?$select=accountEnabled. Devices without a primary user are reported as
    NoPrimaryUser, an HTTP 404 on the user lookup yields UserDeleted and accountEnabled = false yields UserDisabled.
    User lookups are cached so each distinct user is queried once. The report is exported to CSV with the device
    details an administrator needs to decide between re-assigning the primary user, retiring or deleting the device.
.PARAMETER OperatingSystem
    Restrict the check to one platform: Windows, iOS, Android, macOS or Linux (server-side $filter).
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneOrphanedDevices_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneOrphanedDevices.ps1
    Reports every device with no, a deleted or a disabled primary user and writes the CSV to .\Reports.
.EXAMPLE
    PS> .\Get-IntuneOrphanedDevices.ps1 -OperatingSystem Windows -PassThru | Where-Object { $_.Reason -eq 'UserDeleted' }
    Lists Windows devices whose primary user no longer exists in Entra ID.
.EXAMPLE
    PS> .\Get-IntuneOrphanedDevices.ps1 -OutputPath C:\Temp\orphaned.csv -Verbose
    Writes the report to a custom path and shows the user lookups as they happen.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All and User.Read.All (delegated).
    Category    : Devices & remote actions
    Changes     : No
    Notes       : UserDeleted also covers users still in the Entra ID recycle bin (soft-deleted); restore the user within
                  30 days if the device should keep its owner. NoPrimaryUser is expected for userless enrolments such as
                  Autopilot self-deploying mode, shared iPads and kiosks - use the EnrollmentType column to tell them
                  apart. One Graph call is made per distinct user with a 200 ms pause. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list
.LINK
    https://learn.microsoft.com/graph/api/user-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
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

function Get-UserState {
    <# Returns Active, UserDisabled, UserDeleted (HTTP 404) or LookupFailed for an Entra ID user object id. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId
    )
    try {
        $user = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/users/{0}?$select=id,accountEnabled' -f $UserId) -OutputType PSObject -ErrorAction Stop
        if ($user.accountEnabled -eq $false) { return 'UserDisabled' }
        return 'Active'
    }
    catch {
        # The SDK surfaces the Graph error code in the message or ErrorDetails depending on the PowerShell edition.
        $detail = '{0} {1}' -f $_.Exception.Message, $_.ErrorDetails.Message
        if ($detail -match 'Request_ResourceNotFound|does not exist|NotFound|404') { return 'UserDeleted' }
        Write-Warning ('User lookup failed for id {0}: {1}' -f $UserId, $_.Exception.Message)
        return 'LookupFailed'
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneOrphanedDevices_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('DeviceManagementManagedDevices.Read.All', 'User.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,userId,userPrincipalName,operatingSystem,osVersion,managedDeviceOwnerType,deviceEnrollmentType,complianceState,enrolledDateTime,lastSyncDateTime,serialNumber'
if (-not [string]::IsNullOrWhiteSpace($OperatingSystem)) { $uri += "&`$filter=operatingSystem eq '$OperatingSystem'" }
try {
    $devices = @(Invoke-GraphPaged -Uri $uri)
}
catch {
    throw "Failed to retrieve managed devices from Microsoft Graph: $($_.Exception.Message)"
}
Write-Verbose ('{0} managed devices retrieved.' -f $devices.Count)

$userStates = @{}
$report = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Checking primary users' -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    $reason = $null
    if ([string]::IsNullOrWhiteSpace($device.userId)) {
        $reason = 'NoPrimaryUser'
    }
    else {
        $userId = [string]$device.userId
        if (-not $userStates.ContainsKey($userId)) {
            Write-Verbose ('Looking up user {0} ({1}).' -f $userId, $device.userPrincipalName)
            $userStates[$userId] = Get-UserState -UserId $userId
            Start-Sleep -Milliseconds 200
        }
        if ($userStates[$userId] -ne 'Active') { $reason = $userStates[$userId] }
    }
    # LookupFailed devices are not reported as orphaned because their state is unknown; the warning above records them.
    if ($null -eq $reason -or $reason -eq 'LookupFailed') { continue }

    $report.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            Reason            = $reason
            UserPrincipalName = $device.userPrincipalName
            UserId            = $device.userId
            OperatingSystem   = $device.operatingSystem
            OSVersion         = $device.osVersion
            OwnerType         = $device.managedDeviceOwnerType
            EnrollmentType    = $device.deviceEnrollmentType
            ComplianceState   = $device.complianceState
            EnrolledDateTime  = ConvertTo-UtcDateTime -Value $device.enrolledDateTime
            LastSyncDateTime  = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime
            SerialNumber      = $device.serialNumber
            ManagedDeviceId   = $device.id
        })
}
Write-Progress -Activity 'Checking primary users' -Completed

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No orphaned devices were found; no CSV file was written.'
}

$lookupFailures = @($userStates.Values | Where-Object { $_ -eq 'LookupFailed' }).Count
Write-Host ''
Write-Host ('Managed devices checked : {0}' -f $devices.Count) -ForegroundColor Cyan
Write-Host ('Distinct users looked up: {0} ({1} lookups failed)' -f $userStates.Count, $lookupFailures) -ForegroundColor Cyan
Write-Host ('Orphaned devices        : {0}' -f $report.Count) -ForegroundColor Yellow
foreach ($group in ($report | Group-Object -Property Reason | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-15} {1,6}' -f $group.Name, $group.Count)
}

if ($PassThru) {
    $report
}
#endregion Main
