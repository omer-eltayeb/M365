<#
.SYNOPSIS
    Sends a bulk Intune "Sync" remote action to managed devices selected by name, platform, Entra group or all devices.
.DESCRIPTION
    Selects Intune managed devices (v1.0 /deviceManagement/managedDevices) by wildcard device name,
    operating system, membership of an Entra ID group (resolved through /groups/{id}/members of type
    device and matched on azureADDeviceId) or -All, then posts the syncDevice action for each device.
    Every request is wrapped in ShouldProcess so -WhatIf previews and -Confirm:$false runs unattended.
    Emits one result object per device (Requested, Skipped or Failed).
.PARAMETER DeviceName
    One or more wildcard patterns matched against the Intune device name, for example 'LT-FIN-*', 'DT-0042'.
.PARAMETER OperatingSystem
    Restrict the selection to one platform: Windows, iOS, Android, macOS or Linux (server-side $filter).
.PARAMETER GroupName
    Exact display name of an Entra ID group; devices that are members of the group are selected.
.PARAMETER All
    Select every managed device in the tenant. A warning is shown and each device prompts for confirmation
    unless -Confirm:$false is supplied.
.PARAMETER ThrottleMilliseconds
    Pause between sync requests to stay inside the Intune throttling limits. Default 250.
.EXAMPLE
    PS> .\Invoke-IntuneDeviceSync.ps1 -DeviceName 'LT-FIN-*' -WhatIf
    Lists the finance laptops that would receive a sync request without sending anything.
.EXAMPLE
    PS> .\Invoke-IntuneDeviceSync.ps1 -GroupName 'SG-Intune-Pilot' -Confirm:$false | Export-Csv -Path C:\Temp\sync.csv -NoTypeInformation
    Syncs every device in the pilot group without prompting and logs the per-device result to CSV.
.EXAMPLE
    PS> .\Invoke-IntuneDeviceSync.ps1 -OperatingSystem Windows -ThrottleMilliseconds 500
    Requests a sync for every Windows device, prompting for each one (answer "Yes to All" to continue unattended).
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All and DeviceManagementManagedDevices.PrivilegedOperations.All;
                  GroupMember.Read.All only when -GroupName is used (delegated). Intune RBAC: Help Desk Operator or
                  any role that includes the "Sync devices" remote task.
    Category    : Devices & remote actions
    Changes     : Yes
    Notes       : The sync action is queued by the service and executed when the device next checks in; a result of
                  'Requested' means Intune accepted the command, not that the device has synced. Only direct device
                  members of the group are considered (nested groups are not expanded).
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-syncdevice
.LINK
    https://learn.microsoft.com/graph/api/group-list-members
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$DeviceName,

    [Parameter()]
    [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'Linux')]
    [string]$OperatingSystem,

    [Parameter()]
    [string]$GroupName,

    [Parameter()]
    [switch]$All,

    [Parameter()]
    [ValidateRange(0, 10000)]
    [int]$ThrottleMilliseconds = 250
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

function Test-NameMatch {
    <# Returns $true when the name matches at least one of the wildcard patterns. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string[]]$Patterns
    )
    foreach ($pattern in $Patterns) {
        if ($Name -like $pattern) { return $true }
    }
    return $false
}
#endregion Helpers

#region Main
$hasDeviceName = ($null -ne $DeviceName -and $DeviceName.Count -gt 0)
$hasOperatingSystem = -not [string]::IsNullOrWhiteSpace($OperatingSystem)
$hasGroupName = -not [string]::IsNullOrWhiteSpace($GroupName)
if (-not $All -and -not $hasDeviceName -and -not $hasOperatingSystem -and -not $hasGroupName) {
    throw 'Specify at least one selection parameter: -DeviceName, -OperatingSystem, -GroupName or -All.'
}
if ($All -and ($hasDeviceName -or $hasOperatingSystem -or $hasGroupName)) {
    throw '-All cannot be combined with -DeviceName, -OperatingSystem or -GroupName.'
}

$scopes = @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All')
if ($hasGroupName) { $scopes += 'GroupMember.Read.All' }
try {
    Connect-GraphIfNeeded -Scopes $scopes
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0'

# Resolve the Entra group once and keep the Entra device ids of its members for matching against azureADDeviceId.
$groupDeviceIds = $null
if ($hasGroupName) {
    $escapedGroupName = $GroupName.Replace("'", "''")
    try {
        $groups = @(Invoke-GraphPaged -Uri ("{0}/groups?`$filter=displayName eq '{1}'&`$select=id,displayName" -f $graphV1, $escapedGroupName))
    }
    catch {
        throw "Failed to look up group '$GroupName': $($_.Exception.Message)"
    }
    if ($groups.Count -eq 0) { throw "Group '$GroupName' was not found in Entra ID." }
    if ($groups.Count -gt 1) { throw "Group name '$GroupName' is ambiguous ($($groups.Count) groups match); use a unique display name." }

    try {
        $members = @(Invoke-GraphPaged -Uri ('{0}/groups/{1}/members/microsoft.graph.device?$select=id,deviceId,displayName' -f $graphV1, $groups[0].id))
    }
    catch {
        throw "Failed to read the device members of group '$GroupName': $($_.Exception.Message)"
    }
    $groupDeviceIds = @{}
    foreach ($member in $members) {
        if (-not [string]::IsNullOrEmpty($member.deviceId)) { $groupDeviceIds[[string]$member.deviceId] = $true }
    }
    Write-Verbose ("Group '{0}' has {1} device members." -f $GroupName, $groupDeviceIds.Count)
}

$uri = $graphV1 + '/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,lastSyncDateTime,azureADDeviceId'
if ($hasOperatingSystem) { $uri += "&`$filter=operatingSystem eq '$OperatingSystem'" }
try {
    $devices = @(Invoke-GraphPaged -Uri $uri)
}
catch {
    throw "Failed to retrieve managed devices from Microsoft Graph: $($_.Exception.Message)"
}
if ($hasDeviceName) {
    $devices = @($devices | Where-Object { Test-NameMatch -Name ([string]$_.deviceName) -Patterns $DeviceName })
}
if ($null -ne $groupDeviceIds) {
    $devices = @($devices | Where-Object { -not [string]::IsNullOrEmpty($_.azureADDeviceId) -and $groupDeviceIds.ContainsKey([string]$_.azureADDeviceId) })
}
Write-Verbose ('{0} devices selected for sync.' -f $devices.Count)
if ($devices.Count -eq 0) {
    Write-Warning 'No managed devices matched the selection; nothing to do.'
    return
}
if ($All) {
    Write-Warning ('-All selected: a sync will be requested for ALL {0} managed devices. Each device prompts for confirmation unless -Confirm:$false is supplied; use -WhatIf to preview.' -f $devices.Count)
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Requesting Intune device sync' -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    $result = 'Skipped'
    $errorMessage = $null
    $target = '{0} ({1}, {2})' -f $device.deviceName, $device.operatingSystem, $device.userPrincipalName
    if ($PSCmdlet.ShouldProcess($target, 'Send Intune sync request')) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri ('{0}/deviceManagement/managedDevices/{1}/syncDevice' -f $graphV1, $device.id) -ErrorAction Stop | Out-Null
            $result = 'Requested'
        }
        catch {
            $result = 'Failed'
            $errorMessage = $_.Exception.Message
            Write-Warning ('Sync request failed for {0}: {1}' -f $device.deviceName, $errorMessage)
        }
        if ($ThrottleMilliseconds -gt 0) { Start-Sleep -Milliseconds $ThrottleMilliseconds }
    }

    $results.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            UserPrincipalName = $device.userPrincipalName
            OperatingSystem   = $device.operatingSystem
            LastSyncDateTime  = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime
            Result            = $result
            Error             = $errorMessage
        })
}
Write-Progress -Activity 'Requesting Intune device sync' -Completed

Write-Host ''
Write-Host ('Devices selected : {0}' -f $results.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = 'Green'
    if ($group.Name -eq 'Failed') { $colour = 'Red' }
    elseif ($group.Name -eq 'Skipped') { $colour = 'Yellow' }
    Write-Host ('  {0,-12} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
