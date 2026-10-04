<#
.SYNOPSIS
    Renames selected Intune managed devices from a CSV mapping or a naming pattern with {SERIAL}, {SERIAL8}, {USER} and {OS} tokens.
.DESCRIPTION
    Resolves managed devices by exact or wildcard name, by Intune device ID or from a CSV and posts the new name to the beta action
    /deviceManagement/managedDevices/{id}/setDeviceName. The new name comes from a NewName column in -InputCsv or from -NamePattern,
    where {SERIAL} is the serial number, {SERIAL8} its last eight characters, {USER} the primary user's UPN prefix and {OS} the platform.
    Windows names are validated against the 15-character NetBIOS rules, unsupported platforms and duplicate names are skipped with a
    warning, and every rename is wrapped in ShouldProcess. Emits one result object per device.
.PARAMETER DeviceName
    One or more Intune device names; wildcards such as 'DESKTOP-*' are matched client-side, exact names use a server-side $filter.
.PARAMETER DeviceId
    One or more Intune managed device IDs (GUIDs).
.PARAMETER InputCsv
    CSV file with a DeviceName column and either a NewName column (explicit mapping) or no NewName column (device list for -NamePattern).
.PARAMETER NamePattern
    Naming pattern applied to every selected device, for example 'LT-{SERIAL8}' or 'CONTOSO-{USER}'. Tokens are case-insensitive.
.EXAMPLE
    PS> .\Rename-IntuneDevices.ps1 -DeviceName 'DESKTOP-*' -NamePattern 'CT-{SERIAL8}' -WhatIf
    Shows the new name every device still carrying an OEM default name would receive, without renaming anything.
.EXAMPLE
    PS> .\Rename-IntuneDevices.ps1 -InputCsv .\rename.csv -Confirm:$false | Export-Csv .\rename-result.csv -NoTypeInformation
    Renames the devices listed in a CSV with DeviceName and NewName columns without prompting and logs the result.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.PrivilegedOperations.All and DeviceManagementManagedDevices.Read.All (delegated);
                  Intune RBAC: a role that includes the "Rename device" remote task.
    Category    : Devices & remote actions
    Changes     : Yes
    Notes       : setDeviceName exists only on the beta endpoint and may change. Supported platforms: Microsoft Entra joined or co-managed
                  Windows devices (the name changes after a restart; hybrid joined devices are not supported), supervised iOS/iPadOS and
                  macOS. Windows names must be 1-15 letters, digits or hyphens, not all digits and not starting or ending with a hyphen.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-setdevicename?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$DeviceName,

    [Parameter()]
    [string[]]$DeviceId,

    [Parameter()]
    [string]$InputCsv,

    [Parameter()]
    [string]$NamePattern
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

function Resolve-TargetDevice {
    <# Resolves managed devices by id, exact name (server-side $filter) or wildcard pattern (client-side match); de-duplicated by id. #>
    param([string[]]$Names, [string[]]$Ids, [string]$Select)
    $base = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
    $found = @{}; $patterns = @()
    foreach ($id in $Ids) {
        try { $device = Invoke-MgGraphRequest -Method GET -Uri ('{0}/{1}?$select={2}' -f $base, $id, $Select) -OutputType PSObject -ErrorAction Stop; $found[[string]$device.id] = $device }
        catch { Write-Warning ('Managed device id {0} was not found: {1}' -f $id, $_.Exception.Message) }
    }
    foreach ($name in $Names) {
        if ($name -match '[\*\?\[]') { $patterns += $name; continue }
        $hits = @(Invoke-GraphPaged -Uri ("{0}?`$filter=deviceName eq '{1}'&`$select={2}" -f $base, $name.Replace("'", "''"), $Select))
        if ($hits.Count -eq 0) { Write-Warning ("No managed device is named '{0}'." -f $name) }
        foreach ($device in $hits) { $found[[string]$device.id] = $device }
    }
    if ($patterns.Count -gt 0) {
        foreach ($device in @(Invoke-GraphPaged -Uri ('{0}?$select={1}' -f $base, $Select))) {
            foreach ($pattern in $patterns) { if ($device.deviceName -like $pattern) { $found[[string]$device.id] = $device; break } }
        }
    }
    return @($found.Values)
}
#endregion Helpers

#region Main
$names = @($DeviceName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$csvNewNames = @{}
if (-not [string]::IsNullOrWhiteSpace($InputCsv)) {
    $rows = @(Import-Csv -Path $InputCsv)
    if ($rows.Count -eq 0 -or $null -eq $rows[0].PSObject.Properties['DeviceName']) { throw "'$InputCsv' must contain a DeviceName column and at least one row." }
    foreach ($row in ($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.DeviceName) })) {
        $names += $row.DeviceName.Trim()
        if ($null -ne $row.PSObject.Properties['NewName'] -and -not [string]::IsNullOrWhiteSpace($row.NewName)) { $csvNewNames[$row.DeviceName.Trim()] = $row.NewName.Trim() }
    }
}
$ids = @($DeviceId | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$hasPattern = -not [string]::IsNullOrWhiteSpace($NamePattern)
if ($names.Count -eq 0 -and $ids.Count -eq 0) { throw 'Specify the target devices with -DeviceName, -DeviceId or -InputCsv.' }
if ($hasPattern -eq ($csvNewNames.Count -gt 0)) { throw 'Specify exactly one name source: -NamePattern or a NewName column in -InputCsv.' }

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $devices = @(Resolve-TargetDevice -Names $names -Ids $ids -Select 'id,deviceName,operatingSystem,serialNumber,userPrincipalName,isSupervised') }
catch { throw "Failed to resolve the target devices: $($_.Exception.Message)" }
if ($devices.Count -eq 0) { Write-Warning 'No managed devices matched the selection; nothing to do.'; return }

# Windows computer names: 1-15 letters, digits or hyphens, not all digits, no leading or trailing hyphen.
$windowsNamePattern = '^(?!-)(?!.*-$)(?!\d+$)[A-Za-z0-9-]{1,15}$'
$plannedNames = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Renaming devices' -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    $result = 'Skipped'; $errorMessage = $null; $newName = $null
    $os = [string]$device.operatingSystem
    $supported = ($os -eq 'Windows') -or ($os -eq 'macOS') -or (@('iOS', 'iPadOS') -contains $os -and $device.isSupervised -eq $true)
    if (-not $supported) {
        $result = 'NotSupported'; Write-Warning ('Rename is only supported on Windows, macOS and supervised iOS/iPadOS; skipped {0} ({1}).' -f $device.deviceName, $os)
    }
    else {
        if ($hasPattern) {
            $serial = [string]$device.serialNumber
            $serial8 = $serial; if ($serial.Length -gt 8) { $serial8 = $serial.Substring($serial.Length - 8) }
            $userPrefix = ([string]$device.userPrincipalName -split '@')[0]
            $newName = $NamePattern -replace '\{SERIAL8\}', $serial8 -replace '\{SERIAL\}', $serial -replace '\{USER\}', $userPrefix -replace '\{OS\}', $os
        }
        else { $newName = $csvNewNames[[string]$device.deviceName] }

        if ([string]::IsNullOrWhiteSpace($newName) -or $newName -match '[{}]') {
            $result = 'InvalidName'; Write-Warning ('No usable new name for {0} (empty value, unknown token or missing CSV mapping): "{1}"' -f $device.deviceName, $newName)
        }
        elseif ($os -eq 'Windows' -and $newName -notmatch $windowsNamePattern) {
            $result = 'InvalidName'; Write-Warning ('"{0}" is not a valid Windows computer name; skipped {1}.' -f $newName, $device.deviceName)
        }
        elseif ($newName -eq $device.deviceName) { $result = 'Unchanged' }
        elseif ($plannedNames.ContainsKey($newName)) {
            $result = 'DuplicateName'; Write-Warning ('"{0}" is already used for {1} in this run; skipped {2}.' -f $newName, $plannedNames[$newName], $device.deviceName)
        }
        elseif ($PSCmdlet.ShouldProcess(('{0} ({1}, serial {2})' -f $device.deviceName, $os, $device.serialNumber), ('Rename to {0}' -f $newName))) {
            # beta: setDeviceName is not exposed on the v1.0 endpoint.
            $uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices/{0}/setDeviceName' -f $device.id
            try { Invoke-MgGraphRequest -Method POST -Uri $uri -Body @{ deviceName = $newName } -ErrorAction Stop | Out-Null; $result = 'Requested' }
            catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ('Rename failed for {0}: {1}' -f $device.deviceName, $errorMessage) }
            Start-Sleep -Milliseconds 250
        }
        if ($result -ne 'DuplicateName' -and -not [string]::IsNullOrWhiteSpace($newName)) { $plannedNames[$newName] = $device.deviceName }
    }
    $results.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            NewName           = $newName
            OperatingSystem   = $os
            SerialNumber      = $device.serialNumber
            UserPrincipalName = $device.userPrincipalName
            Result            = $result
            Error             = $errorMessage
        })
}
Write-Progress -Activity 'Renaming devices' -Completed

Write-Host ("`nDevices selected : {0}" -f $results.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = @{ Failed = 'Red'; Requested = 'Green' }[$group.Name]; if (-not $colour) { $colour = 'Yellow' }
    Write-Host ('  {0,-15} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
