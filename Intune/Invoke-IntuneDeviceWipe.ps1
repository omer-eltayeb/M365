<#
.SYNOPSIS
    Offboards selected Intune managed devices with Wipe, Retire, Autopilot Reset or Fresh Start, with a red summary and per-device confirmation.
.DESCRIPTION
    Resolves managed devices by exact or wildcard name, by Intune device ID or from a CSV and posts the chosen action to Microsoft
    Graph v1.0: Wipe and AutopilotReset use /managedDevices/{id}/wipe, FreshStart uses /cleanWindowsDevice and Retire uses /retire.
    No -All selector exists. The devices and consequences are printed in red before the first ShouldProcess prompt; one result object per device.
.PARAMETER DeviceName
    One or more Intune device names; wildcards such as 'LT-FIN-*' are matched client-side, exact names use a server-side $filter.
.PARAMETER DeviceId
    One or more Intune managed device IDs (GUIDs).
.PARAMETER InputCsv
    CSV file with a DeviceName column; its rows are added to -DeviceName.
.PARAMETER Action
    Wipe (factory reset), Retire (remove company data and management), AutopilotReset or FreshStart (both Windows only).
.PARAMETER KeepEnrollmentData
    Wipe only: keep the enrollment state and Entra join so the device stays managed after the reset.
.PARAMETER KeepUserData
    Wipe or FreshStart: keep user accounts and data.
.PARAMETER UseProtectedWipe
    Wipe only: protected wipe that resists power interruption (Windows 10 1709 and later); takes longer.
.PARAMETER MacOsUnlockCode
    Wipe only: six-digit PIN that unlocks a macOS device after the wipe.
.EXAMPLE
    PS> .\Invoke-IntuneDeviceWipe.ps1 -InputCsv .\leavers.csv -Action Retire -WhatIf
    Shows which devices from the CSV would be retired without sending anything.
.EXAMPLE
    PS> .\Invoke-IntuneDeviceWipe.ps1 -DeviceName 'LT-LOANER-*' -Action AutopilotReset -Confirm:$false | Export-Csv .\reset.csv -NoTypeInformation
    Sends an Autopilot Reset to every loaner laptop without prompting and logs the per-device result.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.PrivilegedOperations.All and DeviceManagementManagedDevices.Read.All (delegated);
                  Intune RBAC: a role that includes the Wipe and Retire remote tasks (Help Desk Operator does not).
    Category    : Devices & remote actions
    Changes     : Yes
    Notes       : Wipe and Fresh Start are irreversible. Requested means Intune queued the command; offline devices run it at their next
                  check-in. AutopilotReset is the wipe variant the admin center sends (enrollment and Entra join kept, user data removed).
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-wipe
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
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Wipe', 'Retire', 'AutopilotReset', 'FreshStart')]
    [string]$Action,

    [Parameter()]
    [switch]$KeepEnrollmentData,

    [Parameter()]
    [switch]$KeepUserData,

    [Parameter()]
    [switch]$UseProtectedWipe,

    [Parameter()]
    [ValidatePattern('^\d{6}$')]
    [string]$MacOsUnlockCode
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
if (-not [string]::IsNullOrWhiteSpace($InputCsv)) {
    $rows = @(Import-Csv -Path $InputCsv)
    if ($rows.Count -eq 0 -or $null -eq $rows[0].PSObject.Properties['DeviceName']) { throw "'$InputCsv' must contain a DeviceName column and at least one row." }
    $names += @($rows | ForEach-Object { $_.DeviceName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}
$ids = @($DeviceId | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($names.Count -eq 0 -and $ids.Count -eq 0) { throw 'Specify the target devices with -DeviceName, -DeviceId or -InputCsv; this script never acts on all devices.' }
if ($Action -ne 'Wipe' -and ($KeepEnrollmentData -or $UseProtectedWipe -or $MacOsUnlockCode)) { throw '-KeepEnrollmentData, -UseProtectedWipe and -MacOsUnlockCode apply to -Action Wipe only.' }
if ($KeepUserData -and @('Wipe', 'FreshStart') -notcontains $Action) { throw '-KeepUserData applies to -Action Wipe or FreshStart only.' }

$actionPath = 'wipe'; $body = $null
switch ($Action) {
    'Wipe' { $body = @{ keepEnrollmentData = $KeepEnrollmentData.IsPresent; keepUserData = $KeepUserData.IsPresent; useProtectedWipe = $UseProtectedWipe.IsPresent } }
    'AutopilotReset' { $body = @{ keepEnrollmentData = $true; keepUserData = $false } }
    'FreshStart' { $actionPath = 'cleanWindowsDevice'; $body = @{ keepUserData = $KeepUserData.IsPresent } }
    'Retire' { $actionPath = 'retire' }
}
if ($Action -eq 'Wipe' -and $MacOsUnlockCode) { $body['macOsUnlockCode'] = $MacOsUnlockCode }
$impact = @{ Wipe = 'factory-resets the device and removes all data'; Retire = 'removes company data, apps and management'
    AutopilotReset = 'wipes the device and re-provisions it through Autopilot'; FreshStart = 'reinstalls Windows and removes OEM applications' }
$scopes = @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All')
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $devices = @(Resolve-TargetDevice -Names $names -Ids $ids -Select 'id,deviceName,userPrincipalName,operatingSystem,serialNumber') }
catch { throw "Failed to resolve the target devices: $($_.Exception.Message)" }
if ($devices.Count -eq 0) { Write-Warning 'No managed devices matched the selection; nothing to do.'; return }

Write-Host ("`nWARNING: {0} will be sent to {1} device(s). This action {2} and cannot be undone." -f $Action, $devices.Count, $impact[$Action]) -ForegroundColor Red
$devices | ForEach-Object { Write-Host ('  {0,-28} {1,-10} {2,-20} {3}' -f $_.deviceName, $_.operatingSystem, $_.serialNumber, $_.userPrincipalName) -ForegroundColor Red }

$results = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity ('Sending {0}' -f $Action) -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    $result = 'Skipped'; $errorMessage = $null; $target = '{0} ({1}, {2})' -f $device.deviceName, $device.operatingSystem, $device.userPrincipalName
    if (@('AutopilotReset', 'FreshStart') -contains $Action -and $device.operatingSystem -ne 'Windows') {
        $result = 'NotApplicable'; Write-Warning ('{0} is Windows-only; skipped {1}.' -f $Action, $target)
    }
    elseif ($PSCmdlet.ShouldProcess($target, ('{0} - {1}' -f $Action, $impact[$Action]))) {
        $requestParams = @{ Method = 'POST'; Uri = ('https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{0}/{1}' -f $device.id, $actionPath); ErrorAction = 'Stop' }
        if ($null -ne $body) { $requestParams['Body'] = $body }
        try { Invoke-MgGraphRequest @requestParams | Out-Null; $result = 'Requested' }
        catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ('{0} failed for {1}: {2}' -f $Action, $device.deviceName, $errorMessage) }
        Start-Sleep -Milliseconds 250
    }
    $results.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            UserPrincipalName = $device.userPrincipalName
            OperatingSystem   = $device.operatingSystem
            SerialNumber      = $device.serialNumber
            Action            = $Action
            Result            = $result
            Error             = $errorMessage
        })
}
Write-Progress -Activity ('Sending {0}' -f $Action) -Completed

Write-Host ("`n{0} - devices selected: {1}" -f $Action, $results.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = @{ Failed = 'Red'; Requested = 'Green' }[$group.Name]; if (-not $colour) { $colour = 'Yellow' }
    Write-Host ('  {0,-14} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
