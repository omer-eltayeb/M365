<#
.SYNOPSIS
    Sends an Intune remote action (restart, remote lock, shut down, locate, lost mode, key/password rotation, Defender scan) to selected managed devices.
.DESCRIPTION
    Resolves managed devices by exact or wildcard name, by Intune device ID or from a CSV, then posts the chosen action to
    Microsoft Graph /deviceManagement/managedDevices/{id}/{action}. Actions that do not apply to a device's platform are skipped
    with a warning. Every request is wrapped in ShouldProcess (-WhatIf previews, -Confirm:$false runs unattended); one result object per device.
.PARAMETER DeviceName
    One or more Intune device names; wildcards such as 'LT-FIN-*' are matched client-side, exact names use a server-side $filter.
.PARAMETER DeviceId
    One or more Intune managed device IDs (GUIDs).
.PARAMETER InputCsv
    CSV file with a DeviceName column; its rows are added to -DeviceName.
.PARAMETER Action
    rebootNow, remoteLock, shutDown, locateDevice, enableLostMode, disableLostMode, rotateBitLockerKeys, rotateLocalAdminPassword,
    windowsDefenderScan, windowsDefenderUpdateSignatures or logoutSharedAppleDeviceActiveUser.
.PARAMETER FullScan
    With -Action windowsDefenderScan run a full scan instead of the default quick scan.
.PARAMETER LostModeMessage
    Message shown on the lock screen by enableLostMode.
.PARAMETER LostModePhoneNumber
    Phone number shown on the lock screen by enableLostMode.
.PARAMETER ThrottleMilliseconds
    Pause between requests to stay inside the Intune throttling limits. Default 250.
.EXAMPLE
    PS> .\Invoke-IntuneDeviceAction.ps1 -DeviceName 'LT-FIN-*' -Action rebootNow -WhatIf
    Lists the finance laptops that would be restarted without sending anything.
.EXAMPLE
    PS> .\Invoke-IntuneDeviceAction.ps1 -InputCsv .\infected.csv -Action windowsDefenderScan -FullScan -Confirm:$false | Export-Csv .\scan.csv -NoTypeInformation
    Starts a full Defender scan on every device listed in the CSV without prompting and logs the per-device result.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.PrivilegedOperations.All and DeviceManagementManagedDevices.Read.All;
                  DeviceManagementManagedDevices.ReadWrite.All only for rotateBitLockerKeys (delegated). Intune RBAC: a role with the matching remote task.
    Category    : Devices & remote actions
    Changes     : Yes
    Notes       : rotateBitLockerKeys, rotateLocalAdminPassword and enableLostMode exist only on the beta endpoint and may change.
                  Requested means Intune queued the command; it runs when the device next checks in. Lost mode needs supervised
                  iOS/iPadOS devices; key and password rotation need the matching BitLocker or LAPS policy on the device.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-rebootnow
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
    [ValidateSet('rebootNow', 'remoteLock', 'shutDown', 'locateDevice', 'enableLostMode', 'disableLostMode', 'rotateBitLockerKeys',
        'rotateLocalAdminPassword', 'windowsDefenderScan', 'windowsDefenderUpdateSignatures', 'logoutSharedAppleDeviceActiveUser')]
    [string]$Action,

    [Parameter()]
    [switch]$FullScan,

    [Parameter()]
    [string]$LostModeMessage,

    [Parameter()]
    [string]$LostModePhoneNumber,

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
if ($names.Count -eq 0 -and $ids.Count -eq 0) { throw 'Specify at least one target device with -DeviceName, -DeviceId or -InputCsv.' }
$lostModeArgsMissing = [string]::IsNullOrWhiteSpace($LostModeMessage) -or [string]::IsNullOrWhiteSpace($LostModePhoneNumber)
if ($Action -eq 'enableLostMode' -and $lostModeArgsMissing) { throw '-Action enableLostMode requires -LostModeMessage and -LostModePhoneNumber.' }

$windowsOnly = @('windowsDefenderScan', 'windowsDefenderUpdateSignatures', 'rotateBitLockerKeys', 'rotateLocalAdminPassword')
$appleOnly = @('enableLostMode', 'disableLostMode', 'logoutSharedAppleDeviceActiveUser')
# ValidateSet accepts any casing but keeps what was typed; the URL segment must use the exact Graph action name.
$Action = ($windowsOnly + $appleOnly + @('rebootNow', 'remoteLock', 'shutDown', 'locateDevice')) | Where-Object { $_ -eq $Action } | Select-Object -First 1
# beta: these three actions are not exposed on the v1.0 endpoint yet.
$graphVersion = 'v1.0'; if (@('rotateBitLockerKeys', 'rotateLocalAdminPassword', 'enableLostMode') -contains $Action) { $graphVersion = 'beta' }
$body = $null; if ($Action -eq 'windowsDefenderScan') { $body = @{ quickScan = (-not $FullScan.IsPresent) } }
if ($Action -eq 'enableLostMode') { $body = @{ message = $LostModeMessage; phoneNumber = $LostModePhoneNumber } }

$scopes = @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All')
if ($Action -eq 'rotateBitLockerKeys') { $scopes += 'DeviceManagementManagedDevices.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

try { $devices = @(Resolve-TargetDevice -Names $names -Ids $ids -Select 'id,deviceName,userPrincipalName,operatingSystem') }
catch { throw "Failed to resolve the target devices: $($_.Exception.Message)" }
if ($devices.Count -eq 0) { Write-Warning 'No managed devices matched the selection; nothing to do.'; return }

$results = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity ('Sending {0}' -f $Action) -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    $result = 'Skipped'; $errorMessage = $null
    $target = '{0} ({1}, {2})' -f $device.deviceName, $device.operatingSystem, $device.userPrincipalName
    $wrongPlatform = ($windowsOnly -contains $Action -and $device.operatingSystem -ne 'Windows') -or ($appleOnly -contains $Action -and @('iOS', 'iPadOS') -notcontains $device.operatingSystem)
    if ($wrongPlatform) { $result = 'NotApplicable'; Write-Warning ('{0} does not apply to {1}; skipped.' -f $Action, $target) }
    elseif ($PSCmdlet.ShouldProcess($target, ('Send Intune remote action {0}' -f $Action))) {
        $requestParams = @{ Method = 'POST'; Uri = ('https://graph.microsoft.com/{0}/deviceManagement/managedDevices/{1}/{2}' -f $graphVersion, $device.id, $Action); ErrorAction = 'Stop' }
        if ($null -ne $body) { $requestParams['Body'] = $body }
        try { Invoke-MgGraphRequest @requestParams | Out-Null; $result = 'Requested' }
        catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ('{0} failed for {1}: {2}' -f $Action, $device.deviceName, $errorMessage) }
        if ($ThrottleMilliseconds -gt 0) { Start-Sleep -Milliseconds $ThrottleMilliseconds }
    }
    $results.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            UserPrincipalName = $device.userPrincipalName
            OperatingSystem   = $device.operatingSystem
            Action            = $Action
            Result            = $result
            Error             = $errorMessage
        })
}
Write-Progress -Activity ('Sending {0}' -f $Action) -Completed

Write-Host ("`n{0} ({1} endpoint) - devices selected: {2}" -f $Action, $graphVersion, $results.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = 'Green'
    if ($group.Name -eq 'Failed') { $colour = 'Red' } elseif ($group.Name -ne 'Requested') { $colour = 'Yellow' }
    Write-Host ('  {0,-14} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
