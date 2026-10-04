<#
.SYNOPSIS
    Deletes Windows Autopilot device identities (by serial, CSV or never-enrolled age) and optionally the matching Intune and Entra ID device objects.
.DESCRIPTION
    Selects Autopilot identities from v1.0 /deviceManagement/windowsAutopilotDeviceIdentities by serial number, from a CSV, or with
    -NeverEnrolledOlderThanDays (enrollmentState notContacted/unknown, no managed device, no contact within the period) and deletes them
    in Microsoft's recommended order: Intune managed device first (-RemoveIntuneDevice), then the Autopilot identity, then the Entra ID
    device object (-RemoveEntraDevice, /devices resolved by deviceId). Every deletion is wrapped in ShouldProcess; a CSV log is written.
.PARAMETER SerialNumber
    One or more serial numbers of the Autopilot identities to delete.
.PARAMETER InputCsv
    CSV with a SerialNumber column, for example the output of Get-AutopilotDeviceReport.ps1 filtered to the devices to remove.
.PARAMETER NeverEnrolledOlderThanDays
    Select identities that never enrolled and whose last Autopilot contact (or profile assignment date, if never contacted) is older than this many days.
.PARAMETER RemoveIntuneDevice
    Also delete the Intune managed device linked through managedDeviceId (requires DeviceManagementManagedDevices.ReadWrite.All).
.PARAMETER RemoveEntraDevice
    Also delete the Entra ID device object linked through azureActiveDirectoryDeviceId (requires Device.ReadWrite.All and a device admin role).
.PARAMETER LogPath
    CSV log of every selected device and the outcome per object. Defaults to .\Reports\AutopilotRemovals_yyyyMMdd-HHmm.csv.
.EXAMPLE
    PS> .\Remove-AutopilotDevices.ps1 -NeverEnrolledOlderThanDays 180 -WhatIf
    Lists the registrations that never enrolled in the last 180 days without deleting anything.
.EXAMPLE
    PS> .\Remove-AutopilotDevices.ps1 -InputCsv .\retired.csv -RemoveIntuneDevice -RemoveEntraDevice -Confirm:$false
    Removes the retired devices from Intune, Autopilot and Entra ID in that order and logs each result.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementServiceConfig.ReadWrite.All; plus DeviceManagementManagedDevices.ReadWrite.All with -RemoveIntuneDevice and
                  Device.ReadWrite.All with -RemoveEntraDevice (delegated; Entra deletions need Cloud Device Administrator or Intune Administrator).
    Category    : Enrollment & Autopilot
    Changes     : Yes
    Notes       : v1.0 only. Autopilot deletions are asynchronous (the identity can stay visible for up to 30 minutes). Deleting the Entra ID
                  object before the Autopilot identity is gone makes the service recreate it, hence the order. Deleting an Intune record does not wipe the device.
.LINK
    https://learn.microsoft.com/graph/api/intune-enrollment-windowsautopilotdeviceidentity-delete?view=graph-rest-1.0
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$SerialNumber,

    [Parameter()]
    [string]$InputCsv,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$NeverEnrolledOlderThanDays,

    [Parameter()]
    [switch]$RemoveIntuneDevice,

    [Parameter()]
    [switch]$RemoveEntraDevice,

    [Parameter()]
    [string]$LogPath
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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $LogPath = Join-Path -Path $reportFolder -ChildPath ('AutopilotRemovals_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$logFolder = Split-Path -Path $LogPath -Parent
if (-not [string]::IsNullOrWhiteSpace($logFolder) -and -not (Test-Path -Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory -Force | Out-Null }
$serials = @($SerialNumber | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
if (-not [string]::IsNullOrWhiteSpace($InputCsv)) {
    $rows = @(Import-Csv -Path $InputCsv)
    if ($rows.Count -eq 0 -or $null -eq $rows[0].PSObject.Properties['SerialNumber']) { throw "'$InputCsv' must contain a SerialNumber column and at least one row." }
    $serials += @($rows | Where-Object { $_.SerialNumber } | ForEach-Object { $_.SerialNumber.Trim() })
}
$byAge = $PSBoundParameters.ContainsKey('NeverEnrolledOlderThanDays')
if ($serials.Count -eq 0 -and -not $byAge) { throw 'Select the devices with -SerialNumber, -InputCsv or -NeverEnrolledOlderThanDays.' }
$scopes = @('DeviceManagementServiceConfig.ReadWrite.All')
if ($RemoveIntuneDevice) { $scopes += 'DeviceManagementManagedDevices.ReadWrite.All' }; if ($RemoveEntraDevice) { $scopes += 'Device.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graph = 'https://graph.microsoft.com/v1.0'; $base = "$graph/deviceManagement/windowsAutopilotDeviceIdentities"
$select = '$select=id,serialNumber,model,manufacturer,groupTag,enrollmentState,lastContactedDateTime,deploymentProfileAssignedDateTime,managedDeviceId,azureActiveDirectoryDeviceId'
$emptyGuid = '00000000-0000-0000-0000-000000000000'; $devices = @{}
foreach ($serial in ($serials | Select-Object -Unique)) {
    # contains() is the only serialNumber filter the endpoint supports; the exact match is picked client-side.
    try { $hits = @(Invoke-GraphPaged -Uri ("{0}?`$filter=contains(serialNumber,'{1}')&{2}" -f $base, $serial.Replace("'", "''"), $select) | Where-Object { $_.serialNumber -eq $serial }) }
    catch { Write-Warning ('Lookup of serial {0} failed: {1}' -f $serial, $_.Exception.Message); continue }
    if ($hits.Count -eq 0) { Write-Warning ('No Autopilot identity matches serial {0}.' -f $serial); continue }
    foreach ($device in $hits) { $devices[[string]$device.id] = $device }
}
if ($byAge) {
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-$NeverEnrolledOlderThanDays)
    try { $all = @(Invoke-GraphPaged -Uri ('{0}?{1}' -f $base, $select)) } catch { throw "Failed to list Autopilot identities: $($_.Exception.Message)" }
    foreach ($device in $all) {
        $hasManagedDevice = -not [string]::IsNullOrEmpty($device.managedDeviceId) -and $device.managedDeviceId -ne $emptyGuid
        if ($device.enrollmentState -notin @('notContacted', 'unknown') -or $hasManagedDevice) { continue }
        # Never-contacted devices carry the 0001-01-01 placeholder in lastContactedDateTime; the profile assignment date is the next best age marker.
        $reference = [datetime]::MinValue
        foreach ($candidate in @($device.lastContactedDateTime, $device.deploymentProfileAssignedDateTime)) {
            if ($candidate -and ([datetime]$candidate).Year -gt 1) { $reference = ([datetime]$candidate).ToUniversalTime(); break }
        }
        if ($reference.Year -le 1 -or $reference -lt $cutoff) { $devices[[string]$device.id] = $device }
    }
}
if ($devices.Count -eq 0) { Write-Warning 'No Autopilot identities matched the selection; nothing to do.'; return }
$selected = @($devices.Values | Sort-Object -Property serialNumber)
$scope = 'Autopilot identity'; if ($RemoveIntuneDevice) { $scope += ' + Intune device' }; if ($RemoveEntraDevice) { $scope += ' + Entra ID device' }
Write-Host ('{0} device(s) selected for deletion ({1}): {2}' -f $selected.Count, $scope, (@($selected | ForEach-Object { $_.serialNumber }) -join ', ')) -ForegroundColor Red
$results = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($device in $selected) {
    $index++
    Write-Progress -Activity 'Removing Autopilot devices' -Status ('{0} of {1}: {2}' -f $index, $selected.Count, $device.serialNumber) -PercentComplete ([int](($index / $selected.Count) * 100))
    $target = 'Serial {0} ({1} {2}, tag: {3})' -f $device.serialNumber, $device.manufacturer, $device.model, $device.groupTag
    $outcome = @{ Autopilot = 'Skipped'; Intune = 'NotRequested'; Entra = 'NotRequested' }; $errors = @()
    $managedDeviceId = [string]$device.managedDeviceId; if ($managedDeviceId -eq $emptyGuid) { $managedDeviceId = '' }
    $entraDeviceId = [string]$device.azureActiveDirectoryDeviceId; if ($entraDeviceId -eq $emptyGuid) { $entraDeviceId = '' }
    if ($RemoveIntuneDevice) {
        if (-not $managedDeviceId) { $outcome.Intune = 'NoIntuneDevice' }
        elseif ($PSCmdlet.ShouldProcess($target, 'Delete Intune managed device')) {
            try { Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/deviceManagement/managedDevices/{1}' -f $graph, $managedDeviceId) -ErrorAction Stop | Out-Null; $outcome.Intune = 'Deleted' }
            catch { $outcome.Intune = 'Failed'; $errors += ('Intune: ' + $_.Exception.Message) }
        }
        else { $outcome.Intune = 'Skipped' }
    }
    if ($PSCmdlet.ShouldProcess($target, 'Delete Autopilot device identity')) {
        try { Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/{1}' -f $base, $device.id) -ErrorAction Stop | Out-Null; $outcome.Autopilot = 'Deleted' }
        catch { $outcome.Autopilot = 'Failed'; $errors += ('Autopilot: ' + $_.Exception.Message) }
    }
    # The Entra object is only removed after a successful Autopilot deletion; otherwise the service would recreate it on the next sync.
    if ($RemoveEntraDevice -and $outcome.Autopilot -eq 'Deleted' -and $entraDeviceId) {
        try {
            $entra = @(Invoke-GraphPaged -Uri ("{0}/devices?`$filter=deviceId eq '{1}'&`$select=id,displayName" -f $graph, $entraDeviceId))
            if ($entra.Count -eq 0) { $outcome.Entra = 'NoEntraDevice' }
            elseif ($PSCmdlet.ShouldProcess(('{0} (Entra ID device {1})' -f $target, $entra[0].displayName), 'Delete Entra ID device object')) {
                Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/devices/{1}' -f $graph, $entra[0].id) -ErrorAction Stop | Out-Null; $outcome.Entra = 'Deleted'
            }
            else { $outcome.Entra = 'Skipped' }
        }
        catch { $outcome.Entra = 'Failed'; $errors += ('Entra: ' + $_.Exception.Message) }
    }
    elseif ($RemoveEntraDevice) { $outcome.Entra = 'Skipped'; if (-not $entraDeviceId) { $outcome.Entra = 'NoEntraDevice' } }
    if ($errors.Count -gt 0) { Write-Warning ('{0}: {1}' -f $device.serialNumber, ($errors -join ' | ')) }
    Start-Sleep -Milliseconds 200
    $lastContacted = $null
    if ($device.lastContactedDateTime -and ([datetime]$device.lastContactedDateTime).Year -gt 1) { $lastContacted = ([datetime]$device.lastContactedDateTime).ToUniversalTime() }
    $results.Add([PSCustomObject]@{ SerialNumber = $device.serialNumber; Model = $device.model; GroupTag = $device.groupTag; EnrollmentState = $device.enrollmentState
            LastContacted = $lastContacted; AutopilotResult = $outcome.Autopilot; IntuneResult = $outcome.Intune; EntraResult = $outcome.Entra; Error = ($errors -join ' | ') })
}
Write-Progress -Activity 'Removing Autopilot devices' -Completed

$results | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8
Write-Host ("`nLog written to {0}" -f $LogPath) -ForegroundColor Green
Write-Host ('Devices selected : {0}' -f $results.Count) -ForegroundColor Cyan
foreach ($column in @('AutopilotResult', 'IntuneResult', 'EntraResult')) {
    $counts = @($results | Where-Object { $_.$column -ne 'NotRequested' } | Group-Object -Property $column | Sort-Object -Property Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count })
    $colour = 'Green'; if (@($results | Where-Object { $_.$column -eq 'Failed' }).Count -gt 0) { $colour = 'Red' }
    if ($counts.Count -gt 0) { Write-Host ('  {0,-16} {1}' -f $column, ($counts -join ', ')) -ForegroundColor $colour }
}

$results
#endregion Main
