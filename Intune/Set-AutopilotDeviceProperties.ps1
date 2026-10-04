<#
.SYNOPSIS
    Updates the group tag, assigned user or device name of Windows Autopilot device identities, or removes the assigned user.
.DESCRIPTION
    Selects Autopilot identities by serial number, from a CSV or by their current group tag (v1.0 /deviceManagement/
    windowsAutopilotDeviceIdentities, looked up with $filter=contains(serialNumber,'...')) and calls updateDeviceProperties with only
    the properties that differ: groupTag, userPrincipalName plus addressableUserName (display name resolved from Entra ID) and
    displayName. -UnassignUser calls unassignUserFromDevice instead. Every change is wrapped in ShouldProcess; one result object per device.
.PARAMETER SerialNumber
    One or more device serial numbers to update.
.PARAMETER InputCsv
    CSV with a SerialNumber column and optional per-device GroupTag, UserPrincipalName and DisplayName columns (empty cells are ignored).
.PARAMETER CurrentGroupTag
    Select every identity whose current group tag matches this value (wildcards allowed); typically combined with -NewGroupTag.
.PARAMETER NewGroupTag
    Group tag to set on all selected devices. Use an empty string ('') to clear the tag.
.PARAMETER UserPrincipalName
    User to pre-assign to all selected devices; the display name is looked up to populate addressableUserName.
.PARAMETER DisplayName
    Autopilot device name to set. Only valid when exactly one device is selected; use the CSV DisplayName column for bulk renames.
.PARAMETER UnassignUser
    Remove the currently assigned user from the selected devices.
.EXAMPLE
    PS> .\Set-AutopilotDeviceProperties.ps1 -CurrentGroupTag 'Pilot' -NewGroupTag 'Production' -WhatIf
    Lists every Autopilot device tagged Pilot and shows the retag to Production without changing anything.
.EXAMPLE
    PS> .\Set-AutopilotDeviceProperties.ps1 -InputCsv .\assignments.csv -Confirm:$false | Where-Object { $_.Result -ne 'Updated' }
    Applies per-device group tags, users and names from a CSV and lists the rows that were not updated.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementServiceConfig.ReadWrite.All (delegated); User.ReadBasic.All only when -UserPrincipalName or a
                  UserPrincipalName column is used. Intune RBAC: Intune Administrator or "Enrollment programs / Update device".
    Category    : Enrollment & Autopilot
    Changes     : Yes
    Notes       : v1.0 endpoints only. Changes are applied by the Autopilot service asynchronously and become visible after the next
                  sync (usually within 15 minutes); a device that is mid-deployment picks them up only on its next Autopilot session.
.LINK
    https://learn.microsoft.com/graph/api/intune-enrollment-windowsautopilotdeviceidentity-updatedeviceproperties?view=graph-rest-1.0
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
    [string]$CurrentGroupTag,

    [Parameter()]
    [string]$NewGroupTag,

    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$DisplayName,

    [Parameter()]
    [switch]$UnassignUser
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

$script:userCache = @{}
function Get-CachedUser {
    <# Looks up an Entra ID user by UPN once and caches id/displayName/UPN; returns $null when the user does not exist. #>
    param([string]$Upn)
    if (-not $script:userCache.ContainsKey($Upn)) {
        $uri = 'https://graph.microsoft.com/v1.0/users/{0}?$select=id,displayName,userPrincipalName' -f [uri]::EscapeDataString($Upn)
        try { $script:userCache[$Upn] = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop }
        catch { $script:userCache[$Upn] = $null; Write-Warning ("User '{0}' was not found: {1}" -f $Upn, $_.Exception.Message) }
    }
    return $script:userCache[$Upn]
}
#endregion Helpers

#region Main
$base = 'https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities'
$select = '$select=id,serialNumber,model,groupTag,userPrincipalName,addressableUserName,displayName'
$csvRows = @{}; $csvColumns = @(); $serials = @($SerialNumber | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
if (-not [string]::IsNullOrWhiteSpace($InputCsv)) {
    $rows = @(Import-Csv -Path $InputCsv)
    if ($rows.Count -eq 0 -or $null -eq $rows[0].PSObject.Properties['SerialNumber']) { throw "'$InputCsv' must contain a SerialNumber column and at least one row." }
    $csvColumns = @($rows[0].PSObject.Properties.Name)
    foreach ($row in @($rows | Where-Object { $_.SerialNumber })) { $csvRows[$row.SerialNumber.Trim().ToUpperInvariant()] = $row; $serials += $row.SerialNumber.Trim() }
}
if ($serials.Count -eq 0 -and [string]::IsNullOrWhiteSpace($CurrentGroupTag)) { throw 'Select the devices with -SerialNumber, -InputCsv or -CurrentGroupTag.' }
$csvHasChanges = @($csvColumns | Where-Object { $_ -in @('GroupTag', 'UserPrincipalName', 'DisplayName') }).Count -gt 0
if (-not ($PSBoundParameters.ContainsKey('NewGroupTag') -or $UserPrincipalName -or $DisplayName -or $UnassignUser -or $csvHasChanges)) {
    throw 'Specify what to change: -NewGroupTag, -UserPrincipalName, -DisplayName, -UnassignUser or the CSV columns GroupTag/UserPrincipalName/DisplayName.'
}
if ($UnassignUser -and $UserPrincipalName) { throw '-UnassignUser and -UserPrincipalName cannot be combined.' }
$scopes = @('DeviceManagementServiceConfig.ReadWrite.All'); if ($UserPrincipalName -or $csvColumns -contains 'UserPrincipalName') { $scopes += 'User.ReadBasic.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
# Resolve the target identities: contains() is the only serialNumber filter the endpoint supports, so exact matches are picked client-side.
$devices = @{}
foreach ($serial in ($serials | Select-Object -Unique)) {
    try { $hits = @(Invoke-GraphPaged -Uri ("{0}?`$filter=contains(serialNumber,'{1}')&{2}" -f $base, $serial.Replace("'", "''"), $select)) }
    catch { Write-Warning ('Lookup of serial {0} failed: {1}' -f $serial, $_.Exception.Message); continue }
    $exact = @($hits | Where-Object { $_.serialNumber -eq $serial })
    if ($exact.Count -eq 0) { Write-Warning ('No Autopilot identity matches serial {0}.' -f $serial); continue }
    foreach ($device in $exact) { $devices[[string]$device.id] = $device }
}
if (-not [string]::IsNullOrWhiteSpace($CurrentGroupTag)) {
    try { $all = @(Invoke-GraphPaged -Uri ('{0}?{1}' -f $base, $select)) } catch { throw "Failed to list Autopilot identities: $($_.Exception.Message)" }
    foreach ($device in ($all | Where-Object { [string]$_.groupTag -like $CurrentGroupTag })) { $devices[[string]$device.id] = $device }
}
if ($devices.Count -eq 0) { Write-Warning 'No Autopilot identities matched the selection; nothing to do.'; return }
if ($DisplayName -and $devices.Count -gt 1) { throw '-DisplayName can only be used when exactly one device is selected; use the CSV DisplayName column for bulk renames.' }
$results = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($device in $devices.Values) {
    $index++
    Write-Progress -Activity 'Updating Autopilot device properties' -Status ('{0} of {1}' -f $index, $devices.Count) -PercentComplete ([int](($index / $devices.Count) * 100))
    $csv = $csvRows[([string]$device.serialNumber).ToUpperInvariant()]
    $body = @{}; $result = 'NoChange'; $errorMessage = $null; $newUser = $device.userPrincipalName; $newTag = $device.groupTag
    $wantedTag = $null; $wantedUpn = $UserPrincipalName; $wantedName = $DisplayName; if ($PSBoundParameters.ContainsKey('NewGroupTag')) { $wantedTag = $NewGroupTag }
    if ($null -ne $csv) {
        # Empty CSV cells are ignored so a partially filled column never clears existing values; use -NewGroupTag '' to clear tags.
        if ($null -eq $wantedTag -and $csv.GroupTag) { $wantedTag = ([string]$csv.GroupTag).Trim() }
        if (-not $wantedUpn -and $csv.UserPrincipalName) { $wantedUpn = ([string]$csv.UserPrincipalName).Trim() }
        if (-not $wantedName -and $csv.DisplayName) { $wantedName = ([string]$csv.DisplayName).Trim() }
    }
    if ($null -ne $wantedTag -and $wantedTag -cne [string]$device.groupTag) { $body['groupTag'] = $wantedTag; $newTag = $wantedTag }
    if ($wantedName -and $wantedName -cne [string]$device.displayName) { $body['displayName'] = $wantedName }
    if ($wantedUpn -and $wantedUpn -ne [string]$device.userPrincipalName) {
        $user = Get-CachedUser -Upn $wantedUpn
        if ($null -eq $user) { $result = 'UserNotFound' }
        else { $body['userPrincipalName'] = $user.userPrincipalName; $body['addressableUserName'] = $user.displayName; $newUser = $user.userPrincipalName }
    }
    $target = 'Serial {0} ({1}, tag: {2}, user: {3})' -f $device.serialNumber, $device.model, $device.groupTag, $device.userPrincipalName
    try {
        if ($UnassignUser -and $device.userPrincipalName) {
            if ($PSCmdlet.ShouldProcess($target, 'Unassign user')) {
                Invoke-MgGraphRequest -Method POST -Uri ('{0}/{1}/unassignUserFromDevice' -f $base, $device.id) -ErrorAction Stop | Out-Null
                $result = 'Unassigned'; $newUser = $null
            }
            else { $result = 'Skipped' }
        }
        if ($result -ne 'UserNotFound' -and $body.Count -gt 0) {
            if ($PSCmdlet.ShouldProcess($target, ('Update {0}' -f (($body.Keys | Sort-Object) -join ', ')))) {
                Invoke-MgGraphRequest -Method POST -Uri ('{0}/{1}/updateDeviceProperties' -f $base, $device.id) -Body $body -ErrorAction Stop | Out-Null
                $result = 'Updated'
            }
            else { $result = 'Skipped' }
        }
    }
    catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ('Update of serial {0} failed: {1}' -f $device.serialNumber, $errorMessage) }
    Start-Sleep -Milliseconds 200
    $results.Add([PSCustomObject]@{ SerialNumber = $device.serialNumber; Model = $device.model; PreviousGroupTag = $device.groupTag; NewGroupTag = $newTag
            PreviousUser = $device.userPrincipalName; NewUser = $newUser; DisplayName = $wantedName; Result = $result; Error = $errorMessage })
}
Write-Progress -Activity 'Updating Autopilot device properties' -Completed
Write-Host ("`nDevices selected : {0}" -f $results.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = @{ Failed = 'Red'; UserNotFound = 'Red'; Updated = 'Green'; Unassigned = 'Green' }[$group.Name]; if (-not $colour) { $colour = 'Yellow' }
    Write-Host ('  {0,-13} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
