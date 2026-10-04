<#
.SYNOPSIS
    Sets, clears or auto-assigns (from the last logged-on user) the Intune primary user of selected managed devices.
.DESCRIPTION
    Resolves managed devices by exact or wildcard name or from a CSV and changes their primary user through the beta endpoint
    /deviceManagement/managedDevices/{id}/users/$ref (POST with the user's @odata.id, DELETE to clear). The new user comes from
    -UserPrincipalName, a UserPrincipalName CSV column, or the device's usersLoggedOn list (beta). Devices already assigned are skipped.
.PARAMETER DeviceName
    One or more Intune device names; wildcards such as 'LT-FIN-*' are matched client-side, exact names use a server-side $filter.
.PARAMETER UserPrincipalName
    UPN of the user to set as primary user on every selected device.
.PARAMETER InputCsv
    CSV with a DeviceName column and, for per-device mappings, a UserPrincipalName column.
.PARAMETER UseLastLoggedOnUser
    Set the user with the most recent sign-in on each device (usersLoggedOn) as primary user.
.PARAMETER Clear
    Remove the primary user so the device becomes a shared/userless device.
.EXAMPLE
    PS> .\Set-IntuneDevicePrimaryUser.ps1 -InputCsv .\reassign.csv -WhatIf
    Shows which devices would get which primary user from a CSV with DeviceName and UserPrincipalName columns.
.EXAMPLE
    PS> .\Set-IntuneDevicePrimaryUser.ps1 -DeviceName 'LT-*' -UseLastLoggedOnUser -Confirm:$false | Where-Object { $_.Result -ne 'AlreadySet' }
    Aligns the primary user of every laptop with the person who last signed in and lists the devices that changed.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.ReadWrite.All and User.Read.All (delegated).
    Category    : Devices & remote actions
    Changes     : Yes
    Notes       : The users/$ref navigation and the usersLoggedOn property exist only on the beta endpoint and may change. Microsoft documents
                  the change for Windows devices; other platforms may be rejected. The Entra ID registered owner and the Autopilot assigned user are not touched.
.LINK
    https://learn.microsoft.com/mem/intune/remote-actions/find-primary-user
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$DeviceName,

    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$InputCsv,

    [Parameter()]
    [switch]$UseLastLoggedOnUser,

    [Parameter()]
    [switch]$Clear
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
    <# Resolves managed devices by exact name (server-side $filter) or wildcard pattern (client-side match); de-duplicated by id. #>
    param([string[]]$Names, [string]$Select)
    $base = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices'
    $found = @{}; $patterns = @()
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

$script:userCache = @{}
function Get-CachedUser {
    <# Looks up an Entra ID user by UPN or object id once and caches the result; returns $null when the user does not exist. #>
    param([string]$Key)
    if (-not $script:userCache.ContainsKey($Key)) {
        $uri = 'https://graph.microsoft.com/v1.0/users/{0}?$select=id,userPrincipalName' -f [uri]::EscapeDataString($Key)
        try { $script:userCache[$Key] = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop }
        catch { $script:userCache[$Key] = $null; Write-Warning ("User '{0}' was not found: {1}" -f $Key, $_.Exception.Message) }
    }
    return $script:userCache[$Key]
}
#endregion Helpers

#region Main
$names = @($DeviceName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$csvUserByDevice = @{}
if (-not [string]::IsNullOrWhiteSpace($InputCsv)) {
    $rows = @(Import-Csv -Path $InputCsv)
    if ($rows.Count -eq 0 -or $null -eq $rows[0].PSObject.Properties['DeviceName']) { throw "'$InputCsv' must contain a DeviceName column and at least one row." }
    foreach ($row in ($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.DeviceName) })) {
        $names += $row.DeviceName.Trim()
        $upn = $null; if ($null -ne $row.PSObject.Properties['UserPrincipalName']) { $upn = [string]$row.UserPrincipalName }
        if (-not [string]::IsNullOrWhiteSpace($upn)) { $csvUserByDevice[$row.DeviceName.Trim()] = $upn.Trim() }
    }
}
if ($names.Count -eq 0) { throw 'Specify the target devices with -DeviceName or -InputCsv.' }
$modes = @()
if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) { $modes += 'Explicit' }
if ($UseLastLoggedOnUser) { $modes += 'LastLoggedOn' }; if ($Clear) { $modes += 'Clear' }; if ($csvUserByDevice.Count -gt 0) { $modes += 'Csv' }
if ($modes.Count -ne 1) { throw 'Specify exactly one source for the new primary user: -UserPrincipalName, -UseLastLoggedOnUser, -Clear or a UserPrincipalName column in -InputCsv.' }
$mode = $modes[0]

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementManagedDevices.ReadWrite.All', 'User.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $devices = @(Resolve-TargetDevice -Names $names -Select 'id,deviceName,operatingSystem,userId,userPrincipalName') }
catch { throw "Failed to resolve the target devices: $($_.Exception.Message)" }
if ($devices.Count -eq 0) { Write-Warning 'No managed devices matched the selection; nothing to do.'; return }
# beta: the users/$ref navigation and the usersLoggedOn property are not exposed in v1.0.
$betaDevices = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices'; $results = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Setting primary user' -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    $result = 'Skipped'; $errorMessage = $null; $newUser = $null; $userKey = $null
    switch ($mode) {
        'Explicit' { $userKey = $UserPrincipalName }
        'Csv' {
            $userKey = $csvUserByDevice[[string]$device.deviceName]
            if (-not $userKey) { $result = 'NoMapping'; Write-Warning ('No UserPrincipalName is mapped for {0} in the CSV.' -f $device.deviceName) }
        }
        'LastLoggedOn' {
            try {
                $detail = Invoke-MgGraphRequest -Method GET -Uri ('{0}/{1}?$select=usersLoggedOn' -f $betaDevices, $device.id) -OutputType PSObject -ErrorAction Stop
                $latest = @($detail.usersLoggedOn) | Sort-Object -Property { [datetime]$_.lastLogOnDateTime } -Descending | Select-Object -First 1
                if ($null -eq $latest) { $result = 'NoLoggedOnUser'; Write-Warning ('{0} has no logged-on user history.' -f $device.deviceName) } else { $userKey = [string]$latest.userId }
            }
            catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ('usersLoggedOn lookup failed for {0}: {1}' -f $device.deviceName, $errorMessage) }
        }
    }
    if ($result -eq 'Skipped' -and $mode -ne 'Clear') {
        $newUser = Get-CachedUser -Key $userKey
        if ($null -eq $newUser) { $result = 'UserNotFound' }
    }
    $newUserName = '<none>'; if ($null -ne $newUser) { $newUserName = $newUser.userPrincipalName }
    $target = '{0} ({1}, current primary user: {2})' -f $device.deviceName, $device.operatingSystem, $device.userPrincipalName
    if ($result -eq 'Skipped') {
        $alreadySet = ($mode -eq 'Clear' -and [string]::IsNullOrEmpty($device.userId)) -or ($mode -ne 'Clear' -and [string]$device.userId -eq [string]$newUser.id)
        if ($alreadySet) { $result = 'AlreadySet' }
        elseif ($PSCmdlet.ShouldProcess($target, ('Set primary user to {0}' -f $newUserName))) {
            $refUri = '{0}/{1}/users/$ref' -f $betaDevices, $device.id
            $body = @{ '@odata.id' = ('https://graph.microsoft.com/beta/users/{0}' -f $newUser.id) }
            try {
                if ($mode -eq 'Clear') { Invoke-MgGraphRequest -Method DELETE -Uri $refUri -ErrorAction Stop | Out-Null; $result = 'Cleared' }
                else { Invoke-MgGraphRequest -Method POST -Uri $refUri -Body $body -ErrorAction Stop | Out-Null; $result = 'Updated' }
            }
            catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ('Primary user change failed for {0}: {1}' -f $device.deviceName, $errorMessage) }
            Start-Sleep -Milliseconds 250
        }
    }
    $results.Add([PSCustomObject]@{ DeviceName = $device.deviceName; OperatingSystem = $device.operatingSystem; PreviousUser = $device.userPrincipalName
            NewUser = $newUserName; Result = $result; Error = $errorMessage })
}
Write-Progress -Activity 'Setting primary user' -Completed
Write-Host ("`nDevices selected : {0} (mode: {1})" -f $results.Count, $mode) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = @{ Failed = 'Red'; Updated = 'Green'; Cleared = 'Green' }[$group.Name]; if (-not $colour) { $colour = 'Yellow' }
    Write-Host ('  {0,-15} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
