<#
.SYNOPSIS
    Assigns an Intune device category to selected managed devices in bulk, skipping devices that already have it.
.DESCRIPTION
    Looks up the category by display name in Microsoft Graph v1.0 (/deviceManagement/deviceCategories), resolves the target devices
    by exact or wildcard name, by Intune device ID or from a CSV (optionally restricted to one platform) and assigns the category with
    PUT /deviceManagement/managedDevices/{id}/deviceCategory/$ref. Devices already in the category are reported as AlreadyAssigned.
    Every change is wrapped in ShouldProcess, so -WhatIf previews and -Confirm:$false runs unattended. Emits one result object per device.
.PARAMETER CategoryName
    Display name of an existing device category, for example 'Finance' or 'Shared devices'.
.PARAMETER DeviceName
    One or more Intune device names; wildcards such as 'LT-FIN-*' are matched client-side, exact names use a server-side $filter.
.PARAMETER DeviceId
    One or more Intune managed device IDs (GUIDs).
.PARAMETER InputCsv
    CSV file with a DeviceName column; its rows are added to -DeviceName.
.PARAMETER OperatingSystem
    Only devices of this platform are changed: Windows, iOS, Android, macOS or Linux.
.EXAMPLE
    PS> .\Set-IntuneDeviceCategoryBulk.ps1 -CategoryName 'Finance' -DeviceName 'LT-FIN-*' -WhatIf
    Shows which finance laptops would be moved into the Finance category.
.EXAMPLE
    PS> .\Set-IntuneDeviceCategoryBulk.ps1 -CategoryName 'Shared devices' -InputCsv .\kiosks.csv -OperatingSystem Windows -Confirm:$false
    Assigns the category to the Windows devices listed in the CSV without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.ReadWrite.All (delegated). Intune RBAC: Managed devices > Update (for example Intune Administrator).
    Category    : Devices & remote actions
    Changes     : Yes
    Notes       : The category must already exist (Devices > Device categories); the script never creates one. Company Portal only asks
                  users to pick a category while a device has none, so assigning one here also removes that prompt. Category-based
                  dynamic group rules (device.deviceCategory) re-evaluate on the Entra ID side within minutes. A 250 ms pause separates changes.
.LINK
    https://learn.microsoft.com/graph/api/intune-shared-devicecategory-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$CategoryName,

    [Parameter()]
    [string[]]$DeviceName,

    [Parameter()]
    [string[]]$DeviceId,

    [Parameter()]
    [string]$InputCsv,

    [Parameter()]
    [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'Linux')]
    [string]$OperatingSystem
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
    <# Resolves managed devices by id, exact name (server-side $filter) or wildcard pattern (client-side match), optionally limited to one platform. #>
    param([string[]]$Names, [string[]]$Ids, [string]$Platform, [string]$Select)
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
        $uri = '{0}?$select={1}' -f $base, $Select
        if (-not [string]::IsNullOrWhiteSpace($Platform)) { $uri += "&`$filter=operatingSystem eq '$Platform'" }
        foreach ($device in @(Invoke-GraphPaged -Uri $uri)) {
            foreach ($pattern in $patterns) { if ($device.deviceName -like $pattern) { $found[[string]$device.id] = $device; break } }
        }
    }
    $devices = @($found.Values)
    if (-not [string]::IsNullOrWhiteSpace($Platform)) { $devices = @($devices | Where-Object { $_.operatingSystem -eq $Platform }) }
    return $devices
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
if ($names.Count -eq 0 -and $ids.Count -eq 0) { throw 'Specify -DeviceName, -DeviceId or -InputCsv (for a whole platform use -DeviceName * together with -OperatingSystem).' }

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementManagedDevices.ReadWrite.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
$graphV1 = 'https://graph.microsoft.com/v1.0'
try { $categories = @(Invoke-GraphPaged -Uri ($graphV1 + '/deviceManagement/deviceCategories?$select=id,displayName')) }
catch { throw "Failed to list device categories: $($_.Exception.Message)" }
$category = $categories | Where-Object { $_.displayName -eq $CategoryName } | Select-Object -First 1
$existing = ($categories | ForEach-Object { $_.displayName } | Sort-Object) -join ', '
if ($null -eq $category) { throw ("Device category '{0}' was not found. Existing categories: {1}" -f $CategoryName, $existing) }
Write-Verbose ("Category '{0}' resolved to id {1}." -f $category.displayName, $category.id)

$select = 'id,deviceName,userPrincipalName,operatingSystem,deviceCategoryDisplayName'
try { $devices = @(Resolve-TargetDevice -Names $names -Ids $ids -Platform $OperatingSystem -Select $select) }
catch { throw "Failed to resolve the target devices: $($_.Exception.Message)" }
if ($devices.Count -eq 0) { Write-Warning 'No managed devices matched the selection; nothing to do.'; return }

$body = @{ '@odata.id' = ('{0}/deviceManagement/deviceCategories/{1}' -f $graphV1, $category.id) }
$results = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Assigning device category' -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    $result = 'Skipped'; $errorMessage = $null
    $target = '{0} ({1}, {2}, current category: {3})' -f $device.deviceName, $device.operatingSystem, $device.userPrincipalName, $device.deviceCategoryDisplayName
    if ($device.deviceCategoryDisplayName -eq $category.displayName) { $result = 'AlreadyAssigned' }
    elseif ($PSCmdlet.ShouldProcess($target, ("Assign device category '{0}'" -f $category.displayName))) {
        try {
            Invoke-MgGraphRequest -Method PUT -Uri ('{0}/deviceManagement/managedDevices/{1}/deviceCategory/$ref' -f $graphV1, $device.id) -Body $body -ErrorAction Stop | Out-Null
            $result = 'Updated'
        }
        catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ('Category assignment failed for {0}: {1}' -f $device.deviceName, $errorMessage) }
        Start-Sleep -Milliseconds 250
    }
    $results.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            OperatingSystem   = $device.operatingSystem
            UserPrincipalName = $device.userPrincipalName
            PreviousCategory  = $device.deviceCategoryDisplayName
            NewCategory       = $category.displayName
            Result            = $result
            Error             = $errorMessage
        })
}
Write-Progress -Activity 'Assigning device category' -Completed

Write-Host ("`nCategory '{0}' - devices selected: {1}" -f $category.displayName, $results.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = @{ Failed = 'Red'; Updated = 'Green' }[$group.Name]; if (-not $colour) { $colour = 'Yellow' }
    Write-Host ('  {0,-16} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
