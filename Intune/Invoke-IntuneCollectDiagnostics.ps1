<#
.SYNOPSIS
    Triggers the Intune "Collect diagnostics" remote action on selected devices and optionally waits for and downloads the resulting log package.
.DESCRIPTION
    Resolves managed devices by exact or wildcard name, by Intune device ID or from a CSV and posts (beta)
    /deviceManagement/managedDevices/{id}/createDeviceLogCollectionRequest. With -Wait each logCollectionRequests entry is polled
    every 30 seconds until completed, failed or -TimeoutMinutes; -Download calls createDownloadUrl and saves the zip to -DownloadFolder.
.PARAMETER DeviceName
    One or more Intune device names; wildcards such as 'LT-FIN-*' are matched client-side, exact names use a server-side $filter.
.PARAMETER DeviceId
    One or more Intune managed device IDs (GUIDs).
.PARAMETER InputCsv
    CSV file with a DeviceName column; its rows are added to -DeviceName.
.PARAMETER Wait
    Poll the collection requests until they finish or the timeout elapses.
.PARAMETER TimeoutMinutes
    Maximum time to wait for the devices to upload their logs. Default 15.
.PARAMETER Download
    Download the completed log packages (implies -Wait).
.PARAMETER DownloadFolder
    Folder for the downloaded zip files. Defaults to .\Diagnostics; created when missing.
.EXAMPLE
    PS> .\Invoke-IntuneCollectDiagnostics.ps1 -DeviceName 'LT-0042' -Download
    Collects diagnostics from one laptop, waits up to 15 minutes and saves LT-0042_<timestamp>.zip under .\Diagnostics.
.EXAMPLE
    PS> .\Invoke-IntuneCollectDiagnostics.ps1 -InputCsv .\escalations.csv -Confirm:$false | Export-Csv .\requests.csv -NoTypeInformation
    Queues a collection on every device in the CSV without waiting; the packages can be downloaded later from the admin center.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.PrivilegedOperations.All and DeviceManagementManagedDevices.Read.All (delegated); Intune RBAC: Collect diagnostics task.
    Category    : Devices & remote actions
    Changes     : Yes
    Notes       : All log collection endpoints exist only on the beta Graph endpoint and may change. Supported on Windows 10 1909+/11 and
                  Android Enterprise devices; other platforms are skipped. Offline devices stay Pending; the package is kept 30 days once uploaded.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-createdevicelogcollectionrequest?view=graph-rest-beta
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
    [switch]$Wait,

    [Parameter()]
    [int]$TimeoutMinutes = 15,

    [Parameter()]
    [switch]$Download,

    [Parameter()]
    [string]$DownloadFolder = '.\Diagnostics'
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

$scopes = @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All')
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $devices = @(Resolve-TargetDevice -Names $names -Ids $ids -Select 'id,deviceName,userPrincipalName,operatingSystem') }
catch { throw "Failed to resolve the target devices: $($_.Exception.Message)" }
if ($devices.Count -eq 0) { Write-Warning 'No managed devices matched the selection; nothing to do.'; return }
# beta: the log collection endpoints (createDeviceLogCollectionRequest, logCollectionRequests, createDownloadUrl) are beta-only.
$deviceBase = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices'; $graphCall = @{ OutputType = 'PSObject'; ErrorAction = 'Stop' }
$results = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Requesting diagnostics' -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    $item = [PSCustomObject]@{ DeviceName = $device.deviceName; UserPrincipalName = $device.userPrincipalName; OperatingSystem = $device.operatingSystem
        ManagedDeviceId = $device.id; RequestId = $null; Status = 'Skipped'; SizeKB = $null; DownloadPath = $null; Error = $null }
    $target = '{0} ({1}, {2})' -f $device.deviceName, $device.operatingSystem, $device.userPrincipalName
    if (@('Windows', 'Android') -notcontains $device.operatingSystem) { $item.Status = 'NotApplicable'; Write-Warning ('Not supported on {0}; skipped {1}.' -f $device.operatingSystem, $target) }
    elseif ($PSCmdlet.ShouldProcess($target, 'Collect Intune diagnostics')) {
        try {
            $request = Invoke-MgGraphRequest @graphCall -Method POST -Uri ('{0}/{1}/createDeviceLogCollectionRequest' -f $deviceBase, $device.id) -Body @{ templateType = 'predefined' }
            $item.RequestId = $request.id; $item.Status = 'Pending'
        }
        catch { $item.Status = 'Failed'; $item.Error = $_.Exception.Message; Write-Warning ('Request failed for {0}: {1}' -f $device.deviceName, $item.Error) }
        Start-Sleep -Milliseconds 250
    }
    $results.Add($item)
}
Write-Progress -Activity 'Requesting diagnostics' -Completed
$pending = @($results | Where-Object { $_.Status -eq 'Pending' })
if (($Wait -or $Download) -and $pending.Count -gt 0) {
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while ($pending.Count -gt 0 -and (Get-Date) -lt $deadline) {
        Write-Progress -Activity 'Waiting for devices to upload diagnostics' -Status ('{0} request(s) pending; next check in 30 s, timeout at {1:HH:mm}' -f $pending.Count, $deadline)
        Start-Sleep -Seconds 30
        foreach ($item in $pending) {
            try {
                $state = Invoke-MgGraphRequest @graphCall -Method GET -Uri ('{0}/{1}/logCollectionRequests/{2}' -f $deviceBase, $item.ManagedDeviceId, $item.RequestId)
                $item.Status = (Get-Culture).TextInfo.ToTitleCase([string]$state.status); $item.SizeKB = $state.sizeInKB
            }
            catch { Write-Warning ('Status check failed for {0}: {1}' -f $item.DeviceName, $_.Exception.Message) }
        }
        $pending = @($results | Where-Object { $_.Status -eq 'Pending' })
    }
    Write-Progress -Activity 'Waiting for devices to upload diagnostics' -Completed
    if ($pending.Count -gt 0) { Write-Warning ('{0} request(s) still pending after {1} minutes; packages appear in the admin center once uploaded.' -f $pending.Count, $TimeoutMinutes) }
}
if ($Download) {
    if (-not (Test-Path -Path $DownloadFolder)) { New-Item -Path $DownloadFolder -ItemType Directory -Force | Out-Null }
    $savedPreference = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest on 5.1 crawls while rendering progress
    foreach ($item in @($results | Where-Object { $_.Status -eq 'Completed' })) {
        $zipPath = Join-Path -Path $DownloadFolder -ChildPath ('{0}_{1}.zip' -f ($item.DeviceName -replace '[\\/:*?"<>|]', '_'), (Get-Date -Format 'yyyyMMdd-HHmm'))
        try {
            $link = Invoke-MgGraphRequest @graphCall -Method POST -Uri ('{0}/{1}/logCollectionRequests/{2}/createDownloadUrl' -f $deviceBase, $item.ManagedDeviceId, $item.RequestId)
            Invoke-WebRequest -Uri $link.value -OutFile $zipPath -UseBasicParsing -ErrorAction Stop; $item.DownloadPath = (Resolve-Path -Path $zipPath).Path
        }
        catch { $item.Error = $_.Exception.Message; Write-Warning ('Download failed for {0}: {1}' -f $item.DeviceName, $item.Error) }
    }
    $ProgressPreference = $savedPreference
}
Write-Host ("`nDevices selected : {0}" -f $results.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Status | Sort-Object -Property Name)) {
    $colour = @{ Failed = 'Red'; Completed = 'Green' }[$group.Name]; if (-not $colour) { $colour = 'Yellow' }
    Write-Host ('  {0,-14} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
