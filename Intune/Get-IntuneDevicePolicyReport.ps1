<#
.SYNOPSIS
    Reports every configuration profile, compliance policy and (optionally) detected app applied to one or more Intune devices.
.DESCRIPTION
    Resolves managed devices by exact or wildcard name and reads, per device, the beta collections
    /deviceManagement/managedDevices/{id}/deviceConfigurationStates and /deviceCompliancePolicyStates
    (policy name, state, platform, evaluated setting count, targeted user). With -IncludeDetectedApps
    the discovered software inventory (/managedDevices/{id}/detectedApps) is added as DetectedApp rows.
    Writes a CSV and optionally emits the rows to the pipeline.
.PARAMETER DeviceName
    One or more Intune device names. Exact names use a server-side $filter; wildcards such as 'LT-FIN-*' are matched client-side.
.PARAMETER IncludeDetectedApps
    Also list the detected apps (name, version, publisher) of each device as rows of Kind 'DetectedApp'.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\IntuneDevicePolicyReport_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneDevicePolicyReport.ps1 -DeviceName 'LT-FIN-0042'
    Lists every configuration profile and compliance policy evaluated on LT-FIN-0042 with its per-device state.
.EXAMPLE
    PS> .\Get-IntuneDevicePolicyReport.ps1 -DeviceName 'LT-FIN-*' -IncludeDetectedApps -PassThru | Where-Object { $_.State -in 'error', 'conflict' }
    Reports all finance laptops including their software inventory and shows only the policies in error or conflict.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All (delegated)
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : The per-device state collections are read from the beta endpoint, which Microsoft may change without notice.
                  Detected apps are refreshed by the Intune inventory cycle (up to 24 hours) and can add thousands of rows per device.
                  Each device costs 2-3 Graph calls; a 200 ms pause between devices keeps wildcard runs under the throttling limits.
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-deviceconfigurationstate-list?view=graph-rest-beta
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-devicecompliancepolicystate-list?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$DeviceName,

    [Parameter()]
    [switch]$IncludeDetectedApps,

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneDevicePolicyReport_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementManagedDevices.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $devices = @(Resolve-TargetDevice -Names $DeviceName -Select 'id,deviceName,operatingSystem,osVersion,userPrincipalName') }
catch { throw "Failed to resolve the target devices: $($_.Exception.Message)" }
if ($devices.Count -eq 0) { Write-Warning 'No managed devices matched the selection; nothing to report.'; return }

# beta: the per-device policy state collections and detectedApps are only fully populated on the beta endpoint.
$betaDevices = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices'
$stateSources = @(
    [PSCustomObject]@{ Kind = 'Configuration'; Segment = 'deviceConfigurationStates' }
    [PSCustomObject]@{ Kind = 'Compliance'; Segment = 'deviceCompliancePolicyStates' }
)
$results = New-Object -TypeName System.Collections.Generic.List[object]
$failed = 0; $index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Reading device policy states' -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    foreach ($source in $stateSources) {
        try {
            $states = @(Invoke-GraphPaged -Uri ('{0}/{1}/{2}' -f $betaDevices, $device.id, $source.Segment))
        }
        catch {
            $failed++
            Write-Warning ('Could not read {0} for {1}: {2}' -f $source.Segment, $device.deviceName, $_.Exception.Message)
            continue
        }
        foreach ($state in $states) {
            $results.Add([PSCustomObject]@{
                    DeviceName        = $device.deviceName
                    DeviceId          = $device.id
                    OperatingSystem   = $device.operatingSystem
                    Kind              = $source.Kind
                    Name              = $state.displayName
                    State             = $state.state
                    Platform          = $state.platformType
                    SettingCount      = $state.settingCount
                    UserPrincipalName = $state.userPrincipalName
                    Version           = $state.version
                    Publisher         = $null
                })
        }
    }
    if ($IncludeDetectedApps) {
        try {
            $apps = @(Invoke-GraphPaged -Uri ('{0}/{1}/detectedApps?$select=displayName,version,publisher' -f $betaDevices, $device.id))
            foreach ($app in $apps) {
                $results.Add([PSCustomObject]@{ DeviceName = $device.deviceName; DeviceId = $device.id; OperatingSystem = $device.operatingSystem
                        Kind = 'DetectedApp'; Name = $app.displayName; State = 'Detected'; Platform = $device.operatingSystem; SettingCount = $null
                        UserPrincipalName = $device.userPrincipalName; Version = $app.version; Publisher = $app.publisher })
            }
        }
        catch {
            $failed++
            Write-Warning ('Could not read detected apps for {0}: {1}' -f $device.deviceName, $_.Exception.Message)
        }
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading device policy states' -Completed

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ("`nDevices reported : {0}" -f $devices.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Kind | Sort-Object -Property Name)) {
    Write-Host ('  {0,-14} {1,6}' -f $group.Name, $group.Count) -ForegroundColor Green
}
$problemRows = @($results | Where-Object { $_.State -in 'error', 'conflict', 'nonCompliant' }).Count
$problemColour = 'Green'; if ($problemRows -gt 0) { $problemColour = 'Yellow' }
Write-Host ('  Error/conflict/non-compliant rows : {0}' -f $problemRows) -ForegroundColor $problemColour
if ($failed -gt 0) { Write-Host ('  Failed Graph calls : {0}' -f $failed) -ForegroundColor Red }
Write-Host ('Report saved to {0}' -f $OutputPath) -ForegroundColor Cyan
if ($PassThru) { $results }
#endregion Main
