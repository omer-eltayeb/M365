<#
.SYNOPSIS
    Reports the Windows feature version, build and patch level (UBR) of every Intune managed Windows device and flags unsupported or outdated builds.
.DESCRIPTION
    Reads Windows devices from Microsoft Graph v1.0 (/deviceManagement/managedDevices filtered to operatingSystem eq 'Windows'),
    parses osVersion into build and update build revision (UBR) and maps the build to a feature version (Windows 10 22H2, Windows 11
    24H2, LTSC 2019, Server 2022, ...). Devices are flagged EndOfSupport (Windows 10 after 14 October 2025, LTSC builds excepted),
    BelowMinimum (-MinimumBuild) and BelowPatchLevel (-MinimumUbrByBuild). Exports to CSV and prints a distribution by version and build.
.PARAMETER MinimumBuild
    Lowest acceptable build number (third part of osVersion, for example 22631 for Windows 11 23H2). Lower builds are flagged BelowMinimum.
.PARAMETER MinimumUbrByBuild
    Hashtable of build -> minimum UBR, for example @{ 22631 = 4317; 26100 = 2033 }. Devices on a listed build with a lower UBR
    are flagged BelowPatchLevel (use the UBR of the current month's cumulative update).
.PARAMETER AllowWindows10Esu
    Do not flag Windows 10 devices as EndOfSupport (tenant has Extended Security Updates).
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneWindowsVersionReport_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneWindowsVersionReport.ps1
    Reports every Windows device with its feature version and build and flags Windows 10 devices as end of support.
.EXAMPLE
    PS> .\Get-IntuneWindowsVersionReport.ps1 -MinimumBuild 22631 -MinimumUbrByBuild @{ 22631 = 4317; 26100 = 2033 } -PassThru | Where-Object { $_.BelowMinimum -or $_.BelowPatchLevel }
    Lists devices below Windows 11 23H2 or missing the current cumulative update on 23H2 / 24H2.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Updates & remediations
    Changes     : No
    Notes       : osVersion reflects the device's last check-in, so a device patched today shows the old UBR until it syncs.
                  Windows 10 LTSC 2016/2019 and Windows Server builds are not flagged EndOfSupport (own lifecycle); Windows 11
                  21H2 and 22H2 are out of support for most editions too - use -MinimumBuild 22631 to flag them.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list
.LINK
    https://learn.microsoft.com/windows/release-health/release-information
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 999999)]
    [int]$MinimumBuild,

    [Parameter()]
    [hashtable]$MinimumUbrByBuild,

    [Parameter()]
    [switch]$AllowWindows10Esu,

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

function ConvertTo-UtcDateTime {
    <# Converts a Graph date value (string or DateTime) to a UTC [datetime]; $null for empty values or the 0001-01-01 placeholder. #>
    param([object]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { $parsed = ([datetime]$Value).ToUniversalTime() } catch { return $null }
    if ($parsed.Year -le 1) { return $null }
    return $parsed
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneWindowsVersionReport_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementManagedDevices.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$featureVersions = @{
    '10.0.14393' = 'Windows 10 1607 / LTSC 2016'; '10.0.17763' = 'Windows 10 1809 / LTSC 2019'; '10.0.19044' = 'Windows 10 21H2'
    '10.0.19045' = 'Windows 10 22H2'; '10.0.20348' = 'Windows Server 2022'; '10.0.22000' = 'Windows 11 21H2'
    '10.0.22621' = 'Windows 11 22H2'; '10.0.22631' = 'Windows 11 23H2'; '10.0.26100' = 'Windows 11 24H2'
}
# LTSC and Server builds follow their own lifecycle and must not inherit the Windows 10 end-of-support flag.
$longTermBuilds = @(14393, 17763, 20348)

$uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$filter=operatingSystem eq ''Windows''' +
    '&$select=id,deviceName,userPrincipalName,osVersion,lastSyncDateTime,model,complianceState'
try { $devices = @(Invoke-GraphPaged -Uri $uri) } catch { throw "Failed to retrieve Windows devices from Microsoft Graph: $($_.Exception.Message)" }
Write-Verbose ('{0} Windows devices retrieved.' -f $devices.Count)

$report = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($device in $devices) {
    $parsed = $null; $build = $null; $ubr = $null; $buildKey = $null
    if ([version]::TryParse([string]$device.osVersion, [ref]$parsed)) {
        $build = $parsed.Build
        $buildKey = '{0}.{1}.{2}' -f $parsed.Major, $parsed.Minor, $parsed.Build
        if ($parsed.Revision -ge 0) { $ubr = $parsed.Revision }
    }
    $featureVersion = 'Unknown'
    if ($null -ne $buildKey) {
        if ($featureVersions.ContainsKey($buildKey)) { $featureVersion = $featureVersions[$buildKey] }
        elseif ($build -lt 22000) { $featureVersion = 'Windows 10 (build {0})' -f $build }
        else { $featureVersion = 'Windows 11 (build {0})' -f $build }
    }

    $endOfSupport = $featureVersion -like 'Windows 10*' -and $longTermBuilds -notcontains $build -and -not $AllowWindows10Esu
    $belowMinimum = $null
    if ($PSBoundParameters.ContainsKey('MinimumBuild') -and $null -ne $build) { $belowMinimum = $build -lt $MinimumBuild }
    $belowPatchLevel = $null
    if ($null -ne $MinimumUbrByBuild -and $null -ne $build -and $null -ne $ubr) {
        # Accept the build as an int or string key (22631 or '22631') and as the full 3-part build ('10.0.22631').
        foreach ($key in $MinimumUbrByBuild.Keys) {
            if ([string]$key -eq [string]$build -or [string]$key -eq $buildKey) { $belowPatchLevel = $ubr -lt [int]$MinimumUbrByBuild[$key] }
        }
    }

    $report.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            UserPrincipalName = $device.userPrincipalName
            OSVersion         = $device.osVersion
            FeatureVersion    = $featureVersion
            Build             = $build
            UBR               = $ubr
            EndOfSupport      = $endOfSupport
            BelowMinimum      = $belowMinimum
            BelowPatchLevel   = $belowPatchLevel
            ComplianceState   = $device.complianceState
            Model             = $device.model
            LastSyncDateTime  = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime
            ManagedDeviceId   = $device.id
        })
}

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else { Write-Warning 'No Windows devices were found; no CSV file was written.' }

Write-Host ('Windows devices : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host ('{0,-30} {1,7}  {2}' -f 'FeatureVersion', 'Devices', 'Top builds (devices)') -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property FeatureVersion | Sort-Object -Property Name)) {
    $colour = 'Green'; if ($group.Group[0].EndOfSupport) { $colour = 'Red' }
    $builds = @($group.Group | Group-Object -Property OSVersion | Sort-Object -Property Count -Descending | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })
    $buildText = ($builds | Select-Object -First 3) -join ', '
    if ($builds.Count -gt 3) { $buildText += ' +{0} more' -f ($builds.Count - 3) }
    Write-Host ('{0,-30} {1,7}  {2}' -f $group.Name, $group.Count, $buildText) -ForegroundColor $colour
}
$eos = @($report | Where-Object { $_.EndOfSupport }).Count
$eosColour = 'Green'; if ($eos -gt 0) { $eosColour = 'Red' }
Write-Host ('End of support  : {0}' -f $eos) -ForegroundColor $eosColour
if ($PSBoundParameters.ContainsKey('MinimumBuild')) { Write-Host ('Below build {0} : {1}' -f $MinimumBuild, @($report | Where-Object { $_.BelowMinimum }).Count) -ForegroundColor Yellow }
if ($null -ne $MinimumUbrByBuild) { Write-Host ('Below patch level: {0}' -f @($report | Where-Object { $_.BelowPatchLevel }).Count) -ForegroundColor Yellow }

if ($PassThru) { $report }
#endregion Main
