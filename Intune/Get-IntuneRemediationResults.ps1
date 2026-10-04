<#
.SYNOPSIS
    Reports the run results of Intune remediation (proactive remediation) scripts per package and, optionally, per device.
.DESCRIPTION
    Lists remediation packages from the Microsoft Graph beta endpoint (/deviceManagement/deviceHealthScripts), reads each
    package's /runSummary (devices with and without issues, script errors, remediated and recurring issues, last run) and writes
    a summary CSV. With -IncludeDeviceResults every package's /deviceRunStates is read with the managed device expanded and a
    second CSV (<OutputPath name>_Devices.csv) lists detection and remediation state, script output and errors per device.
.PARAMETER ScriptName
    Wildcard pattern matched against the package display name (for example 'Fix-*'). Default: all packages.
.PARAMETER IncludeDeviceResults
    Also read per-device run states (one paged call per package) and write the _Devices CSV.
.PARAMETER OnlyFailures
    Report only packages with detection/remediation errors or recurring issues and, per device, only devices whose scripts failed or whose issue is not remediated.
.PARAMETER OutputPath
    Summary CSV file to create. Defaults to .\Reports\IntuneRemediationResults_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Emit the summary objects to the pipeline, or the device result objects when -IncludeDeviceResults is used.
.EXAMPLE
    PS> .\Get-IntuneRemediationResults.ps1
    Writes one row per remediation package with its run summary counters to .\Reports.
.EXAMPLE
    PS> .\Get-IntuneRemediationResults.ps1 -ScriptName 'Fix-*' -IncludeDeviceResults -OnlyFailures -PassThru | Format-Table Script, Device, DetectionState, RemediationState, RemediationError
    Shows the devices on which the Fix-* packages failed or still detect the issue, including the remediation error text.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role
    Category    : Updates & remediations
    Changes     : No
    Notes       : Remediations exist only on the beta endpoint, which Microsoft may change without notice, and require Windows
                  Enterprise E3/E5, Education A3/A5, Windows 365 or VDA licensing. Output and error columns are truncated to
                  300 characters. Device run states can be large; a 200 ms pause between packages limits throttling. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-devicehealthscriptrunsummary-get?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ScriptName = '*',

    [Parameter()]
    [switch]$IncludeDeviceResults,

    [Parameter()]
    [switch]$OnlyFailures,

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

function ConvertTo-ShortText {
    <# Collapses line breaks and truncates script output so the CSV stays readable. #>
    param([object]$Value, [int]$MaxLength = 300)
    $text = ([string]$Value -replace '[\r\n]+', ' ').Trim()
    if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength) + '...' }
    return $text
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneRemediationResults_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$devicePath = ($OutputPath -replace '\.[^.\\/]+$', '') + '_Devices.csv'

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$baseUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'   # beta: remediations are not available in v1.0
try { $packages = @(Invoke-GraphPaged -Uri ($baseUri + '?$select=id,displayName,publisher')) }
catch { throw "Failed to list remediation packages: $($_.Exception.Message)" }
$packages = @($packages | Where-Object { $_.displayName -like $ScriptName } | Sort-Object -Property displayName)
Write-Verbose ('{0} remediation packages match "{1}".' -f $packages.Count, $ScriptName)

$summary = New-Object -TypeName System.Collections.Generic.List[object]; $deviceRows = New-Object -TypeName System.Collections.Generic.List[object]
$totals = @{ Issues = 0; Remediated = 0; DetectionErrors = 0; RemediationErrors = 0 }; $index = 0
foreach ($package in $packages) {
    $index++
    Write-Progress -Activity 'Reading remediation results' -Status ('{0} of {1}: {2}' -f $index, $packages.Count, $package.displayName) -PercentComplete ([int](($index / $packages.Count) * 100))
    try {
        $run = Invoke-MgGraphRequest -Method GET -Uri ('{0}/{1}/runSummary' -f $baseUri, $package.id) -OutputType PSObject -ErrorAction Stop
        $hasFailures = ([int]$run.detectionScriptErrorDeviceCount + [int]$run.remediationScriptErrorDeviceCount + [int]$run.issueReoccurredDeviceCount) -gt 0
        if (-not $OnlyFailures -or $hasFailures) {
            $totals.Issues += [int]$run.issueDetectedDeviceCount; $totals.Remediated += [int]$run.issueRemediatedDeviceCount
            $totals.DetectionErrors += [int]$run.detectionScriptErrorDeviceCount; $totals.RemediationErrors += [int]$run.remediationScriptErrorDeviceCount
            $summary.Add([PSCustomObject]@{
                    Script            = $package.displayName
                    Publisher         = $package.publisher
                    LastRun           = ConvertTo-UtcDateTime -Value $run.lastScriptRunDateTime
                    IssueDetected     = $run.issueDetectedDeviceCount
                    NoIssue           = $run.noIssueDetectedDeviceCount
                    Remediated        = $run.issueRemediatedDeviceCount
                    Reoccurred        = $run.issueReoccurredDeviceCount
                    DetectionErrors   = $run.detectionScriptErrorDeviceCount
                    RemediationErrors = $run.remediationScriptErrorDeviceCount
                    Id                = $package.id
                })
        }
        if ($IncludeDeviceResults) {
            $statesUri = '{0}/{1}/deviceRunStates?$expand=managedDevice($select=deviceName,userPrincipalName,osVersion)' -f $baseUri, $package.id
            foreach ($state in @(Invoke-GraphPaged -Uri $statesUri)) {
                # A device "fails" when a script errored, remediation failed, or detection still reports the issue without a successful remediation.
                $failed = $state.detectionState -eq 'scriptError' -or $state.remediationState -in @('remediationFailed', 'scriptError') -or
                    ($state.detectionState -eq 'fail' -and $state.remediationState -ne 'success')
                if ($OnlyFailures -and -not $failed) { continue }
                $deviceRows.Add([PSCustomObject]@{
                        Script                = $package.displayName
                        Device                = $state.managedDevice.deviceName
                        UPN                   = $state.managedDevice.userPrincipalName
                        OSVersion             = $state.managedDevice.osVersion
                        DetectionState        = $state.detectionState
                        RemediationState      = $state.remediationState
                        IsFailure             = $failed
                        LastStateUpdate       = ConvertTo-UtcDateTime -Value $state.lastStateUpdateDateTime
                        LastSync              = ConvertTo-UtcDateTime -Value $state.lastSyncDateTime
                        PreRemediationOutput  = ConvertTo-ShortText -Value $state.preRemediationDetectionScriptOutput
                        DetectionError        = ConvertTo-ShortText -Value $state.preRemediationDetectionScriptError
                        RemediationError      = ConvertTo-ShortText -Value $state.remediationScriptError
                        PostRemediationOutput = ConvertTo-ShortText -Value $state.postRemediationDetectionScriptOutput
                        ManagedDeviceId       = $state.managedDevice.id
                    })
            }
        }
    }
    catch { Write-Warning ("Failed to read results for '{0}' ({1}): {2}" -f $package.displayName, $package.id, $_.Exception.Message) }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading remediation results' -Completed

if ($summary.Count -gt 0) { $summary | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8; Write-Host ('Summary written to {0}' -f $OutputPath) -ForegroundColor Green }
else { Write-Warning 'No remediation packages matched the selection; no summary CSV was written.' }
if ($IncludeDeviceResults -and $deviceRows.Count -gt 0) {
    $deviceRows | Export-Csv -Path $devicePath -NoTypeInformation -Encoding UTF8; Write-Host ('Device results written to {0}' -f $devicePath) -ForegroundColor Green
}

Write-Host ('Packages reported                       : {0}' -f $summary.Count) -ForegroundColor Cyan
Write-Host ('Devices with issues / remediated        : {0} / {1}' -f $totals.Issues, $totals.Remediated) -ForegroundColor Yellow
Write-Host ('Script errors (detection / remediation) : {0} / {1}' -f $totals.DetectionErrors, $totals.RemediationErrors) -ForegroundColor Red
if ($IncludeDeviceResults) { Write-Host ('Device rows (failures)                  : {0} ({1})' -f $deviceRows.Count, @($deviceRows | Where-Object { $_.IsFailure }).Count) -ForegroundColor Cyan }

if ($PassThru) { if ($IncludeDeviceResults) { $deviceRows } else { $summary } }
#endregion Main
