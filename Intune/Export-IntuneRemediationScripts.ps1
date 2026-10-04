<#
.SYNOPSIS
    Exports every Intune remediation (proactive remediation) script package with its detection and remediation scripts, settings and assignments.
.DESCRIPTION
    Lists remediation packages from the Microsoft Graph beta endpoint (/deviceManagement/deviceHealthScripts?$expand=assignments),
    reads each package to obtain the base64 script bodies and writes one folder per package containing the package JSON,
    Detect.ps1 and Remediate.ps1 exactly as uploaded. A RemediationScripts.csv index lists name, publisher, run-as account,
    32-bit and signature settings, run schedule, assignment targets and last modified date for documentation or backup.
.PARAMETER OutputFolder
    Root folder for the export. Defaults to .\IntuneRemediationsExport_yyyyMMdd-HHmm and is created when missing.
.PARAMETER PassThru
    Also emit the CSV index rows to the pipeline.
.EXAMPLE
    PS> .\Export-IntuneRemediationScripts.ps1
    Exports all remediation packages to .\IntuneRemediationsExport_<timestamp>\<PackageName>\ and writes the CSV index.
.EXAMPLE
    PS> .\Export-IntuneRemediationScripts.ps1 -OutputFolder D:\Backups\Remediations -PassThru | Where-Object { $_.RunAs -eq 'user' }
    Exports to D:\Backups\Remediations and lists the packages that run in the signed-in user's context.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Updates & remediations
    Changes     : No
    Notes       : Remediations are only exposed on the beta endpoint, which Microsoft may change without notice, and require
                  Windows Enterprise E3/E5, Education A3/A5, Windows 365 or VDA licensing. Script bodies are returned only by
                  the single-package GET, so one extra call per package is made with a 200 ms pause. Built-in Microsoft
                  packages are exported too. AssignedGroups shows group IDs (no Group.Read.All scope is requested).
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-devicehealthscript-list?view=graph-rest-beta
.LINK
    https://learn.microsoft.com/mem/intune/fundamentals/remediations
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

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

function Get-SafeFolderName {
    <# Builds a file-system safe, length-limited folder name with a short id suffix so duplicate package names cannot collide. #>
    param([string]$Name, [string]$Id)
    $clean = ([string]$Name -replace '[\\/:*?"<>|\x00-\x1F]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Unnamed' }
    if ($clean.Length -gt 80) { $clean = $clean.Substring(0, 80).TrimEnd() }
    return ('{0}_{1}' -f $clean, $Id.Substring(0, [Math]::Min(8, $Id.Length)))
}

function ConvertTo-AssignmentText {
    <# Returns the target label ('All devices', 'Group:<id>', 'Exclude:<id>') and the run schedule of one remediation assignment. #>
    param([object]$Assignment)
    $target = $Assignment.target
    switch ([string]$target.'@odata.type') {
        '#microsoft.graph.allDevicesAssignmentTarget' { $label = 'All devices' }
        '#microsoft.graph.allLicensedUsersAssignmentTarget' { $label = 'All users' }
        '#microsoft.graph.exclusionGroupAssignmentTarget' { $label = 'Exclude:{0}' -f $target.groupId }
        default { $label = 'Group:{0}' -f $target.groupId }
    }
    $schedule = $Assignment.runSchedule
    $scheduleText = 'None'
    if ($null -ne $schedule) {
        $timeZone = 'local time'
        if ($schedule.useUtc -eq $true) { $timeZone = 'UTC' }
        switch ([string]$schedule.'@odata.type') {
            '#microsoft.graph.deviceHealthScriptHourlySchedule' { $scheduleText = 'Every {0} hour(s)' -f $schedule.interval }
            '#microsoft.graph.deviceHealthScriptDailySchedule' { $scheduleText = 'Every {0} day(s) at {1} {2}' -f $schedule.interval, $schedule.time, $timeZone }
            '#microsoft.graph.deviceHealthScriptRunOnceSchedule' { $scheduleText = 'Once on {0} at {1} {2}' -f $schedule.date, $schedule.time, $timeZone }
            default { $scheduleText = ([string]$schedule.'@odata.type') -replace '^#microsoft\.graph\.', '' }
        }
    }
    if ($Assignment.runRemediationScript -eq $false) { $scheduleText += ' (detect only)' }
    return [PSCustomObject]@{ Target = $label; Schedule = $scheduleText }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('IntuneRemediationsExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
# .NET file APIs ignore the PowerShell current location, so work with an absolute provider path.
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementConfiguration.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$baseUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'   # beta: remediations are not available in v1.0
try { $packages = @(Invoke-GraphPaged -Uri ($baseUri + '?$expand=assignments')) } catch { throw "Failed to list remediation packages: $($_.Exception.Message)" }
Write-Verbose ('{0} remediation packages found.' -f $packages.Count)

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$failed = 0
$index = 0
foreach ($package in $packages) {
    $index++
    $name = [string]$package.displayName
    Write-Progress -Activity 'Exporting remediation packages' -Status ('{0} of {1}: {2}' -f $index, $packages.Count, $name) -PercentComplete ([int](($index / $packages.Count) * 100))
    try {
        # The list call omits the script bodies; only the single-item GET returns detectionScriptContent / remediationScriptContent.
        $detail = Invoke-MgGraphRequest -Method GET -Uri ('{0}/{1}' -f $baseUri, $package.id) -OutputType PSObject -ErrorAction Stop
        $assignments = @($package.assignments | Where-Object { $null -ne $_ })
        if ($null -eq $package.PSObject.Properties['assignments']) { $assignments = @(Invoke-GraphPaged -Uri ('{0}/{1}/assignments' -f $baseUri, $package.id)) }
        $detail | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $assignments -Force

        $packageFolder = Join-Path -Path $OutputFolder -ChildPath (Get-SafeFolderName -Name $name -Id ([string]$package.id))
        if (-not (Test-Path -LiteralPath $packageFolder)) { New-Item -Path $packageFolder -ItemType Directory -Force | Out-Null }
        # WriteAllBytes keeps the uploaded encoding and BOM intact instead of re-encoding the script text.
        if (-not [string]::IsNullOrEmpty($detail.detectionScriptContent)) {
            [System.IO.File]::WriteAllBytes((Join-Path -Path $packageFolder -ChildPath 'Detect.ps1'), [Convert]::FromBase64String($detail.detectionScriptContent))
        }
        if (-not [string]::IsNullOrEmpty($detail.remediationScriptContent)) {
            [System.IO.File]::WriteAllBytes((Join-Path -Path $packageFolder -ChildPath 'Remediate.ps1'), [Convert]::FromBase64String($detail.remediationScriptContent))
        }
        $detail | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path -Path $packageFolder -ChildPath 'Package.json') -Encoding UTF8

        $assignmentText = @($assignments | ForEach-Object { ConvertTo-AssignmentText -Assignment $_ })
        $lastModified = $null
        if (-not [string]::IsNullOrEmpty([string]$detail.lastModifiedDateTime)) { $lastModified = ([datetime]$detail.lastModifiedDateTime).ToUniversalTime() }
        $rows.Add([PSCustomObject]@{
                Name                  = $name
                Publisher             = $detail.publisher
                RunAs                 = $detail.runAsAccount
                RunAs32Bit            = $detail.runAs32Bit
                EnforceSignatureCheck = $detail.enforceSignatureCheck
                Schedule              = (@($assignmentText | ForEach-Object { $_.Schedule } | Select-Object -Unique) -join '; ')
                AssignedGroups        = (@($assignmentText | ForEach-Object { $_.Target }) -join '; ')
                HasRemediationScript  = (-not [string]::IsNullOrEmpty($detail.remediationScriptContent))
                LastModified          = $lastModified
                Id                    = $package.id
                Folder                = $packageFolder
            })
    }
    catch {
        $failed++
        Write-Warning ("Failed to export remediation package '{0}' ({1}): {2}" -f $name, $package.id, $_.Exception.Message)
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Exporting remediation packages' -Completed

if ($rows.Count -gt 0) {
    $rows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'RemediationScripts.csv') -NoTypeInformation -Encoding UTF8
}
else { Write-Warning 'No remediation packages were exported; the CSV index was not written.' }

Write-Host ''
Write-Host ('Export folder        : {0}' -f $OutputFolder) -ForegroundColor Cyan
Write-Host ('Packages found       : {0}' -f $packages.Count) -ForegroundColor Cyan
Write-Host ('Packages exported    : {0}' -f $rows.Count) -ForegroundColor Green
Write-Host ('Unassigned packages  : {0}' -f @($rows | Where-Object { [string]::IsNullOrEmpty($_.AssignedGroups) }).Count) -ForegroundColor Yellow
if ($failed -gt 0) { Write-Host ('Failed               : {0}' -f $failed) -ForegroundColor Red }

if ($PassThru) { $rows }
#endregion Main
