<#
.SYNOPSIS
    Deployment status summary (succeeded, failed, error, conflict, pending) for Intune configuration profiles and administrative templates.
.DESCRIPTION
    Lists device configuration profiles (v1.0 /deviceManagement/deviceConfigurations) and administrative
    templates (beta /deviceManagement/groupPolicyConfigurations), then reads the device status overview of
    each profile (/{id}/deviceStatusOverview). With -IncludeDeviceStatuses the per-device (/deviceStatuses)
    and per-user (/userStatuses) rows are written to a second CSV named <OutputPath>_Devices.csv. The result
    is exported to CSV and the profiles with the most failures are printed.
.PARAMETER ProfileName
    Wildcard pattern (for example 'WIN-*') applied to the profile display name.
.PARAMETER OnlyWithErrors
    Keep only profiles that report at least one failed, error or conflict device.
.PARAMETER IncludeDeviceStatuses
    Also download the per-device and per-user status rows of every profile into <OutputPath>_Devices.csv.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneConfigurationProfileStatus_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the summary rows to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneConfigurationProfileStatus.ps1
    Exports one row per configuration profile and administrative template with its deployment status counts.
.EXAMPLE
    PS> .\Get-IntuneConfigurationProfileStatus.ps1 -OnlyWithErrors -IncludeDeviceStatuses -Verbose
    Reports only the profiles with failures and writes the affected devices and users to <OutputPath>_Devices.csv.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : Administrative templates are only exposed on the beta endpoint, which Microsoft may change without
                  notice; if a tenant does not return a status overview for them, the rows are kept with empty counts
                  and a single warning is shown. Settings catalog policies use the Intune reports API instead and are
                  not covered here. The overview is an aggregate refreshed periodically (see LastStatusUpdate).
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-deviceconfiguration-list
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-deviceconfigurationdeviceoverview-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ProfileName,

    [Parameter()]
    [switch]$OnlyWithErrors,

    [Parameter()]
    [switch]$IncludeDeviceStatuses,

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
    <# Normalises a Graph date value (string or DateTime) to a UTC [datetime]; returns $null for empty or 0001-01-01 placeholders. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { $parsed = [datetime]$Value } catch { return $null }
    if ($parsed.Year -le 1) { return $null }
    return $parsed.ToUniversalTime()
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneConfigurationProfileStatus_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('DeviceManagementConfiguration.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$sources = @(
    [PSCustomObject]@{ Type = 'DeviceConfiguration'; BaseUri = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations'; ListQuery = '?$select=id,displayName,lastModifiedDateTime,version' }
    # beta: administrative templates (groupPolicyConfigurations) are not available in v1.0
    [PSCustomObject]@{ Type = 'AdministrativeTemplate'; BaseUri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'; ListQuery = '?$select=id,displayName,lastModifiedDateTime' }
)

$report = New-Object -TypeName System.Collections.Generic.List[object]
$statusRows = New-Object -TypeName System.Collections.Generic.List[object]
$failed = 0
foreach ($source in $sources) {
    try {
        $profiles = @(Invoke-GraphPaged -Uri ($source.BaseUri + $source.ListQuery))
    }
    catch {
        Write-Warning ('Could not list {0} profiles: {1}' -f $source.Type, $_.Exception.Message)
        continue
    }
    if (-not [string]::IsNullOrWhiteSpace($ProfileName)) {
        $profiles = @($profiles | Where-Object { $_.displayName -like $ProfileName })
    }
    Write-Verbose ('{0}: {1} profiles to inspect.' -f $source.Type, $profiles.Count)

    $overviewSupported = $true
    $index = 0
    foreach ($profile in $profiles) {
        $index++
        Write-Progress -Activity ('Reading {0} status' -f $source.Type) -Status ('{0} of {1}: {2}' -f $index, $profiles.Count, $profile.displayName) -PercentComplete ([int](($index / $profiles.Count) * 100))
        $itemUri = '{0}/{1}' -f $source.BaseUri, $profile.id
        $overview = $null
        if ($overviewSupported) {
            try {
                $overview = Invoke-MgGraphRequest -Method GET -Uri ($itemUri + '/deviceStatusOverview') -OutputType PSObject -ErrorAction Stop
            }
            catch {
                # A 404/400 on the very first profile means the tenant does not expose the overview for this type at all.
                if ($index -eq 1 -and $_.Exception.Message -match '404|400|NotFound|BadRequest') {
                    $overviewSupported = $false
                    Write-Warning ('The status overview is not available for {0} profiles; their rows are reported without counts.' -f $source.Type)
                }
                else {
                    $failed++
                    Write-Warning ("Could not read status for profile '{0}' ({1}): {2}" -f $profile.displayName, $profile.id, $_.Exception.Message)
                }
            }
        }

        $errorTotal = [int]$overview.failedCount + [int]$overview.errorCount + [int]$overview.conflictCount
        if ($OnlyWithErrors -and $errorTotal -eq 0) { continue }
        $report.Add([PSCustomObject]@{
                ProfileName      = $profile.displayName
                PolicyType       = $source.Type
                ProfileKind      = ([string]$profile.'@odata.type' -replace '^#microsoft\.graph\.', '')
                Succeeded        = $overview.successCount
                Failed           = $overview.failedCount
                Error            = $overview.errorCount
                Conflict         = $overview.conflictCount
                Pending          = $overview.pendingCount
                NotApplicable    = $overview.notApplicableCount
                TotalDevices     = [int]$overview.successCount + [int]$overview.pendingCount + [int]$overview.notApplicableCount + $errorTotal
                LastStatusUpdate = ConvertTo-UtcDateTime -Value $overview.lastUpdateDateTime
                LastModified     = ConvertTo-UtcDateTime -Value $profile.lastModifiedDateTime
                Version          = $profile.version
                ProfileId        = $profile.id
            })

        if ($IncludeDeviceStatuses -and $overviewSupported) {
            try {
                foreach ($status in @(Invoke-GraphPaged -Uri ($itemUri + '/deviceStatuses'))) {
                    $statusRows.Add([PSCustomObject]@{ ProfileName = $profile.displayName; PolicyType = $source.Type; Kind = 'Device'; Name = $status.deviceDisplayName; UserPrincipalName = $status.userPrincipalName; Status = $status.status; DeviceCount = 1; LastReportedDateTime = ConvertTo-UtcDateTime -Value $status.lastReportedDateTime; ProfileId = $profile.id })
                }
                foreach ($status in @(Invoke-GraphPaged -Uri ($itemUri + '/userStatuses'))) {
                    $statusRows.Add([PSCustomObject]@{ ProfileName = $profile.displayName; PolicyType = $source.Type; Kind = 'User'; Name = $status.userDisplayName; UserPrincipalName = $status.userPrincipalName; Status = $status.status; DeviceCount = $status.devicesCount; LastReportedDateTime = ConvertTo-UtcDateTime -Value $status.lastReportedDateTime; ProfileId = $profile.id })
                }
            }
            catch {
                Write-Warning ("Could not read device/user statuses for profile '{0}': {1}" -f $profile.displayName, $_.Exception.Message)
            }
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Progress -Activity ('Reading {0} status' -f $source.Type) -Completed
}

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No profiles matched the criteria; no CSV file was written.'
}
if ($IncludeDeviceStatuses -and $statusRows.Count -gt 0) {
    $statusPath = ($OutputPath -replace '\.csv$', '') + '_Devices.csv'
    $statusRows | Export-Csv -Path $statusPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Device and user statuses written to {0} ({1} rows)' -f $statusPath, $statusRows.Count) -ForegroundColor Green
}

Write-Host ''
Write-Host ('Profiles in report            : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host ('Profiles that could not be read: {0}' -f $failed) -ForegroundColor Cyan
Write-Host ('Profiles with failures        : {0}' -f @($report | Where-Object { ([int]$_.Failed + [int]$_.Error + [int]$_.Conflict) -gt 0 }).Count) -ForegroundColor Yellow
Write-Host 'Profiles with the most failed/error/conflict devices:' -ForegroundColor Cyan
foreach ($row in ($report | Sort-Object -Property { [int]$_.Failed + [int]$_.Error + [int]$_.Conflict } -Descending | Select-Object -First 10)) {
    if (([int]$row.Failed + [int]$row.Error + [int]$row.Conflict) -eq 0) { continue }
    Write-Host ('  {0,-60} {1,5} failed, {2,5} error, {3,5} conflict' -f $row.ProfileName, $row.Failed, $row.Error, $row.Conflict) -ForegroundColor Yellow
}

if ($PassThru) {
    $report
}
#endregion Main
