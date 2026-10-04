<#
.SYNOPSIS
    Install status overview (installed / failed / pending / not applicable) for every assigned Intune app.
.DESCRIPTION
    Lists assigned apps from Microsoft Graph (v1.0 /deviceAppManagement/mobileApps with
    isAssigned eq true), derives a friendly AppType from @odata.type and reads the beta
    /installSummary of each app for device and user install counts. With -IncludeDeviceDetail the
    beta /deviceStatuses collection is read for apps with failures and the failed devices are
    written to a second CSV (<OutputPath base>_FailedDevices.csv). Prints the top 10 apps by failures.
.PARAMETER AppName
    Wildcard pattern applied to the app display name, for example 'Microsoft 365*'.
.PARAMETER OnlyWithFailures
    Report only apps with at least one failed device or user installation.
.PARAMETER IncludeDeviceDetail
    For apps with failures, also collect the failed device installations into <OutputPath base>_FailedDevices.csv.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneAppInstallStatus_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the per-app summary objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneAppInstallStatus.ps1
    Exports install counts for every assigned app and prints the ten apps with the most failed devices.
.EXAMPLE
    PS> .\Get-IntuneAppInstallStatus.ps1 -OnlyWithFailures -IncludeDeviceDetail -OutputPath C:\Temp\AppStatus.csv
    Exports only failing apps to C:\Temp\AppStatus.csv and the affected devices to C:\Temp\AppStatus_FailedDevices.csv.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementApps.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Apps & app protection
    Changes     : No
    Notes       : installSummary and deviceStatuses exist only on the beta endpoint and may change without notice.
                  One Graph call is made per app (two for failing apps with -IncludeDeviceDetail) with a 200 ms pause
                  between apps. Counts come from the Intune reporting pipeline and can lag device check-ins by up to
                  24 hours. ErrorCodeHex is the unsigned form shown in the Intune admin center (for example 0x87D1041C).
.LINK
    https://learn.microsoft.com/graph/api/intune-apps-mobileapp-list
.LINK
    https://learn.microsoft.com/graph/api/intune-apps-mobileappinstallsummary-get?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$AppName,

    [Parameter()]
    [switch]$OnlyWithFailures,

    [Parameter()]
    [switch]$IncludeDeviceDetail,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneAppInstallStatus_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$detailPath = [System.IO.Path]::ChangeExtension($OutputPath, $null) + '_FailedDevices.csv'

try {
    Connect-GraphIfNeeded -Scopes @('DeviceManagementApps.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0'
$graphBeta = 'https://graph.microsoft.com/beta'   # beta: installSummary and deviceStatuses are not exposed in v1.0
$listUri = $graphV1 + '/deviceAppManagement/mobileApps?$filter=isAssigned eq true&$select=id,displayName,publisher,createdDateTime,lastModifiedDateTime'
try {
    $apps = @(Invoke-GraphPaged -Uri $listUri)
}
catch {
    throw "Failed to retrieve assigned apps from Microsoft Graph: $($_.Exception.Message)"
}
if (-not [string]::IsNullOrWhiteSpace($AppName)) {
    $apps = @($apps | Where-Object { $_.displayName -like $AppName })
}
Write-Verbose ('{0} assigned apps selected.' -f $apps.Count)
if ($apps.Count -eq 0) {
    Write-Warning 'No assigned apps matched the specified criteria; nothing to report.'
    return
}

$report = New-Object -TypeName System.Collections.Generic.List[object]
$failedDevices = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($app in $apps) {
    $index++
    Write-Progress -Activity 'Reading app install summaries' -Status ('{0} of {1}: {2}' -f $index, $apps.Count, $app.displayName) -PercentComplete ([int](($index / $apps.Count) * 100))
    $appType = ([string]$app.'@odata.type') -replace '^#microsoft\.graph\.', ''

    $summary = $null
    try {
        $summary = Invoke-MgGraphRequest -Method GET -Uri ('{0}/deviceAppManagement/mobileApps/{1}/installSummary' -f $graphBeta, $app.id) -OutputType PSObject -ErrorAction Stop
    }
    catch {
        Write-Warning ("Install summary unavailable for '{0}' ({1}): {2}" -f $app.displayName, $appType, $_.Exception.Message)
    }

    if ($null -ne $summary) {
        $failedDeviceCount = [int]$summary.failedDeviceCount
        $failedUserCount = [int]$summary.failedUserCount
        if (-not $OnlyWithFailures -or $failedDeviceCount -gt 0 -or $failedUserCount -gt 0) {
            $report.Add([PSCustomObject]@{
                    AppName                   = $app.displayName
                    AppId                     = $app.id
                    AppType                   = $appType
                    Publisher                 = $app.publisher
                    CreatedDateTime           = ConvertTo-UtcDateTime -Value $app.createdDateTime
                    LastModifiedDateTime      = ConvertTo-UtcDateTime -Value $app.lastModifiedDateTime
                    InstalledDeviceCount      = [int]$summary.installedDeviceCount
                    FailedDeviceCount         = $failedDeviceCount
                    PendingInstallDeviceCount = [int]$summary.pendingInstallDeviceCount
                    NotInstalledDeviceCount   = [int]$summary.notInstalledDeviceCount
                    NotApplicableDeviceCount  = [int]$summary.notApplicableDeviceCount
                    InstalledUserCount        = [int]$summary.installedUserCount
                    FailedUserCount           = $failedUserCount
                })

            if ($IncludeDeviceDetail -and $failedDeviceCount -gt 0) {
                try {
                    $statuses = @(Invoke-GraphPaged -Uri ('{0}/deviceAppManagement/mobileApps/{1}/deviceStatuses' -f $graphBeta, $app.id))
                    foreach ($status in ($statuses | Where-Object { $_.installState -in @('failed', 'uninstallFailed') })) {
                        $errorCodeHex = $null
                        if ($null -ne $status.errorCode) {
                            # Graph returns signed integers; the admin center and documentation show the unsigned hex form.
                            $errorCodeHex = '0x{0:X8}' -f ([int64]$status.errorCode -band 4294967295)
                        }
                        $failedDevices.Add([PSCustomObject]@{
                                AppName            = $app.displayName
                                AppId              = $app.id
                                DeviceName         = $status.deviceName
                                UserPrincipalName  = $status.userPrincipalName
                                InstallState       = $status.installState
                                InstallStateDetail = $status.installStateDetail
                                ErrorCode          = $status.errorCode
                                ErrorCodeHex       = $errorCodeHex
                                LastSyncDateTime   = ConvertTo-UtcDateTime -Value $status.lastSyncDateTime
                                OSVersion          = $status.osVersion
                            })
                    }
                }
                catch {
                    Write-Warning ("Device statuses unavailable for '{0}': {1}" -f $app.displayName, $_.Exception.Message)
                }
            }
        }
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading app install summaries' -Completed

if ($report.Count -gt 0) {
    $report | Sort-Object -Property FailedDeviceCount -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No apps matched the specified criteria; no CSV file was written.'
}
if ($IncludeDeviceDetail) {
    if ($failedDevices.Count -gt 0) {
        $failedDevices | Export-Csv -Path $detailPath -NoTypeInformation -Encoding UTF8
        Write-Host ('Failed device detail written to {0} ({1} rows)' -f $detailPath, $failedDevices.Count) -ForegroundColor Green
    }
    else {
        Write-Host 'No failed device installations found; no detail CSV written.' -ForegroundColor Green
    }
}

Write-Host ''
Write-Host ('Apps reported         : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host ('Apps with failures    : {0}' -f @($report | Where-Object { $_.FailedDeviceCount -gt 0 -or $_.FailedUserCount -gt 0 }).Count) -ForegroundColor Cyan
$topFailures = @($report | Where-Object { $_.FailedDeviceCount -gt 0 } | Sort-Object -Property FailedDeviceCount -Descending | Select-Object -First 10)
if ($topFailures.Count -gt 0) {
    Write-Host 'Top apps by failed devices:' -ForegroundColor Cyan
    foreach ($item in $topFailures) {
        Write-Host ('  {0,6}  {1} ({2})' -f $item.FailedDeviceCount, $item.AppName, $item.AppType) -ForegroundColor Yellow
    }
}

if ($PassThru) {
    $report
}
#endregion Main
