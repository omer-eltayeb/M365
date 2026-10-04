<#
.SYNOPSIS
    Reports OneDrive for Business user activity, sync adoption and external sharing from the Graph usage reports.
.DESCRIPTION
    Downloads the OneDrive activity user detail report (/reports/getOneDriveActivityUserDetail) for the selected period and
    outputs one row per user with viewed/edited, synced, internally shared and externally shared file counts, the total
    actions, last activity date, days since it, an IsInactive flag and external sharing flags. -IncludeDaily adds the
    tenant-wide daily file activity (/reports/getOneDriveActivityFileCounts) as <OutputPath base>_Daily.csv.
.PARAMETER Period
    Report period: D7, D30, D90 or D180 (days). Default D30.
.PARAMETER DaysInactive
    Days without any OneDrive activity after which a user is flagged IsInactive. Default 30.
.PARAMETER ExternalShareThreshold
    Number of externally shared files above which a user is flagged HighExternalSharing. Default 20.
.PARAMETER OnlyExternalSharers
    Export only users who shared at least one file externally in the period.
.PARAMETER IncludeDaily
    Also export the daily viewed/edited, synced and shared file counts for the period to a second CSV.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365OneDriveActivity_<Period>_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the user objects (and, with -IncludeDaily, the daily objects) to the pipeline.
.EXAMPLE
    PS> .\Get-M365OneDriveActivityReport.ps1
    Exports 30 days of OneDrive activity per user and prints adoption, sync usage and the top external sharers.
.EXAMPLE
    PS> .\Get-M365OneDriveActivityReport.ps1 -Period D90 -OnlyExternalSharers -ExternalShareThreshold 50 -OutputPath C:\Temp\Sharing.csv
    Exports only users who shared files externally in the last 90 days and flags those above 50 externally shared files.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Reports.Read.All (delegated); Reports Reader or Global Reader role
    Category    : Usage & adoption reports
    Changes     : No
    Notes       : Report data lags about 48 hours; dates are UTC days and counts cover the selected period only, so pick a -Period
                  of at least -DaysInactive days. UPNs are hashed when "Display concealed user, group, and site names in all reports" is on.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getonedriveactivityuserdetail
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period = 'D30',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 30,

    [Parameter()]
    [ValidateRange(0, 1000000)]
    [int]$ExternalShareThreshold = 20,

    [Parameter()]
    [switch]$OnlyExternalSharers,

    [Parameter()]
    [switch]$IncludeDaily,

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

function Get-UsageReportCsv {
    <# Downloads a Microsoft Graph usage report (CSV) and imports it. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportFunction,

        [Parameter(Mandatory = $true)]
        [string]$Period
    )
    $uri = 'https://graph.microsoft.com/v1.0/reports/{0}(period=''{1}'')' -f $ReportFunction, $Period
    $tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('{0}_{1}.csv' -f $ReportFunction, [guid]::NewGuid())
    try {
        Invoke-MgGraphRequest -Method GET -Uri $uri -OutputFilePath $tempCsv -ErrorAction Stop
        return @(Import-Csv -Path $tempCsv)
    }
    finally {
        if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue }
    }
}

function ConvertTo-ReportObject {
    <# Converts a raw report row to PascalCase properties; empty cells become $null, True/False/Yes/No [bool], whole numbers [int64] (not in Name/Id columns), "...Date" columns [datetime]. #>
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Row
    )
    $props = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        $name = $property.Name -replace '[^A-Za-z0-9]', ''
        [string]$text = $property.Value
        $number = [int64]0; $date = [datetime]::MinValue
        if ([string]::IsNullOrEmpty($text)) { $props[$name] = $null }
        elseif ($text -in @('True', 'False', 'Yes', 'No')) { $props[$name] = ($text -eq 'True' -or $text -eq 'Yes') }
        elseif ($property.Name -notmatch 'Name$|Id$' -and [int64]::TryParse($text, [ref]$number)) { $props[$name] = $number }
        elseif ($property.Name -like '*Date*' -and [datetime]::TryParse($text, [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date)) { $props[$name] = $date }
        else { $props[$name] = $text }
    }
    return [PSCustomObject]$props
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365OneDriveActivity_{0}_{1}.csv' -f $Period, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$dailyOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_Daily.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

$dailyReport = @()
try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All')
    Write-Verbose "Downloading getOneDriveActivityUserDetail for period $Period."
    $report = @(Get-UsageReportCsv -ReportFunction 'getOneDriveActivityUserDetail' -Period $Period)
    if ($IncludeDaily) { $dailyReport = @(Get-UsageReportCsv -ReportFunction 'getOneDriveActivityFileCounts' -Period $Period) }
}
catch {
    throw "Failed to retrieve the OneDrive activity reports from Microsoft Graph: $($_.Exception.Message)"
}

$today = [datetime]::UtcNow.Date
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($row in $report) {
    $counter++
    if ($counter % 250 -eq 0) { Write-Progress -Activity 'Shaping users' -Status "$counter of $($report.Count)" -PercentComplete ([int](($counter / $report.Count) * 100)) }
    $r = ConvertTo-ReportObject -Row $row
    $daysSince = $null; if ($null -ne $r.LastActivityDate) { $daysSince = [int](($today - $r.LastActivityDate).TotalDays) }
    $sharedExternally = [int64]$r.SharedExternallyFileCount
    $rows.Add([PSCustomObject]@{
            UserPrincipalName         = $r.UserPrincipalName
            IsDeleted                 = [bool]$r.IsDeleted
            LastActivityDate          = $r.LastActivityDate
            DaysSinceLastActivity     = $daysSince
            IsInactive                = ($null -eq $r.LastActivityDate -or $daysSince -ge $DaysInactive)
            ViewedOrEditedFileCount   = [int64]$r.ViewedOrEditedFileCount
            SyncedFileCount           = [int64]$r.SyncedFileCount
            SharedInternallyFileCount = [int64]$r.SharedInternallyFileCount
            SharedExternallyFileCount = $sharedExternally
            TotalActions              = [int64]$r.ViewedOrEditedFileCount + [int64]$r.SyncedFileCount + [int64]$r.SharedInternallyFileCount + $sharedExternally
            UsesSync                  = ([int64]$r.SyncedFileCount -gt 0)
            HighExternalSharing       = ($sharedExternally -gt $ExternalShareThreshold)
            AssignedProducts          = $r.AssignedProducts
            ReportRefreshDate         = $r.ReportRefreshDate
        })
}
Write-Progress -Activity 'Shaping users' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'SharedExternallyFileCount'; Descending = $true }, UserPrincipalName)
if ($OnlyExternalSharers) { $output = @($output | Where-Object { $_.SharedExternallyFileCount -gt 0 }) }
if ($output.Count -eq 0) { Write-Warning 'No rows matched the selected filter; the CSV will be empty.' }
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$daily = @($dailyReport | ForEach-Object { ConvertTo-ReportObject -Row $_ } | Sort-Object -Property ReportDate |
    Select-Object -Property ReportDate, ViewedOrEdited, Synced, SharedInternally, SharedExternally)
if ($daily.Count -gt 0) { $daily | Export-Csv -Path $dailyOutputPath -NoTypeInformation -Encoding UTF8 }

$current = @($rows | Where-Object { -not $_.IsDeleted })
$active = @($current | Where-Object { $null -ne $_.LastActivityDate })
$syncUsers = @($current | Where-Object { $_.UsesSync })
$externalSharers = @($current | Where-Object { $_.SharedExternallyFileCount -gt 0 })
$activePercent = 0; if ($current.Count -gt 0) { $activePercent = [math]::Round(($active.Count / $current.Count) * 100, 1) }
$syncPercent = 0; if ($active.Count -gt 0) { $syncPercent = [math]::Round(($syncUsers.Count / $active.Count) * 100, 1) }
Write-Host ('OneDrive activity ({0})' -f $Period) -ForegroundColor Cyan
Write-Host ('  Active users in period              : {0} of {1} ({2} %; {3} deleted users excluded)' -f $active.Count, $current.Count, $activePercent, ($rows.Count - $current.Count))
Write-Host ('  Using the sync client               : {0} ({1} % of active users)' -f $syncUsers.Count, $syncPercent)
Write-Host ('  {0,-36}: {1}' -f ('Inactive for {0}+ days' -f $DaysInactive), @($current | Where-Object { $_.IsInactive }).Count) -ForegroundColor Yellow
$highSharers = @($externalSharers | Where-Object { $_.HighExternalSharing })
Write-Host ('  {0,-36}: {1} of {2} external sharers' -f ('Sharing more than {0} files externally' -f $ExternalShareThreshold), $highSharers.Count, $externalSharers.Count) -ForegroundColor Yellow
foreach ($user in ($externalSharers | Sort-Object -Property SharedExternallyFileCount -Descending | Select-Object -First 10)) {
    Write-Host ('    Top external sharer {0,-45} {1,8} files' -f $user.UserPrincipalName, $user.SharedExternallyFileCount)
}
Write-Host ('  CSV : {0}' -f $OutputPath)
if ($daily.Count -gt 0) { Write-Host ('  Daily CSV : {0}' -f $dailyOutputPath) }

if ($PassThru) { $output }
if ($PassThru -and $daily.Count -gt 0) { $daily }
#endregion Main
