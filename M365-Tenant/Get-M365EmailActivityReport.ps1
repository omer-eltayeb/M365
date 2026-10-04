<#
.SYNOPSIS
    Reports Exchange Online email activity per user (sent, received, read, meetings) from the Graph usage reports.
.DESCRIPTION
    Downloads the email activity user detail report (/reports/getEmailActivityUserDetail) for the selected period and
    outputs one row per user with send, receive, read and meeting counts, the total activity, the last activity date,
    the days since it and an IsInactive flag. With -IncludeDaily it also writes the tenant-wide daily totals from
    /reports/getEmailActivityCounts to <OutputPath base>_Daily.csv. Prints totals, averages, top users and inactive mailboxes.
.PARAMETER Period
    Report period: D7, D30, D90 or D180 (days). Default D30.
.PARAMETER DaysInactive
    Days without any email activity after which a user is flagged IsInactive. Default 30.
.PARAMETER Top
    Number of top senders and receivers to print in the console summary. Default 10.
.PARAMETER IncludeDaily
    Also export the daily send / receive / read / meeting totals for the period to a second CSV.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365EmailActivity_<Period>_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the user objects (and, with -IncludeDaily, the daily objects) to the pipeline.
.EXAMPLE
    PS> .\Get-M365EmailActivityReport.ps1
    Exports 30 days of email activity per user and prints the top 10 senders and receivers.
.EXAMPLE
    PS> .\Get-M365EmailActivityReport.ps1 -Period D90 -DaysInactive 60 -IncludeDaily -Top 20 -OutputPath C:\Temp\Email.csv
    Uses the 90-day report, flags users without email activity for 60 days, prints 20 top users and writes C:\Temp\Email_Daily.csv.
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
    Notes       : Report data lags about 48 hours; dates are UTC days and counts cover the selected period only, so pick a
                  -Period of at least -DaysInactive days. Names and UPNs appear as hashes when "Display concealed user,
                  group, and site names in all reports" is on (Microsoft 365 admin center > Org settings > Reports).
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getemailactivityuserdetail
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
    [ValidateRange(1, 100)]
    [int]$Top = 10,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365EmailActivity_{0}_{1}.csv' -f $Period, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
# Path.Combine tolerates an empty folder (bare file name in -OutputPath) where Join-Path would throw.
$dailyOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_Daily.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

$dailyReport = @()
try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All')
    Write-Verbose "Downloading getEmailActivityUserDetail for period $Period."
    $report = @(Get-UsageReportCsv -ReportFunction 'getEmailActivityUserDetail' -Period $Period)
    if ($IncludeDaily) { $dailyReport = @(Get-UsageReportCsv -ReportFunction 'getEmailActivityCounts' -Period $Period) }
}
catch {
    throw "Failed to retrieve the email activity reports from Microsoft Graph: $($_.Exception.Message)"
}

$today = [datetime]::UtcNow.Date
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($row in $report) {
    $counter++
    if ($counter % 250 -eq 0) { Write-Progress -Activity 'Shaping users' -Status "$counter of $($report.Count)" -PercentComplete ([int](($counter / $report.Count) * 100)) }
    $r = ConvertTo-ReportObject -Row $row
    $daysSince = $null; if ($null -ne $r.LastActivityDate) { $daysSince = [int](($today - $r.LastActivityDate).TotalDays) }
    $rows.Add([PSCustomObject]@{
            UserPrincipalName      = $r.UserPrincipalName
            DisplayName            = $r.DisplayName
            IsDeleted              = [bool]$r.IsDeleted
            DeletedDate            = $r.DeletedDate
            LastActivityDate       = $r.LastActivityDate
            DaysSinceLastActivity  = $daysSince
            IsInactive             = ($null -eq $r.LastActivityDate -or $daysSince -ge $DaysInactive)
            SendCount              = [int64]$r.SendCount
            ReceiveCount           = [int64]$r.ReceiveCount
            ReadCount              = [int64]$r.ReadCount
            MeetingCreatedCount    = [int64]$r.MeetingCreatedCount
            MeetingInteractedCount = [int64]$r.MeetingInteractedCount
            TotalActivity          = [int64]$r.SendCount + [int64]$r.ReceiveCount + [int64]$r.ReadCount + [int64]$r.MeetingCreatedCount + [int64]$r.MeetingInteractedCount
            AssignedProducts       = $r.AssignedProducts
            ReportRefreshDate      = $r.ReportRefreshDate
        })
}
Write-Progress -Activity 'Shaping users' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'TotalActivity'; Descending = $true }, UserPrincipalName)
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$daily = @($dailyReport | ForEach-Object { ConvertTo-ReportObject -Row $_ } | Sort-Object -Property ReportDate |
    Select-Object -Property ReportDate, Send, Receive, Read, MeetingCreated, MeetingInteracted)
if ($daily.Count -gt 0) { $daily | Export-Csv -Path $dailyOutputPath -NoTypeInformation -Encoding UTF8 }

# Deleted users stay in the CSV but are excluded from the summary figures.
$current = @($rows | Where-Object { -not $_.IsDeleted })
$active = @($current | Where-Object { $null -ne $_.LastActivityDate })
$inactive = @($current | Where-Object { $_.IsInactive })
$totalSent = [int64]($current | Measure-Object -Property SendCount -Sum).Sum
$totalReceived = [int64]($current | Measure-Object -Property ReceiveCount -Sum).Sum
$totalRead = [int64]($current | Measure-Object -Property ReadCount -Sum).Sum
$activePercent = 0; if ($current.Count -gt 0) { $activePercent = [math]::Round(($active.Count / $current.Count) * 100, 1) }
$avgSent = 0; $avgReceived = 0
if ($active.Count -gt 0) { $avgSent = [math]::Round($totalSent / $active.Count, 1); $avgReceived = [math]::Round($totalReceived / $active.Count, 1) }
Write-Host ('Email activity ({0})' -f $Period) -ForegroundColor Cyan
Write-Host ('  Active users in period              : {0} of {1} ({2} %; {3} deleted users excluded)' -f $active.Count, $current.Count, $activePercent, ($rows.Count - $current.Count))
Write-Host ('  {0,-36}: {1}' -f ('Inactive for {0}+ days' -f $DaysInactive), $inactive.Count) -ForegroundColor Yellow
Write-Host ('  Sent / received / read              : {0} / {1} / {2}' -f $totalSent, $totalReceived, $totalRead)
Write-Host ('  Per active user (sent / received)   : {0} / {1}' -f $avgSent, $avgReceived)
Write-Host ('  Top {0} senders' -f $Top)
foreach ($user in ($current | Sort-Object -Property SendCount -Descending | Select-Object -First $Top)) { Write-Host ('    {0,-50} {1,8}' -f $user.UserPrincipalName, $user.SendCount) }
Write-Host ('  Top {0} receivers' -f $Top)
foreach ($user in ($current | Sort-Object -Property ReceiveCount -Descending | Select-Object -First $Top)) { Write-Host ('    {0,-50} {1,8}' -f $user.UserPrincipalName, $user.ReceiveCount) }
Write-Host ('  CSV : {0}' -f $OutputPath)
if ($daily.Count -gt 0) { Write-Host ('  Daily CSV : {0}' -f $dailyOutputPath) }

if ($PassThru) { $output }
if ($PassThru -and $daily.Count -gt 0) { $daily }
#endregion Main
