<#
.SYNOPSIS
    Reports which Microsoft 365 Apps (Outlook, Word, Excel, PowerPoint, OneNote, Teams) and platforms each user actually uses.
.DESCRIPTION
    Downloads the Microsoft 365 Apps usage user detail report (/reports/getM365AppUserDetail) for the selected period
    and outputs one row per user with the platforms (Windows, Mac, Mobile, Web) and apps used, an app count, the last
    activation and activity dates, an IsInactive flag and an IsWebOnly flag for users who work in the browser without a
    desktop client (possibly a missing Microsoft 365 Apps installation). -IncludeCounts adds the daily active users
    per platform (/reports/getM365AppPlatformUserCounts) as <OutputPath base>_PlatformCounts.csv.
.PARAMETER Period
    Report period: D7, D30, D90 or D180 (days). Default D30.
.PARAMETER DaysInactive
    Days without any Microsoft 365 Apps activity after which a user is flagged IsInactive. Default 30.
.PARAMETER OnlyWebOnly
    Export only users who used the web apps but no Windows or Mac desktop app in the period.
.PARAMETER IncludeCounts
    Also export the daily active user counts per platform to a second CSV.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365AppsUsage_<Period>_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the user objects (and, with -IncludeCounts, the daily platform objects) to the pipeline.
.EXAMPLE
    PS> .\Get-M365AppsUsageReport.ps1
    Exports 30 days of app and platform usage per user and prints platform and app adoption percentages.
.EXAMPLE
    PS> .\Get-M365AppsUsageReport.ps1 -Period D90 -OnlyWebOnly -IncludeCounts -OutputPath C:\Temp\WebOnlyUsers.csv
    Lists users who only used the web apps in the last 90 days and writes the daily platform counts next to the CSV.
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
    Notes       : Report data lags about 48 hours; dates are UTC days and usage flags cover the selected period only, so pick a
                  -Period of at least -DaysInactive days. UPNs appear as hashes when "Display concealed user, group, and site
                  names in all reports" is on (Microsoft 365 admin center > Settings > Org settings > Reports).
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getm365appuserdetail
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
    [switch]$OnlyWebOnly,

    [Parameter()]
    [switch]$IncludeCounts,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365AppsUsage_{0}_{1}.csv' -f $Period, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$countsOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_PlatformCounts.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

$countsReport = @()
try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All')
    Write-Verbose "Downloading getM365AppUserDetail for period $Period."
    $report = @(Get-UsageReportCsv -ReportFunction 'getM365AppUserDetail' -Period $Period)
    if ($IncludeCounts) { $countsReport = @(Get-UsageReportCsv -ReportFunction 'getM365AppPlatformUserCounts' -Period $Period) }
}
catch {
    throw "Failed to retrieve the Microsoft 365 Apps usage reports from Microsoft Graph: $($_.Exception.Message)"
}

$platforms = @('Windows', 'Mac', 'Mobile', 'Web')
$apps = @('Outlook', 'Word', 'Excel', 'PowerPoint', 'OneNote', 'Teams')
$today = [datetime]::UtcNow.Date
$usage = @{}
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($row in $report) {
    $counter++
    if ($counter % 250 -eq 0) { Write-Progress -Activity 'Shaping users' -Status "$counter of $($report.Count)" -PercentComplete ([int](($counter / $report.Count) * 100)) }
    $r = ConvertTo-ReportObject -Row $row
    $daysSince = $null; if ($null -ne $r.LastActivityDate) { $daysSince = [int](($today - $r.LastActivityDate).TotalDays) }
    # The report has one Yes/No column per platform and per app; the converter already turned them into booleans.
    $platformsUsed = @($platforms | Where-Object { [bool]$r.$_ })
    $appsUsed = @($apps | Where-Object { [bool]$r.$_ })
    foreach ($used in ($platformsUsed + $appsUsed)) { $usage[$used] = [int]$usage[$used] + 1 }
    $rows.Add([PSCustomObject]@{
            UserPrincipalName     = $r.UserPrincipalName
            LastActivationDate    = $r.LastActivationDate
            LastActivityDate      = $r.LastActivityDate
            DaysSinceLastActivity = $daysSince
            IsInactive            = ($null -eq $r.LastActivityDate -or $daysSince -ge $DaysInactive)
            UsesWindows           = [bool]$r.Windows
            UsesMac               = [bool]$r.Mac
            UsesMobile            = [bool]$r.Mobile
            UsesWeb               = [bool]$r.Web
            IsWebOnly             = ([bool]$r.Web -and -not [bool]$r.Windows -and -not [bool]$r.Mac)
            Platforms             = ($platformsUsed -join ';')
            Apps                  = ($appsUsed -join ';')
            AppCount              = $appsUsed.Count
            ReportRefreshDate     = $r.ReportRefreshDate
        })
}
Write-Progress -Activity 'Shaping users' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'AppCount'; Descending = $true }, UserPrincipalName)
if ($OnlyWebOnly) { $output = @($output | Where-Object { $_.IsWebOnly }) }
if ($output.Count -eq 0) { Write-Warning 'No rows matched the selected filter; the CSV will be empty.' }
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$counts = @($countsReport | ForEach-Object { ConvertTo-ReportObject -Row $_ } | Sort-Object -Property ReportDate |
    Select-Object -Property ReportDate, Windows, Mac, Mobile, Web)
if ($counts.Count -gt 0) { $counts | Export-Csv -Path $countsOutputPath -NoTypeInformation -Encoding UTF8 }

$active = @($rows | Where-Object { $null -ne $_.LastActivityDate })
$inactive = @($rows | Where-Object { $_.IsInactive })
$webOnly = @($rows | Where-Object { $_.IsWebOnly })
$activePercent = 0; if ($rows.Count -gt 0) { $activePercent = [math]::Round(($active.Count / $rows.Count) * 100, 1) }
Write-Host ('Microsoft 365 Apps usage ({0})' -f $Period) -ForegroundColor Cyan
Write-Host ('  Active users in period              : {0} of {1} ({2} %)' -f $active.Count, $rows.Count, $activePercent)
Write-Host ('  {0,-36}: {1}' -f ('Inactive for {0}+ days' -f $DaysInactive), $inactive.Count) -ForegroundColor Yellow
Write-Host ('  Web only (no desktop client)        : {0}' -f $webOnly.Count) -ForegroundColor Yellow
Write-Host ('  {0,-20} {1,8} {2,12}' -f 'Platform / app', 'Users', '% of active')
foreach ($name in ($platforms + $apps)) {
    $users = [int]$usage[$name]
    $percent = 0; if ($active.Count -gt 0) { $percent = [math]::Round(($users / $active.Count) * 100, 1) }
    Write-Host ('  {0,-20} {1,8} {2,10} %' -f $name, $users, $percent)
}
Write-Host ('  CSV : {0}' -f $OutputPath)
if ($counts.Count -gt 0) { Write-Host ('  Platform counts CSV : {0}' -f $countsOutputPath) }

if ($PassThru) { $output }
if ($PassThru -and $counts.Count -gt 0) { $counts }
#endregion Main
