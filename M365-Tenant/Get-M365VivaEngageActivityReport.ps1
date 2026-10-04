<#
.SYNOPSIS
    Reports Viva Engage (Yammer) user activity, communities and device usage from the Graph usage reports.
.DESCRIPTION
    Downloads the Yammer activity user detail report (/reports/getYammerActivityUserDetail) for the selected period and
    outputs one row per user with the user state, posted, read and liked counts, total engagement, last activity date, days
    since it and an IsInactive flag. -IncludeCommunities adds /reports/getYammerGroupsActivityDetail (members, activity and an
    IsInactive flag per community) as <OutputPath base>_Communities.csv; -IncludeDevices adds
    /reports/getYammerDeviceUsageUserDetail (web, phone and tablet usage per user) as <OutputPath base>_Devices.csv.
.PARAMETER Period
    Report period: D7, D30, D90 or D180 (days). Default D30.
.PARAMETER DaysInactive
    Days without any Viva Engage activity after which a user or community is flagged IsInactive. Default 30.
.PARAMETER IncludeCommunities
    Also export community (group) activity to a second CSV.
.PARAMETER IncludeDevices
    Also export per-user device usage (web, Windows Phone, Android, iPhone, iPad, other) to a third CSV.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365VivaEngageActivity_<Period>_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the user objects (and, with the Include switches, the community and device objects) to the pipeline.
.EXAMPLE
    PS> .\Get-M365VivaEngageActivityReport.ps1
    Exports 30 days of Viva Engage activity per user and prints the share of active users.
.EXAMPLE
    PS> .\Get-M365VivaEngageActivityReport.ps1 -Period D90 -IncludeCommunities -IncludeDevices -OutputPath C:\Temp\VivaEngage.csv
    Also writes C:\Temp\VivaEngage_Communities.csv and C:\Temp\VivaEngage_Devices.csv for the last 90 days.
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
    Notes       : Yammer was renamed Viva Engage; the Graph report functions and CSV columns still use the Yammer name. Tenants
                  without Viva Engage get an empty or HTTP 403 response. Data lags about 48 hours; counts cover the selected period
                  only, so pick a -Period of at least -DaysInactive days. Names and UPNs are hashed when concealed names are on.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getyammeractivityuserdetail
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
    [switch]$IncludeCommunities,

    [Parameter()]
    [switch]$IncludeDevices,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365VivaEngageActivity_{0}_{1}.csv' -f $Period, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$communitiesOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_Communities.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))
$devicesOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_Devices.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

$communitiesReport = @(); $devicesReport = @()
try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All')
    Write-Verbose "Downloading getYammerActivityUserDetail for period $Period."
    $report = @(Get-UsageReportCsv -ReportFunction 'getYammerActivityUserDetail' -Period $Period)
    if ($IncludeCommunities) { $communitiesReport = @(Get-UsageReportCsv -ReportFunction 'getYammerGroupsActivityDetail' -Period $Period) }
    if ($IncludeDevices) { $devicesReport = @(Get-UsageReportCsv -ReportFunction 'getYammerDeviceUsageUserDetail' -Period $Period) }
}
catch {
    throw "Failed to retrieve the Viva Engage (Yammer) reports from Microsoft Graph: $($_.Exception.Message)"
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
            UserPrincipalName     = $r.UserPrincipalName
            DisplayName           = $r.DisplayName
            UserState             = $r.UserState
            StateChangeDate       = $r.StateChangeDate
            LastActivityDate      = $r.LastActivityDate
            DaysSinceLastActivity = $daysSince
            IsInactive            = ($null -eq $r.LastActivityDate -or $daysSince -ge $DaysInactive)
            PostedCount           = [int64]$r.PostedCount
            ReadCount             = [int64]$r.ReadCount
            LikedCount            = [int64]$r.LikedCount
            TotalEngagement       = [int64]$r.PostedCount + [int64]$r.ReadCount + [int64]$r.LikedCount
            AssignedProducts      = $r.AssignedProducts
            ReportRefreshDate     = $r.ReportRefreshDate
        })
}
Write-Progress -Activity 'Shaping users' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'TotalEngagement'; Descending = $true }, UserPrincipalName)
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$communities = @($communitiesReport | ForEach-Object { ConvertTo-ReportObject -Row $_ } | Select-Object -Property @{ Name = 'CommunityDisplayName'; Expression = { $_.GroupDisplayName } },
    IsDeleted, OwnerPrincipalName, GroupType, Office365Connected, MemberCount, LastActivityDate, PostedCount, ReadCount, LikedCount, NetworkDisplayName,
    @{ Name = 'IsInactive'; Expression = { $null -eq $_.LastActivityDate -or ($today - $_.LastActivityDate).TotalDays -ge $DaysInactive } })
if ($communities.Count -gt 0) { $communities | Sort-Object -Property CommunityDisplayName | Export-Csv -Path $communitiesOutputPath -NoTypeInformation -Encoding UTF8 }
$devices = @($devicesReport | ForEach-Object { ConvertTo-ReportObject -Row $_ } | Select-Object -Property UserPrincipalName, DisplayName, UserState,
    LastActivityDate, UsedWeb, UsedWindowsPhone, UsedAndroidPhone, UsediPhone, UsediPad, UsedOthers)
if ($devices.Count -gt 0) { $devices | Sort-Object -Property UserPrincipalName | Export-Csv -Path $devicesOutputPath -NoTypeInformation -Encoding UTF8 }

# Deleted and suspended Viva Engage users stay in the CSV but are excluded from the percentages.
$current = @($rows | Where-Object { [string]::IsNullOrEmpty($_.UserState) -or $_.UserState -eq 'Active' })
$active = @($current | Where-Object { $null -ne $_.LastActivityDate })
$activePercent = 0; if ($current.Count -gt 0) { $activePercent = [math]::Round(($active.Count / $current.Count) * 100, 1) }
$totals = foreach ($name in @('PostedCount', 'ReadCount', 'LikedCount')) { [int64]($current | Measure-Object -Property $name -Sum).Sum }
Write-Host ('Viva Engage activity ({0})' -f $Period) -ForegroundColor Cyan
Write-Host ('  Active users in period              : {0} of {1} ({2} %; {3} deleted or suspended users excluded)' -f $active.Count, $current.Count, $activePercent, ($rows.Count - $current.Count))
Write-Host ('  {0,-36}: {1}' -f ('Inactive for {0}+ days' -f $DaysInactive), @($current | Where-Object { $_.IsInactive }).Count) -ForegroundColor Yellow
Write-Host ('  Posts / reads / likes               : {0} / {1} / {2}' -f $totals[0], $totals[1], $totals[2])
if ($communities.Count -gt 0) {
    $liveCommunities = @($communities | Where-Object { -not $_.IsDeleted })
    $ownerless = @($liveCommunities | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.OwnerPrincipalName) }).Count
    Write-Host ('  Communities (inactive / ownerless)  : {0} ({1} / {2})' -f $liveCommunities.Count, @($liveCommunities | Where-Object { $_.IsInactive }).Count, $ownerless) -ForegroundColor Yellow
    Write-Host ('  Communities CSV : {0}' -f $communitiesOutputPath)
}
if ($devices.Count -gt 0) { Write-Host ('  Devices CSV : {0}' -f $devicesOutputPath) }
Write-Host ('  CSV : {0}' -f $OutputPath)

if ($PassThru) { $output }
if ($PassThru -and $communities.Count -gt 0) { $communities }
if ($PassThru -and $devices.Count -gt 0) { $devices }
#endregion Main
