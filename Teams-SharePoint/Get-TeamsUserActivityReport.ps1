<#
.SYNOPSIS
    Reports Microsoft Teams activity per user (messages, calls, meetings, media minutes) and flags inactive and licensed-but-inactive users.
.DESCRIPTION
    Downloads the Microsoft Graph usage report /reports/getTeamsUserActivityUserDetail(period='D30') as CSV and reshapes every
    row into PascalCase properties: chat and channel message counts, calls, meetings organised and attended, audio / video /
    screen-share minutes and the licence and deletion state. Each user gets DaysSinceLastActivity, IsInactive (no activity for
    -DaysInactive days or none in the period) and IsLicensedButInactive, which points at paid licences that are not used in Teams.
.PARAMETER Period
    Usage report period: D7, D30, D90 or D180. Default D30. Choose a period at least as long as -DaysInactive.
.PARAMETER DaysInactive
    Number of days without Teams activity after which a user is flagged IsInactive. Default 30.
.PARAMETER OnlyInactive
    Export only users flagged IsInactive.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsUserActivity_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsUserActivityReport.ps1
    Exports the 30-day activity of every user and shows how many licensed users have not touched Teams in 30 days.
.EXAMPLE
    PS> .\Get-TeamsUserActivityReport.ps1 -Period D90 -DaysInactive 60 -OnlyInactive -OutputPath C:\Temp\TeamsInactiveUsers.csv -Verbose
    Uses the 90-day report and exports only users idle for 60 days or more, ready for a licence clean-up review.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Reports.Read.All (delegated). The Reports Reader, Global Reader or Teams Administrator role is enough.
    Category    : Teams apps, settings & usage
    Changes     : No
    Notes       : Usage report data lags about 48 hours behind real time. If "Display concealed user, group, and site names in all
                  reports" is enabled (Microsoft 365 admin center > Settings > Org settings > Reports) the UPN column contains hashes;
                  turn the setting off before running the report when real names are needed. Counts are totals for the selected period;
                  durations are converted to minutes. Deleted accounts stay in the report (IsDeleted) and are not counted as licensed-but-inactive.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getteamsuseractivityuserdetail
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
    [switch]$OnlyInactive,

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

function Get-GraphReportCsv {
    <# Downloads a usage report (Graph answers with a redirect to a CSV) into a temp file and imports it. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    $tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('GraphReport_{0}.csv' -f [guid]::NewGuid().ToString('N'))
    try {
        Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputFilePath $tempCsv -ErrorAction Stop
        return @(Import-Csv -Path $tempCsv -Encoding UTF8)
    }
    finally {
        if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue }
    }
}

function Get-ReportValue {
    <# Returns a report column value by name (header spacing differences are ignored); $null when the column is missing or empty. #>
    param([Parameter(Mandatory = $true)][object]$Row, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $script:reportColumns) {
        $script:reportColumns = @{}
        foreach ($column in $Row.PSObject.Properties.Name) { $script:reportColumns[($column -replace '\s+', ' ')] = $column }
    }
    $actualName = $script:reportColumns[($Name -replace '\s+', ' ')]
    if ($null -eq $actualName -or [string]::IsNullOrWhiteSpace([string]$Row.$actualName)) { return $null }
    return $Row.$actualName
}

function Get-ReportInt {
    <# Casts a report counter column to [int]; 0 when the column is missing or empty. #>
    param([Parameter(Mandatory = $true)][object]$Row, [Parameter(Mandatory = $true)][string]$Name)
    return [int][string](Get-ReportValue -Row $Row -Name $Name)
}

function Get-ReportDate {
    <# Converts a report date column (yyyy-MM-dd) to a UTC [datetime]; $null when empty. #>
    param([Parameter(Mandatory = $true)][object]$Row, [Parameter(Mandatory = $true)][string]$Name)
    $value = Get-ReportValue -Row $Row -Name $Name
    if ($null -eq $value) { return $null }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { return $parsed.ToUniversalTime() }
    return $null
}

function Get-ReportDuration {
    <# Returns a duration in minutes from the "<Name> In Seconds" column, falling back to the ISO 8601 column (for example PT1H2M). #>
    param([Parameter(Mandatory = $true)][object]$Row, [Parameter(Mandatory = $true)][string]$Name)
    $seconds = Get-ReportValue -Row $Row -Name "$Name In Seconds"
    if ($null -ne $seconds) { return [math]::Round(([double]$seconds) / 60, 1) }
    $iso = Get-ReportValue -Row $Row -Name $Name
    if ($null -eq $iso) { return 0 }
    try { return [math]::Round([System.Xml.XmlConvert]::ToTimeSpan([string]$iso).TotalMinutes, 1) } catch { return $null }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsUserActivity_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if ($DaysInactive -gt [int]$Period.TrimStart('D')) { Write-Warning "DaysInactive ($DaysInactive) exceeds the report period ($Period); activity older than the period is not visible, so such users are flagged inactive." }

try { Connect-GraphIfNeeded -Scopes @('Reports.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
Write-Progress -Activity 'Teams user activity report' -Status "Downloading getTeamsUserActivityUserDetail(period='$Period')"
try { $report = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getTeamsUserActivityUserDetail(period='$Period')") }
catch { throw "Failed to download the Teams user activity report: $($_.Exception.Message)" }
$now = [datetime]::UtcNow
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($entry in $report) {
    $counter++
    if ($counter % 250 -eq 0) { Write-Progress -Activity 'Teams user activity report' -Status "Processing $counter of $($report.Count) users" -PercentComplete ([int](($counter / $report.Count) * 100)) }
    $lastActivity = Get-ReportDate -Row $entry -Name 'Last Activity Date'
    $daysSinceLastActivity = $null
    if ($null -ne $lastActivity) { $daysSinceLastActivity = [int][math]::Floor(($now - $lastActivity).TotalDays) }
    $isLicensed = ((Get-ReportValue -Row $entry -Name 'Is Licensed') -eq 'Yes')
    $isDeleted = ((Get-ReportValue -Row $entry -Name 'Is Deleted') -eq 'True')
    $isInactive = ($null -eq $lastActivity -or $daysSinceLastActivity -ge $DaysInactive)
    $teamChat = Get-ReportInt -Row $entry -Name 'Team Chat Message Count'
    $privateChat = Get-ReportInt -Row $entry -Name 'Private Chat Message Count'
    $rows.Add([PSCustomObject]@{
        UserPrincipalName       = Get-ReportValue -Row $entry -Name 'User Principal Name'
        UserId                  = Get-ReportValue -Row $entry -Name 'User Id'
        LastActivityDate        = $lastActivity
        DaysSinceLastActivity   = $daysSinceLastActivity
        IsInactive              = $isInactive
        IsLicensed              = $isLicensed
        IsLicensedButInactive   = ($isLicensed -and $isInactive -and -not $isDeleted)
        IsDeleted               = $isDeleted
        AssignedProducts        = Get-ReportValue -Row $entry -Name 'Assigned Products'
        TeamChatMessageCount    = $teamChat
        PrivateChatMessageCount = $privateChat
        TotalMessageCount       = $teamChat + $privateChat
        PostMessages            = Get-ReportInt -Row $entry -Name 'Post Messages'
        ReplyMessages           = Get-ReportInt -Row $entry -Name 'Reply Messages'
        CallCount               = Get-ReportInt -Row $entry -Name 'Call Count'
        MeetingCount            = Get-ReportInt -Row $entry -Name 'Meeting Count'
        MeetingsOrganizedCount  = Get-ReportInt -Row $entry -Name 'Meetings Organized Count'
        MeetingsAttendedCount   = Get-ReportInt -Row $entry -Name 'Meetings Attended Count'
        AudioMinutes            = Get-ReportDuration -Row $entry -Name 'Audio Duration'
        VideoMinutes            = Get-ReportDuration -Row $entry -Name 'Video Duration'
        ScreenShareMinutes      = Get-ReportDuration -Row $entry -Name 'Screen Share Duration'
        ReportRefreshDate       = Get-ReportDate -Row $entry -Name 'Report Refresh Date'
    })
}
Write-Progress -Activity 'Teams user activity report' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'TotalMessageCount'; Descending = $true }, UserPrincipalName)
if ($OnlyInactive) { $output = @($output | Where-Object { $_.IsInactive }) }
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No users to export (the report is empty or nobody matches -OnlyInactive); no CSV was written.' }

$activeUsers = @($rows | Where-Object { -not $_.IsInactive -and -not $_.IsDeleted })
$liveUsers = @($rows | Where-Object { -not $_.IsDeleted })
$activePercent = 0; if ($liveUsers.Count -gt 0) { $activePercent = [math]::Round(($activeUsers.Count / $liveUsers.Count) * 100, 1) }
Write-Host "Teams user activity summary ($Period, inactive after $DaysInactive days)" -ForegroundColor Cyan
Write-Host ('  Users in report (deleted)     : {0} ({1})' -f $rows.Count, @($rows | Where-Object { $_.IsDeleted }).Count)
Write-Host ('  Active users                  : {0} ({1} % of non-deleted users)' -f $activeUsers.Count, $activePercent) -ForegroundColor Green
Write-Host ('  Inactive users                : {0}' -f @($liveUsers | Where-Object { $_.IsInactive }).Count) -ForegroundColor Yellow
Write-Host ('  Licensed but inactive         : {0}' -f @($rows | Where-Object { $_.IsLicensedButInactive }).Count) -ForegroundColor Yellow
Write-Host '  Top collaborators (messages, meetings):'
foreach ($user in ($output | Where-Object { $_.TotalMessageCount -gt 0 } | Select-Object -First 10)) { Write-Host ('    {0,-45} {1,7} {2,6}' -f $user.UserPrincipalName, $user.TotalMessageCount, $user.MeetingCount) }
Write-Host ('  Rows exported                 : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
