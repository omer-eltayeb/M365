<#
.SYNOPSIS
    Reports Microsoft 365 group activity, membership, guests, owners and storage from the Graph usage reports.
.DESCRIPTION
    Downloads the Microsoft 365 groups activity detail report (/reports/getOffice365GroupsActivityDetail) for the selected
    period and outputs one row per group with the owner, group type, member and guest counts, last activity date, days since
    it, an IsInactive flag, mail and file activity counts and the mailbox, site and total storage in GB. -IncludeDaily adds the
    tenant-wide daily group activity (/reports/getOffice365GroupsActivityCounts) as <OutputPath base>_Daily.csv.
.PARAMETER Period
    Report period: D7, D30, D90 or D180 (days). Default D30.
.PARAMETER DaysInactive
    Days without mail, file or Viva Engage activity after which a group is flagged IsInactive. Default 90.
.PARAMETER OnlyInactive
    Export only groups flagged IsInactive (the console summary still covers every group in the report).
.PARAMETER IncludeDaily
    Also export the daily emails received and Viva Engage messages posted, read and liked across all groups.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365GroupsActivity_<Period>_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the group objects (and, with -IncludeDaily, the daily objects) to the pipeline.
.EXAMPLE
    PS> .\Get-M365GroupsActivityReport.ps1
    Exports every Microsoft 365 group with activity and storage figures and prints the inactive and ownerless ones.
.EXAMPLE
    PS> .\Get-M365GroupsActivityReport.ps1 -Period D180 -DaysInactive 120 -OnlyInactive -OutputPath C:\Temp\StaleGroups.csv
    Uses the 180-day report and exports only groups without any activity for 120 days, ready for an expiration or cleanup review.
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
    Notes       : Report data lags about 48 hours; dates are UTC days and activity counts cover the selected period only, so pick
                  a -Period of at least -DaysInactive days (D90 or D180 with the default threshold). Group names and owner UPNs
                  appear as hashes when "Display concealed user, group, and site names in all reports" is on (admin center > Org settings > Reports).
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getoffice365groupsactivitydetail
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
    [int]$DaysInactive = 90,

    [Parameter()]
    [switch]$OnlyInactive,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365GroupsActivity_{0}_{1}.csv' -f $Period, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$dailyOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_Daily.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

$dailyReport = @()
try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All')
    Write-Verbose "Downloading getOffice365GroupsActivityDetail for period $Period."
    $report = @(Get-UsageReportCsv -ReportFunction 'getOffice365GroupsActivityDetail' -Period $Period)
    if ($IncludeDaily) { $dailyReport = @(Get-UsageReportCsv -ReportFunction 'getOffice365GroupsActivityCounts' -Period $Period) }
}
catch {
    throw "Failed to retrieve the groups activity reports from Microsoft Graph: $($_.Exception.Message)"
}

$today = [datetime]::UtcNow.Date
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($row in $report) {
    $counter++
    if ($counter % 250 -eq 0) { Write-Progress -Activity 'Shaping groups' -Status "$counter of $($report.Count)" -PercentComplete ([int](($counter / $report.Count) * 100)) }
    $r = ConvertTo-ReportObject -Row $row
    $daysSince = $null; if ($null -ne $r.LastActivityDate) { $daysSince = [int](($today - $r.LastActivityDate).TotalDays) }
    # The guest column is documented as "External Member Count" but some downloads name it "Guest Count".
    $guests = [int64]$r.ExternalMemberCount; if ($null -ne $r.GuestCount) { $guests = [int64]$r.GuestCount }
    $rows.Add([PSCustomObject]@{
            GroupDisplayName              = $r.GroupDisplayName
            GroupId                       = $r.GroupId
            GroupType                     = $r.GroupType
            IsDeleted                     = [bool]$r.IsDeleted
            OwnerPrincipalName            = $r.OwnerPrincipalName
            IsOwnerless                   = [string]::IsNullOrWhiteSpace([string]$r.OwnerPrincipalName)
            MemberCount                   = [int64]$r.MemberCount
            ExternalMemberCount           = $guests
            HasGuests                     = ($guests -gt 0)
            LastActivityDate              = $r.LastActivityDate
            DaysSinceLastActivity         = $daysSince
            IsInactive                    = ($null -eq $r.LastActivityDate -or $daysSince -ge $DaysInactive)
            ExchangeReceivedEmailCount    = [int64]$r.ExchangeReceivedEmailCount
            SharePointActiveFileCount     = [int64]$r.SharePointActiveFileCount
            MailboxGB                     = [math]::Round([int64]$r.ExchangeMailboxStorageUsedByte / 1GB, 2)
            SiteGB                        = [math]::Round([int64]$r.SharePointSiteStorageUsedByte / 1GB, 2)
            TotalGB                       = [math]::Round(([int64]$r.ExchangeMailboxStorageUsedByte + [int64]$r.SharePointSiteStorageUsedByte) / 1GB, 2)
            ReportRefreshDate             = $r.ReportRefreshDate
        })
}
Write-Progress -Activity 'Shaping groups' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'TotalGB'; Descending = $true }, GroupDisplayName)
if ($OnlyInactive) { $output = @($output | Where-Object { $_.IsInactive }) }
if ($output.Count -eq 0) { Write-Warning 'No rows matched the selected filter; the CSV will be empty.' }
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$daily = @($dailyReport | ForEach-Object { ConvertTo-ReportObject -Row $_ } | Sort-Object -Property ReportDate |
    Select-Object -Property ReportDate, ExchangeEmailsReceived, YammerMessagesPosted, YammerMessagesRead, YammerMessagesLiked)
if ($daily.Count -gt 0) { $daily | Export-Csv -Path $dailyOutputPath -NoTypeInformation -Encoding UTF8 }

$current = @($rows | Where-Object { -not $_.IsDeleted })
$inactive = @($current | Where-Object { $_.IsInactive })
$totalGB = [math]::Round([double]($current | Measure-Object -Property TotalGB -Sum).Sum, 2)
$inactivePercent = 0; if ($current.Count -gt 0) { $inactivePercent = [math]::Round(($inactive.Count / $current.Count) * 100, 1) }
Write-Host ('Microsoft 365 groups activity ({0})' -f $Period) -ForegroundColor Cyan
Write-Host ('  Groups (current / deleted)          : {0} / {1}' -f $current.Count, ($rows.Count - $current.Count))
Write-Host ('  {0,-36}: {1} ({2} %)' -f ('Inactive for {0}+ days' -f $DaysInactive), $inactive.Count, $inactivePercent) -ForegroundColor Yellow
Write-Host ('  Groups with guests                  : {0}' -f @($current | Where-Object { $_.HasGuests }).Count) -ForegroundColor Yellow
Write-Host ('  Ownerless groups                    : {0}' -f @($current | Where-Object { $_.IsOwnerless }).Count) -ForegroundColor Yellow
Write-Host ('  Storage (mailboxes + sites)         : {0} GB' -f $totalGB)
Write-Host '  Largest groups by storage'
foreach ($group in ($current | Sort-Object -Property TotalGB -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,-50} {1,10} GB  ({2} members)' -f $group.GroupDisplayName, $group.TotalGB, $group.MemberCount)
}
Write-Host ('  CSV : {0}' -f $OutputPath)
if ($daily.Count -gt 0) { Write-Host ('  Daily CSV : {0}' -f $dailyOutputPath) }

if ($PassThru) { $output }
if ($PassThru -and $daily.Count -gt 0) { $daily }
#endregion Main
