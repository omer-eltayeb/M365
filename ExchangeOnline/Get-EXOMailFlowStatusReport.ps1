<#
.SYNOPSIS
    Daily mail flow volumes per event type (good mail, spam, malware, phish, edge blocks, rules) as a pivot table and raw CSV.
.DESCRIPTION
    Reads the Exchange Online Protection mail flow status report with Get-MailFlowStatusReport for the chosen window (default
    the last 30 days, maximum 90) and optional direction / event type filters, following -Page until every row is read.
    The raw rows (Date, EventType, Direction, MessageCount) are saved to <OutputPath base>_Raw.csv, and the main CSV is a pivot
    with one row per Date and Direction, one column per event type and a Total column. The console prints the totals and
    daily averages per event type, which makes spikes in spam, phishing or rule hits easy to spot.
.PARAMETER StartDate
    First day of the report window. Defaults to EndDate minus DaysBack. Data is kept for 90 days.
.PARAMETER EndDate
    Last day of the report window. Defaults to today.
.PARAMETER DaysBack
    Number of days to report when StartDate is not given. Default 30, maximum 90.
.PARAMETER EventType
    One or more event types to include, for example GoodMail, Spam, EmailMalware, EmailPhish, EdgeBlockSpam or TransportRules.
    When omitted, every event type is returned.
.PARAMETER Direction
    Inbound, Outbound or IntraOrg. When omitted, all directions are returned and the pivot keeps one row per direction and day.
.PARAMETER OutputPath
    Path of the pivot CSV. Defaults to .\Reports\EXOMailFlowStatus_yyyyMMdd-HHmm.csv; the raw rows go to <base>_Raw.csv.
.PARAMETER PassThru
    Also emits the pivot rows to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMailFlowStatusReport.ps1
    Exports the last 30 days for all directions and event types and prints the totals and daily averages.
.EXAMPLE
    PS> .\Get-EXOMailFlowStatusReport.ps1 -DaysBack 90 -Direction Inbound -EventType EmailPhish, EmailMalware -PassThru | Sort-Object Total -Descending | Select-Object -First 5
    Shows the five inbound days with the most phishing and malware detections in the last quarter.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator, Global Reader or Security Reader (View-Only Recipients role).
    Category    : Mail flow & organization
    Changes     : No
    Notes       : Report data is aggregated per UTC day and the most recent 24-48 hours can still be incomplete. Event types
                  depend on licensing: EmailPhish / EmailMalware need Exchange Online Protection; Defender for Office 365 adds
                  further detections that are only visible in the Defender portal reports.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-mailflowstatusreport
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [datetime]$StartDate,

    [Parameter()]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$DaysBack = 30,

    [Parameter()]
    [string[]]$EventType,

    [Parameter()]
    [ValidateSet('Inbound', 'Outbound', 'IntraOrg')]
    [string]$Direction,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-ExchangeIfNeeded {
    <# Connects to Exchange Online (or Security & Compliance PowerShell) only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Compliance
    )
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($Compliance) {
        $active = @($connections | Where-Object { $_.ConnectionUri -like '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Security & Compliance PowerShell.'
            Connect-IPPSSession -ErrorAction Stop
        }
    }
    else {
        $active = @($connections | Where-Object { $_.ConnectionUri -notlike '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
    }
}
#endregion Helpers

#region Main
if (-not $PSBoundParameters.ContainsKey('StartDate')) { $StartDate = $EndDate.AddDays(-$DaysBack) }
if ($StartDate -ge $EndDate) { throw 'StartDate must be earlier than EndDate.' }
if ($StartDate -lt (Get-Date).AddDays(-90)) { throw 'The mail flow status report covers the last 90 days only.' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMailFlowStatus_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$rawPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_Raw.csv')

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

$reportParams = @{ StartDate = $StartDate; EndDate = $EndDate; ErrorAction = 'Stop' }
if ($PSBoundParameters.ContainsKey('EventType')) { $reportParams['EventType'] = $EventType }
if ($PSBoundParameters.ContainsKey('Direction')) { $reportParams['Direction'] = $Direction }
$rawRows = New-Object -TypeName System.Collections.Generic.List[object]
$pageNumber = 0
try {
    do {
        $pageNumber++
        Write-Progress -Activity 'Reading mail flow status report' -Status ('Page {0}; {1} rows so far' -f $pageNumber, $rawRows.Count)
        $page = @(Get-MailFlowStatusReport @reportParams -Page $pageNumber -PageSize 5000)
        foreach ($entry in $page) {
            $rawRows.Add([PSCustomObject]@{
                    Date         = ([datetime]$entry.Date).Date
                    EventType    = [string]$entry.EventType
                    Direction    = [string]$entry.Direction
                    MessageCount = [long]$entry.MessageCount
                })
        }
    } while ($page.Count -eq 5000 -and $pageNumber -lt 1000)
}
catch {
    throw "Get-MailFlowStatusReport failed: $($_.Exception.Message)"
}
finally {
    Write-Progress -Activity 'Reading mail flow status report' -Completed
}
Write-Verbose "Report returned $($rawRows.Count) row(s)."

$eventTypes = @($rawRows | Select-Object -ExpandProperty EventType -Unique | Sort-Object)
$pivot = New-Object -TypeName System.Collections.Generic.List[object]
# One pivot row per day and direction; the key sorts chronologically because the date is formatted yyyy-MM-dd.
foreach ($group in ($rawRows | Group-Object -Property { '{0:yyyy-MM-dd}|{1}' -f $_.Date, $_.Direction } | Sort-Object -Property Name)) {
    $row = [ordered]@{ Date = $group.Group[0].Date; Direction = $group.Group[0].Direction }
    $total = [long]0
    foreach ($type in $eventTypes) {
        $count = [long](($group.Group | Where-Object { $_.EventType -eq $type } | Measure-Object -Property MessageCount -Sum).Sum)
        $row[$type] = $count
        $total += $count
    }
    $row['Total'] = $total
    $pivot.Add([PSCustomObject]$row)
}

if ($pivot.Count -gt 0) {
    $pivot | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    $rawRows | Sort-Object -Property Date, Direction, EventType | Export-Csv -Path $rawPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'The report returned no data for this window; no CSV written.'
}

$dayCount = @($pivot | Select-Object -ExpandProperty Date -Unique).Count
Write-Host ''
Write-Host ('Mail flow status {0:yyyy-MM-dd} to {1:yyyy-MM-dd} ({2} day(s) with data{3})' -f $StartDate, $EndDate, $dayCount, $(if ($Direction) { ", $Direction" } else { '' })) -ForegroundColor Cyan
Write-Host ('  {0,-22} {1,14} {2,14}' -f 'EventType', 'Total', 'Daily average')
foreach ($type in $eventTypes) {
    $sum = [long](($rawRows | Where-Object { $_.EventType -eq $type } | Measure-Object -Property MessageCount -Sum).Sum)
    $colour = 'Gray'
    if ($type -match 'Spam|Malware|Phish|Block' -and $sum -gt 0) { $colour = 'Yellow' }
    Write-Host ('  {0,-22} {1,14:N0} {2,14:N1}' -f $type, $sum, $(if ($dayCount -gt 0) { $sum / $dayCount } else { 0 })) -ForegroundColor $colour
}
$grandTotal = [long](($rawRows | Measure-Object -Property MessageCount -Sum).Sum)
Write-Host ('  {0,-22} {1,14:N0} {2,14:N1}' -f 'All events', $grandTotal, $(if ($dayCount -gt 0) { $grandTotal / $dayCount } else { 0 })) -ForegroundColor Green
if ($pivot.Count -gt 0) { Write-Host ('  Reports: {0}; {1}' -f $OutputPath, $rawPath) }

if ($PassThru) {
    $pivot
}
#endregion Main
