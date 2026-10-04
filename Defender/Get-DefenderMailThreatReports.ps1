<#
.SYNOPSIS
    Exports the Defender for Office 365 threat protection status as a daily matrix, the mail flow status report and optionally the per-message detail.
.DESCRIPTION
    Reads Get-MailTrafficATPReport (aggregated by day, paged) for the last -DaysBack days and pivots it into one row per
    day and direction with a column per detection type (Spoof DMARC, URL detonation, Anti-malware Engine, ...) plus a
    total - the main CSV. Get-MailFlowStatusReport (EdgeBlockSpam, EmailMalware, EmailPhish, GoodMail, SpamDetections and
    TransportRules per day) goes to <base>_MailFlowStatus.csv and, with -IncludeDetail, the per-message rows of
    Get-MailDetailATPReport (last 10 days at most) to <base>_Detail.csv. The console summary lists totals per detection
    type and mail flow disposition and, with detail, the most targeted recipients and the top sender domains.
.PARAMETER DaysBack
    Number of days to report (1-90). Default 30. The detail report is capped at the last 10 days by the service.
.PARAMETER IncludeDetail
    Also export the per-message detections (Get-MailDetailATPReport, limited to 10,000 rows by the service).
.PARAMETER OutputPath
    Path of the main CSV; the companion files use the same base name. Defaults to .\Reports\DefenderMailThreats_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the daily matrix rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderMailThreatReports.ps1
    Exports 30 days of daily detection counts and the mail flow status report, then prints the totals per detection type.
.EXAMPLE
    PS> .\Get-DefenderMailThreatReports.ps1 -DaysBack 10 -IncludeDetail -OutputPath C:\Temp\Threats.csv
    Writes Threats.csv, Threats_MailFlowStatus.csv and Threats_Detail.csv and shows the most targeted recipients and sender domains.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Reader, Global Reader or Security Administrator (Exchange Online PowerShell session)
    Category    : Email threat operations
    Changes     : No
    Notes       : Detection types that belong to Defender for Office 365 Plan 1/2 (Safe Links, Safe Attachments, impersonation)
                  only appear in licensed tenants; EOP-only tenants see the core filtering types. Dates are UTC and the most
                  recent day is usually incomplete. Report columns were renamed across module versions, so a few columns fall back to alternative names.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-mailtrafficatpreport
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$DaysBack = 30,

    [Parameter()]
    [switch]$IncludeDetail,

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

function Invoke-PagedReport {
    <# Runs a reporting cmdlet page by page (PageSize 5000, Page 1-1000) until a short page signals the end of the data. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $page = 1
    do {
        Write-Progress -Activity $Command -Status ('Page {0} - {1} rows so far' -f $page, $results.Count)
        $batch = @(& $Command @Parameters -Page $page -PageSize 5000 -ErrorAction Stop)
        foreach ($row in $batch) { $results.Add($row) }
        $page++
    } while ($batch.Count -eq 5000 -and $page -le 1000)
    Write-Progress -Activity $Command -Completed
    return $results
}

#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderMailThreats_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$basePath = $OutputPath -replace '\.[^.\\/]+$', ''
try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

# The reporting cmdlets expect UTC; the detail report never goes back further than 10 days.
$end = (Get-Date).ToUniversalTime()
$start = $end.AddDays(-$DaysBack)
try {
    $atpRows = @(Invoke-PagedReport -Command 'Get-MailTrafficATPReport' -Parameters @{ StartDate = $start; EndDate = $end; AggregateBy = 'Day' })
}
catch {
    throw "Get-MailTrafficATPReport failed: $($_.Exception.Message)"
}

# Pivot: one row per day and direction, one column per detection type (spaces and punctuation removed from the names).
$typeTotals = @{}
foreach ($row in $atpRows) { $typeTotals[[string]$row.EventType] += [int]$row.MessageCount }
$matrix = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($group in ($atpRows | Group-Object -Property { '{0:yyyy-MM-dd}|{1}' -f [datetime]$_.Date, $_.Direction } | Sort-Object -Property Name)) {
    $keyParts = $group.Name -split '\|'
    $row = [ordered]@{ Date = [datetime]$keyParts[0]; Direction = $keyParts[1] }
    $total = 0
    foreach ($eventType in @($typeTotals.Keys | Where-Object { $_ -ne '' } | Sort-Object)) {
        $count = [int](@($group.Group | Where-Object { [string]$_.EventType -eq $eventType } | ForEach-Object { [int]$_.MessageCount } | Measure-Object -Sum).Sum)
        $row[($eventType -replace '[^A-Za-z0-9]', '')] = $count
        $total += $count
    }
    $row['Total'] = $total
    $matrix.Add([PSCustomObject]$row)
}
if ($matrix.Count -gt 0) { $matrix | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

$flowRows = @()
try {
    $flowRows = @(Get-MailFlowStatusReport -StartDate $start -EndDate $end -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Date         = [datetime]$_.Date
                Direction    = [string]$_.Direction
                EventType    = [string]$_.EventType
                MessageCount = [int]$(if ($null -ne $_.PSObject.Properties['MessageCount']) { $_.MessageCount } else { $_.PSObject.Properties['Count'].Value })
            }
        })
    if ($flowRows.Count -gt 0) { $flowRows | Sort-Object -Property Date, Direction, EventType | Export-Csv -Path "${basePath}_MailFlowStatus.csv" -NoTypeInformation -Encoding UTF8 }
}
catch { Write-Warning "Get-MailFlowStatusReport failed; the mail flow status file was not written: $($_.Exception.Message)" }

$detailRows = @()
if ($IncludeDetail) {
    if ($DaysBack -gt 10) { Write-Warning 'The detail report only covers the last 10 days; the matrix still covers the full window.' }
    try {
        $detailParams = @{ StartDate = $end.AddDays(-[math]::Min($DaysBack, 10)); EndDate = $end }
        $detailRows = @(Invoke-PagedReport -Command 'Get-MailDetailATPReport' -Parameters $detailParams | ForEach-Object {
                [PSCustomObject]@{
                    Date             = [datetime]$_.Date
                    EventType        = [string]$_.EventType
                    Direction        = [string]$_.Direction
                    SenderAddress    = [string]$_.SenderAddress
                    RecipientAddress = [string]$_.RecipientAddress
                    Subject          = [string]$_.Subject
                    MessageTraceId   = [string]$_.MessageTraceId
                    Verdict          = [string]$(if ($null -ne $_.PSObject.Properties['VerdictType']) { $_.VerdictType } else { $_.Verdict })
                    Action           = [string]$(if ($null -ne $_.PSObject.Properties['Action']) { $_.Action } else { $_.DeliveryAction })
                    FileName         = [string]$_.FileName
                }
            })
        if ($detailRows.Count -gt 0) { $detailRows | Sort-Object -Property Date -Descending | Export-Csv -Path "${basePath}_Detail.csv" -NoTypeInformation -Encoding UTF8 }
        if ($detailRows.Count -ge 10000) { Write-Warning 'The detail report returned 10,000 rows, which is the service limit; older detections are missing.' }
    }
    catch { Write-Warning "Get-MailDetailATPReport failed; the detail file was not written: $($_.Exception.Message)" }
}

Write-Host ''
Write-Host ('Threat protection status - {0:yyyy-MM-dd} to {1:yyyy-MM-dd} (UTC), {2} day/direction row(s)' -f $start, $end, $matrix.Count) -ForegroundColor Cyan
Write-Host '  Detections by type:' -ForegroundColor Cyan
foreach ($entry in ($typeTotals.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 12)) {
    Write-Host ('    {0,-40} {1,10}' -f $entry.Key, $entry.Value)
}
if ($flowRows.Count -gt 0) {
    Write-Host '  Mail flow status:' -ForegroundColor Cyan
    foreach ($group in ($flowRows | Group-Object -Property EventType | Sort-Object -Property Name)) {
        Write-Host ('    {0,-40} {1,10}' -f $group.Name, (@($group.Group | Measure-Object -Property MessageCount -Sum).Sum))
    }
}
if ($detailRows.Count -gt 0) {
    $sections = @(@{ Title = 'Most targeted recipients'; Values = @($detailRows | ForEach-Object { $_.RecipientAddress }) },
        @{ Title = 'Top sender domains'; Values = @($detailRows | ForEach-Object { ([string]$_.SenderAddress -split '@')[-1].ToLowerInvariant() }) })
    foreach ($section in $sections) {
        Write-Host "  $($section.Title):" -ForegroundColor Cyan
        foreach ($group in ($section.Values | Where-Object { $_ -ne '' } | Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
            Write-Host ('    {0,-50} {1,6}' -f $group.Name, $group.Count)
        }
    }
}
Write-Host ('  Files: {0}{1}' -f $OutputPath, $(if ($IncludeDetail) { ' (+ _MailFlowStatus.csv, _Detail.csv)' } else { ' (+ _MailFlowStatus.csv)' }))

if ($PassThru) { $matrix }
#endregion Main
