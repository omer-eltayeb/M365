<#
.SYNOPSIS
    Builds a cross-workload activity timeline for one or more users from the unified audit log.
.DESCRIPTION
    Searches every record type for the given users one day at a time with Search-UnifiedAuditLog (ReturnLargeSet paging),
    parses AuditData and produces one timeline row per event with workload, operation, a best-effort Detail column (mail
    subject, file name, site, team, cmdlet parameters or target UPN), client IP, user agent and result. Exports a CSV and
    optionally an HTML page; prints counts by workload and operation, client IPs with first/last seen and the activity span.
.PARAMETER UserIds
    One or more user principal names whose activity is collected (mandatory).
.PARAMETER DaysBack
    Number of days to search back from now (default 7, maximum 180). Ignored when -StartDate is used.
.PARAMETER StartDate
    Start of the search window (UTC). Use with -EndDate instead of -DaysBack.
.PARAMETER EndDate
    End of the search window (UTC). Defaults to now.
.PARAMETER IncludeRawJson
    Add the raw AuditData JSON as the last CSV column for deeper analysis.
.PARAMETER HtmlPath
    Optional path of an HTML version of the timeline (ConvertTo-Html), handy for sharing with an investigator.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewAuditUserTimeline_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the timeline rows to the pipeline.
.EXAMPLE
    PS> .\Search-PurviewAuditUserTimeline.ps1 -UserIds alex@contoso.com
    Exports everything Alex did (or that was done to Alex's objects) in the last 7 days and prints the IP and workload summary.
.EXAMPLE
    PS> .\Search-PurviewAuditUserTimeline.ps1 -UserIds alex@contoso.com, kim@contoso.com -DaysBack 30 -IncludeRawJson -HtmlPath C:\Cases\Case42\Timeline.html
    Builds a 30-day timeline for two users with the raw JSON in the CSV and an HTML copy for the case file.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); unified audit log ingestion must be enabled
    Category    : Audit log scenarios
    Changes     : No
    Notes       : Uses an Exchange Online session because Search-UnifiedAuditLog is an Exchange Online cmdlet. The window is sliced
                  into one-day searches because a ReturnLargeSet session returns at most 50,000 records; a very active user can still
                  exceed that in one day (MailItemsAccessed). Times are UTC. Detail is best effort; -IncludeRawJson keeps every field.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/search-unifiedauditlog
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'DaysBack')]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$UserIds,

    [Parameter(ParameterSetName = 'DaysBack')]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 7,

    [Parameter(Mandatory = $true, ParameterSetName = 'Dates')]
    [datetime]$StartDate,

    [Parameter(ParameterSetName = 'Dates')]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [switch]$IncludeRawJson,

    [Parameter()]
    [string]$HtmlPath,

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

function Search-AuditRecords {
    <# Pages through Search-UnifiedAuditLog with ReturnLargeSet and returns de-duplicated records. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter()]
        [string[]]$RecordType,

        [Parameter()]
        [string[]]$Operations,

        [Parameter()]
        [string[]]$UserIds,

        [Parameter()]
        [string]$FreeText
    )
    $sessionId = [guid]::NewGuid().ToString()
    $records = New-Object -TypeName System.Collections.Generic.List[object]
    $seen = @{}
    do {
        $searchParams = @{ StartDate = $StartDate; EndDate = $EndDate; SessionId = $sessionId; SessionCommand = 'ReturnLargeSet'; ResultSize = 5000; ErrorAction = 'Stop' }
        if ($RecordType) { $searchParams['RecordType'] = $RecordType }
        if ($Operations) { $searchParams['Operations'] = $Operations }
        if ($UserIds) { $searchParams['UserIds'] = $UserIds }
        if ($FreeText) { $searchParams['FreeText'] = $FreeText }
        $page = @(Search-UnifiedAuditLog @searchParams)
        foreach ($record in $page) {
            if (-not $seen.ContainsKey($record.Identity)) {
                $seen[$record.Identity] = $true
                $records.Add($record)
            }
        }
    } while ($page.Count -gt 0)
    return $records
}
#endregion Helpers

#region Main
if ($PSCmdlet.ParameterSetName -eq 'DaysBack') { $StartDate = (Get-Date).AddDays(-$DaysBack) }
if ($EndDate -le $StartDate) { throw 'EndDate must be later than StartDate.' }
if (($EndDate - $StartDate).TotalDays -gt 90) { Write-Warning 'Window longer than 90 days: records beyond Audit (Standard) retention need Audit (Premium) retention policies.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewAuditUserTimeline_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }
# One search session per day keeps every slice under the 50,000-record ReturnLargeSet ceiling.
$records = New-Object -TypeName System.Collections.Generic.List[object]
$totalDays = [int][math]::Ceiling(($EndDate - $StartDate).TotalDays)
for ($day = 0; $day -lt $totalDays; $day++) {
    $sliceStart = $StartDate.AddDays($day)
    $sliceEnd = $StartDate.AddDays($day + 1)
    if ($sliceEnd -gt $EndDate) { $sliceEnd = $EndDate }
    Write-Progress -Activity 'Audit log search' -Status ('Day {0}/{1} ({2:yyyy-MM-dd}): {3} records' -f ($day + 1), $totalDays, $sliceStart, $records.Count) -PercentComplete (100 * $day / $totalDays)
    try { $records.AddRange(@(Search-AuditRecords -StartDate $sliceStart -EndDate $sliceEnd -UserIds $UserIds)) }
    catch { Write-Warning ('Search for {0:yyyy-MM-dd} failed: {1}' -f $sliceStart, $_.Exception.Message) }
}
Write-Progress -Activity 'Audit log search' -Completed
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "Could not parse AuditData for record $($record.Identity); skipped."; continue }
    # Each workload names its descriptive field differently; take the first one that is present.
    $detail = ''
    foreach ($candidate in @($audit.Subject, $audit.Item.Subject, $audit.SourceFileName, $audit.TeamName, $audit.SiteUrl)) { if (-not $detail -and $candidate) { $detail = [string]$candidate } }
    if (-not $detail -and $audit.Parameters) { $detail = @($audit.Parameters | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; ' }
    if (-not $detail -and $audit.Target) { $detail = [string](@($audit.Target | Where-Object { $_.Type -eq 5 } | Select-Object -First 1).ID) }
    $userAgent = [string]$(if ($audit.UserAgent) { $audit.UserAgent } else { $audit.ClientInfoString })
    if (-not $userAgent) { $userAgent = [string](@($audit.ExtendedProperties | Where-Object { $_.Name -eq 'UserAgent' } | Select-Object -First 1).Value) }
    $row = [ordered]@{ CreationTime = [datetime]$record.CreationDate; UserId = [string]$record.UserIds; Workload = [string]$audit.Workload; RecordType = [string]$record.RecordType }
    $row['Operation'] = [string]$audit.Operation
    $row['ObjectId'] = ([string]$audit.ObjectId).Substring(0, [math]::Min(200, ([string]$audit.ObjectId).Length))
    $row['Detail'] = $detail
    $row['ClientIP'] = [string]$(if ($audit.ClientIP) { $audit.ClientIP } elseif ($audit.ClientIPAddress) { $audit.ClientIPAddress } else { $audit.ActorIpAddress })
    $row['UserAgent'] = $userAgent.Substring(0, [math]::Min(150, $userAgent.Length))
    $row['ResultStatus'] = [string]$audit.ResultStatus; $row['Id'] = [string]$audit.Id
    if ($IncludeRawJson) { $row['AuditData'] = [string]$record.AuditData }
    $results.Add([PSCustomObject]$row)
}
$results = @($results | Sort-Object -Property CreationTime)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
if ($HtmlPath -and $results.Count -gt 0) {
    $htmlFolder = Split-Path -Path $HtmlPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($htmlFolder) -and -not (Test-Path -Path $htmlFolder)) { New-Item -Path $htmlFolder -ItemType Directory -Force | Out-Null }
    $title = 'Audit timeline for {0} ({1:yyyy-MM-dd} to {2:yyyy-MM-dd} UTC)' -f ($UserIds -join ', '), $StartDate, $EndDate
    $style = '<style>body{font-family:Segoe UI,Arial;font-size:12px}table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:3px 6px;text-align:left}th{background:#eee}</style>'
    $results | Select-Object -Property CreationTime, UserId, Workload, Operation, Detail, ObjectId, ClientIP, UserAgent, ResultStatus |
        ConvertTo-Html -Title $title -Head $style -PreContent ('<h2>{0}</h2>' -f $title) | Set-Content -Path $HtmlPath -Encoding UTF8
}
Write-Host 'User activity timeline summary' -ForegroundColor Cyan
Write-Host ('  Users    : {0}' -f ($UserIds -join ', '))
Write-Host ('  Window   : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} UTC, {2} event(s) in {3} day slice(s)' -f $StartDate, $EndDate, $results.Count, $totalDays)
if ($results.Count -gt 0) { Write-Host ('  Activity : first {0:yyyy-MM-dd HH:mm}, last {1:yyyy-MM-dd HH:mm}' -f $results[0].CreationTime, $results[-1].CreationTime) }
foreach ($section in @(@('By workload', 'Workload', 20), @('Top operations', 'Operation', 10))) {
    Write-Host ('  {0}:' -f $section[0])
    $groups = $results | Group-Object -Property $section[1] | Sort-Object -Property Count -Descending | Select-Object -First $section[2]
    foreach ($group in $groups) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
}
Write-Host '  Client IP addresses (count, address, first seen / last seen):'
foreach ($group in ($results | Where-Object { $_.ClientIP } | Group-Object -Property ClientIP | Sort-Object -Property Count -Descending | Select-Object -First 15)) {
    $span = $group.Group | Measure-Object -Property CreationTime -Minimum -Maximum
    Write-Host ('    {0,7}  {1,-40} {2:yyyy-MM-dd HH:mm} / {3:yyyy-MM-dd HH:mm}' -f $group.Count, $group.Name, $span.Minimum, $span.Maximum)
}
Write-Host ('  Report   : {0}{1}' -f $OutputPath, $(if ($HtmlPath) { "  (HTML: $HtmlPath)" } else { '' }))
if ($PassThru) { $results }
#endregion Main
