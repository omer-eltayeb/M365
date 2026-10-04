<#
.SYNOPSIS
    Reports SharePoint and OneDrive file activity (access, download, delete, move, upload) from the unified audit log.
.DESCRIPTION
    Searches RecordType SharePointFileOperation with Search-UnifiedAuditLog one day at a time (ReturnLargeSet paging),
    parses AuditData and flattens file, site, client and application details into one row per event. Wildcard filters
    narrow the output to a site or file name. Exports a CSV and prints counts by operation, downloads per user (flagging
    mass downloads), deletions per user and the busiest sites.
.PARAMETER DaysBack
    Number of days to search back from now (default 7, maximum 180). Ignored when -StartDate is used.
.PARAMETER StartDate
    Start of the search window (UTC). Use with -EndDate instead of -DaysBack.
.PARAMETER EndDate
    End of the search window (UTC). Defaults to now.
.PARAMETER UserIds
    One or more user principal names to filter on (server-side).
.PARAMETER Operations
    File operations to include. Defaults to access, download, delete (all stages), modify, move, copy, rename, upload and sync downloads.
.PARAMETER SiteUrl
    Wildcard filter on the site URL, for example https://contoso.sharepoint.com/sites/Finance*.
.PARAMETER FileName
    Wildcard filter on the source file name, for example *.xlsx or Budget*.
.PARAMETER DownloadThreshold
    Number of downloads per user in the window at which the user is flagged as a mass download (default 100).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewAuditFileActivity_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the flattened records to the pipeline.
.EXAMPLE
    PS> .\Search-PurviewAuditFileActivity.ps1
    Exports the last 7 days of file activity for the whole tenant and prints the download, deletion and site summaries.
.EXAMPLE
    PS> .\Search-PurviewAuditFileActivity.ps1 -DaysBack 30 -UserIds alex@contoso.com -Operations FileDownloaded, FileSyncDownloadedFull -DownloadThreshold 50 -Verbose
    Checks one user's downloads over 30 days and flags the user when 50 or more files were downloaded.
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
    Notes       : Search-UnifiedAuditLog is an Exchange Online cmdlet, so an Exchange Online session is used. The window is sliced
                  into one-day searches because a ReturnLargeSet session returns at most 50,000 records; days with more events need
                  a user or operation filter. Dates are UTC. Audit (Standard) keeps 180 days; beyond 90 days a warning is shown.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/search-unifiedauditlog
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'DaysBack')]
param(
    [Parameter(ParameterSetName = 'DaysBack')]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 7,

    [Parameter(Mandatory = $true, ParameterSetName = 'Dates')]
    [datetime]$StartDate,

    [Parameter(ParameterSetName = 'Dates')]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [string[]]$UserIds,

    [Parameter()]
    [string[]]$Operations = @('FileAccessed', 'FileDownloaded', 'FileDeleted', 'FileDeletedFirstStageRecycleBin', 'FileDeletedSecondStageRecycleBin',
        'FileModified', 'FileMoved', 'FileCopied', 'FileRenamed', 'FileUploaded', 'FileSyncDownloadedFull', 'FileRecycled'),

    [Parameter()]
    [string]$SiteUrl,

    [Parameter()]
    [string]$FileName,

    [Parameter()]
    [ValidateRange(1, 100000)]
    [int]$DownloadThreshold = 100,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewAuditFileActivity_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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
    try { $records.AddRange(@(Search-AuditRecords -StartDate $sliceStart -EndDate $sliceEnd -RecordType 'SharePointFileOperation' -Operations $Operations -UserIds $UserIds)) }
    catch { Write-Warning ('Search for {0:yyyy-MM-dd} failed: {1}' -f $sliceStart, $_.Exception.Message) }
}
Write-Progress -Activity 'Audit log search' -Completed
$userTypeNames = @{ '0' = 'Regular'; '2' = 'Admin'; '3' = 'DcAdmin'; '4' = 'System'; '5' = 'Application'; '6' = 'ServicePrincipal'; '10' = 'Guest' }
$auditFields = @('SiteUrl', 'SourceRelativeUrl', 'SourceFileName', 'SourceFileExtension', 'DestinationRelativeUrl', 'DestinationFileName',
    'ClientIP', 'ItemType', 'EventSource', 'Workload', 'ApplicationDisplayName', 'CorrelationId')
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "Could not parse AuditData for record $($record.Identity); skipped."; continue }
    if (($SiteUrl -and [string]$audit.SiteUrl -notlike $SiteUrl) -or ($FileName -and [string]$audit.SourceFileName -notlike $FileName)) { continue }
    $userAgent = [string]$audit.UserAgent
    $row = [ordered]@{ CreationTime = [datetime]$record.CreationDate; Operation = [string]$audit.Operation; UserId = [string]$audit.UserId }
    $row['UserType'] = $(if ($userTypeNames.ContainsKey([string]$audit.UserType)) { $userTypeNames[[string]$audit.UserType] } else { [string]$audit.UserType })
    foreach ($field in $auditFields) { $row[$field] = [string]$audit.$field }
    $row['UserAgent'] = $userAgent.Substring(0, [math]::Min(150, $userAgent.Length))
    $results.Add([PSCustomObject]$row)
}
$results = @($results | Sort-Object -Property CreationTime)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'The search returned no file activity for the given window and filters.' }
$downloads = @($results | Where-Object { 'FileDownloaded', 'FileSyncDownloadedFull' -contains $_.Operation } | Group-Object -Property UserId | Sort-Object -Property Count -Descending)
$deletions = @($results | Where-Object { $_.Operation -like 'FileDeleted*' -or $_.Operation -eq 'FileRecycled' } | Group-Object -Property UserId | Sort-Object -Property Count -Descending)
Write-Host 'SharePoint / OneDrive file activity summary' -ForegroundColor Cyan
Write-Host ('  Window : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} UTC, {2} record(s) in {3} day slice(s)' -f $StartDate, $EndDate, $results.Count, $totalDays)
Write-Host '  By operation:'
foreach ($group in ($results | Group-Object -Property Operation | Sort-Object -Property Count -Descending)) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
Write-Host ('  Downloads per user (top 10; {0} user(s) at or above the threshold of {1}):' -f @($downloads | Where-Object { $_.Count -ge $DownloadThreshold }).Count, $DownloadThreshold)
foreach ($group in ($downloads | Select-Object -First 10)) {
    Write-Host ('    {0,7}  {1}{2}' -f $group.Count, $group.Name, $(if ($group.Count -ge $DownloadThreshold) { '  <-- MASS DOWNLOAD' } else { '' }))
}
Write-Host '  Deletions per user (top 10):'
foreach ($group in ($deletions | Select-Object -First 10)) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
Write-Host '  Top sites:'
foreach ($group in ($results | Group-Object -Property SiteUrl | Sort-Object -Property Count -Descending | Select-Object -First 10)) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
Write-Host ('  Report : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
