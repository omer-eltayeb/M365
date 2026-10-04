<#
.SYNOPSIS
    Reports who did what in eDiscovery and content search (searches, previews, exports, purges, case and hold changes) from the unified audit log.
.DESCRIPTION
    Runs Search-UnifiedAuditLog for the record types Discovery (eDiscovery (Standard) and content search) and AeD (eDiscovery
    (Premium)) over the last -DaysBack days, paging with ReturnLargeSet, and flattens the AuditData JSON into CreationTime, UserId,
    Operation, ObjectId, CaseName, Cmdlet, Query, ResultStatus and ClientIP. Server-side filters cover operations and users; the case
    name is filtered client-side. Writes a CSV and prints a summary by operation and by user, with export and purge activities
    listed separately because they move data out of the tenant or delete it. The script is read-only.
.PARAMETER DaysBack
    Number of days to look back, 1-180 (default 30). Audit (Standard) keeps 180 days.
.PARAMETER Operation
    One or more operations, for example SearchCreated, SearchExportDownloaded, SearchPurged, CaseMemberAdded, HoldCreated.
.PARAMETER UserId
    One or more user principal names whose activities are returned.
.PARAMETER CaseName
    Case name or wildcard pattern; only records whose AuditData names that case are kept.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewEDiscoveryActivity_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the flattened records to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewEDiscoveryActivityAudit.ps1
    Exports 30 days of eDiscovery and content search activity and lists every export and purge.
.EXAMPLE
    PS> .\Get-PurviewEDiscoveryActivityAudit.ps1 -DaysBack 90 -Operation SearchPurged, SearchExportDownloaded -Verbose
    Shows who purged or downloaded search results during the last 90 days.
.EXAMPLE
    PS> .\Get-PurviewEDiscoveryActivityAudit.ps1 -CaseName 'Legal*' -PassThru | Group-Object UserId | Sort-Object Count -Descending
    Shows which users were most active in the Legal cases.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Exchange Online PowerShell session); unified audit logging must be enabled
    Category    : eDiscovery & content search
    Changes     : No
    Notes       : Search-UnifiedAuditLog is an Exchange Online cmdlet, so an Exchange Online session is used, not a compliance one.
                  Audit records can take up to 24 hours to appear. A ReturnLargeSet session returns at most 50,000 records per record
                  type; narrow -DaysBack or the filters if the warning appears. Dates are UTC.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/search-unifiedauditlog
.LINK
    https://learn.microsoft.com/purview/audit-log-activities
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 30,

    [Parameter()]
    [string[]]$Operation,

    [Parameter()]
    [string[]]$UserId,

    [Parameter()]
    [string]$CaseName,

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

function Get-AuditField {
    <# Returns the first non-empty value among the given property names of a parsed AuditData object; record types name the same field differently. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $AuditData,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )
    if ($null -eq $AuditData) { return $null }
    foreach ($name in $Names) {
        $property = $AuditData.PSObject.Properties[$name]
        if ($null -ne $property -and -not [string]::IsNullOrEmpty([string]$property.Value)) { return $property.Value }
    }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewEDiscoveryActivity_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$endDate = Get-Date
$startDate = $endDate.AddDays(-$DaysBack)
$searchParams = @{ StartDate = $startDate; EndDate = $endDate; SessionCommand = 'ReturnLargeSet'; ResultSize = 5000; ErrorAction = 'Stop' }
if ($PSBoundParameters.ContainsKey('Operation')) { $searchParams['Operations'] = $Operation }
if ($PSBoundParameters.ContainsKey('UserId')) { $searchParams['UserIds'] = $UserId }

# Discovery = eDiscovery (Standard) and content search; AeD = eDiscovery (Premium). Each record type gets its own paged session.
$records = New-Object -TypeName System.Collections.Generic.List[object]
$seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
foreach ($recordType in 'Discovery', 'AeD') {
    $sessionId = [guid]::NewGuid().ToString()
    $page = 0; $expected = 0; $fetched = 0
    do {
        $page++
        Write-Progress -Activity 'Searching the unified audit log' -Status ('{0}: page {1}, {2} of {3} records' -f $recordType, $page, $fetched, $expected)
        try { $batch = @(Search-UnifiedAuditLog @searchParams -RecordType $recordType -SessionId $sessionId) }
        catch { Write-Warning ('{0} page {1} failed: {2}' -f $recordType, $page, $_.Exception.Message); break }
        if ($batch.Count -eq 0) { break }
        if ($page -eq 1) {
            $expected = [int]$batch[0].ResultCount
            if ($expected -ge 50000) { Write-Warning ('{0} holds {1} records but ReturnLargeSet pages through at most 50,000; narrow -DaysBack or add filters.' -f $recordType, $expected) }
        }
        foreach ($entry in $batch) { if ($seen.Add([string]$entry.Identity)) { $records.Add($entry) } }
        $fetched += $batch.Count
    } while ($fetched -lt $expected -and $page -lt 10)
    Write-Verbose ('{0}: {1} records returned.' -f $recordType, $fetched)
}
Write-Progress -Activity 'Searching the unified audit log' -Completed

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    $audit = $null
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Verbose "Could not parse AuditData for record $($record.Identity): $($_.Exception.Message)" }
    $query = [string](Get-AuditField -AuditData $audit -Names 'Query', 'ContentMatchQuery')
    if ($query.Length -gt 300) { $query = $query.Substring(0, 300) + '...' }
    $operationName = [string]$record.Operations
    $results.Add([PSCustomObject]@{
            CreationTime    = [datetime]$record.CreationDate
            UserId          = [string]$record.UserIds
            Operation       = $operationName
            RecordType      = [string]$record.RecordType
            ObjectId        = [string](Get-AuditField -AuditData $audit -Names 'ObjectId')
            CaseName        = [string](Get-AuditField -AuditData $audit -Names 'Case', 'CaseName')
            Cmdlet          = [string](Get-AuditField -AuditData $audit -Names 'Cmdlet')
            Query           = $query
            ResultStatus    = [string](Get-AuditField -AuditData $audit -Names 'ResultStatus')
            ClientIP        = [string](Get-AuditField -AuditData $audit -Names 'ClientIP', 'ClientIPAddress')
            IsExportOrPurge = ($operationName -match 'Export|Purge')
        })
}
if ($CaseName) { $results = @($results | Where-Object { $_.CaseName -like $CaseName }) }
$results = @($results | Sort-Object -Property CreationTime)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No eDiscovery audit records matched the window and filters.' }

Write-Host "`neDiscovery activity summary" -ForegroundColor Cyan
Write-Host ('  Window          : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} UTC-based, {2} record(s)' -f $startDate.ToUniversalTime(), $endDate.ToUniversalTime(), $results.Count)
Write-Host '  By operation    :'
foreach ($group in ($results | Group-Object -Property Operation | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,6}  {1}' -f $group.Count, $group.Name)
}
Write-Host '  By user         :'
foreach ($group in ($results | Group-Object -Property UserId | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,6}  {1}' -f $group.Count, $group.Name)
}
$sensitive = @($results | Where-Object { $_.IsExportOrPurge })
Write-Host ('  Exports/purges  : {0}' -f $sensitive.Count) -ForegroundColor $(if ($sensitive.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($entry in ($sensitive | Select-Object -First 25)) {
    Write-Host ('    {0:yyyy-MM-dd HH:mm}  {1,-28} {2,-24} {3}' -f $entry.CreationTime, $entry.Operation, $entry.UserId, $entry.ObjectId) -ForegroundColor Yellow
}
if ($sensitive.Count -gt 25) { Write-Host ('    ... {0} more in the CSV (filter on IsExportOrPurge).' -f ($sensitive.Count - 25)) -ForegroundColor Yellow }
if ($results.Count -gt 0) { Write-Host ('  Report          : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
