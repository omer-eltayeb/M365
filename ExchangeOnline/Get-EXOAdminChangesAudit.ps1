<#
.SYNOPSIS
    Reports the Exchange Online admin cmdlets that were run (who, what, on which object, from where) from the unified audit log.
.DESCRIPTION
    Searches the unified audit log for RecordType ExchangeAdmin with Search-UnifiedAuditLog (ReturnLargeSet paging, 5000
    records per page, de-duplicated by record Identity) over the last -DaysBack days and parses AuditData into one row per
    cmdlet execution: time, admin, cmdlet, target object, parameters (Name=Value), client IP, external access flag and
    result. Optional wildcard filters on the cmdlet name and object, plus an admin filter. Writes a CSV and prints the top
    cmdlets and admins.
.PARAMETER DaysBack
    Number of days to search back from now (1-180; Audit Standard keeps 180 days). Default: 7.
.PARAMETER Operation
    Wildcard filter on the cmdlet name, for example Set-Mailbox or *TransportRule*.
.PARAMETER UserId
    One or more admin UPNs; only their cmdlet executions are returned (server-side filter).
.PARAMETER ObjectId
    Wildcard filter on the target object, for example *finance* or a mailbox UPN.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOAdminChanges_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOAdminChangesAudit.ps1
    Reports every Exchange admin cmdlet executed in the last 7 days.
.EXAMPLE
    PS> .\Get-EXOAdminChangesAudit.ps1 -DaysBack 30 -Operation '*TransportRule*' -PassThru | Format-Table CreationTimeUtc, UserId, Operation, ObjectId
    Shows who created, changed or removed mail flow rules in the last 30 days.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Organization Management / Compliance Management) in Exchange Online
    Category    : Administration, audit & migration
    Changes     : No
    Notes       : Search-AdminAuditLog and New-AdminAuditLogSearch are retired; the unified audit log is the only source for admin
                  audit data. Entries made by the service itself appear with UserId NT AUTHORITY\SYSTEM. A single ReturnLargeSet
                  session returns at most 50,000 records - reduce -DaysBack or add filters when the warning appears. Times are UTC.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/search-unifiedauditlog
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 7,

    [Parameter()]
    [string]$Operation,

    [Parameter()]
    [string[]]$UserId,

    [Parameter()]
    [string]$ObjectId,

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
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOAdminChanges_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$endDate = (Get-Date).ToUniversalTime()
$startDate = $endDate.AddDays(-$DaysBack)
$searchParams = @{
    RecordType     = 'ExchangeAdmin'
    StartDate      = $startDate
    EndDate        = $endDate
    SessionId      = [guid]::NewGuid().ToString()
    SessionCommand = 'ReturnLargeSet'
    ResultSize     = 5000
    ErrorAction    = 'Stop'
}
if ($PSBoundParameters.ContainsKey('UserId')) { $searchParams['UserIds'] = $UserId }

# The same SessionId returns the next page on every call until the service sends an empty set (50,000 records at most).
$records = New-Object -TypeName System.Collections.Generic.List[object]
$seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
$expected = 0
$fetched = 0
$page = 0
do {
    $page++
    $percent = 0
    if ($expected -gt 0) { $percent = [math]::Min(100, ($fetched / $expected) * 100) }
    Write-Progress -Activity 'Searching the unified audit log (ExchangeAdmin)' -Status "Page $page - $fetched of $expected records" -PercentComplete $percent
    try { $batch = @(Search-UnifiedAuditLog @searchParams) }
    catch { Write-Warning "Audit log search failed on page ${page}: $($_.Exception.Message)"; break }
    if ($batch.Count -eq 0) { break }
    if ($page -eq 1) {
        $expected = [int]$batch[0].ResultCount
        if ($expected -ge 50000) { Write-Warning 'The search holds 50,000 or more records, but one session returns at most 50,000. Reduce -DaysBack or add -UserId.' }
    }
    $fetched += $batch.Count
    foreach ($entry in $batch) { if ($seen.Add([string]$entry.Identity)) { $records.Add($entry) } }
    Write-Verbose "Page ${page}: $($batch.Count) records ($fetched of $expected)."
} while ($fetched -lt $expected -and $page -lt 10)
Write-Progress -Activity 'Searching the unified audit log (ExchangeAdmin)' -Completed

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    $audit = $null
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Verbose "Could not parse AuditData for record $($record.Identity): $($_.Exception.Message)"; continue }

    $cmdletName = [string]$audit.Operation
    $target = [string]$audit.ObjectId
    if ($Operation -and $cmdletName -notlike $Operation) { continue }
    if ($ObjectId -and $target -notlike $ObjectId) { continue }
    $parameters = ''
    if ($null -ne $audit.PSObject.Properties['Parameters']) {
        $parameters = (@($audit.Parameters | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) -join '; ')
        if ($parameters.Length -gt 500) { $parameters = $parameters.Substring(0, 500) + '...' }
    }

    $results.Add([PSCustomObject]@{
            CreationTimeUtc = $record.CreationDate
            UserId          = [string]$audit.UserId
            Operation       = $cmdletName
            ObjectId        = $target
            Parameters      = $parameters
            ClientIP        = [string]$audit.ClientIP
            ExternalAccess  = [bool]$audit.ExternalAccess
            ResultStatus    = [string]$audit.ResultStatus
            RecordId        = [string]$record.Identity
        })
}

if ($results.Count -eq 0) { Write-Warning "No ExchangeAdmin audit records matched in the last $DaysBack day(s); nothing to export."; return }
$results | Sort-Object -Property CreationTimeUtc -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$external = @($results | Where-Object { $_.ExternalAccess }).Count
$failed = @($results | Where-Object { $_.ResultStatus -notin @('True', 'Success', '') }).Count

Write-Host "Exchange admin audit summary ($($results.Count) cmdlet executions, $startDate to $endDate UTC)" -ForegroundColor Cyan
Write-Host ('  Records fetched / matched : {0} / {1}' -f $records.Count, $results.Count)
Write-Host ('  Distinct admins           : {0}' -f @($results | Select-Object -Property UserId -Unique).Count)
Write-Host ('  External (service/partner): {0}' -f $external) -ForegroundColor $(if ($external -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Failed executions         : {0}' -f $failed)
Write-Host '  Top cmdlets:' -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Operation | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,-45} {1,6}' -f $group.Name, $group.Count)
}
Write-Host '  Top admins:' -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property UserId | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,-45} {1,6}' -f $group.Name, $group.Count)
}
Write-Host ('  Report                    : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
