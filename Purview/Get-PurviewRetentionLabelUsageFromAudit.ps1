<#
.SYNOPSIS
    Reports retention label activity (applied, removed, changed, record declared) from the unified audit log.
.DESCRIPTION
    Connects to Exchange Online and pages through Search-UnifiedAuditLog (SessionCommand ReturnLargeSet) for the
    retention label operations TagApplied, TagRemoved, TagUpdated and RecordDeclared over the last -DaysBack days.
    The AuditData JSON of every record is flattened into CreationTime, Operation, UserId, Workload, SiteUrl,
    SourceFileName, ObjectId, DestinationLabel, SourceLabel, ClientIP and ApplicationDisplayName. Label GUIDs are
    resolved to names with Get-ComplianceTag (Security & Compliance session) unless -SkipLabelResolve is used, and
    removals of record labels are flagged. Writes a CSV and prints a summary by operation, label, user and site.
.PARAMETER DaysBack
    Number of days to search back from now, 1-180 (default 30). Audit (Standard) keeps 180 days.
.PARAMETER Operations
    Audit operations to search. Defaults to TagApplied, TagRemoved, TagUpdated and RecordDeclared.
.PARAMETER SkipLabelResolve
    Do not open a Security & Compliance session to resolve label GUIDs and record-label status; faster, but labels that
    the audit record identifies by GUID stay as GUIDs and IsRecordLabelRemoval is always False.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewRetentionLabelAudit_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the flattened records to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewRetentionLabelUsageFromAudit.ps1
    Exports the last 30 days of retention label activity to .\Reports\PurviewRetentionLabelAudit_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-PurviewRetentionLabelUsageFromAudit.ps1 -DaysBack 90 -PassThru | Where-Object { $_.IsRecordLabelRemoval } | Format-Table CreationTime, UserId, SourceLabel, SourceFileName
    Shows who removed record labels from content during the last 90 days.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Exchange Online); View-Only Retention Management for the label
                  lookup. Unified audit logging must be enabled (Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled).
    Category    : Retention & records management
    Changes     : No
    Notes       : Search-UnifiedAuditLog is an Exchange Online cmdlet, so an Exchange Online session is opened; the label
                  lookup additionally opens a Security & Compliance session. A ReturnLargeSet session returns at most
                  50,000 records - narrow -DaysBack when the warning appears. Labels applied by a library default label
                  or by auto-apply policies may appear with the policy rule GUID as UserId, and default-label assignments
                  are not always audited. CreationTime is UTC. Audit (Premium) extends retention up to 10 years.
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/search-unifiedauditlog
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
    [ValidateNotNullOrEmpty()]
    [string[]]$Operations = @('TagApplied', 'TagRemoved', 'TagUpdated', 'RecordDeclared'),

    [Parameter()]
    [switch]$SkipLabelResolve,

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

function Write-TopValue {
    <# Prints the most frequent values of one property as an indented "value : count" list. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory = $true)][string]$Property,
        [Parameter()][int]$Top = 5
    )
    Write-Host ('  {0}' -f $Title) -ForegroundColor Cyan
    $groups = @($Rows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.$Property) } |
            Group-Object -Property $Property | Sort-Object -Property Count -Descending | Select-Object -First $Top)
    if ($groups.Count -eq 0) { Write-Host '    (none)' -ForegroundColor Gray }
    foreach ($group in $groups) { Write-Host ('    {0,-60} : {1}' -f $group.Name, $group.Count) }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewRetentionLabelAudit_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

# Label GUID -> name and the set of record labels, used to decode audit records and to flag record removals.
$labelNameByGuid = @{}
$recordLabels = New-Object -TypeName System.Collections.Generic.List[string]
if (-not $SkipLabelResolve) {
    try {
        Connect-ExchangeIfNeeded -Compliance
        foreach ($label in @(Get-ComplianceTag -ErrorAction Stop)) {
            $labelNameByGuid[[string]$label.Guid] = [string]$label.Name
            if ([bool]$label.IsRecordLabel) { $recordLabels.Add([string]$label.Name) }
        }
    }
    catch { Write-Warning "Label lookup skipped - could not read retention labels: $($_.Exception.Message)" }
}

$startDate = (Get-Date).AddDays(-$DaysBack)
$endDate = Get-Date
$sessionId = [guid]::NewGuid().ToString()
$records = @{}
$expected = 0
Write-Verbose ("Searching audit log from {0:u} to {1:u} for operations: {2}" -f $startDate, $endDate, ($Operations -join ', '))
do {
    try {
        $page = @(Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations $Operations -SessionId $sessionId -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop)
    }
    catch { throw "Search-UnifiedAuditLog failed: $($_.Exception.Message)" }
    foreach ($record in $page) { $records[[string]$record.Identity] = $record }
    if ($page.Count -gt 0 -and $expected -eq 0) { $expected = [int]$page[0].ResultCount }
    $percent = [math]::Min(100, [int](100 * $records.Count / [math]::Max(1, $expected)))
    Write-Progress -Activity 'Searching the unified audit log' -Status ('{0} of {1} records' -f $records.Count, $expected) -PercentComplete $percent
} while ($page.Count -gt 0 -and $records.Count -lt $expected)
Write-Progress -Activity 'Searching the unified audit log' -Completed
if ($expected -ge 50000) { Write-Warning 'The search hit the 50,000 record limit of a ReturnLargeSet session; reduce -DaysBack for complete results.' }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records.Values) {
    try { $data = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch {
        Write-Warning "Could not parse AuditData for record $($record.Identity): $($_.Exception.Message)"
        continue
    }
    $labels = @{}
    foreach ($field in 'DestinationLabel', 'SourceLabel') {
        $value = [string]$data.$field
        if ($value -match '^[0-9a-fA-F-]{36}$' -and $labelNameByGuid.ContainsKey($value)) { $value = $labelNameByGuid[$value] }
        $labels[$field] = $value
    }
    $userId = [string]$data.UserId
    if ([string]::IsNullOrWhiteSpace($userId)) { $userId = [string]$record.UserIds }
    $rows.Add([PSCustomObject]@{
            CreationTime           = [datetime]$record.CreationDate
            Operation              = [string]$record.Operations
            UserId                 = $userId
            Workload               = [string]$data.Workload
            SiteUrl                = [string]$data.SiteUrl
            SourceFileName         = [string]$data.SourceFileName
            ObjectId               = [string]$data.ObjectId
            DestinationLabel       = $labels['DestinationLabel']
            SourceLabel            = $labels['SourceLabel']
            IsRecordLabelRemoval   = ([string]$record.Operations -eq 'TagRemoved' -and $recordLabels.Contains($labels['SourceLabel']))
            ClientIP               = [string]$data.ClientIP
            ApplicationDisplayName = [string]$data.ApplicationDisplayName
            RecordType             = [string]$record.RecordType
        })
}
$rows = @($rows | Sort-Object -Property CreationTime -Descending)

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

$recordRemovals = @($rows | Where-Object { $_.IsRecordLabelRemoval }).Count
Write-Host "`nRetention label audit summary (last $DaysBack days)" -ForegroundColor Cyan
Write-Host ('  Records exported : {0}' -f $rows.Count)
Write-TopValue -Title 'By operation' -Rows $rows -Property 'Operation' -Top 10
Write-TopValue -Title 'Top labels applied (DestinationLabel)' -Rows @($rows | Where-Object { $_.Operation -ne 'TagRemoved' }) -Property 'DestinationLabel'
Write-TopValue -Title 'Top users' -Rows $rows -Property 'UserId'
Write-TopValue -Title 'Top sites' -Rows $rows -Property 'SiteUrl'
Write-Host ('  Record label removals : {0}' -f $recordRemovals) -ForegroundColor $(if ($recordRemovals -gt 0) { 'Red' } else { 'Green' })
Write-Host ('  Report : {0}' -f $OutputPath)

if ($PassThru) {
    $rows
}
#endregion Main
