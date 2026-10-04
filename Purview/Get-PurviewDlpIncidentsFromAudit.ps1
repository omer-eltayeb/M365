<#
.SYNOPSIS
    Reports Purview DLP rule matches from the unified audit log for Exchange, SharePoint/OneDrive and endpoint devices.
.DESCRIPTION
    Connects to Exchange Online and pages through Search-UnifiedAuditLog (SessionCommand ReturnLargeSet) for the
    ComplianceDLPExchange, ComplianceDLPSharePoint and ComplianceDLPEndpoint record types, de-duplicates records by
    Identity and parses the AuditData JSON. Every matched rule becomes one row: policy, rule, actions, severity, the
    matched sensitive information types (name, count, confidence) and the item (subject/sender/recipients, file/site/
    owner or device/application/extension/enforcement mode). Writes a CSV and prints summaries by policy and rule,
    sensitive information type, user, workload and severity. The script is read-only.
.PARAMETER DaysBack
    Days to look back, 1-180 (default 7). Audit (Standard) keeps 180 days of records.
.PARAMETER Workloads
    One or more of Exchange, SharePoint, Endpoint (default: all three). SharePoint also covers OneDrive.
.PARAMETER IncludeAll
    Also include DlpRuleUndo (user override / false positive) and DlpInfo events, not only DlpRuleMatch.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewDlpIncidents_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewDlpIncidentsFromAudit.ps1
    Exports all DLP rule matches of the last 7 days for every workload and prints the summaries.
.EXAMPLE
    PS> .\Get-PurviewDlpIncidentsFromAudit.ps1 -DaysBack 30 -Workloads Endpoint -IncludeAll -Verbose
    Exports 30 days of Endpoint DLP matches, user overrides and false-positive reports.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Exchange Online); unified audit logging must be enabled
    Category    : Data loss prevention
    Changes     : No
    Notes       : Search-UnifiedAuditLog is an Exchange Online cmdlet, so an Exchange Online session is used, not a Security
                  & Compliance one. -RecordType takes one value, so each record type gets its own session; a session returns
                  at most 50,000 records (use a smaller -DaysBack if warned). Events arrive 60-90 minutes after the activity.
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
    [ValidateSet('Exchange', 'SharePoint', 'Endpoint')]
    [string[]]$Workloads = @('Exchange', 'SharePoint', 'Endpoint'),

    [Parameter()]
    [switch]$IncludeAll,

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

function ConvertTo-SitText {
    <# Formats the matched sensitive information types of one rule as "Name (xCount, Confidence%)". #>
    param([Parameter()][AllowNull()]$Rule)
    $parts = New-Object -TypeName System.Collections.Generic.List[string]
    if ($null -eq $Rule -or $null -eq $Rule.ConditionsMatched) { return '' }
    foreach ($sit in @($Rule.ConditionsMatched.SensitiveInformation)) {
        if ($null -ne $sit) { $parts.Add(('{0} (x{1}, {2}%)' -f $sit.SensitiveInformationTypeName, $sit.Count, $sit.Confidence)) }
    }
    return ($parts -join '; ')
}

function Get-DlpObjectText {
    <# Describes the matched item from whichever workload metadata block the record carries. #>
    param([Parameter(Mandatory = $true)]$Audit)
    $mail = $Audit.ExchangeMetaData
    if ($null -ne $mail) { return ('Subject: {0} | From: {1} | Recipients: {2}' -f $mail.Subject, $mail.From, $mail.RecipientCount) }
    $file = $Audit.SharePointMetaData
    if ($null -ne $file) { return ('File: {0} | Site: {1} | Owner: {2}' -f $file.FileName, $file.SiteCollectionUrl, $file.FileOwner) }
    $device = $Audit.EndpointMetaData
    if ($null -ne $device) {
        # EnforcementMode is numeric in the audit schema; these are the documented values.
        $modes = @{ '0' = 'None'; '1' = 'Audit'; '2' = 'Warn'; '3' = 'WarnAndBypass'; '4' = 'Block'; '5' = 'Allow' }
        $mode = [string]$device.EnforcementMode
        if ($modes.ContainsKey($mode)) { $mode = $modes[$mode] }
        return ('Device: {0} | App: {1} | Ext: {2} | Enforcement: {3}' -f $device.DeviceName, $device.Application, $device.FileExtension, $mode)
    }
    return [string]$Audit.ObjectId
}
#endregion Helpers

#region Main
$startDate = (Get-Date).AddDays(-$DaysBack)
$endDate = Get-Date
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewDlpIncidents_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$recordTypes = @{ Exchange = 'ComplianceDLPExchange'; SharePoint = 'ComplianceDLPSharePoint'; Endpoint = 'ComplianceDLPEndpoint' }
$operations = @('DlpRuleMatch') + $(if ($IncludeAll) { @('DlpRuleUndo', 'DlpInfo') } else { @() })
$records = New-Object -TypeName System.Collections.Generic.List[object]
$seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
foreach ($workload in $Workloads) {
    # -RecordType accepts one value, so each record type gets its own ReturnLargeSet session; page until the service returns nothing.
    $searchParams = @{
        StartDate = $startDate; EndDate = $endDate; RecordType = $recordTypes[$workload]; Operations = $operations
        SessionId = [guid]::NewGuid().ToString(); SessionCommand = 'ReturnLargeSet'; ResultSize = 5000; ErrorAction = 'Stop'
    }
    $page = 0
    do {
        $page++
        Write-Progress -Activity 'Searching the unified audit log' -Status ('{0}: page {1} ({2} records so far)' -f $searchParams.RecordType, $page, $records.Count)
        try { $batch = @(Search-UnifiedAuditLog @searchParams) }
        catch { Write-Warning ('{0}: page {1} failed: {2}' -f $searchParams.RecordType, $page, $_.Exception.Message); $batch = @() }
        if ($page -eq 1 -and $batch.Count -gt 0 -and [int]$batch[0].ResultCount -ge 50000) {
            Write-Warning ('{0}: more than 50,000 records match; a session cannot return them all. Use a smaller -DaysBack.' -f $searchParams.RecordType)
        }
        foreach ($entry in $batch) { if ($seen.Add([string]$entry.Identity)) { $records.Add($entry) } }
    } while ($batch.Count -gt 0 -and $page -lt 10)
}
Write-Progress -Activity 'Searching the unified audit log' -Completed

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "Could not parse AuditData for record $($record.Identity): $($_.Exception.Message)"; continue }
    $objectText = Get-DlpObjectText -Audit $audit
    # One row per matched rule; DlpInfo and DlpRuleUndo records may carry no rule details, so keep those as a single row.
    $matches = @(foreach ($policy in @($audit.PolicyDetails)) { foreach ($rule in @($policy.Rules)) { if ($null -ne $rule) { @{ Policy = $policy; Rule = $rule } } } })
    if ($matches.Count -eq 0) { $matches = @(@{ Policy = $null; Rule = $null }) }
    foreach ($match in $matches) {
        $results.Add([PSCustomObject]@{
                CreationTime       = [datetime]$record.CreationDate
                Workload           = [string]$audit.Workload
                Operation          = [string]$audit.Operation
                UserId             = [string]$audit.UserId
                PolicyName         = [string]$match.Policy.PolicyName
                RuleName           = [string]$match.Rule.RuleName
                Actions            = (@($match.Rule.Actions) -join ';')
                Severity           = [string]$match.Rule.Severity
                SensitiveInfoTypes = ConvertTo-SitText -Rule $match.Rule
                Object             = $objectText
                ClientIP           = [string]$audit.ClientIP
                RecordId           = [string]$audit.Id
            })
    }
}
$results = @($results | Sort-Object -Property CreationTime)

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No DLP audit records were found for the selected window, workloads and operations.' }

# One row per matched sensitive information type (count/confidence suffix removed) for the SIT summary.
$sitRows = @(foreach ($row in $results) { foreach ($sit in ($row.SensitiveInfoTypes -split '; ')) { if ($sit) { [PSCustomObject]@{ Sit = ($sit -replace ' \(x\d*, \d*%\)$', '') } } } })

Write-Host 'Purview DLP incidents summary' -ForegroundColor Cyan
Write-Host ('  Window  : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm}, workloads: {2}' -f $startDate, $endDate, ($Workloads -join ', '))
Write-Host ('  Records : {0} audit records, {1} rule-match rows' -f $records.Count, $results.Count)
if ($results.Count -gt 0) {
    $summaries = @(
        @{ Title = 'By policy / rule'; Rows = $results; Property = @('PolicyName', 'RuleName') },
        @{ Title = 'Top sensitive information types'; Rows = $sitRows; Property = @('Sit') },
        @{ Title = 'Top users'; Rows = $results; Property = @('UserId') },
        @{ Title = 'By workload'; Rows = $results; Property = @('Workload') },
        @{ Title = 'By severity'; Rows = $results; Property = @('Severity') }
    )
    foreach ($summary in $summaries) {
        Write-Host ('  {0}:' -f $summary.Title)
        foreach ($group in ($summary.Rows | Group-Object -Property $summary.Property | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
            Write-Host ('    {0,7}  {1}' -f $group.Count, $(if ([string]::IsNullOrWhiteSpace($group.Name)) { '(none)' } else { $group.Name }))
        }
    }
    Write-Host ('  Report  : {0}' -f $OutputPath)
}

if ($PassThru) { $results }
#endregion Main
