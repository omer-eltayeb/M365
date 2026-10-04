<#
.SYNOPSIS
    Reports DLP policy-tip overrides and false-positive reports from the unified audit log and highlights rules that need tuning.
.DESCRIPTION
    Connects to Exchange Online and pages through Search-UnifiedAuditLog (ReturnLargeSet) for the ComplianceDLPExchange,
    ComplianceDLPSharePoint and ComplianceDLPEndpoint record types with the DlpRuleMatch and DlpRuleUndo operations.
    DlpRuleUndo records (SharePoint/OneDrive) carry ExceptionInfo.Reason - Override, FalsePositive or DocumentChange - and
    the user's justification; Exchange records carry the same flags inside DlpRuleMatch, and endpoint overrides appear as
    EnforcementMode WarnAndBypass with a justification. One row is written per overridden rule, the DlpRuleMatch counts give
    the override rate per rule, and rules above the thresholds are listed as tuning candidates. Read-only.
.PARAMETER DaysBack
    Days to look back, 1-180 (default 30).
.PARAMETER Workloads
    One or more of Exchange, SharePoint, Endpoint (default: all three). SharePoint also covers OneDrive.
.PARAMETER MinMatches
    Minimum number of rule matches before a rule can become a tuning candidate (default 5).
.PARAMETER OverrideRateThreshold
    Override + false-positive share (percent of matches) from which a rule is a tuning candidate (default 20).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewDlpOverrides_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewDlpOverridesAndFalsePositives.ps1
    Reports 30 days of overrides and false-positive reports across all workloads and lists tuning candidates.
.EXAMPLE
    PS> .\Get-PurviewDlpOverridesAndFalsePositives.ps1 -DaysBack 90 -Workloads Exchange -MinMatches 20 -OverrideRateThreshold 10 -Verbose
    Reviews a quarter of Exchange DLP activity with stricter tuning thresholds.
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
    Notes       : Search-UnifiedAuditLog is an Exchange Online cmdlet, so an Exchange Online session is used, not a Security &
                  Compliance one. A session returns at most 50,000 records per record type - reduce -DaysBack if a warning appears.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/search-unifiedauditlog
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 30,

    [Parameter()]
    [ValidateSet('Exchange', 'SharePoint', 'Endpoint')]
    [string[]]$Workloads = @('Exchange', 'SharePoint', 'Endpoint'),

    [Parameter()]
    [int]$MinMatches = 5,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$OverrideRateThreshold = 20,

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

function Get-OverrideInfo {
    <# Returns @{ Type; Justification } when the record is an override, false-positive report or document change; $null otherwise. #>
    param([Parameter(Mandatory = $true)]$Audit)
    $exception = $Audit.ExceptionInfo
    $endpoint = $Audit.EndpointMetaData
    if ($Audit.Operation -eq 'DlpRuleUndo') { return @{ Type = $(if ($exception.Reason) { [string]$exception.Reason } else { 'Undo' }); Justification = [string]$exception.Justification } }
    if ($exception.FalsePositive -eq $true) { return @{ Type = 'FalsePositive'; Justification = [string]$exception.Justification } }
    if ($exception.Override -eq $true) { return @{ Type = 'Override'; Justification = [string]$exception.Justification } }
    # Endpoint: clicking through a "block with override" warning is logged as EnforcementMode 3 (WarnAndBypass) plus the justification.
    if ($null -ne $endpoint -and ([string]$endpoint.EnforcementMode -eq '3' -or [string]$endpoint.Justification)) {
        return @{ Type = 'Override'; Justification = [string]$endpoint.Justification }
    }
    return $null
}

function Get-DlpObjectText {
    <# Describes the matched item from whichever workload metadata block the record carries. #>
    param([Parameter(Mandatory = $true)]$Audit)
    if ($null -ne $Audit.ExchangeMetaData) { return ('Subject: {0} | From: {1}' -f $Audit.ExchangeMetaData.Subject, $Audit.ExchangeMetaData.From) }
    if ($null -ne $Audit.SharePointMetaData) { return ('File: {0} | Site: {1}' -f $Audit.SharePointMetaData.FileName, $Audit.SharePointMetaData.SiteCollectionUrl) }
    if ($null -ne $Audit.EndpointMetaData) { return ('Device: {0} | App: {1}' -f $Audit.EndpointMetaData.DeviceName, $Audit.EndpointMetaData.Application) }
    return [string]$Audit.ObjectId
}
#endregion Helpers

#region Main
$startDate = (Get-Date).AddDays(-$DaysBack)
$endDate = Get-Date
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewDlpOverrides_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$recordTypes = @{ Exchange = 'ComplianceDLPExchange'; SharePoint = 'ComplianceDLPSharePoint'; Endpoint = 'ComplianceDLPEndpoint' }
$records = New-Object -TypeName System.Collections.Generic.List[object]
$seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
foreach ($workload in $Workloads) {
    # -RecordType accepts one value, so each record type gets its own ReturnLargeSet session; page until the service returns nothing.
    $searchParams = @{
        StartDate = $startDate; EndDate = $endDate; RecordType = $recordTypes[$workload]; Operations = @('DlpRuleUndo', 'DlpRuleMatch')
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
# Per "Policy / Rule": how often it matched and how often users overrode it or reported a false positive.
$ruleStats = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "Could not parse AuditData for record $($record.Identity): $($_.Exception.Message)"; continue }
    $override = Get-OverrideInfo -Audit $audit
    $objectText = Get-DlpObjectText -Audit $audit
    foreach ($policy in @($audit.PolicyDetails)) {
        foreach ($rule in @($policy.Rules)) {
            if ($null -eq $rule) { continue }
            $key = '{0} / {1}' -f $policy.PolicyName, $rule.RuleName
            if (-not $ruleStats.ContainsKey($key)) { $ruleStats[$key] = @{ Matches = 0; Overrides = 0 } }
            if ($audit.Operation -eq 'DlpRuleMatch') { $ruleStats[$key].Matches++ }
            if ($null -eq $override) { continue }
            if ($override.Type -in 'Override', 'FalsePositive') { $ruleStats[$key].Overrides++ }
            $justification = [string]$override.Justification
            if ($justification.Length -gt 300) { $justification = $justification.Substring(0, 297) + '...' }
            $results.Add([PSCustomObject]@{
                    CreationTime  = [datetime]$record.CreationDate
                    Workload      = [string]$audit.Workload
                    UserId        = [string]$audit.UserId
                    PolicyName    = [string]$policy.PolicyName
                    RuleName      = [string]$rule.RuleName
                    OverrideType  = [string]$override.Type
                    Justification = $justification
                    Object        = $objectText
                    SITs          = (@($rule.ConditionsMatched.SensitiveInformation | ForEach-Object { $_.SensitiveInformationTypeName }) -join '; ')
                })
        }
    }
}
$results = @($results | Sort-Object -Property CreationTime)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No DLP overrides or false-positive reports were found for the selected window and workloads.' }

# Override rate per rule, highest first; rules below -MinMatches matches are kept in the list but cannot become candidates.
$rates = @(foreach ($key in $ruleStats.Keys) {
        $stat = $ruleStats[$key]
        [PSCustomObject]@{ Rule = $key; Matches = $stat.Matches; Overrides = $stat.Overrides; RatePercent = [math]::Round(100 * $stat.Overrides / [math]::Max(1, $stat.Matches), 1) }
    }) | Sort-Object -Property RatePercent, Overrides -Descending
$candidates = @($rates | Where-Object { $_.Matches -ge $MinMatches -and $_.RatePercent -ge $OverrideRateThreshold })

Write-Host 'Purview DLP override and false-positive summary' -ForegroundColor Cyan
Write-Host ('  Window          : {0:yyyy-MM-dd} to {1:yyyy-MM-dd}, workloads: {2}' -f $startDate, $endDate, ($Workloads -join ', '))
Write-Host ('  Audit records   : {0} ({1} rules matched)' -f $records.Count, $ruleStats.Count)
Write-Host ('  Override rows   : {0} ({1})' -f $results.Count, (@($results | Group-Object -Property OverrideType | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }) -join ', '))
Write-Host '  Override rate per rule (top 10):'
foreach ($rate in ($rates | Where-Object { $_.Overrides -gt 0 } | Select-Object -First 10)) {
    Write-Host ('    {0,6}%  {1,5} of {2,-5} {3}' -f $rate.RatePercent, $rate.Overrides, $rate.Matches, $rate.Rule)
}
Write-Host '  Top overriding users:'
foreach ($group in ($results | Group-Object -Property UserId | Sort-Object -Property Count -Descending | Select-Object -First 10)) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
Write-Host ('  Tuning candidates (>= {0} matches and >= {1}% overridden): {2}' -f $MinMatches, $OverrideRateThreshold, $candidates.Count) -ForegroundColor Yellow
foreach ($candidate in $candidates) { Write-Host ('    {0} - {1}% of {2} matches overridden' -f $candidate.Rule, $candidate.RatePercent, $candidate.Matches) -ForegroundColor Yellow }
Write-Host ('  Report          : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
