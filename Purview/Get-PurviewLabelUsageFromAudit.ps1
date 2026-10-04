<#
.SYNOPSIS
    Reports sensitivity label activity (applied, changed, removed) from the unified audit log.
.DESCRIPTION
    Searches the unified audit log (Search-UnifiedAuditLog, Exchange Online session) for the sensitivity label
    operations raised by Office apps, Outlook, SharePoint, OneDrive and the Purview Information Protection client,
    pages through the result set with ReturnLargeSet, de-duplicates by Identity and parses the AuditData JSON into
    flat columns: label and previous label (GUIDs resolved via Get-Label), action source (manual, automatic, recommended,
    default), label event type (upgrade, downgrade, removal), justification, client IP and application. Writes a CSV
    and prints summaries by label, operation, action source, top users and downgrades.
.PARAMETER DaysBack
    Number of days to search back from now, 1-180 (default 30). Audit (Standard) retains 180 days.
.PARAMETER SkipLabelResolve
    Do not open a Security & Compliance session to resolve label GUIDs to display names (GUIDs are kept as-is).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewLabelUsage_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the flattened event objects to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewLabelUsageFromAudit.ps1
    Exports the last 30 days of sensitivity label events for the whole tenant and prints the summaries.
.EXAMPLE
    PS> .\Get-PurviewLabelUsageFromAudit.ps1 -DaysBack 90 -SkipLabelResolve -PassThru | Where-Object { $_.LabelEventType -eq 'LabelDowngraded' }
    Exports 90 days of label activity without resolving label names and lists every downgrade (with the user's justification) on the pipeline.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Exchange Online); Compliance Administrator, Information Protection Admin or Global Reader for label resolution
    Category    : Information protection
    Changes     : No
    Notes       : Search-UnifiedAuditLog is an Exchange Online cmdlet; label names come from a second, Security & Compliance
                  session unless -SkipLabelResolve is used. One ReturnLargeSet session returns at most 50,000 records; the script
                  warns when the window holds more (reduce -DaysBack or slice the window with Search-PurviewAuditLog.ps1). UTC dates.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/search-unifiedauditlog
.LINK
    https://learn.microsoft.com/office/office-365-management-api/office-365-management-activity-api-schema
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 30,

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

function Get-AuditField {
    <# Returns the first non-empty value of the given property names across the given objects; workloads nest and name the same field differently. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Objects,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )
    foreach ($object in $Objects) {
        if ($null -eq $object) { continue }
        foreach ($name in $Names) {
            $property = $object.PSObject.Properties[$name]
            if ($null -ne $property -and -not [string]::IsNullOrEmpty([string]$property.Value)) { return $property.Value }
        }
    }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewLabelUsage_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$labelNames = @{}
if (-not $SkipLabelResolve) {
    try {
        Connect-ExchangeIfNeeded -Compliance
        foreach ($label in @(Get-Label -ErrorAction Stop)) {
            foreach ($key in @($label.Guid, $label.ImmutableId)) { if ($null -ne $key) { $labelNames[([string]$key).ToLowerInvariant()] = [string]$label.DisplayName } }
        }
    }
    catch { Write-Warning "Label names could not be resolved, GUIDs are kept: $($_.Exception.Message)" }
}

$endDate = Get-Date
$startDate = $endDate.AddDays(-$DaysBack)
$operations = 'SensitivityLabelApplied', 'SensitivityLabelUpdated', 'SensitivityLabelRemoved', 'FileSensitivityLabelApplied',
'FileSensitivityLabelChanged', 'FileSensitivityLabelRemoved', 'SiteSensitivityLabelApplied'
$searchParams = @{
    StartDate = $startDate; EndDate = $endDate; Operations = $operations; ResultSize = 5000; ErrorAction = 'Stop'
    SessionId = [guid]::NewGuid().ToString(); SessionCommand = 'ReturnLargeSet'
}
$records = New-Object -TypeName System.Collections.Generic.List[object]
$seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
$page = 0
do {
    $page++
    Write-Progress -Activity 'Searching the unified audit log for sensitivity label events' -Status ('Page {0}: {1} records so far' -f $page, $records.Count)
    try { $batch = @(Search-UnifiedAuditLog @searchParams) }
    catch { throw "Search-UnifiedAuditLog failed on page ${page}: $($_.Exception.Message)" }
    if ($page -eq 1 -and $batch.Count -gt 0 -and [int]$batch[0].ResultCount -ge 50000) {
        Write-Warning 'The window holds 50,000 or more records, the most one ReturnLargeSet session can return. Reduce -DaysBack to capture everything.'
    }
    foreach ($entry in $batch) { if ($seen.Add([string]$entry.Identity)) { $records.Add($entry) } }
} while ($batch.Count -gt 0)
Write-Progress -Activity 'Searching the unified audit log for sensitivity label events' -Completed

# SensitivityLabelEventData enums as documented in the Office 365 Management Activity API schema.
$actionSources = @{ '0' = 'None'; '1' = 'Default'; '2' = 'Auto'; '3' = 'Manual'; '4' = 'Recommended' }
$eventTypes = @{ '1' = 'LabelUpgraded'; '2' = 'LabelDowngraded'; '3' = 'LabelRemoved'; '4' = 'LabelChangedSameOrder' }
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    $audit = $null
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Verbose "Could not parse AuditData for record $($record.Identity): $($_.Exception.Message)" }
    # Office and SharePoint events nest the label details in SensitivityLabelEventData; others keep them at the top level.
    $sources = @((Get-AuditField -Objects $audit -Names 'SensitivityLabelEventData'), $audit)
    $labelId = [string](Get-AuditField -Objects $sources -Names 'SensitivityLabelId')
    $oldLabelId = [string](Get-AuditField -Objects $sources -Names 'OldSensitivityLabelId')
    $actionSource = [string](Get-AuditField -Objects $sources -Names 'ActionSource')
    if ($actionSources.ContainsKey($actionSource)) { $actionSource = $actionSources[$actionSource] }
    $eventType = [string](Get-AuditField -Objects $sources -Names 'LabelEventType')
    if ($eventTypes.ContainsKey($eventType)) { $eventType = $eventTypes[$eventType] }

    $results.Add([PSCustomObject]@{
            CreationTime          = [datetime]$record.CreationDate
            Operation             = [string]$record.Operations
            UserId                = [string](Get-AuditField -Objects $audit, $record -Names 'UserId', 'UserIds')
            Workload              = [string](Get-AuditField -Objects $audit -Names 'Workload')
            ObjectId              = [string](Get-AuditField -Objects $audit -Names 'ObjectId')
            Label                 = $(if ($labelNames.ContainsKey($labelId.ToLowerInvariant())) { $labelNames[$labelId.ToLowerInvariant()] } else { $labelId })
            SensitivityLabelId    = $labelId
            OldLabel              = $(if ($labelNames.ContainsKey($oldLabelId.ToLowerInvariant())) { $labelNames[$oldLabelId.ToLowerInvariant()] } else { $oldLabelId })
            OldSensitivityLabelId = $oldLabelId
            ActionSource          = $actionSource
            LabelEventType        = $eventType
            JustificationText     = [string](Get-AuditField -Objects $sources -Names 'JustificationText')
            ClientIP              = [string](Get-AuditField -Objects $audit -Names 'ClientIP', 'ClientIPAddress')
            Application           = [string](Get-AuditField -Objects $audit -Names 'Application', 'ApplicationDisplayName', 'ClientInfoString')
            RecordType            = [string]$record.RecordType
        })
}
$results = @($results | Sort-Object -Property CreationTime)

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No sensitivity label events were found in the selected window.' }

$downgrades = @($results | Where-Object { $_.LabelEventType -eq 'LabelDowngraded' }).Count
$removals = @($results | Where-Object { $_.Operation -like '*Removed' }).Count
Write-Host ''
Write-Host 'Sensitivity label usage summary' -ForegroundColor Cyan
Write-Host ('  Window           : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} ({2} days)' -f $startDate, $endDate, $DaysBack)
Write-Host ('  Events           : {0}' -f $results.Count)
Write-Host ('  Downgrades       : {0} (plus {1} label removals)' -f $downgrades, $removals) -ForegroundColor $(if ($downgrades -gt 0) { 'Yellow' } else { 'Gray' })
if ($results.Count -gt 0) {
    foreach ($summary in @(@('By label        ', 'Label'), @('By operation    ', 'Operation'), @('By action source', 'ActionSource'), @('Top users       ', 'UserId'))) {
        Write-Host ('  {0}:' -f $summary[0])
        foreach ($group in ($results | Group-Object -Property $summary[1] | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
            Write-Host ('    {0,7}  {1}' -f $group.Count, $(if ([string]::IsNullOrWhiteSpace($group.Name)) { '(not recorded)' } else { $group.Name }))
        }
    }
    Write-Host ('  Report           : {0}' -f $OutputPath)
}

if ($PassThru) {
    $results
}
#endregion Main
