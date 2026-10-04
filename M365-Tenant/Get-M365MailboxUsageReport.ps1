<#
.SYNOPSIS
    Reports Exchange Online mailbox sizes, quotas and archive adoption from the Graph usage reports (no Exchange module needed).
.DESCRIPTION
    Downloads the mailbox usage detail report (/reports/getMailboxUsageDetail) for the selected period and outputs one row
    per mailbox with the storage used, the prohibit-send quota and the percentage of it in use, a NearQuota flag, deleted-item
    size, archive status, recipient type and days since the last activity. -IncludeQuotaStatus adds the daily mailbox counts
    per quota state (/reports/getMailboxUsageQuotaStatusMailboxCounts) as <OutputPath base>_QuotaStatus.csv.
.PARAMETER Period
    Report period: D7, D30, D90 or D180 (days). Default D30.
.PARAMETER ThresholdPercent
    Percentage of the prohibit-send quota at which a mailbox is flagged NearQuota. Default 80.
.PARAMETER RecipientType
    Export only mailboxes of this recipient type, for example UserMailbox or SharedMailbox (spaces and case are ignored).
.PARAMETER IncludeQuotaStatus
    Also export the daily number of mailboxes under limit, warned, send-prohibited and send/receive-prohibited.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365MailboxUsage_<Period>_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the mailbox objects (and, with -IncludeQuotaStatus, the daily quota objects) to the pipeline.
.EXAMPLE
    PS> .\Get-M365MailboxUsageReport.ps1
    Exports every mailbox with size and quota figures and prints how many are at 80 % or more of their send quota.
.EXAMPLE
    PS> .\Get-M365MailboxUsageReport.ps1 -RecipientType SharedMailbox -ThresholdPercent 90 -IncludeQuotaStatus -OutputPath C:\Temp\Shared.csv
    Exports only shared mailboxes, flags those at 90 % or more and writes the daily quota status next to the CSV.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Reports.Read.All (delegated); Reports Reader or Global Reader role
    Category    : Usage & adoption reports
    Changes     : No
    Notes       : Graph-based alternative to Get-EXOMailboxSizeReport.ps1 in the ExchangeOnline folder; data lags about 48 hours.
                  Not every tenant's report has the Recipient Type column (the script warns when it is missing). Names and UPNs
                  appear as hashes when "Display concealed user, group, and site names in all reports" is on (admin center > Org settings > Reports).
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getmailboxusagedetail
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period = 'D30',

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$ThresholdPercent = 80,

    [Parameter()]
    [string]$RecipientType,

    [Parameter()]
    [switch]$IncludeQuotaStatus,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-GraphIfNeeded {
    <# Connects to Microsoft Graph only when there is no usable session for the required scopes. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )
    $context = Get-MgContext
    $missingScopes = @()
    if ($null -ne $context) {
        $missingScopes = @($Scopes | Where-Object { $context.Scopes -notcontains $_ })
    }
    if ($null -eq $context -or $missingScopes.Count -gt 0) {
        Write-Verbose "Connecting to Microsoft Graph with scopes: $($Scopes -join ', ')"
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
    }
    else {
        Write-Verbose "Reusing existing Microsoft Graph session for $($context.Account)."
    }
}

function Get-UsageReportCsv {
    <# Downloads a Microsoft Graph usage report (CSV) and imports it. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportFunction,

        [Parameter(Mandatory = $true)]
        [string]$Period
    )
    $uri = 'https://graph.microsoft.com/v1.0/reports/{0}(period=''{1}'')' -f $ReportFunction, $Period
    $tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('{0}_{1}.csv' -f $ReportFunction, [guid]::NewGuid())
    try {
        Invoke-MgGraphRequest -Method GET -Uri $uri -OutputFilePath $tempCsv -ErrorAction Stop
        return @(Import-Csv -Path $tempCsv)
    }
    finally {
        if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue }
    }
}

function ConvertTo-ReportObject {
    <# Converts a raw report row to PascalCase properties; empty cells become $null, True/False/Yes/No [bool], whole numbers [int64] (not in Name/Id columns), "...Date" columns [datetime]. #>
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Row
    )
    $props = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        $name = $property.Name -replace '[^A-Za-z0-9]', ''
        [string]$text = $property.Value
        $number = [int64]0; $date = [datetime]::MinValue
        if ([string]::IsNullOrEmpty($text)) { $props[$name] = $null }
        elseif ($text -in @('True', 'False', 'Yes', 'No')) { $props[$name] = ($text -eq 'True' -or $text -eq 'Yes') }
        elseif ($property.Name -notmatch 'Name$|Id$' -and [int64]::TryParse($text, [ref]$number)) { $props[$name] = $number }
        elseif ($property.Name -like '*Date*' -and [datetime]::TryParse($text, [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date)) { $props[$name] = $date }
        else { $props[$name] = $text }
    }
    return [PSCustomObject]$props
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365MailboxUsage_{0}_{1}.csv' -f $Period, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$quotaOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_QuotaStatus.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

$quotaReport = @()
try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All')
    Write-Verbose "Downloading getMailboxUsageDetail for period $Period."
    $report = @(Get-UsageReportCsv -ReportFunction 'getMailboxUsageDetail' -Period $Period)
    if ($IncludeQuotaStatus) { $quotaReport = @(Get-UsageReportCsv -ReportFunction 'getMailboxUsageQuotaStatusMailboxCounts' -Period $Period) }
}
catch {
    throw "Failed to retrieve the mailbox usage reports from Microsoft Graph: $($_.Exception.Message)"
}
if ($report.Count -gt 0 -and $null -eq $report[0].PSObject.Properties['Recipient Type']) {
    Write-Warning 'The report has no "Recipient Type" column in this tenant; RecipientType stays empty and -RecipientType cannot filter.'
}

$today = [datetime]::UtcNow.Date
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($row in $report) {
    $counter++
    if ($counter % 250 -eq 0) { Write-Progress -Activity 'Shaping mailboxes' -Status "$counter of $($report.Count)" -PercentComplete ([int](($counter / $report.Count) * 100)) }
    $r = ConvertTo-ReportObject -Row $row
    $daysSince = $null; if ($null -ne $r.LastActivityDate) { $daysSince = [int](($today - $r.LastActivityDate).TotalDays) }
    $sendQuota = [int64]$r.ProhibitSendQuotaByte
    $percentOfQuota = $null; if ($sendQuota -gt 0) { $percentOfQuota = [math]::Round(([int64]$r.StorageUsedByte / $sendQuota) * 100, 1) }
    $rows.Add([PSCustomObject]@{
            DisplayName           = $r.DisplayName
            UserPrincipalName     = $r.UserPrincipalName
            RecipientType         = $r.RecipientType
            IsDeleted             = [bool]$r.IsDeleted
            LastActivityDate      = $r.LastActivityDate
            DaysSinceLastActivity = $daysSince
            ItemCount             = [int64]$r.ItemCount
            StorageUsedGB         = [math]::Round([int64]$r.StorageUsedByte / 1GB, 2)
            QuotaGB               = [math]::Round($sendQuota / 1GB, 2)
            PercentOfQuota        = $percentOfQuota
            NearQuota             = ($null -ne $percentOfQuota -and $percentOfQuota -ge $ThresholdPercent)
            DeletedItemsGB        = [math]::Round([int64]$r.DeletedItemSizeByte / 1GB, 2)
            HasArchive            = [bool]$r.HasArchive
            ReportRefreshDate     = $r.ReportRefreshDate
        })
}
Write-Progress -Activity 'Shaping mailboxes' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'StorageUsedGB'; Descending = $true }, DisplayName)
if (-not [string]::IsNullOrWhiteSpace($RecipientType)) {
    $output = @($output | Where-Object { ([string]$_.RecipientType -replace ' ', '') -eq ($RecipientType -replace ' ', '') })
}
if ($output.Count -eq 0) { Write-Warning 'No rows matched the selected filter; the CSV will be empty.' }
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$quotaStatus = @($quotaReport | ForEach-Object { ConvertTo-ReportObject -Row $_ } | Sort-Object -Property ReportDate |
    Select-Object -Property ReportDate, UnderLimit, WarningIssued, SendProhibited, SendReceiveProhibited, Indeterminate)
if ($quotaStatus.Count -gt 0) { $quotaStatus | Export-Csv -Path $quotaOutputPath -NoTypeInformation -Encoding UTF8 }

$current = @($rows | Where-Object { -not $_.IsDeleted })
$nearQuota = @($current | Where-Object { $_.NearQuota })
$withArchive = @($current | Where-Object { $_.HasArchive })
$totalGB = [math]::Round([double]($current | Measure-Object -Property StorageUsedGB -Sum).Sum, 2)
$averageGB = 0; $archivePercent = 0
if ($current.Count -gt 0) { $averageGB = [math]::Round($totalGB / $current.Count, 2); $archivePercent = [math]::Round(($withArchive.Count / $current.Count) * 100, 1) }
Write-Host ('Mailbox usage ({0})' -f $Period) -ForegroundColor Cyan
Write-Host ('  Mailboxes (current / deleted)       : {0} / {1}' -f $current.Count, ($rows.Count - $current.Count))
Write-Host ('  Storage used (total / average)      : {0} GB / {1} GB' -f $totalGB, $averageGB)
Write-Host ('  {0,-36}: {1}' -f ('Near quota (>= {0} % of send quota)' -f $ThresholdPercent), $nearQuota.Count) -ForegroundColor Yellow
Write-Host ('  Archive enabled                     : {0} ({1} %)' -f $withArchive.Count, $archivePercent)
foreach ($group in ($current | Where-Object { -not [string]::IsNullOrEmpty($_.RecipientType) } | Group-Object -Property RecipientType | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-34}: {1} mailboxes, {2} GB' -f $group.Name, $group.Count, [math]::Round([double]($group.Group | Measure-Object -Property StorageUsedGB -Sum).Sum, 2))
}
Write-Host ('  CSV : {0}' -f $OutputPath)
if ($quotaStatus.Count -gt 0) { Write-Host ('  Quota status CSV : {0}' -f $quotaOutputPath) }

if ($PassThru) { $output }
if ($PassThru -and $quotaStatus.Count -gt 0) { $quotaStatus }
#endregion Main
