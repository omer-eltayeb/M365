<#
.SYNOPSIS
    Reports the top mail senders and recipients, the top spam and malware targets and the most common malware families.
.DESCRIPTION
    Runs Get-MailTrafficSummaryReport once per category (TopMailSender, TopMailRecipient, TopSpamRecipient,
    TopMalwareRecipient and TopMalware) for the chosen window - default the last 7 days, maximum 90 - and normalises the
    generic C1 / C2 columns into Category, Address (or malware name), MessageCount and Rank. Senders whose volume exceeds
    -OutboundThreshold are flagged (IsAboveThreshold), the usual sign of a compromised account or an unsanctioned bulk mailer.
    All rows go to one CSV and the console prints the top 10 of each category.
.PARAMETER Category
    One or more categories to query. Default: all five.
.PARAMETER StartDate
    First day of the window. Defaults to EndDate minus DaysBack. Data is kept for 90 days.
.PARAMETER EndDate
    Last day of the window. Defaults to today.
.PARAMETER DaysBack
    Number of days to report when StartDate is not given. Default 7, maximum 90.
.PARAMETER OutboundThreshold
    Message count above which a TopMailSender entry is flagged. Default 5000.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOTopSendersRecipients_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the rows to the pipeline.
.EXAMPLE
    PS> .\Get-EXOTopSendersAndRecipients.ps1
    Reports the last 7 days for all categories and prints the top 10 of each.
.EXAMPLE
    PS> .\Get-EXOTopSendersAndRecipients.ps1 -Category TopMailSender -DaysBack 1 -OutboundThreshold 1000 -PassThru | Where-Object { $_.IsAboveThreshold }
    Finds mailboxes that sent more than 1000 messages yesterday - a quick compromised-account check.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator, Global Reader or Security Reader (View-Only Recipients role).
    Category    : Mail flow & organization
    Changes     : No
    Notes       : The report is aggregated per UTC day and lags by up to 24 hours, so a 1-day window may still be incomplete.
                  Counts are per message, not per recipient, and TopMailSender includes mail sent to internal recipients. The
                  service returns only the top entries of each category, so the row count per category is limited.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-mailtrafficsummaryreport
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('TopMailSender', 'TopMailRecipient', 'TopSpamRecipient', 'TopMalwareRecipient', 'TopMalware')]
    [string[]]$Category = @('TopMailSender', 'TopMailRecipient', 'TopSpamRecipient', 'TopMalwareRecipient', 'TopMalware'),

    [Parameter()]
    [datetime]$StartDate,

    [Parameter()]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$DaysBack = 7,

    [Parameter()]
    [ValidateRange(1, 10000000)]
    [int]$OutboundThreshold = 5000,

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
if (-not $PSBoundParameters.ContainsKey('StartDate')) { $StartDate = $EndDate.AddDays(-$DaysBack) }
if ($StartDate -ge $EndDate) { throw 'StartDate must be earlier than EndDate.' }
if ($StartDate -lt (Get-Date).AddDays(-90)) { throw 'The mail traffic summary report covers the last 90 days only.' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOTopSendersRecipients_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($categoryName in $Category) {
    $index++
    Write-Progress -Activity 'Reading mail traffic summary' -Status $categoryName -PercentComplete (($index / $Category.Count) * 100)
    try {
        $entries = @(Get-MailTrafficSummaryReport -Category $categoryName -StartDate $StartDate -EndDate $EndDate -ErrorAction Stop)
    }
    catch {
        Write-Warning "Category '$categoryName' could not be read: $($_.Exception.Message)"
        continue
    }
    # The report uses generic columns: C1 is the address (or malware name) and C2 the message count, returned as text.
    $parsed = @(foreach ($entry in $entries) {
            $count = [long]0
            if (-not [long]::TryParse([string]$entry.C2, [ref]$count)) { Write-Verbose "Skipping unparsable count '$($entry.C2)' for $($entry.C1)."; continue }
            [PSCustomObject]@{ Address = [string]$entry.C1; MessageCount = $count }
        })
    $rank = 0
    foreach ($item in ($parsed | Sort-Object -Property MessageCount -Descending)) {
        $rank++
        $rows.Add([PSCustomObject]@{
                Category         = $categoryName
                Rank             = $rank
                Address          = $item.Address
                MessageCount     = $item.MessageCount
                IsAboveThreshold = ($categoryName -eq 'TopMailSender' -and $item.MessageCount -gt $OutboundThreshold)
                StartDate        = $StartDate.Date
                EndDate          = $EndDate.Date
            })
    }
    Write-Verbose "$categoryName returned $($parsed.Count) entr(ies)."
}
Write-Progress -Activity 'Reading mail traffic summary' -Completed

if ($rows.Count -gt 0) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No data was returned for this window; no CSV written.'
}

$flagged = @($rows | Where-Object { $_.IsAboveThreshold })
Write-Host ''
Write-Host ('Mail traffic summary {0:yyyy-MM-dd} to {1:yyyy-MM-dd}' -f $StartDate, $EndDate) -ForegroundColor Cyan
foreach ($categoryName in $Category) {
    $top = @($rows | Where-Object { $_.Category -eq $categoryName } | Sort-Object -Property Rank | Select-Object -First 10)
    Write-Host ('  {0} ({1} entries)' -f $categoryName, @($rows | Where-Object { $_.Category -eq $categoryName }).Count) -ForegroundColor White
    foreach ($item in $top) {
        Write-Host ('    {0,2}. {1,-55} {2,10:N0}' -f $item.Rank, $item.Address, $item.MessageCount) -ForegroundColor $(if ($item.IsAboveThreshold) { 'Yellow' } else { 'Gray' })
    }
}
if ($flagged.Count -gt 0) {
    $flaggedAddresses = @($flagged | Select-Object -ExpandProperty Address) -join ', '
    Write-Warning ('{0} sender(s) exceeded {1:N0} messages ({2}). Check for account compromise or move bulk mail to a dedicated connector.' -f $flagged.Count, $OutboundThreshold, $flaggedAddresses)
}
if ($rows.Count -gt 0) { Write-Host ('  Report: {0}' -f $OutputPath) }

if ($PassThru) {
    $rows
}
#endregion Main
