<#
.SYNOPSIS
    Reports automatic reply (out of office) settings of Exchange Online mailboxes and flags stale or risky configurations.
.DESCRIPTION
    Runs Get-MailboxAutoReplyConfiguration once per selected mailbox and reports AutoReplyState, schedule, external
    audience and the internal/external messages (HTML stripped, truncated to 200 characters). Flags: replies active for
    more than -MaxDays, external replies sent to all senders (not only contacts) and scheduled windows that already ended.
    Mailboxes come from -Identity, a CSV with a UserPrincipalName column or - with a warning - every user mailbox.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID).
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER OnlyEnabled
    Export only mailboxes whose AutoReplyState is Enabled or Scheduled.
.PARAMETER MaxDays
    Number of days after which an active automatic reply is flagged LongRunning. Default 30.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOOutOfOffice_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOOutOfOfficeReport.ps1 -OnlyEnabled
    Reports every user mailbox with an enabled or scheduled automatic reply and writes .\Reports\EXOOutOfOffice_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOOutOfOfficeReport.ps1 -InputCsv .\Leavers.csv -MaxDays 90 -PassThru | Where-Object { $_.Issues }
    Shows leavers whose auto-reply has been on for over 90 days, replies to everyone externally or has an expired schedule.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients or Global Reader (the report is read-only)
    Category    : Mailbox content & settings
    Changes     : No
    Notes       : Legacy RPS cmdlet, one call per mailbox - slow across a large tenant. For replies in the Enabled state
                  (no schedule) Exchange keeps the StartTime/EndTime last saved by Outlook or OWA, so DaysSinceStart is an
                  approximation of how long the reply has been on. A Scheduled reply whose EndTime has passed is inactive
                  although the state still reads Scheduled.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-mailboxautoreplyconfiguration
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$OnlyEnabled,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$MaxDays = 30,

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

function ConvertTo-PlainText {
    <# Strips HTML tags and entities from an auto-reply body, collapses whitespace and truncates to MaxLength characters. #>
    param(
        [Parameter()][AllowNull()][string]$Html,
        [Parameter()][int]$MaxLength = 200
    )
    if ([string]::IsNullOrWhiteSpace($Html)) { return '' }
    $text = $Html -replace '(?is)<(style|script|head)[^>]*>.*?</\1>', ' ' -replace '(?i)<br\s*/?>|</p>|</div>|</li>', ' ' -replace '<[^>]+>', ''
    $text = ([System.Net.WebUtility]::HtmlDecode($text) -replace '\s+', ' ').Trim()
    if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength) + '...' }
    return $text
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOOutOfOffice_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails')
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    Write-Warning 'No -Identity or -InputCsv specified: every user mailbox in the tenant is queried, one call per mailbox. This can take a long time.'
    try { foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -Properties $mailboxProperties -ErrorAction Stop)) { $mailboxes.Add($mailbox) } }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$now = Get-Date
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $upn = $mailbox.UserPrincipalName
    Write-Progress -Activity 'Reading automatic reply configuration' -Status "$index of $($mailboxes.Count) - $upn" -PercentComplete (($index / $mailboxes.Count) * 100)
    try { $config = Get-MailboxAutoReplyConfiguration -Identity $upn -ErrorAction Stop }
    catch { Write-Warning "Could not read the automatic reply configuration of '$upn': $($_.Exception.Message)"; continue }

    $state = [string]$config.AutoReplyState
    if ($OnlyEnabled -and $state -eq 'Disabled') { continue }
    $startTime = $config.StartTime -as [datetime]
    $endTime = $config.EndTime -as [datetime]
    $scheduleEnded = ($state -eq 'Scheduled' -and $null -ne $endTime -and $endTime -lt $now)
    $active = ($state -eq 'Enabled' -or ($state -eq 'Scheduled' -and -not $scheduleEnded -and ($null -eq $startTime -or $startTime -le $now)))
    $daysSinceStart = $null
    if ($state -ne 'Disabled' -and $null -ne $startTime -and $startTime -le $now) { $daysSinceStart = ($now - $startTime).Days }
    $externalMessage = ConvertTo-PlainText -Html ([string]$config.ExternalMessage)
    $externalToAll = ($active -and [string]$config.ExternalAudience -eq 'All' -and $externalMessage.Length -gt 0)
    $longRunning = ($active -and $null -ne $daysSinceStart -and $daysSinceStart -gt $MaxDays)

    $issues = @()
    if ($longRunning) { $issues += ('Active for {0} days' -f $daysSinceStart) }
    if ($externalToAll) { $issues += 'External reply to all senders' }
    if ($scheduleEnded) { $issues += ('Schedule ended {0:yyyy-MM-dd}' -f $endTime) }

    $results.Add([PSCustomObject]@{
            DisplayName       = $mailbox.DisplayName
            UserPrincipalName = $upn
            MailboxType       = [string]$mailbox.RecipientTypeDetails
            AutoReplyState    = $state
            Active            = $active
            StartTime         = $startTime
            EndTime           = $endTime
            DaysSinceStart    = $daysSinceStart
            ExternalAudience  = [string]$config.ExternalAudience
            InternalMessage   = ConvertTo-PlainText -Html ([string]$config.InternalMessage)
            ExternalMessage   = $externalMessage
            LongRunning       = $longRunning
            ExternalToAll     = $externalToAll
            ScheduleEnded     = $scheduleEnded
            Issues            = ($issues -join '; ')
        })
}
Write-Progress -Activity 'Reading automatic reply configuration' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes matched the selection; nothing to export.'; return }
$results | Sort-Object -Property Active, DaysSinceStart -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$longRunningRows = @($results | Where-Object { $_.LongRunning } | Sort-Object -Property DaysSinceStart -Descending)
$externalCount = @($results | Where-Object { $_.ExternalToAll }).Count
$endedCount = @($results | Where-Object { $_.ScheduleEnded }).Count

$stateCounts = @{}
foreach ($group in @($results | Group-Object -Property AutoReplyState)) { $stateCounts[$group.Name] = $group.Count }
Write-Host "Automatic reply summary ($($results.Count) mailboxes reported)" -ForegroundColor Cyan
Write-Host ('  Enabled / Scheduled / Disabled : {0} / {1} / {2}' -f [int]$stateCounts['Enabled'], [int]$stateCounts['Scheduled'], [int]$stateCounts['Disabled'])
Write-Host ('  Currently active               : {0}' -f @($results | Where-Object { $_.Active }).Count)
Write-Host ('  Active for more than {0,4} days : {1}' -f $MaxDays, $longRunningRows.Count) -ForegroundColor $(if ($longRunningRows.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in @($longRunningRows | Select-Object -First 15)) {
    Write-Host ('    {0,5} days  {1}  since {2:yyyy-MM-dd}' -f $row.DaysSinceStart, $row.UserPrincipalName, $row.StartTime) -ForegroundColor Yellow
}
Write-Host ('  External reply to all senders  : {0}' -f $externalCount) -ForegroundColor $(if ($externalCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Scheduled windows already ended: {0}' -f $endedCount)
Write-Host ('  Report                         : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
