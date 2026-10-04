<#
.SYNOPSIS
    Runs a message trace for the last 10 days with full paging and exports the results with status and sender/recipient summaries.
.DESCRIPTION
    Queries Get-MessageTraceV2 (or the classic Get-MessageTrace when V2 is not available in the session) for the given window
    and filters: sender / recipient addresses, delivery status, source / destination IP and Message-ID. V2 has no page
    parameter, so the script requests 5000 rows at a time and moves the end of the window back to the oldest Received value
    returned until everything is read; the classic cmdlet is paged with -Page / -PageSize 5000. -Subject is applied client-side.
    One row per recipient is written to CSV and the console shows the counts per status and the top senders and recipients.
.PARAMETER StartDate
    Start of the trace window (local time). Defaults to 48 hours ago; the service keeps at most 10 days of trace data.
.PARAMETER EndDate
    End of the trace window. Defaults to now.
.PARAMETER SenderAddress
    One or more sender addresses; wildcards such as *@partner.example are accepted.
.PARAMETER RecipientAddress
    One or more recipient addresses; wildcards are accepted.
.PARAMETER Status
    Delivery status filter: Delivered, Failed, Pending, Quarantined, FilteredAsSpam, Expanded or GettingStatus.
.PARAMETER FromIP
    Source IP address of the sending server (inbound mail).
.PARAMETER ToIP
    Destination IP address (outbound mail).
.PARAMETER MessageId
    Internet Message-ID header value, with or without angle brackets.
.PARAMETER Subject
    Keeps only messages whose subject contains this text (evaluated after the trace is downloaded).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOMessageTrace_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the trace rows to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMessageTrace.ps1 -RecipientAddress finance@contoso.com -Status Failed, Quarantined -StartDate (Get-Date).AddDays(-5)
    Lists the failed and quarantined messages addressed to the finance mailbox during the last 5 days.
.EXAMPLE
    PS> .\Get-EXOMessageTrace.ps1 -SenderAddress *@partner.example -Subject 'Invoice' -PassThru | Group-Object -Property Status
    Traces all mail from the partner domain in the last 48 hours, keeps the invoices and groups them by status.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Message Tracking or View-Only Recipients role (held by Exchange Administrator and Global Reader).
    Category    : Mail flow & organization
    Changes     : No
    Notes       : Trace data older than 10 days needs a historical search (Start-EXOHistoricalSearch.ps1). Get-MessageTrace is
                  being retired in favour of Get-MessageTraceV2. Busy tenants return huge result sets; narrow the filters first.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-messagetracev2
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-messagetrace
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [datetime]$StartDate = (Get-Date).AddHours(-48),

    [Parameter()]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [string[]]$SenderAddress,

    [Parameter()]
    [string[]]$RecipientAddress,

    [Parameter()]
    [ValidateSet('Delivered', 'Failed', 'Pending', 'Quarantined', 'FilteredAsSpam', 'Expanded', 'GettingStatus')]
    [string[]]$Status,

    [Parameter()]
    [string]$FromIP,

    [Parameter()]
    [string]$ToIP,

    [Parameter()]
    [string]$MessageId,

    [Parameter()]
    [string]$Subject,

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
if ($StartDate -ge $EndDate) { throw 'StartDate must be earlier than EndDate.' }
if ($StartDate -lt (Get-Date).AddDays(-10)) { throw 'Message trace covers the last 10 days only; use Start-EXOHistoricalSearch.ps1 for older messages.' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMessageTrace_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

$traceParams = @{ StartDate = $StartDate; EndDate = $EndDate; ErrorAction = 'Stop' }
foreach ($name in 'SenderAddress', 'RecipientAddress', 'Status', 'FromIP', 'ToIP', 'MessageId') {
    if ($PSBoundParameters.ContainsKey($name)) { $traceParams[$name] = $PSBoundParameters[$name] }
}
$messages = New-Object -TypeName System.Collections.Generic.List[object]
$seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
$v2Command = Get-Command -Name Get-MessageTraceV2 -ErrorAction SilentlyContinue
try {
    if ($null -ne $v2Command) {
        # V2 returns newest first: each round moves EndDate back to the oldest Received value and, where the cmdlet supports it,
        # StartingRecipientAddress lets the service resume exactly after the last row of the previous round.
        $supportsResume = $v2Command.Parameters.ContainsKey('StartingRecipientAddress')
        while ($true) {
            Write-Progress -Activity 'Running message trace' -Status ('Get-MessageTraceV2: {0} messages so far; window end {1:yyyy-MM-dd HH:mm:ss}' -f $messages.Count, $traceParams['EndDate'])
            $page = @(Get-MessageTraceV2 @traceParams -ResultSize 5000)
            foreach ($message in $page) { if ($seen.Add(('{0}|{1}' -f $message.MessageTraceId, $message.RecipientAddress))) { $messages.Add($message) } }
            if ($page.Count -lt 5000) { break }
            $last = $page[-1]
            if ($last.Received -ge $traceParams['EndDate']) { break }
            $traceParams['EndDate'] = $last.Received
            if ($supportsResume) { $traceParams['StartingRecipientAddress'] = $last.RecipientAddress }
        }
    }
    else {
        $pageNumber = 0
        do {
            $pageNumber++
            Write-Progress -Activity 'Running message trace' -Status ('Get-MessageTrace page {0}; {1} messages so far' -f $pageNumber, $messages.Count)
            $page = @(Get-MessageTrace @traceParams -Page $pageNumber -PageSize 5000)
            foreach ($message in $page) { $messages.Add($message) }
        } while ($page.Count -eq 5000 -and $pageNumber -lt 1000)
    }
}
catch {
    throw "Message trace failed: $($_.Exception.Message)"
}
finally {
    Write-Progress -Activity 'Running message trace' -Completed
}

$rows = @(@(foreach ($message in $messages) {
        if ($PSBoundParameters.ContainsKey('Subject') -and [string]$message.Subject -notlike "*$Subject*") { continue }
        [PSCustomObject]@{
            Received         = $message.Received
            SenderAddress    = $message.SenderAddress
            RecipientAddress = $message.RecipientAddress
            Subject          = $message.Subject
            Status           = [string]$message.Status
            FromIP           = $message.FromIP
            ToIP             = $message.ToIP
            Size             = $message.Size
            MessageId        = $message.MessageId
            MessageTraceId   = [string]$message.MessageTraceId
        }
    }) | Sort-Object -Property Received -Descending)

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'The trace returned no messages for these filters; no CSV written.' }

Write-Host ''
Write-Host ('Message trace summary ({0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm})' -f $StartDate, $EndDate) -ForegroundColor Cyan
Write-Host ('  Messages (recipient rows): {0}' -f $rows.Count)
foreach ($group in ($rows | Group-Object -Property Status | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-16} {1}' -f $group.Name, $group.Count) -ForegroundColor $(if ($group.Name -in @('Failed', 'Quarantined', 'FilteredAsSpam')) { 'Yellow' } else { 'Gray' })
}
foreach ($property in 'SenderAddress', 'RecipientAddress') {
    Write-Host ('  Top {0}s:' -f ($property -replace 'Address$', '').ToLowerInvariant())
    foreach ($group in ($rows | Group-Object -Property $property | Sort-Object -Property Count -Descending | Select-Object -First 5)) {
        Write-Host ('    {0,-50} {1}' -f $group.Name, $group.Count)
    }
}
if ($rows.Count -gt 0) { Write-Host ('  Report: {0}' -f $OutputPath) }

if ($PassThru) {
    $rows
}
#endregion Main
