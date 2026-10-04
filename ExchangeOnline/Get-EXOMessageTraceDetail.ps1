<#
.SYNOPSIS
    Shows the event timeline (receive, transport rules, spam / malware verdicts, deliver, fail, defer) of one message per recipient.
.DESCRIPTION
    Identifies a message either by -MessageTraceId plus -RecipientAddress, or by its Internet -MessageId (the message trace is
    queried first to find every recipient and the matching MessageTraceId). For each recipient the detail events are read with
    Get-MessageTraceDetailV2 (falls back to Get-MessageTraceDetail when V2 is not available) and returned as rows: Date, Event,
    Action, Detail and Data, where the XML-like Data property is flattened into readable "Name=value" pairs. The rows are
    written to CSV and printed as a per-recipient timeline in the console.
.PARAMETER MessageTraceId
    MessageTraceId of the message (from Get-EXOMessageTrace.ps1 or Get-MessageTraceV2). Requires -RecipientAddress.
.PARAMETER RecipientAddress
    Recipient address(es) to show. Mandatory with -MessageTraceId; optional filter with -MessageId.
.PARAMETER MessageId
    Internet Message-ID header value, with or without angle brackets; all recipients found in the trace are included.
.PARAMETER StartDate
    Start of the search window used to locate the message. Defaults to 10 days ago (the trace retention limit).
.PARAMETER EndDate
    End of the search window. Defaults to now.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOMessageTraceDetail_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the event rows to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMessageTraceDetail.ps1 -MessageId '<CAF1b2c3@mail.partner.example>'
    Finds every recipient of the message in the last 10 days and prints one timeline per recipient.
.EXAMPLE
    PS> .\Get-EXOMessageTraceDetail.ps1 -MessageTraceId 8f7a3c9e-0f1e-4d2b-9a6c-1234567890ab -RecipientAddress finance@contoso.com -PassThru
    Shows the hops of one recipient copy and returns the event rows to the pipeline.
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
    Notes       : Detail events exist for the last 10 days only; older messages need a MessageTraceDetail historical search
                  (Start-EXOHistoricalSearch.ps1). Events are not available for messages still in a Pending state and can lag
                  the trace itself by a few minutes. The Data column is truncated to 300 characters.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-messagetracedetailv2
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-messagetracedetail
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'ByTraceId')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByTraceId')]
    [guid]$MessageTraceId,

    [Parameter(Mandatory = $true, ParameterSetName = 'ByTraceId')]
    [Parameter(ParameterSetName = 'ByMessageId')]
    [string[]]$RecipientAddress,

    [Parameter(Mandatory = $true, ParameterSetName = 'ByMessageId')]
    [string]$MessageId,

    [Parameter()]
    [datetime]$StartDate = (Get-Date).AddDays(-10).AddMinutes(5),   # small margin: the service rejects windows older than 10 days

    [Parameter()]
    [datetime]$EndDate = (Get-Date),

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

function ConvertFrom-TraceData {
    <# Flattens the Data XML (<root><MEP Name="..." String="..."/>...</root>) into "Name=value; ..." truncated to 300 characters. #>
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Data
    )
    if ([string]::IsNullOrWhiteSpace($Data)) { return $null }
    $text = ($Data -replace '\s+', ' ').Trim()
    try {
        $xml = [xml]$Data
        $pairs = @(foreach ($node in @($xml.SelectNodes('//MEP'))) {
                $values = @($node.Attributes | Where-Object { $_.Name -ne 'Name' } | ForEach-Object { $_.Value })
                '{0}={1}' -f $node.GetAttribute('Name'), ($values -join ',')
            })
        if ($pairs.Count -gt 0) { $text = $pairs -join '; ' }
    }
    catch {
        Write-Verbose "Data could not be parsed as XML: $($_.Exception.Message)"
    }
    if ($text.Length -gt 300) { $text = $text.Substring(0, 300) + '...' }
    return $text
}
#endregion Helpers

#region Main
if ($StartDate -ge $EndDate) { throw 'StartDate must be earlier than EndDate.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMessageTraceDetail_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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
$useV2 = $null -ne (Get-Command -Name Get-MessageTraceDetailV2 -ErrorAction SilentlyContinue)
Write-Verbose "Using $(if ($useV2) { 'Get-MessageTraceDetailV2' } else { 'Get-MessageTraceDetail' })."

# Each (MessageTraceId, RecipientAddress) pair is one recipient copy of the message and has its own event chain.
$targets = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSCmdlet.ParameterSetName -eq 'ByTraceId') {
    foreach ($recipient in $RecipientAddress) { $targets.Add([PSCustomObject]@{ MessageTraceId = $MessageTraceId; RecipientAddress = $recipient }) }
}
else {
    $traceParams = @{ MessageId = $MessageId; StartDate = $StartDate; EndDate = $EndDate; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('RecipientAddress')) { $traceParams['RecipientAddress'] = $RecipientAddress }
    try {
        if ($useV2) { $trace = @(Get-MessageTraceV2 @traceParams -ResultSize 5000) }
        else { $trace = @(Get-MessageTrace @traceParams -PageSize 5000) }
    }
    catch {
        throw "Message trace lookup for Message-ID '$MessageId' failed: $($_.Exception.Message)"
    }
    if ($trace.Count -eq 0) { throw "No trace entry found for Message-ID '$MessageId' between $StartDate and $EndDate (trace data is kept for 10 days)." }
    foreach ($entry in ($trace | Sort-Object -Property MessageTraceId, RecipientAddress -Unique)) {
        $targets.Add([PSCustomObject]@{ MessageTraceId = [guid]$entry.MessageTraceId; RecipientAddress = [string]$entry.RecipientAddress })
    }
    Write-Verbose "Trace found $($targets.Count) recipient cop(ies) of the message."
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($target in $targets) {
    $index++
    Write-Progress -Activity 'Reading message trace details' -Status $target.RecipientAddress -PercentComplete (($index / $targets.Count) * 100)
    $detailParams = @{ MessageTraceId = $target.MessageTraceId; RecipientAddress = $target.RecipientAddress; StartDate = $StartDate; EndDate = $EndDate; ErrorAction = 'Stop' }
    try {
        if ($useV2) { $events = @(Get-MessageTraceDetailV2 @detailParams) }
        else { $events = @(Get-MessageTraceDetail @detailParams) }
    }
    catch {
        Write-Warning "Details for $($target.RecipientAddress) (trace $($target.MessageTraceId)) could not be read: $($_.Exception.Message)"
        continue
    }
    if ($events.Count -eq 0) { Write-Warning "No detail events yet for $($target.RecipientAddress); events for pending messages appear after delivery or expiry." }
    foreach ($traceEvent in ($events | Sort-Object -Property Date)) {
        $rows.Add([PSCustomObject]@{
                RecipientAddress = $target.RecipientAddress
                MessageTraceId   = [string]$target.MessageTraceId
                Date             = $traceEvent.Date
                Event            = [string]$traceEvent.Event
                Action           = [string]$traceEvent.Action
                Detail           = [string]$traceEvent.Detail
                Data             = ConvertFrom-TraceData -Data ([string]$traceEvent.Data)
                MessageId        = [string]$traceEvent.MessageId
            })
    }
}
Write-Progress -Activity 'Reading message trace details' -Completed

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No detail events were returned; no CSV written.' }

foreach ($group in ($rows | Group-Object -Property RecipientAddress)) {
    Write-Host ''
    Write-Host ('Timeline for {0} (MessageTraceId {1})' -f $group.Name, $group.Group[0].MessageTraceId) -ForegroundColor Cyan
    foreach ($row in $group.Group) {
        $colour = 'Gray'
        if ($row.Event -match 'Fail|Defer|Spam|Malware|Phish|Quarantine|Drop') { $colour = 'Yellow' }
        elseif ($row.Event -match 'Deliver|Send') { $colour = 'Green' }
        Write-Host ('  {0:yyyy-MM-dd HH:mm:ss}  {1,-22} {2}' -f $row.Date, $row.Event, $row.Detail) -ForegroundColor $colour
    }
}
Write-Host ''
Write-Host ('Recipient copies: {0}; events: {1}{2}' -f $targets.Count, $rows.Count, $(if ($rows.Count -gt 0) { "; report: $OutputPath" } else { '' }))

if ($PassThru) {
    $rows
}
#endregion Main
