<#
.SYNOPSIS
    Submits, lists and waits for historical message trace searches (mail older than 10 days, up to 90 days back).
.DESCRIPTION
    Message trace keeps 10 days of data; anything older must be requested as a historical search that Exchange Online runs in
    the background and delivers as a downloadable CSV. Start-HistoricalSearch submits a job (report type, date range, sender /
    recipient filters, direction, notification address), -Status lists the existing jobs with Get-HistoricalSearch (JobId,
    title, status, submit date, row count, download URL), and -JobId (or -Wait on a new job) polls a job every 60 seconds until
    it is finished and prints its FileUrl. Submitting is wrapped in ShouldProcess, so -WhatIf and -Confirm work.
.PARAMETER ReportTitle
    Title of the search as shown in the admin center. Defaults to <ReportType>_yyyyMMdd-HHmm.
.PARAMETER StartDate
    Start of the search window (at most 90 days ago).
.PARAMETER EndDate
    End of the search window.
.PARAMETER ReportType
    MessageTrace (default), MessageTraceDetail, ATPReport, ATPV2, DLP, Malware, Phish, Spam, Spoof or TransportRule.
.PARAMETER SenderAddress
    Sender address filter (one or more addresses).
.PARAMETER RecipientAddress
    Recipient address filter (one or more addresses).
.PARAMETER Direction
    All (default), Received (inbound) or Sent (outbound).
.PARAMETER NotifyAddress
    Address(es) notified by e-mail when the report is ready.
.PARAMETER Wait
    After submitting, poll the new job until it completes; also accepted together with -JobId.
.PARAMETER Status
    List all historical searches of the tenant instead of submitting one.
.PARAMETER JobId
    Poll an existing search until it is finished and print its download URL.
.PARAMETER TimeoutMinutes
    Stop waiting after this many minutes; the job itself keeps running server-side. Default 120.
.PARAMETER PassThru
    Also emits the job object(s) to the pipeline.
.EXAMPLE
    PS> .\Start-EXOHistoricalSearch.ps1 -StartDate (Get-Date).AddDays(-60) -EndDate (Get-Date).AddDays(-30) -RecipientAddress finance@contoso.com -NotifyAddress admin@contoso.com
    Submits a MessageTrace search for the finance mailbox covering 30-60 days ago and prints the JobId.
.EXAMPLE
    PS> .\Start-EXOHistoricalSearch.ps1 -Status -PassThru | Where-Object { $_.Status -eq 'Done' } | Select-Object ReportTitle, Rows, FileUrl
    Lists every search and shows the download URLs of the finished ones.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Message Tracking or View-Only Recipients role (held by Exchange Administrator and Global Reader).
    Category    : Mail flow & organization
    Changes     : Yes
    Notes       : A tenant can submit 250 historical searches per day; searches take minutes to several hours and the result CSV
                  stays available for 10 days. The FileUrl is protected by the admin portal sign-in, so open it in a browser as
                  an administrator - it cannot be downloaded with Invoke-WebRequest from the PowerShell session.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/start-historicalsearch
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-historicalsearch
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Start')]
param(
    [Parameter(ParameterSetName = 'Start')]
    [string]$ReportTitle,

    [Parameter(Mandatory = $true, ParameterSetName = 'Start')]
    [datetime]$StartDate,

    [Parameter(Mandatory = $true, ParameterSetName = 'Start')]
    [datetime]$EndDate,

    [Parameter(ParameterSetName = 'Start')]
    [ValidateSet('MessageTrace', 'MessageTraceDetail', 'ATPReport', 'ATPV2', 'DLP', 'Malware', 'Phish', 'Spam', 'Spoof', 'TransportRule')]
    [string]$ReportType = 'MessageTrace',

    [Parameter(ParameterSetName = 'Start')]
    [string[]]$SenderAddress,

    [Parameter(ParameterSetName = 'Start')]
    [string[]]$RecipientAddress,

    [Parameter(ParameterSetName = 'Start')]
    [ValidateSet('All', 'Received', 'Sent')]
    [string]$Direction = 'All',

    [Parameter(ParameterSetName = 'Start')]
    [string[]]$NotifyAddress,

    [Parameter(ParameterSetName = 'Start')]
    [Parameter(ParameterSetName = 'Wait')]
    [switch]$Wait,

    [Parameter(Mandatory = $true, ParameterSetName = 'Status')]
    [switch]$Status,

    [Parameter(Mandatory = $true, ParameterSetName = 'Wait')]
    [guid]$JobId,

    [Parameter(ParameterSetName = 'Start')]
    [Parameter(ParameterSetName = 'Wait')]
    [ValidateRange(1, 1440)]
    [int]$TimeoutMinutes = 120,

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

function Wait-HistoricalSearchJob {
    <# Polls a job until it leaves NotStarted / InProgress or the timeout elapses; returns the last job object seen. #>
    param(
        [Parameter(Mandatory = $true)]
        [guid]$Id,

        [Parameter(Mandatory = $true)]
        [int]$Timeout
    )
    $deadline = (Get-Date).AddMinutes($Timeout)
    do {
        $job = Get-HistoricalSearch -JobId $Id -ErrorAction Stop
        if ($null -eq $job) { throw "Historical search $Id was not found." }
        if ([string]$job.Status -notin @('NotStarted', 'InProgress')) { break }
        Write-Progress -Activity 'Waiting for historical search' -Status ('"{0}" is {1}; next check in 60s; giving up at {2:HH:mm}' -f $job.ReportTitle, $job.Status, $deadline)
        Start-Sleep -Seconds 60
    } while ((Get-Date) -lt $deadline)
    Write-Progress -Activity 'Waiting for historical search' -Completed
    if ([string]$job.Status -in @('NotStarted', 'InProgress')) { Write-Warning "Timeout after $Timeout minute(s); the search is still $($job.Status) and keeps running server-side." }
    return $job
}
#endregion Helpers

#region Main
try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

# Stable report columns; Select-Object keeps them in this order and leaves missing ones empty.
$jobProperties = @('JobId', 'ReportTitle', 'ReportType', 'Status', 'SubmitDate', 'CompletionDate', 'StartDate', 'EndDate', 'Rows', 'FileUrl', 'ErrorDescription')
$results = @()
if ($Status) {
    try { $results = @(Get-HistoricalSearch -ErrorAction Stop | Sort-Object -Property SubmitDate -Descending | Select-Object -Property $jobProperties) }
    catch { throw "Get-HistoricalSearch failed: $($_.Exception.Message)" }
    Write-Host ''
    Write-Host ('Historical searches: {0}' -f $results.Count) -ForegroundColor Cyan
    foreach ($group in ($results | Group-Object -Property Status)) { Write-Host ('  {0,-12} {1}' -f $group.Name, $group.Count) }
    $results | Select-Object -First 15 | Format-Table -Property JobId, ReportTitle, ReportType, Status, SubmitDate, Rows -AutoSize | Out-Host
}
elseif ($PSCmdlet.ParameterSetName -eq 'Wait') {
    $job = Wait-HistoricalSearchJob -Id $JobId -Timeout $TimeoutMinutes
    $results = @($job | Select-Object -Property $jobProperties)
}
else {
    if ($StartDate -ge $EndDate) { throw 'StartDate must be earlier than EndDate.' }
    if ($StartDate -lt (Get-Date).AddDays(-90)) { throw 'Historical search covers the last 90 days only.' }
    if ([string]::IsNullOrWhiteSpace($ReportTitle)) { $ReportTitle = '{0}_{1}' -f $ReportType, (Get-Date -Format 'yyyyMMdd-HHmm') }
    $searchParams = @{ ReportTitle = $ReportTitle; ReportType = $ReportType; StartDate = $StartDate; EndDate = $EndDate; Direction = $Direction; ErrorAction = 'Stop' }
    foreach ($name in 'SenderAddress', 'RecipientAddress', 'NotifyAddress') {
        if ($PSBoundParameters.ContainsKey($name)) { $searchParams[$name] = $PSBoundParameters[$name] }
    }
    $description = '{0} search "{1}" from {2:yyyy-MM-dd HH:mm} to {3:yyyy-MM-dd HH:mm}' -f $ReportType, $ReportTitle, $StartDate, $EndDate
    if ($PSCmdlet.ShouldProcess($description, 'Submit historical search (counts against the quota of 250 searches per day)')) {
        try { $job = Start-HistoricalSearch @searchParams }
        catch { throw "Start-HistoricalSearch failed: $($_.Exception.Message)" }
        Write-Host ('Submitted {0}; JobId {1}' -f $description, $job.JobId) -ForegroundColor Green
        if ($Wait) { $job = Wait-HistoricalSearchJob -Id $job.JobId -Timeout $TimeoutMinutes }
        $results = @($job | Select-Object -Property $jobProperties)
    }
}

if (-not $Status -and $results.Count -gt 0) {
    $row = $results[0]
    Write-Host ''
    Write-Host ('Historical search "{0}" ({1}) is {2}' -f $row.ReportTitle, $row.JobId, $row.Status) -ForegroundColor $(if ([string]$row.Status -eq 'Done') { 'Green' } else { 'Yellow' })
    if (-not [string]::IsNullOrEmpty($row.FileUrl)) { Write-Host ('  {0} rows. Open the FileUrl in a browser signed in as an administrator: {1}' -f $row.Rows, $row.FileUrl) }
    elseif ([string]$row.Status -in @('NotStarted', 'InProgress')) { Write-Host ('  Check again later with: .\Start-EXOHistoricalSearch.ps1 -JobId {0}' -f $row.JobId) }
    if (-not [string]::IsNullOrEmpty($row.ErrorDescription)) { Write-Warning ([string]$row.ErrorDescription) }
}

if ($PassThru) {
    $results
}
#endregion Main
