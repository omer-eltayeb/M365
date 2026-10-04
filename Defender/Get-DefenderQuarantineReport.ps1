<#
.SYNOPSIS
    Exports quarantined messages with sender, recipients, verdict, policy, release status and expiry, plus a triage summary.
.DESCRIPTION
    Pages through Get-QuarantineMessage (1000 messages per page) for the last -DaysBack days, applying the server-side
    filters you pass (quarantine type, sender, recipient, policy, release status, direction), and writes one row per
    quarantined message to CSV: Identity, received time, sender and domain, joined recipients, subject, verdict
    (Type/QuarantineTypes), policy name and type, release status, released users, expiry and size. The console summary
    shows counts per verdict and policy, top sender domains and recipients, pending release requests and near-expiry messages.
.PARAMETER DaysBack
    Number of days of quarantine history to read (1-30; the quarantine keeps at most 30 days). Default 7.
.PARAMETER EndReceivedDate
    Upper bound of the received time window. Default: now.
.PARAMETER QuarantineTypes
    Only messages with these verdicts: Bulk, DataLossPrevention, FileTypeBlock, HighConfPhish, Malware, Phish, Spam, SPOMalware, TransportRule.
.PARAMETER SenderAddress
    One or more sender addresses to filter on.
.PARAMETER RecipientAddress
    One or more recipient addresses to filter on.
.PARAMETER PolicyName
    Name of the anti-spam, anti-phishing, anti-malware, Safe Attachments or mail flow rule policy that quarantined the message.
.PARAMETER ReleaseStatus
    Only messages in these states: Approved, Denied, Error, NotReleased, PreparingToRelease, Released, Requested.
.PARAMETER Direction
    Inbound or Outbound.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderQuarantine_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderQuarantineReport.ps1
    Exports everything quarantined in the last 7 days and prints the triage summary.
.EXAMPLE
    PS> .\Get-DefenderQuarantineReport.ps1 -DaysBack 30 -QuarantineTypes HighConfPhish, Malware -ReleaseStatus Released -PassThru | Sort-Object -Property ReceivedTime
    Lists high confidence phishing and malware messages that were released in the last 30 days - the ones worth a second look.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Reader, Global Reader or Security Administrator (Exchange Online PowerShell session)
    Category    : Email threat operations
    Changes     : No
    Notes       : Dates are evaluated in UTC by the service. The list view returns the recipients known at quarantine time;
                  query one message with Get-QuarantineMessage -Identity to see per-recipient release details. Large tenants
                  can hold hundreds of thousands of messages - narrow the window or filters instead of reading everything.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-quarantinemessage
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$DaysBack = 7,

    [Parameter()]
    [datetime]$EndReceivedDate,

    [Parameter()]
    [ValidateSet('Bulk', 'DataLossPrevention', 'FileTypeBlock', 'HighConfPhish', 'Malware', 'Phish', 'Spam', 'SPOMalware', 'TransportRule')]
    [string[]]$QuarantineTypes,

    [Parameter()]
    [string[]]$SenderAddress,

    [Parameter()]
    [string[]]$RecipientAddress,

    [Parameter()]
    [string]$PolicyName,

    [Parameter()]
    [ValidateSet('Approved', 'Denied', 'Error', 'NotReleased', 'PreparingToRelease', 'Released', 'Requested')]
    [string[]]$ReleaseStatus,

    [Parameter()]
    [ValidateSet('Inbound', 'Outbound')]
    [string]$Direction,

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

function Write-TopValues {
    <# Prints the most frequent values of a projection (verdicts, policies, sender domains, recipients). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter()]
        [object[]]$Values,

        [Parameter()]
        [int]$Top = 5
    )
    Write-Host "  $Title" -ForegroundColor Cyan
    foreach ($group in ($Values | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Group-Object | Sort-Object -Property Count, Name -Descending | Select-Object -First $Top)) {
        Write-Host ('    {0,-60} {1,7}' -f $group.Name, $group.Count)
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderQuarantine_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

$end = $(if ($PSBoundParameters.ContainsKey('EndReceivedDate')) { $EndReceivedDate } else { Get-Date })
$queryParams = @{ StartReceivedDate = $end.AddDays(-$DaysBack); EndReceivedDate = $end; PageSize = 1000; ErrorAction = 'Stop' }
foreach ($name in @('QuarantineTypes', 'SenderAddress', 'RecipientAddress', 'PolicyName', 'ReleaseStatus', 'Direction')) {
    if ($PSBoundParameters.ContainsKey($name)) { $queryParams[$name] = $PSBoundParameters[$name] }
}
Write-Verbose ('Reading quarantine from {0:u} to {1:u}.' -f $queryParams.StartReceivedDate, $end)

# Get-QuarantineMessage pages explicitly (Page 1-1000, PageSize up to 1000); a short page marks the end of the result set.
$messages = New-Object -TypeName System.Collections.Generic.List[object]
$page = 1
do {
    Write-Progress -Activity 'Reading quarantine' -Status ('Page {0} - {1} messages so far' -f $page, $messages.Count)
    try { $batch = @(Get-QuarantineMessage @queryParams -Page $page) }
    catch { throw "Failed to read quarantine page ${page}: $($_.Exception.Message)" }
    foreach ($message in $batch) { $messages.Add($message) }
    $page++
} while ($batch.Count -eq 1000 -and $page -le 1000)
Write-Progress -Activity 'Reading quarantine' -Completed

$now = Get-Date
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($message in $messages) {
    # Size arrives as text such as "41.9 KB (42,944 bytes)"; the byte count in brackets is the reliable part.
    $sizeKB = $(if ([string]$message.Size -match '\(([\d,\.\s]+)\s*bytes\)') { [math]::Round(([int64]($Matches[1] -replace '[^\d]', '')) / 1KB, 1) } else { $null })
    $sender = [string]$message.SenderAddress
    $expires = $(if ($null -ne $message.Expires) { [datetime]$message.Expires } else { $null })
    $rows.Add([PSCustomObject]@{
            Identity         = [string]$message.Identity
            ReceivedTime     = [datetime]$message.ReceivedTime
            SenderAddress    = $sender
            SenderDomain     = $(if ($sender -match '@([^@>\s]+)$') { $Matches[1].ToLowerInvariant() } else { $null })
            RecipientAddress = (@($message.RecipientAddress) -join ';')
            RecipientCount   = $message.RecipientCount
            Subject          = [string]$message.Subject
            Type             = [string]$message.Type
            QuarantineTypes  = (@($message.QuarantineTypes) -join ';')
            PolicyName       = [string]$message.PolicyName
            PolicyType       = [string]$message.PolicyType
            Direction        = [string]$message.Direction
            ReleaseStatus    = [string]$message.ReleaseStatus
            Released         = ([string]$message.Released -eq 'True')
            ReleasedUser     = (@($message.ReleasedUser) -join ';')
            Expires          = $expires
            DaysUntilExpiry  = $(if ($null -ne $expires) { [int][math]::Floor(($expires - $now).TotalDays) } else { $null })
            SizeKB           = $sizeKB
            MessageId        = [string]$message.MessageId
        })
}

if ($rows.Count -gt 0) { $rows | Sort-Object -Property ReceivedTime -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

$requested = @($rows | Where-Object { $_.ReleaseStatus -eq 'Requested' }).Count
$expiringSoon = @($rows | Where-Object { $null -ne $_.DaysUntilExpiry -and $_.DaysUntilExpiry -le 3 -and -not $_.Released }).Count
Write-Host ''
Write-Host ('Quarantine summary - {0} message(s) in the last {1} day(s)' -f $rows.Count, $DaysBack) -ForegroundColor Cyan
Write-TopValues -Title 'By verdict (Type)' -Values @($rows | ForEach-Object { $_.Type }) -Top 10
Write-TopValues -Title 'By policy' -Values @($rows | ForEach-Object { $_.PolicyName })
Write-TopValues -Title 'Top sender domains' -Values @($rows | ForEach-Object { $_.SenderDomain })
Write-TopValues -Title 'Top recipients' -Values @($rows | ForEach-Object { $_.RecipientAddress -split ';' })
Write-Host ('  Pending release requests : {0}' -f $requested) -ForegroundColor $(if ($requested -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Expiring within 3 days   : {0}' -f $expiringSoon)
if ($rows.Count -gt 0) { Write-Host ('  Report                   : {0}' -f $OutputPath) }

if ($PassThru) { $rows }
#endregion Main
