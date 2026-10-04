<#
.SYNOPSIS
    Releases (or deletes) quarantined messages by identity, from a CSV, or by an explicit filter, with safety checks per message.
.DESCRIPTION
    Resolves the quarantined messages to act on - from -Identity values, the Identity column of -InputCsv, or a
    Get-QuarantineMessage query when -Filter is used with sender, recipient, subject wildcard or verdict filters - then
    calls Release-QuarantineMessage (to all original recipients, or to -User) or Delete-QuarantineMessage (-Delete) for
    each one under ShouldProcess. Already released messages are skipped and Malware or HighConfPhish verdicts are refused
    unless -Force is given. One result object per message (Released, Deleted, Skipped or Failed) is written to the pipeline.
.PARAMETER Identity
    One or more quarantine message identities in the form GUID\GUID (from Get-QuarantineMessage or Get-DefenderQuarantineReport.ps1).
.PARAMETER InputCsv
    CSV file with an Identity column, for example a filtered export of Get-DefenderQuarantineReport.ps1.
.PARAMETER Filter
    Select messages with a query; at least one of -SenderAddress, -RecipientAddress, -Subject or -QuarantineTypes is required.
.PARAMETER SenderAddress
    Sender addresses to match (filter mode).
.PARAMETER RecipientAddress
    Recipient addresses to match (filter mode).
.PARAMETER Subject
    Subject wildcard pattern, for example 'Invoice*' (filter mode, evaluated client-side with -like).
.PARAMETER QuarantineTypes
    Verdicts to match (filter mode): Bulk, DataLossPrevention, FileTypeBlock, HighConfPhish, Malware, Phish, Spam, SPOMalware, TransportRule.
.PARAMETER DaysBack
    Received-time window for filter mode (1-30). Default 7.
.PARAMETER User
    Release only to these recipients instead of all original recipients.
.PARAMETER AllowSender
    Also add the sender as an allow entry so future messages are not quarantined (review it later in the Tenant Allow/Block List).
.PARAMETER ReportFalsePositive
    Report the message to Microsoft as a false positive (spam verdicts only).
.PARAMETER Force
    Allow releasing messages with a Malware or HighConfPhish verdict.
.PARAMETER Delete
    Delete the messages from quarantine instead of releasing them.
.EXAMPLE
    PS> .\Release-DefenderQuarantineMessages.ps1 -InputCsv .\release.csv
    Releases every message listed in the CSV (Identity column) to all original recipients, prompting for each one.
.EXAMPLE
    PS> .\Release-DefenderQuarantineMessages.ps1 -Filter -SenderAddress newsletter@partner.example -QuarantineTypes Bulk, Spam -WhatIf
    Shows which bulk and spam messages from that sender (last 7 days) would be released, without releasing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Administrator, or the Quarantine Administrator role in Defender for Office 365 (Exchange Online PowerShell session)
    Category    : Email threat operations
    Changes     : Yes
    Notes       : Get-QuarantineMessage -Identity returns ALL messages when the identity does not exist, so identities are
                  format-checked and the returned object is compared with the requested identity before anything is released.
                  -AllowSender creates a Tenant Allow/Block List allow entry; -ReportFalsePositive only applies to spam verdicts.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/release-quarantinemessage
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Identity')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(Mandatory = $true, ParameterSetName = 'Filter')]
    [switch]$Filter,

    [Parameter(ParameterSetName = 'Filter')]
    [string[]]$SenderAddress,

    [Parameter(ParameterSetName = 'Filter')]
    [string[]]$RecipientAddress,

    [Parameter(ParameterSetName = 'Filter')]
    [string]$Subject,

    [Parameter(ParameterSetName = 'Filter')]
    [ValidateSet('Bulk', 'DataLossPrevention', 'FileTypeBlock', 'HighConfPhish', 'Malware', 'Phish', 'Spam', 'SPOMalware', 'TransportRule')]
    [string[]]$QuarantineTypes,

    [Parameter(ParameterSetName = 'Filter')]
    [ValidateRange(1, 30)]
    [int]$DaysBack = 7,

    [Parameter()]
    [string[]]$User,

    [Parameter()]
    [switch]$AllowSender,

    [Parameter()]
    [switch]$ReportFalsePositive,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$Delete
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
$hasFilter = $null -ne $SenderAddress -or $null -ne $RecipientAddress -or $PSBoundParameters.ContainsKey('Subject') -or $null -ne $QuarantineTypes
if ($Filter -and -not $hasFilter) { throw 'Filter mode requires at least one of -SenderAddress, -RecipientAddress, -Subject or -QuarantineTypes.' }
if ($Delete -and ($AllowSender -or $ReportFalsePositive -or $null -ne $User)) { throw '-AllowSender, -ReportFalsePositive and -User apply to releases only, not to -Delete.' }

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

$messages = New-Object -TypeName System.Collections.Generic.List[object]
if ($Filter) {
    $queryParams = @{ StartReceivedDate = (Get-Date).AddDays(-$DaysBack); EndReceivedDate = (Get-Date); PageSize = 1000; ErrorAction = 'Stop' }
    foreach ($name in @('SenderAddress', 'RecipientAddress', 'QuarantineTypes')) { if ($PSBoundParameters.ContainsKey($name)) { $queryParams[$name] = $PSBoundParameters[$name] } }
    if (-not $Delete) { $queryParams['ReleaseStatus'] = @('NotReleased', 'Requested') }
    $page = 1
    do {
        Write-Progress -Activity 'Searching quarantine' -Status ('Page {0} - {1} match(es) so far' -f $page, $messages.Count)
        try { $batch = @(Get-QuarantineMessage @queryParams -Page $page) }
        catch { throw "Failed to search the quarantine (page $page): $($_.Exception.Message)" }
        foreach ($message in $batch) {
            if (-not $PSBoundParameters.ContainsKey('Subject') -or [string]$message.Subject -like $Subject) { $messages.Add($message) }
        }
        $page++
    } while ($batch.Count -eq 1000 -and $page -le 1000)
    Write-Progress -Activity 'Searching quarantine' -Completed
}
else {
    $ids = $(if ($PSCmdlet.ParameterSetName -eq 'Csv') { @(Import-Csv -Path $InputCsv -ErrorAction Stop | ForEach-Object { [string]$_.Identity }) } else { $Identity })
    foreach ($id in @($ids | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } | Select-Object -Unique)) {
        # A malformed or unknown identity makes Get-QuarantineMessage return every message, so validate before and after the call.
        if ($id -notmatch '^[0-9a-fA-F-]{36}\\[0-9a-fA-F-]{36}$') { Write-Warning "'$id' is not a quarantine identity (expected GUID\GUID); skipped."; continue }
        try {
            $found = @(Get-QuarantineMessage -Identity $id -ErrorAction Stop | Where-Object { [string]$_.Identity -eq $id })
            if ($found.Count -eq 1) { $messages.Add($found[0]) } else { Write-Warning "No quarantined message with identity '$id' was found." }
        }
        catch { Write-Warning "Could not read quarantined message '$id': $($_.Exception.Message)" }
    }
}
Write-Verbose "$($messages.Count) quarantined message(s) selected."

$actionText = $(if ($Delete) { 'Delete from quarantine' } elseif ($PSBoundParameters.ContainsKey('User')) { "Release to $($User -join ', ')" } else { 'Release to all original recipients' })
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($message in $messages) {
    $verdicts = @(@($message.QuarantineTypes) + @($message.Type) | ForEach-Object { [string]$_ } | Select-Object -Unique)
    $row = [PSCustomObject]@{
        Identity         = [string]$message.Identity
        ReceivedTime     = $message.ReceivedTime
        SenderAddress    = [string]$message.SenderAddress
        RecipientAddress = (@($message.RecipientAddress) -join ';')
        Subject          = [string]$message.Subject
        Verdict          = ($verdicts -join ';')
        ReleaseStatus    = [string]$message.ReleaseStatus
        Result           = 'Pending'
        Message          = $null
    }
    $rows.Add($row)
    if (-not $Delete -and [string]$message.ReleaseStatus -eq 'Released') { $row.Result = 'Skipped'; $row.Message = 'Already released'; continue }
    $dangerous = (@($verdicts -match '^(Malware|HighConfPhish)$').Count -gt 0)
    if (-not $Delete -and -not $Force -and $dangerous) { $row.Result = 'Skipped'; $row.Message = 'Malware or high confidence phishing verdict - use -Force to release anyway'; continue }
    $target = '"{0}" from {1} received {2:yyyy-MM-dd HH:mm} [{3}]' -f $message.Subject, $message.SenderAddress, $message.ReceivedTime, ($verdicts -join ',')
    if (-not $PSCmdlet.ShouldProcess($target, $actionText)) { $row.Result = 'Skipped'; $row.Message = 'Not confirmed (or -WhatIf)'; continue }
    try {
        if ($Delete) { Delete-QuarantineMessage -Identity $message.Identity -Confirm:$false -ErrorAction Stop; $row.Result = 'Deleted' }
        else {
            $releaseParams = @{ Identity = $message.Identity; Confirm = $false; ErrorAction = 'Stop' }
            if ($PSBoundParameters.ContainsKey('User')) { $releaseParams['User'] = $User } else { $releaseParams['ReleaseToAll'] = $true }
            if ($AllowSender) { $releaseParams['AllowSender'] = $true }
            if ($ReportFalsePositive) { $releaseParams['ReportFalsePositive'] = $true }
            Release-QuarantineMessage @releaseParams | Out-Null; $row.Result = 'Released'
        }
    }
    catch { $row.Result = 'Failed'; $row.Message = $_.Exception.Message; Write-Warning "$actionText failed for '$($message.Subject)' ($($message.Identity)): $($_.Exception.Message)" }
}

Write-Host ''
Write-Host ('Quarantine {0} - {1} message(s) selected' -f $(if ($Delete) { 'deletion' } else { 'release' }), $rows.Count) -ForegroundColor Cyan
foreach ($group in ($rows | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = switch ($group.Name) { 'Failed' { 'Red' } 'Skipped' { 'Yellow' } default { 'Green' } }
    Write-Host ('  {0,-10} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$rows
#endregion Main
