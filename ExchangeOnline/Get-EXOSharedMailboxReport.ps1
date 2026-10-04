<#
.SYNOPSIS
    Reports shared (and optionally room/equipment) mailboxes with size, license, delegation and hygiene findings.
.DESCRIPTION
    Enumerates shared mailboxes with Get-EXOMailbox, reads size and last activity with Get-EXOMailboxStatistics and
    counts explicit FullAccess (Get-EXOMailboxPermission), SendAs (Get-EXORecipientPermission) and SendOnBehalf
    delegates. Each row carries findings that usually need attention: over 50 GB without a license, hold or
    archive without a license, sign-in not blocked, sent-items copy disabled, or no delegates at all (orphaned).
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) to report instead of all shared mailboxes.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER IncludeResources
    Also include room and equipment mailboxes. Delegation and sent-items findings are only evaluated for shared mailboxes.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOSharedMailboxes_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOSharedMailboxReport.ps1
    Reports every shared mailbox and writes .\Reports\EXOSharedMailboxes_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOSharedMailboxReport.ps1 -IncludeResources -PassThru | Where-Object { $_.Findings -like '*license*' }
    Includes room and equipment mailboxes and returns only the rows with a licensing finding.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients or Global Reader (the report is read-only)
    Category    : Mailbox lifecycle & compliance
    Changes     : No
    Notes       : Three REST calls per mailbox - expect 2-3 seconds each. A shared mailbox needs no license up to 50 GB; larger
                  mailboxes, an archive or a litigation hold require Exchange Online Plan 2 (or Plan 1 plus Exchange Online
                  Archiving). Block sign-in with Update-MgUser -AccountEnabled:$false (Graph); fix sent-items copies with
                  Set-Mailbox -MessageCopyForSentAsEnabled $true -MessageCopyForSendOnBehalfEnabled $true.
.LINK
    https://learn.microsoft.com/exchange/collaboration-exo/shared-mailboxes
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
    [switch]$IncludeResources,

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

function ConvertTo-GB {
    <# Converts Exchange size text such as "1.5 GB (1,610,612,736 bytes)" to GB with 2 decimals; "Unlimited" or empty returns $null. #>
    param([Parameter()][AllowNull()]$Size)
    if ($null -ne $Size -and $Size.ToString() -match '\(([\d,\.]+)\s+bytes\)') {
        return [math]::Round(([double]($Matches[1] -replace '[,\.]', '')) / 1GB, 2)
    }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOSharedMailboxes_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'PrimarySmtpAddress', 'RecipientTypeDetails', 'ExchangeGuid', 'WhenCreated',
    'ArchiveStatus', 'LitigationHoldEnabled', 'InPlaceHolds', 'ProhibitSendReceiveQuota', 'MessageCopyForSentAsEnabled',
    'MessageCopyForSendOnBehalfEnabled', 'SKUAssigned', 'AccountDisabled', 'GrantSendOnBehalfTo')
$recipientTypes = @('SharedMailbox')
if ($IncludeResources) { $recipientTypes += @('RoomMailbox', 'EquipmentMailbox') }

$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try {
            $mailbox = Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop
            # The findings assume shared-mailbox semantics, so user mailboxes passed by mistake are skipped.
            if ($recipientTypes -contains [string]$mailbox.RecipientTypeDetails) { $mailboxes.Add($mailbox) } else { Write-Warning "Skipping '$id' - it is a $($mailbox.RecipientTypeDetails)." }
        }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    try {
        foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails $recipientTypes -Properties $mailboxProperties -ErrorAction Stop)) {
            $mailboxes.Add($mailbox)
        }
    }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $upn = $mailbox.UserPrincipalName
    Write-Progress -Activity 'Collecting shared mailbox details' -Status "$index of $($mailboxes.Count) - $($mailbox.DisplayName)" -PercentComplete (($index / $mailboxes.Count) * 100)

    $stats = $null
    try { $stats = Get-EXOMailboxStatistics -ExchangeGuid $mailbox.ExchangeGuid -Properties LastUserActionTime -ErrorAction Stop }
    catch { Write-Warning "Could not read statistics for '$upn': $($_.Exception.Message)" }
    $sizeGB = ConvertTo-GB -Size $stats.TotalItemSize

    $fullAccessCount = $sendAsCount = $null
    try {
        $fullAccessCount = @(Get-EXOMailboxPermission -Identity $upn -ErrorAction Stop |
            Where-Object { $_.IsInherited -ne $true -and $_.Deny -ne $true -and $_.User -notlike 'NT AUTHORITY\SELF' -and (@($_.AccessRights) -join ',') -match 'FullAccess' }).Count
    }
    catch { Write-Warning "Could not read FullAccess permissions for '$upn': $($_.Exception.Message)" }

    try {
        $sendAsCount = @(Get-EXORecipientPermission -Identity $upn -ErrorAction Stop |
            Where-Object { $_.Trustee -notlike 'NT AUTHORITY\SELF' -and [string]$_.AccessControlType -eq 'Allow' -and (@($_.AccessRights) -join ',') -match 'SendAs' }).Count
    }
    catch { Write-Warning "Could not read SendAs permissions for '$upn': $($_.Exception.Message)" }

    $sendOnBehalfCount = @($mailbox.GrantSendOnBehalfTo | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
    $holdCount = @($mailbox.InPlaceHolds | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
    $licensed = ($mailbox.SKUAssigned -eq $true)
    $isShared = ([string]$mailbox.RecipientTypeDetails -eq 'SharedMailbox')

    $findings = New-Object -TypeName System.Collections.Generic.List[string]
    if (-not $licensed -and $null -ne $sizeGB -and $sizeGB -gt 50) { $findings.Add('Over 50 GB without a license') }
    if (-not $licensed -and ([bool]$mailbox.LitigationHoldEnabled -or $holdCount -gt 0 -or [string]$mailbox.ArchiveStatus -eq 'Active')) { $findings.Add('Hold or archive without a license') }
    if (-not [bool]$mailbox.AccountDisabled) { $findings.Add('Sign-in not blocked') }
    if ($isShared -and ($mailbox.MessageCopyForSentAsEnabled -ne $true -or $mailbox.MessageCopyForSendOnBehalfEnabled -ne $true)) { $findings.Add('Sent items copy disabled') }
    if ($isShared -and $fullAccessCount -eq 0 -and $sendAsCount -eq 0 -and $sendOnBehalfCount -eq 0) { $findings.Add('No delegates') }

    $results.Add([PSCustomObject]@{
            DisplayName        = $mailbox.DisplayName
            PrimarySmtpAddress = [string]$mailbox.PrimarySmtpAddress
            MailboxType        = [string]$mailbox.RecipientTypeDetails
            SizeGB             = $sizeGB
            ItemCount          = $stats.ItemCount
            QuotaGB            = ConvertTo-GB -Size $mailbox.ProhibitSendReceiveQuota
            Licensed           = $licensed
            SignInBlocked      = [bool]$mailbox.AccountDisabled
            ArchiveEnabled     = ([string]$mailbox.ArchiveStatus -eq 'Active')
            LitigationHold     = [bool]$mailbox.LitigationHoldEnabled
            InPlaceHoldCount   = $holdCount
            FullAccessCount    = $fullAccessCount
            SendAsCount        = $sendAsCount
            SendOnBehalfCount  = $sendOnBehalfCount
            LastUserActionTime = $stats.LastUserActionTime
            WhenCreated        = $mailbox.WhenCreated
            Findings           = ($findings -join '; ')
        })
}
Write-Progress -Activity 'Collecting shared mailbox details' -Completed

if ($results.Count -eq 0) { Write-Warning 'No shared mailboxes were found; nothing to export.'; return }
$results | Sort-Object -Property SizeGB -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$totalGB = ($results | Where-Object { $null -ne $_.SizeGB } | Measure-Object -Property SizeGB -Sum).Sum
Write-Host 'Shared mailbox report summary' -ForegroundColor Cyan
Write-Host ('  Mailboxes reported                : {0} ({1} licensed, {2:N2} GB in total)' -f $results.Count, @($results | Where-Object { $_.Licensed }).Count, [double]$totalGB)
foreach ($name in @('Over 50 GB without a license', 'Hold or archive without a license', 'Sign-in not blocked', 'Sent items copy disabled', 'No delegates')) {
    $count = @($results | Where-Object { $_.Findings -like "*$name*" }).Count
    Write-Host ('  {0,-34}: {1}' -f $name, $count) -ForegroundColor $(if ($count -gt 0) { 'Yellow' } else { 'Green' })
}
Write-Host ('  Report                            : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
