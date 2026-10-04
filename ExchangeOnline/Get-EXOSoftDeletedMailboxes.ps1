<#
.SYNOPSIS
    Reports soft-deleted and inactive mailboxes with purge dates, holds and size, and can restore content into another mailbox.
.DESCRIPTION
    Lists soft-deleted mailboxes with Get-EXOMailbox -SoftDeletedMailbox (or inactive mailboxes kept by a hold with
    -InactiveMailboxOnly), reads their size with Get-EXOMailboxStatistics -IncludeSoftDeletedRecipients and calculates
    the days left before Exchange permanently purges each soft-deleted mailbox (30 days after WhenSoftDeleted; inactive
    mailboxes are kept for as long as a hold applies). With -Restore the content of one soft-deleted or inactive mailbox
    is copied into an existing mailbox through New-MailboxRestoreRequest -AllowLegacyDNMismatch (ShouldProcess).
.PARAMETER InactiveMailboxOnly
    Report inactive mailboxes (Get-EXOMailbox -InactiveMailboxOnly) instead of all soft-deleted mailboxes.
.PARAMETER Restore
    Restore mode: copy the content of the soft-deleted mailbox given by -Identity into -TargetMailbox.
.PARAMETER Identity
    The soft-deleted or inactive mailbox to restore. Use the ExchangeGuid from the report when several deleted mailboxes share an address.
.PARAMETER TargetMailbox
    Existing mailbox (UPN or primary SMTP address) that receives the restored content.
.PARAMETER TargetRootFolder
    Optional folder in the target mailbox under which the content is restored, for example "Restored - J. Smith".
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOSoftDeletedMailboxes_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects (or the restore request) to the pipeline.
.EXAMPLE
    PS> .\Get-EXOSoftDeletedMailboxes.ps1
    Lists every soft-deleted mailbox with DaysUntilPurge and writes .\Reports\EXOSoftDeletedMailboxes_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOSoftDeletedMailboxes.ps1 -Restore -Identity 7f3c2b9e-1234-4a5b-9c8d-0e1f2a3b4c5d -TargetMailbox manager@contoso.com -TargetRootFolder 'Restored - J. Smith'
    Queues a restore request that copies the deleted mailbox into a folder of the manager's mailbox after confirmation.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients or Global Reader for the report; Exchange Administrator (Recipient Management) for -Restore
    Category    : Mailbox lifecycle & compliance
    Changes     : Optional (-Restore)
    Notes       : A mailbox is soft-deleted when its user is deleted or its Exchange license is removed; restoring the Entra user
                  within 30 days (Restore-MgDirectoryDeletedItem) brings the mailbox back intact and is preferable to copying
                  content. Add -SourceIsArchive / -TargetIsArchive to New-MailboxRestoreRequest for archive content. Inactive
                  mailboxes need no license and are purged only after every hold is released (plus the 30-day delay hold).
.LINK
    https://learn.microsoft.com/exchange/recipients-in-exchange-online/delete-or-restore-mailboxes
.LINK
    https://learn.microsoft.com/powershell/module/exchange/new-mailboxrestorerequest
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Report')]
param(
    [Parameter(ParameterSetName = 'Report')]
    [switch]$InactiveMailboxOnly,

    [Parameter(Mandatory = $true, ParameterSetName = 'Restore')]
    [switch]$Restore,

    [Parameter(Mandatory = $true, ParameterSetName = 'Restore')]
    [string]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Restore')]
    [string]$TargetMailbox,

    [Parameter(ParameterSetName = 'Restore')]
    [string]$TargetRootFolder,

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
try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'PrimarySmtpAddress', 'RecipientTypeDetails', 'ExchangeGuid', 'ExternalDirectoryObjectId',
    'WhenSoftDeleted', 'WhenCreated', 'IsInactiveMailbox', 'LitigationHoldEnabled', 'InPlaceHolds', 'ArchiveStatus')

if ($Restore) {
    # Soft-deleted and inactive mailboxes live in different views, so look in both before giving up.
    $candidates = @()
    foreach ($scope in @(@{ SoftDeletedMailbox = $true }, @{ InactiveMailboxOnly = $true })) {
        try { $candidates = @(Get-EXOMailbox -Identity $Identity -Properties $mailboxProperties @scope -ErrorAction Stop) } catch { $candidates = @() }
        if ($candidates.Count -gt 0) { break }
    }
    if ($candidates.Count -eq 0) { throw "No soft-deleted or inactive mailbox matches '$Identity'. Run the report first and use the ExchangeGuid." }
    if ($candidates.Count -gt 1) { throw "'$Identity' matches $($candidates.Count) deleted mailboxes; use the ExchangeGuid from the report instead." }
    $source = $candidates[0]
    try { $target = Get-EXOMailbox -Identity $TargetMailbox -Properties PrimarySmtpAddress -ErrorAction Stop }
    catch { throw "Target mailbox '$TargetMailbox' was not found: $($_.Exception.Message)" }

    $operation = "Restore content of deleted mailbox '$($source.DisplayName)' ($($source.ExchangeGuid), deleted $($source.WhenSoftDeleted))"
    if ($PSCmdlet.ShouldProcess([string]$target.PrimarySmtpAddress, $operation)) {
        $restoreParams = @{ SourceMailbox = [string]$source.ExchangeGuid; TargetMailbox = [string]$target.PrimarySmtpAddress; AllowLegacyDNMismatch = $true; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($TargetRootFolder)) { $restoreParams['TargetRootFolder'] = $TargetRootFolder }
        try { $request = New-MailboxRestoreRequest @restoreParams }
        catch { throw "New-MailboxRestoreRequest failed: $($_.Exception.Message)" }
        Write-Host ("Restore request '{0}' created with status '{1}'." -f $request.Name, $request.Status) -ForegroundColor Green
        Write-Host ("Track progress with: Get-MailboxRestoreRequest -TargetMailbox '{0}' | Get-MailboxRestoreRequestStatistics" -f $target.PrimarySmtpAddress)
        if ($PassThru) { $request }
    }
    return
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOSoftDeletedMailboxes_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$getParams = @{ ResultSize = 'Unlimited'; Properties = $mailboxProperties; ErrorAction = 'Stop' }
if ($InactiveMailboxOnly) { $getParams['InactiveMailboxOnly'] = $true } else { $getParams['SoftDeletedMailbox'] = $true }
try { $mailboxes = @(Get-EXOMailbox @getParams) }
catch { throw "Failed to retrieve soft-deleted mailboxes: $($_.Exception.Message)" }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$now = Get-Date
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    Write-Progress -Activity 'Reading soft-deleted mailboxes' -Status "$index of $($mailboxes.Count) - $($mailbox.DisplayName)" -PercentComplete (($index / $mailboxes.Count) * 100)
    $stats = $null
    try { $stats = Get-EXOMailboxStatistics -ExchangeGuid $mailbox.ExchangeGuid -IncludeSoftDeletedRecipients -ErrorAction Stop }
    catch { Write-Warning "Could not read statistics for '$($mailbox.PrimarySmtpAddress)': $($_.Exception.Message)" }

    $ageDays = $null
    $daysUntilPurge = $null
    if ($null -ne $mailbox.WhenSoftDeleted) {
        $ageDays = [int][math]::Floor((New-TimeSpan -Start ([datetime]$mailbox.WhenSoftDeleted) -End $now).TotalDays)
        # Only plain soft-deleted mailboxes are purged after 30 days; inactive mailboxes stay until their holds are released.
        if (-not [bool]$mailbox.IsInactiveMailbox) { $daysUntilPurge = [math]::Max(0, 30 - $ageDays) }
    }

    $results.Add([PSCustomObject]@{
            DisplayName               = $mailbox.DisplayName
            PrimarySmtpAddress        = [string]$mailbox.PrimarySmtpAddress
            UserPrincipalName         = $mailbox.UserPrincipalName
            MailboxType               = [string]$mailbox.RecipientTypeDetails
            WhenSoftDeleted           = $mailbox.WhenSoftDeleted
            AgeDays                   = $ageDays
            DaysUntilPurge            = $daysUntilPurge
            IsInactiveMailbox         = [bool]$mailbox.IsInactiveMailbox
            LitigationHold            = [bool]$mailbox.LitigationHoldEnabled
            InPlaceHoldCount          = @($mailbox.InPlaceHolds | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
            SizeGB                    = ConvertTo-GB -Size $stats.TotalItemSize
            ItemCount                 = $stats.ItemCount
            ArchiveStatus             = [string]$mailbox.ArchiveStatus
            ExchangeGuid              = [string]$mailbox.ExchangeGuid
            ExternalDirectoryObjectId = [string]$mailbox.ExternalDirectoryObjectId
            WhenCreated               = $mailbox.WhenCreated
        })
}
Write-Progress -Activity 'Reading soft-deleted mailboxes' -Completed

if ($results.Count -eq 0) { Write-Host 'No soft-deleted mailboxes were found; nothing to export.' -ForegroundColor Green; return }
$results | Sort-Object -Property DaysUntilPurge, WhenSoftDeleted | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$purgeSoon = @($results | Where-Object { $null -ne $_.DaysUntilPurge -and $_.DaysUntilPurge -le 7 }).Count

Write-Host ''
Write-Host 'Soft-deleted mailbox summary' -ForegroundColor Cyan
Write-Host ('  Mailboxes found           : {0} ({1:N2} GB)' -f $results.Count, [double]($results | Where-Object { $null -ne $_.SizeGB } | Measure-Object -Property SizeGB -Sum).Sum)
Write-Host ('  Inactive (kept by holds)  : {0}' -f @($results | Where-Object { $_.IsInactiveMailbox }).Count)
Write-Host ('  Purged within 7 days      : {0}' -f $purgeSoon) -ForegroundColor $(if ($purgeSoon -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Report                    : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
