<#
.SYNOPSIS
    Reports Recoverable Items folder usage against quota for Exchange Online mailboxes and optionally starts the Managed Folder Assistant.
.DESCRIPTION
    Reads the Recoverable Items subfolders (Deletions, Versions, Purges, DiscoveryHolds, Audits, Calendar Logging,
    SubstrateHolds) with Get-EXOMailboxFolderStatistics -FolderScope RecoverableItems and the quotas and hold state with
    Get-EXOMailbox. Each mailbox gets a PercentOfQuota value and is flagged at -ThresholdPercent; -RunMfa starts the
    Managed Folder Assistant on flagged mailboxes. Mailboxes come from -Identity, a UserPrincipalName CSV or all user mailboxes.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID).
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER ThresholdPercent
    Percentage of RecoverableItemsQuota at or above which a mailbox is flagged AboveThreshold. Default 80.
.PARAMETER RunMfa
    Start the Managed Folder Assistant (Start-ManagedFolderAssistant) on every flagged mailbox. Supports -WhatIf / -Confirm.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXORecoverableItems_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXORecoverableItemsReport.ps1
    Reports Recoverable Items usage of every user mailbox and writes .\Reports\EXORecoverableItems_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXORecoverableItemsReport.ps1 -InputCsv .\Custodians.csv -ThresholdPercent 90 -RunMfa -Confirm:$false
    Reports the listed mailboxes and starts the Managed Folder Assistant on those at 90 % of quota or more without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients or Global Reader for the report; Exchange Administrator (Recipient Management) for -RunMfa
    Category    : Mailbox content & settings
    Changes     : Optional (-RunMfa)
    Notes       : Exchange Online raises RecoverableItemsQuota from 30 GB to 100 GB automatically for mailboxes on hold.
                  The assistant only purges items whose retention expired and that are not on hold; a hold mailbox near
                  100 GB needs an archive with auto-expanding archiving so Recoverable Items can overflow into it.
.LINK
    https://learn.microsoft.com/exchange/security-and-compliance/recoverable-items-folder/recoverable-items-folder
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$ThresholdPercent = 80,

    [Parameter()]
    [switch]$RunMfa,

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

function ConvertTo-Bytes {
    <# Converts Exchange size text such as "30 GB (32,212,254,720 bytes)" to a byte count; "Unlimited" or empty returns $null. #>
    param([Parameter()][AllowNull()]$Size)
    if ($null -ne $Size -and $Size.ToString() -match '\(([\d,]+) bytes\)') { return [long]($Matches[1] -replace ',', '') }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXORecoverableItems_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails', 'RecoverableItemsQuota', 'RecoverableItemsWarningQuota', 'LitigationHoldEnabled',
    'InPlaceHolds', 'ComplianceTagHoldApplied', 'DelayHoldApplied', 'DelayReleaseHoldApplied', 'RetainDeletedItemsFor')
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    Write-Warning 'No -Identity or -InputCsv specified: every user mailbox in the tenant is scanned, one call per mailbox. This can take a long time.'
    try { foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -Properties $mailboxProperties -ErrorAction Stop)) { $mailboxes.Add($mailbox) } }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $upn = $mailbox.UserPrincipalName
    Write-Progress -Activity 'Reading Recoverable Items statistics' -Status "$index of $($mailboxes.Count) - $upn" -PercentComplete (($index / $mailboxes.Count) * 100)
    try { $folders = @(Get-EXOMailboxFolderStatistics -Identity $upn -FolderScope RecoverableItems -ErrorAction Stop) }
    catch { Write-Warning "Could not read Recoverable Items statistics for '$upn': $($_.Exception.Message)"; continue }

    # The root folder is returned too, so summing FolderSize of every row gives the total without double counting subfolders.
    $folderBytes = @{}
    $totalBytes = [long]0
    foreach ($folder in $folders) {
        $bytes = [long](ConvertTo-Bytes -Size $folder.FolderSize)
        $folderBytes[[string]$folder.Name] = $bytes
        $totalBytes += $bytes
    }

    $holdTypes = @()
    if ($mailbox.LitigationHoldEnabled) { $holdTypes += 'Litigation' }
    if (@($mailbox.InPlaceHolds).Count -gt 0) { $holdTypes += ('InPlace/Retention ({0})' -f @($mailbox.InPlaceHolds).Count) }
    if ($mailbox.ComplianceTagHoldApplied) { $holdTypes += 'RetentionLabel' }
    if ($mailbox.DelayHoldApplied -or $mailbox.DelayReleaseHoldApplied) { $holdTypes += 'DelayHold' }

    $quotaBytes = ConvertTo-Bytes -Size $mailbox.RecoverableItemsQuota
    $percentOfQuota = $null
    if ($null -ne $quotaBytes -and $quotaBytes -gt 0) { $percentOfQuota = [math]::Round(($totalBytes / $quotaBytes) * 100, 1) }
    $aboveThreshold = ($null -ne $percentOfQuota -and $percentOfQuota -ge $ThresholdPercent)

    $mfaResult = 'Not requested'
    if ($RunMfa -and -not $aboveThreshold) { $mfaResult = 'Below threshold' }
    elseif ($RunMfa -and $PSCmdlet.ShouldProcess($upn, 'Start the Managed Folder Assistant')) {
        try { Start-ManagedFolderAssistant -Identity $upn -ErrorAction Stop; $mfaResult = 'MFA started' }
        catch { $mfaResult = "Failed: $($_.Exception.Message)"; Write-Warning "Could not start the Managed Folder Assistant on '$upn': $($_.Exception.Message)" }
    }
    elseif ($RunMfa) { $mfaResult = 'Not confirmed' }

    $results.Add([PSCustomObject]@{
            DisplayName                    = $mailbox.DisplayName
            UserPrincipalName              = $upn
            MailboxType                    = [string]$mailbox.RecipientTypeDetails
            OnHold                         = ($holdTypes.Count -gt 0)
            HoldTypes                      = ($holdTypes -join '; ')
            RetainDeletedItemsFor          = [string]$mailbox.RetainDeletedItemsFor
            TotalRecoverableItemsGB        = [math]::Round($totalBytes / 1GB, 2)
            DeletionsMB                    = [math]::Round([double]$folderBytes['Deletions'] / 1MB, 2)
            VersionsMB                     = [math]::Round([double]$folderBytes['Versions'] / 1MB, 2)
            PurgesMB                       = [math]::Round([double]$folderBytes['Purges'] / 1MB, 2)
            DiscoveryHoldsMB               = [math]::Round([double]$folderBytes['DiscoveryHolds'] / 1MB, 2)
            AuditsMB                       = [math]::Round([double]$folderBytes['Audits'] / 1MB, 2)
            CalendarLoggingMB              = [math]::Round([double]$folderBytes['Calendar Logging'] / 1MB, 2)
            SubstrateHoldsMB               = [math]::Round([double]$folderBytes['SubstrateHolds'] / 1MB, 2)
            RecoverableItemsQuotaGB        = $(if ($null -ne $quotaBytes) { [math]::Round($quotaBytes / 1GB, 2) })
            RecoverableItemsWarningQuotaGB = [math]::Round([double](ConvertTo-Bytes -Size $mailbox.RecoverableItemsWarningQuota) / 1GB, 2)
            PercentOfQuota                 = $percentOfQuota
            AboveThreshold                 = $aboveThreshold
            MfaResult                      = $mfaResult
        })
}
Write-Progress -Activity 'Reading Recoverable Items statistics' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes could be evaluated; nothing to export.'; return }
$results | Sort-Object -Property PercentOfQuota -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$flagged = @($results | Where-Object { $_.AboveThreshold } | Sort-Object -Property PercentOfQuota -Descending)
$totalGB = ($results | Measure-Object -Property TotalRecoverableItemsGB -Sum).Sum

$onHold = @($results | Where-Object { $_.OnHold }).Count
Write-Host ('Recoverable Items summary: {0} mailboxes, {1:N2} GB in Recoverable Items, {2} on hold' -f $results.Count, [double]$totalGB, $onHold) -ForegroundColor Cyan
Write-Host ('  At or above {0}% of quota: {1}' -f $ThresholdPercent, $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in @($flagged | Select-Object -First 15)) {
    Write-Host ('    {0,6:N1}%  {1}  {2:N2} of {3:N2} GB  {4}' -f $row.PercentOfQuota, $row.UserPrincipalName, $row.TotalRecoverableItemsGB, $row.RecoverableItemsQuotaGB, $row.HoldTypes)
}
if ($RunMfa) {
    $started = @($results | Where-Object { $_.MfaResult -eq 'MFA started' }).Count
    $failed = @($results | Where-Object { $_.MfaResult -like 'Failed*' }).Count
    Write-Host ('  Managed Folder Assistant: {0} started, {1} failed' -f $started, $failed) -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })
}
Write-Host ('  Report: {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
