<#
.SYNOPSIS
    Reports which client access protocols (POP, IMAP, SMTP AUTH, ActiveSync, EWS, MAPI, OWA, Outlook clients) each mailbox can use.
.DESCRIPTION
    Reads the protocol switches of every selected mailbox with Get-EXOCASMailbox (ActiveSync, IMAP, POP, MAPI, EWS, OWA,
    OWA for Devices, Outlook Mobile, Universal Outlook, Outlook for Mac, EWS client restrictions, OWA and ActiveSync policies)
    and the organization SMTP AUTH default from Get-TransportConfig. SmtpClientAuthenticationDisabled on a mailbox is a
    tri-state override (True, False or blank = inherit the organization default), so the report derives EffectiveSmtpAuth
    per mailbox and flags every mailbox that can still use POP, IMAP or SMTP AUTH. Writes a CSV and prints a protocol summary.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) to report instead of all mailboxes.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER RecipientTypeDetails
    Mailbox types to include when neither -Identity nor -InputCsv is used. Default: UserMailbox.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOCasMailboxProtocols_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOCasMailboxProtocolReport.ps1
    Reports every user mailbox and shows how many can still use POP, IMAP or SMTP AUTH.
.EXAMPLE
    PS> .\Get-EXOCasMailboxProtocolReport.ps1 -RecipientTypeDetails UserMailbox, SharedMailbox -PassThru | Where-Object { $_.EffectiveSmtpAuth }
    Includes shared mailboxes and returns only the mailboxes that are effectively allowed to use SMTP AUTH.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients + View-Only Configuration (or Global Reader)
    Category    : Client access & mobile devices
    Changes     : No
    Notes       : Basic authentication is retired for every protocol except SMTP AUTH, so POP and IMAP are only usable by OAuth
                  capable clients; disabling them anyway removes the attack surface. A blank EwsAllowOutlook / EwsAllowMacOutlook
                  means the client is not restricted. Use Set-EXODisableLegacyProtocols.ps1 to act on the flagged mailboxes.
.LINK
    https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission
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

    [Parameter(ParameterSetName = 'All')]
    [ValidateSet('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox')]
    [string[]]$RecipientTypeDetails = @('UserMailbox'),

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
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOCasMailboxProtocols_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try { $orgSmtpAuthDisabled = [bool](Get-TransportConfig -ErrorAction Stop).SmtpClientAuthenticationDisabled }
catch { throw "Failed to read the transport configuration: $($_.Exception.Message)" }

$casProperties = @('DisplayName', 'PrimarySmtpAddress', 'ActiveSyncEnabled', 'ImapEnabled', 'PopEnabled', 'MAPIEnabled', 'EwsEnabled', 'OWAEnabled',
    'OWAforDevicesEnabled', 'SmtpClientAuthenticationDisabled', 'OwaMailboxPolicy', 'ActiveSyncMailboxPolicy', 'EwsAllowOutlook', 'EwsAllowMacOutlook',
    'EwsApplicationAccessPolicy', 'UniversalOutlookEnabled', 'OutlookMobileEnabled', 'MacOutlookEnabled')
$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$casMailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $casMailboxes.Add((Get-EXOCASMailbox -Identity $id -Properties $casProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    try {
        foreach ($cas in (Get-EXOCASMailbox -ResultSize Unlimited -RecipientTypeDetails $RecipientTypeDetails -Properties $casProperties -ErrorAction Stop)) {
            $casMailboxes.Add($cas)
        }
    }
    catch { throw "Failed to retrieve CAS mailbox settings: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($cas in $casMailboxes) {
    $index++
    if ($index % 100 -eq 0) { Write-Progress -Activity 'Evaluating client access protocols' -Status "$index of $($casMailboxes.Count)" -PercentComplete (($index / $casMailboxes.Count) * 100) }

    # The REST cmdlet returns the override as True, False or blank; blank means the organization default applies.
    $overrideText = [string]$cas.SmtpClientAuthenticationDisabled
    $smtpAuthOverride = 'Inherit'
    $smtpAuthEnabled = -not $orgSmtpAuthDisabled
    if ($overrideText -eq 'True') { $smtpAuthOverride = 'Disabled'; $smtpAuthEnabled = $false }
    elseif ($overrideText -eq 'False') { $smtpAuthOverride = 'Enabled'; $smtpAuthEnabled = $true }

    $flags = @()
    if ([bool]$cas.PopEnabled) { $flags += 'POP enabled' }
    if ([bool]$cas.ImapEnabled) { $flags += 'IMAP enabled' }
    if ($smtpAuthEnabled) { $flags += 'SMTP AUTH enabled' }

    $results.Add([PSCustomObject]@{
            DisplayName                = $cas.DisplayName
            PrimarySmtpAddress         = [string]$cas.PrimarySmtpAddress
            PopEnabled                 = [bool]$cas.PopEnabled
            ImapEnabled                = [bool]$cas.ImapEnabled
            SmtpAuthOverride           = $smtpAuthOverride
            EffectiveSmtpAuth          = $smtpAuthEnabled
            ActiveSyncEnabled          = [bool]$cas.ActiveSyncEnabled
            EwsEnabled                 = [bool]$cas.EwsEnabled
            MapiEnabled                = [bool]$cas.MAPIEnabled
            OwaEnabled                 = [bool]$cas.OWAEnabled
            OwaForDevicesEnabled       = [bool]$cas.OWAforDevicesEnabled
            OutlookMobileEnabled       = [bool]$cas.OutlookMobileEnabled
            UniversalOutlookEnabled    = [bool]$cas.UniversalOutlookEnabled
            MacOutlookEnabled          = [bool]$cas.MacOutlookEnabled
            EwsAllowOutlook            = [string]$cas.EwsAllowOutlook
            EwsAllowMacOutlook         = [string]$cas.EwsAllowMacOutlook
            EwsApplicationAccessPolicy = [string]$cas.EwsApplicationAccessPolicy
            OwaMailboxPolicy           = [string]$cas.OwaMailboxPolicy
            ActiveSyncMailboxPolicy    = [string]$cas.ActiveSyncMailboxPolicy
            Flags                      = ($flags -join '; ')
        })
}
Write-Progress -Activity 'Evaluating client access protocols' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes were found; nothing to export.'; return }
$results | Sort-Object -Property DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$flagged = @($results | Where-Object { $_.Flags -ne '' }).Count
$smtpAuthCount = @($results | Where-Object { $_.EffectiveSmtpAuth }).Count

Write-Host "Client access protocol summary ($($results.Count) mailboxes)" -ForegroundColor Cyan
Write-Host ('  Org SMTP AUTH default      : {0}' -f $(if ($orgSmtpAuthDisabled) { 'Disabled' } else { 'Enabled' })) -ForegroundColor $(if ($orgSmtpAuthDisabled) { 'Green' } else { 'Yellow' })
Write-Host ('  POP enabled                : {0}' -f @($results | Where-Object { $_.PopEnabled }).Count)
Write-Host ('  IMAP enabled               : {0}' -f @($results | Where-Object { $_.ImapEnabled }).Count)
Write-Host ('  SMTP AUTH effectively on   : {0} ({1} explicit mailbox overrides)' -f $smtpAuthCount, @($results | Where-Object { $_.SmtpAuthOverride -eq 'Enabled' }).Count)
Write-Host ('  ActiveSync enabled         : {0}' -f @($results | Where-Object { $_.ActiveSyncEnabled }).Count)
Write-Host ('  EWS enabled                : {0}' -f @($results | Where-Object { $_.EwsEnabled }).Count)
Write-Host ('  OWA disabled               : {0}' -f @($results | Where-Object { -not $_.OwaEnabled }).Count)
Write-Host ('  Flagged (POP/IMAP/SMTP)    : {0}' -f $flagged) -ForegroundColor $(if ($flagged -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Report                     : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
