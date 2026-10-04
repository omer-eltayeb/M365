<#
.SYNOPSIS
    Disables legacy client protocols (POP, IMAP, SMTP AUTH, ActiveSync, EWS) on mailboxes and optionally at the organization level.
.DESCRIPTION
    Reads the protocol switches of each selected mailbox with Get-EXOCASMailbox and disables the requested protocols with
    Set-CASMailbox (POP and IMAP when no protocol switch is given); mailboxes where they are already off are skipped. -OrgLevel
    also disables SMTP AUTH for the organization (Set-TransportConfig) and POP/IMAP on every CAS mailbox plan (Set-CASMailboxPlan)
    so new mailboxes start with the protocols off. Nothing changes unless -Apply is given; every change uses ShouldProcess. CSV results.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) to process instead of all user mailboxes.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to process.
.PARAMETER DisablePop
    Disable POP3. Used by default together with -DisableImap when no protocol switch is given.
.PARAMETER DisableImap
    Disable IMAP4. Used by default together with -DisablePop when no protocol switch is given.
.PARAMETER DisableSmtpAuth
    Set SmtpClientAuthenticationDisabled to True on the mailbox (explicit per-mailbox SMTP AUTH block).
.PARAMETER DisableActiveSync
    Disable Exchange ActiveSync (also blocks Outlook for iOS and Android, which relies on the ActiveSync switch).
.PARAMETER DisableEws
    Disable Exchange Web Services (breaks Outlook for Mac, Teams calendar integration and many add-ins - use with care).
.PARAMETER OrgLevel
    Also disable SMTP AUTH organization-wide and POP/IMAP on all CAS mailbox plans before processing the mailboxes.
.PARAMETER Apply
    Perform the changes. Without it the script only reports what would be disabled.
.PARAMETER OutputPath
    Path of the CSV results file. Defaults to .\Reports\EXODisableLegacyProtocols_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\Set-EXODisableLegacyProtocols.ps1
    Reports every user mailbox that still has POP or IMAP enabled without changing anything.
.EXAMPLE
    PS> .\Set-EXODisableLegacyProtocols.ps1 -DisablePop -DisableImap -DisableSmtpAuth -OrgLevel -Apply -Confirm:$false
    Disables SMTP AUTH org-wide, turns POP/IMAP off on all mailbox plans and user mailboxes, and blocks SMTP AUTH per mailbox.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator (Organization Configuration role for -OrgLevel); View-Only Recipients for the report
    Category    : Client access & mobile devices
    Changes     : Yes
    Notes       : SMTP AUTH counts as already disabled when the mailbox override is True, or blank while the organization default
                  is disabled. Devices and apps that still need SMTP AUTH get a per-mailbox exception with Set-CASMailbox
                  -SmtpClientAuthenticationDisabled $false. Protocol changes can take up to an hour to take effect.
.LINK
    https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/pop3-and-imap4/enable-or-disable-pop3-or-imap4-access
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
    [switch]$DisablePop,

    [Parameter()]
    [switch]$DisableImap,

    [Parameter()]
    [switch]$DisableSmtpAuth,

    [Parameter()]
    [switch]$DisableActiveSync,

    [Parameter()]
    [switch]$DisableEws,

    [Parameter()]
    [switch]$OrgLevel,

    [Parameter()]
    [switch]$Apply,

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
if (-not ($DisablePop -or $DisableImap -or $DisableSmtpAuth -or $DisableActiveSync -or $DisableEws)) { $DisablePop = $true; $DisableImap = $true }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXODisableLegacyProtocols_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }
try { $orgSmtpAuthDisabled = [bool](Get-TransportConfig -ErrorAction Stop).SmtpClientAuthenticationDisabled }
catch { throw "Failed to read the transport configuration: $($_.Exception.Message)" }

# Phase 1 collects every target with the protocols that are still on; phase 2 applies the changes under ShouldProcess.
$targets = New-Object -TypeName System.Collections.Generic.List[object]
if ($OrgLevel) {
    $orgPending = @()
    if (-not $orgSmtpAuthDisabled) { $orgPending += 'SMTP AUTH' }
    $orgParams = @{ SmtpClientAuthenticationDisabled = $true }
    $targets.Add([PSCustomObject]@{ Target = 'Organization'; TargetType = 'TransportConfig'; Cmdlet = 'Set-TransportConfig'; Pending = $orgPending; Params = $orgParams })
    try { $plans = @(Get-CASMailboxPlan -ErrorAction Stop) }
    catch { Write-Warning "Could not read the CAS mailbox plans: $($_.Exception.Message)"; $plans = @() }
    foreach ($plan in $plans) {
        $planPending = @()
        if ([bool]$plan.PopEnabled) { $planPending += 'POP' }
        if ([bool]$plan.ImapEnabled) { $planPending += 'IMAP' }
        $planParams = @{ Identity = [string]$plan.Identity; PopEnabled = $false; ImapEnabled = $false }
        $targets.Add([PSCustomObject]@{ Target = $plan.Name; TargetType = 'CasMailboxPlan'; Cmdlet = 'Set-CASMailboxPlan'; Pending = $planPending; Params = $planParams })
    }
}

$selection = @($Identity)
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
$casProperties = @('DisplayName', 'PrimarySmtpAddress', 'PopEnabled', 'ImapEnabled', 'SmtpClientAuthenticationDisabled', 'ActiveSyncEnabled', 'EwsEnabled')
$casMailboxes = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($id in $selection) {
    try { $casMailboxes.Add((Get-EXOCASMailbox -Identity $id -Properties $casProperties -ErrorAction Stop)) }
    catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
}
if ($selection.Count -eq 0) {
    try { $casMailboxes.AddRange(@(Get-EXOCASMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -Properties $casProperties -ErrorAction Stop)) }
    catch { throw "Failed to retrieve CAS mailbox settings: $($_.Exception.Message)" }
}
foreach ($cas in $casMailboxes) {
    $address = [string]$cas.PrimarySmtpAddress
    $setParams = @{ Identity = $address }
    $pending = @()
    if ($DisablePop -and [bool]$cas.PopEnabled) { $setParams['PopEnabled'] = $false; $pending += 'POP' }
    if ($DisableImap -and [bool]$cas.ImapEnabled) { $setParams['ImapEnabled'] = $false; $pending += 'IMAP' }
    if ($DisableActiveSync -and [bool]$cas.ActiveSyncEnabled) { $setParams['ActiveSyncEnabled'] = $false; $pending += 'ActiveSync' }
    if ($DisableEws -and [bool]$cas.EwsEnabled) { $setParams['EwsEnabled'] = $false; $pending += 'EWS' }
    # The override is True, False or blank (inherit): SMTP AUTH is on when it is False, or blank while the org default allows it.
    $smtpOverride = [string]$cas.SmtpClientAuthenticationDisabled
    $smtpAuthOn = ($smtpOverride -eq 'False') -or ($smtpOverride -eq '' -and -not $orgSmtpAuthDisabled)
    if ($DisableSmtpAuth -and $smtpAuthOn) { $setParams['SmtpClientAuthenticationDisabled'] = $true; $pending += 'SMTP AUTH' }
    $targets.Add([PSCustomObject]@{ Target = $address; TargetType = 'Mailbox'; Cmdlet = 'Set-CASMailbox'; Pending = $pending; Params = $setParams })
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($item in $targets) {
    $index++
    Write-Progress -Activity 'Disabling legacy protocols' -Status "$index of $($targets.Count) - $($item.Target)" -PercentComplete (($index / $targets.Count) * 100)
    $action = (@($item.Pending) -join ', ')
    $result = 'Already disabled'
    if (@($item.Pending).Count -gt 0) {
        if (-not $Apply) { $result = "Would disable: $action" }
        elseif ($PSCmdlet.ShouldProcess($item.Target, "Disable $action")) {
            $params = $item.Params
            try { & $item.Cmdlet @params -ErrorAction Stop; $result = "Disabled: $action" }
            catch { $result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not disable $action on '$($item.Target)': $($_.Exception.Message)" }
        }
        else { $result = 'Not confirmed' }
    }
    $results.Add([PSCustomObject]@{ Target = $item.Target; TargetType = $item.TargetType; EnabledBefore = $action; Result = $result })
}
Write-Progress -Activity 'Disabling legacy protocols' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes could be evaluated; nothing to export.'; return }
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$failed = @($results | Where-Object { $_.Result -like 'Failed*' }).Count

Write-Host "Legacy protocol summary ($($results.Count) targets evaluated)" -ForegroundColor Cyan
Write-Host ('  Already disabled : {0}' -f @($results | Where-Object { $_.Result -eq 'Already disabled' }).Count) -ForegroundColor Green
Write-Host ('  Would disable    : {0}' -f @($results | Where-Object { $_.Result -like 'Would disable*' }).Count) -ForegroundColor Yellow
Write-Host ('  Disabled         : {0}' -f @($results | Where-Object { $_.Result -like 'Disabled:*' }).Count) -ForegroundColor Green
Write-Host ('  Not confirmed    : {0}' -f @($results | Where-Object { $_.Result -eq 'Not confirmed' }).Count)
Write-Host ('  Failed           : {0}' -f $failed) -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })
if (-not $Apply) { Write-Host '  Read-only mode: add -Apply to disable the protocols.' -ForegroundColor Yellow }
Write-Host ('  Results          : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
