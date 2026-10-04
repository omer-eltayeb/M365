<#
.SYNOPSIS
    Reports mailbox auditing status (tenant default, per-mailbox settings, bypass accounts) and can restore the defaults.
.DESCRIPTION
    Reads AuditDisabled from Get-OrganizationConfig (mailbox auditing on by default is active when it is False), then
    collects AuditEnabled, AuditLogAgeLimit, DefaultAuditSet and the Admin/Delegate/Owner action lists for each mailbox
    with Get-EXOMailbox. A mailbox is flagged when AuditEnabled is False or when an action set was customized (the logon
    type is missing from DefaultAuditSet). Accounts excluded from auditing through Get-MailboxAuditBypassAssociation are
    exported to <report>_BypassAccounts.csv. -SetDefaults runs Set-Mailbox -AuditEnabled $true -DefaultAuditSet
    Admin,Delegate,Owner on flagged mailboxes with ShouldProcess (-WhatIf / -Confirm).
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) to report instead of all mailboxes.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER RecipientTypeDetails
    Mailbox types to include. Default: UserMailbox and SharedMailbox.
.PARAMETER SetDefaults
    Re-enable auditing and restore the default action sets on flagged mailboxes. Without it the script is read-only.
.PARAMETER SkipBypassCheck
    Skip Get-MailboxAuditBypassAssociation, which enumerates every recipient and is slow in large tenants.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOMailboxAudit_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMailboxAuditStatus.ps1
    Reports the tenant default, every user and shared mailbox, and writes the bypass accounts to a second CSV.
.EXAMPLE
    PS> .\Get-EXOMailboxAuditStatus.ps1 -SetDefaults -SkipBypassCheck -WhatIf
    Shows which mailboxes would have auditing re-enabled or their action sets restored, without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Configuration + View-Only Recipients (or Global Reader) for the report; Exchange Administrator for -SetDefaults
    Category    : Mailbox lifecycle & compliance
    Changes     : Optional (-SetDefaults)
    Notes       : While AuditDisabled is False the tenant default overrides a per-mailbox AuditEnabled = False, so those mailboxes
                  are still audited; customized action sets and bypass associations do reduce what is logged. If AuditDisabled is
                  True nothing is audited for any mailbox - fix it with Set-OrganizationConfig -AuditDisabled $false. Bypass entries
                  are removed with Set-MailboxAuditBypassAssociation -Identity <account> -AuditBypassEnabled $false.
.LINK
    https://learn.microsoft.com/purview/audit-mailboxes
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
    [ValidateSet('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox')]
    [string[]]$RecipientTypeDetails = @('UserMailbox', 'SharedMailbox'),

    [Parameter()]
    [switch]$SetDefaults,

    [Parameter()]
    [switch]$SkipBypassCheck,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMailboxAudit_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$bypassPath = [System.IO.Path]::Combine([string]$outputFolder, ([System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_BypassAccounts.csv'))

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try { $orgAuditOn = -not [bool](Get-OrganizationConfig -ErrorAction Stop).AuditDisabled }
catch { throw "Failed to read the organization configuration: $($_.Exception.Message)" }
if (-not $orgAuditOn) { Write-Warning 'Mailbox auditing on by default is OFF for this tenant (AuditDisabled = True); no mailbox actions are being recorded.' }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails', 'AuditEnabled', 'AuditLogAgeLimit', 'DefaultAuditSet', 'AuditAdmin', 'AuditDelegate', 'AuditOwner')
$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    try {
        foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails $RecipientTypeDetails -Properties $mailboxProperties -ErrorAction Stop)) {
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
    if ($index % 50 -eq 0 -or $SetDefaults) { Write-Progress -Activity 'Checking mailbox auditing' -Status "$index of $($mailboxes.Count) - $upn" -PercentComplete (($index / $mailboxes.Count) * 100) }

    # Changing an action list with Set-Mailbox removes that logon type from DefaultAuditSet, which is how customization is detected.
    $defaultSet = @($mailbox.DefaultAuditSet | ForEach-Object { [string]$_ })
    $customized = @('Admin', 'Delegate', 'Owner' | Where-Object { $defaultSet -notcontains $_ })
    $isDefault = ([bool]$mailbox.AuditEnabled -and $customized.Count -eq 0)
    $ageDays = $null
    if ("$($mailbox.AuditLogAgeLimit)" -match '^(\d+)\.') { $ageDays = [int]$Matches[1] }

    $result = 'Report only'
    if ($isDefault) { $result = 'Default configuration' }
    elseif ($SetDefaults) {
        if ($PSCmdlet.ShouldProcess($upn, 'Enable mailbox auditing with the default Admin, Delegate and Owner action sets')) {
            try {
                Set-Mailbox -Identity $upn -AuditEnabled $true -DefaultAuditSet Admin, Delegate, Owner -ErrorAction Stop
                $result = 'Defaults restored'
            }
            catch { $result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not restore audit defaults on '$upn': $($_.Exception.Message)" }
        }
        else { $result = 'Not confirmed' }
    }

    $results.Add([PSCustomObject]@{
            DisplayName            = $mailbox.DisplayName
            UserPrincipalName      = $upn
            MailboxType            = [string]$mailbox.RecipientTypeDetails
            AuditEnabled           = [bool]$mailbox.AuditEnabled
            AuditLogAgeDays        = $ageDays
            DefaultAuditSet        = ($defaultSet -join ', ')
            CustomizedLogonTypes   = ($customized -join ', ')
            IsDefaultConfiguration = $isDefault
            AdminActionCount       = @($mailbox.AuditAdmin).Count
            DelegateActionCount    = @($mailbox.AuditDelegate).Count
            OwnerActionCount       = @($mailbox.AuditOwner).Count
            Result                 = $result
        })
}
Write-Progress -Activity 'Checking mailbox auditing' -Completed

$bypassAccounts = @()
if (-not $SkipBypassCheck) {
    Write-Verbose 'Enumerating mailbox audit bypass associations (this reads every recipient).'
    try {
        $bypassAccounts = @(Get-MailboxAuditBypassAssociation -ResultSize Unlimited -ErrorAction Stop | Where-Object { $_.AuditBypassEnabled } |
            Select-Object -Property Name, @{ Name = 'Identity'; Expression = { [string]$_.Identity } }, AuditBypassEnabled, WhenChanged)
        if ($bypassAccounts.Count -gt 0) { $bypassAccounts | Export-Csv -Path $bypassPath -NoTypeInformation -Encoding UTF8 }
    }
    catch { Write-Warning "Could not read audit bypass associations: $($_.Exception.Message)" }
}

if ($results.Count -eq 0) { Write-Warning 'No mailboxes were found; nothing to export.'; return }
$results | Sort-Object -Property IsDefaultConfiguration, DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$flagged = @($results | Where-Object { -not $_.IsDefaultConfiguration }).Count

Write-Host 'Mailbox auditing summary' -ForegroundColor Cyan
Write-Host ('  Auditing on by default (tenant) : {0}' -f $(if ($orgAuditOn) { 'On' } else { 'OFF - nothing is audited' })) -ForegroundColor $(if ($orgAuditOn) { 'Green' } else { 'Red' })
Write-Host ('  Mailboxes checked               : {0} ({1} with AuditEnabled = False)' -f $results.Count, @($results | Where-Object { -not $_.AuditEnabled }).Count)
Write-Host ('  Customized action sets          : {0}' -f @($results | Where-Object { $_.CustomizedLogonTypes -ne '' }).Count)
Write-Host ('  Flagged (non-default)           : {0}' -f $flagged) -ForegroundColor $(if ($flagged -gt 0) { 'Yellow' } else { 'Green' })
if ($SetDefaults) { Write-Host ('  Defaults restored               : {0}' -f @($results | Where-Object { $_.Result -eq 'Defaults restored' }).Count) -ForegroundColor Green }
if (-not $SkipBypassCheck) {
    Write-Host ('  Audit bypass accounts           : {0}' -f $bypassAccounts.Count) -ForegroundColor $(if ($bypassAccounts.Count -gt 0) { 'Yellow' } else { 'Green' })
    if ($bypassAccounts.Count -gt 0) { Write-Host ('  Bypass accounts CSV             : {0}' -f $bypassPath) -ForegroundColor Yellow }
}
Write-Host ('  Report                          : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
