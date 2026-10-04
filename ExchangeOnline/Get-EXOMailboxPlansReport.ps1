<#
.SYNOPSIS
    Reports Exchange Online mailbox plans and CAS mailbox plans (the defaults every new mailbox inherits) and can harden them.
.DESCRIPTION
    Joins Get-MailboxPlan (quotas, retention policy, role assignment policy, size limits, deleted item retention) with
    Get-CASMailboxPlan (ActiveSync, POP, IMAP, OWA policy) by plan name and counts the mailboxes on each plan. With
    -SetDefaults it applies -RetentionPolicy and/or -RetainDeletedItemsDays through Set-MailboxPlan and disables POP/IMAP
    through Set-CASMailboxPlan under ShouldProcess. Plan changes only affect mailboxes created afterwards.
.PARAMETER Plan
    One or more plan names (for example ExchangeOnlineEnterprise-<guid>) to report or change. Default: all plans.
.PARAMETER SetDefaults
    Apply the requested plan changes. Without it the script is read-only.
.PARAMETER RetentionPolicy
    Name of the MRM retention policy new mailboxes should receive (Set-MailboxPlan -RetentionPolicy).
.PARAMETER DisablePopImap
    Disable POP3 and IMAP4 for new mailboxes (Set-CASMailboxPlan -PopEnabled $false -ImapEnabled $false).
.PARAMETER RetainDeletedItemsDays
    Deleted item retention in days for new mailboxes (Set-MailboxPlan -RetainDeletedItemsFor); 30 is the maximum.
.PARAMETER SkipMailboxCount
    Skip the Get-EXOMailbox enumeration that counts mailboxes per plan (faster in very large tenants).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOMailboxPlans_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMailboxPlansReport.ps1
    Reports every mailbox plan with its CAS settings and mailbox count, and writes .\Reports\EXOMailboxPlans_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOMailboxPlansReport.ps1 -SetDefaults -DisablePopImap -RetainDeletedItemsDays 30 -RetentionPolicy 'Corporate Retention' -WhatIf
    Shows which plans would be changed so that new mailboxes get no POP/IMAP, 30-day deleted item retention and the corporate policy.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Configuration (or Global Reader) for the report; Exchange Administrator for -SetDefaults
    Category    : Mailbox lifecycle & compliance
    Changes     : Optional (-SetDefaults)
    Notes       : Plans map to licenses: ExchangeOnline = Plan 1, ExchangeOnlineEnterprise = Plan 2, ExchangeOnlineDeskless = Kiosk / F3,
                  ExchangeOnlineEssentials = Business Basic; the GUID suffix is tenant specific. Align existing mailboxes with
                  Get-EXOMailbox -ResultSize Unlimited | Set-Mailbox -RetentionPolicy <name> and Set-CASMailbox -PopEnabled $false -ImapEnabled $false.
.LINK
    https://learn.microsoft.com/exchange/recipients-in-exchange-online/manage-user-mailboxes/mailbox-plans
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$Plan,

    [Parameter()]
    [switch]$SetDefaults,

    [Parameter()]
    [string]$RetentionPolicy,

    [Parameter()]
    [switch]$DisablePopImap,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$RetainDeletedItemsDays,

    [Parameter()]
    [switch]$SkipMailboxCount,

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

function ConvertTo-Size {
    <# Converts Exchange size text such as "50 GB (53,687,091,200 bytes)" to GB or MB with 2 decimals; "Unlimited" or empty returns $null. #>
    param([Parameter()][AllowNull()]$Size, [Parameter()][ValidateSet('GB', 'MB')][string]$Unit = 'GB')
    if ($null -ne $Size -and $Size.ToString() -match '\(([\d,\.]+)\s+bytes\)') {
        $divisor = 1GB
        if ($Unit -eq 'MB') { $divisor = 1MB }
        return [math]::Round(([double]($Matches[1] -replace '[,\.]', '')) / $divisor, 2)
    }
    return $null
}
#endregion Helpers

#region Main
$wantsRetention = -not [string]::IsNullOrWhiteSpace($RetentionPolicy)
$wantsDeletedItems = $PSBoundParameters.ContainsKey('RetainDeletedItemsDays')
$deletedItemsSpan = '{0}.00:00:00' -f $RetainDeletedItemsDays
if ($SetDefaults -and -not ($wantsRetention -or $DisablePopImap -or $wantsDeletedItems)) { throw 'Specify -RetentionPolicy, -DisablePopImap and/or -RetainDeletedItemsDays with -SetDefaults.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMailboxPlans_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

if ($wantsRetention) {
    try { $RetentionPolicy = [string](Get-RetentionPolicy -Identity $RetentionPolicy -ErrorAction Stop).Name }
    catch { throw "Retention policy '$RetentionPolicy' was not found: $($_.Exception.Message)" }
}

try {
    $plans = @(Get-MailboxPlan -ErrorAction Stop)
    $casPlans = @{}
    foreach ($casPlan in @(Get-CASMailboxPlan -ErrorAction Stop)) { $casPlans[[string]$casPlan.Name] = $casPlan }
}
catch { throw "Failed to read mailbox plans: $($_.Exception.Message)" }
if ($PSBoundParameters.ContainsKey('Plan')) {
    $requestedPlans = @($Plan)
    $plans = @($plans | Where-Object { $requestedPlans -contains [string]$_.Name -or $requestedPlans -contains [string]$_.DisplayName })
    if ($plans.Count -eq 0) { throw "None of the requested plans were found. Run the script without -Plan to list the plan names." }
}

$mailboxCounts = @{}
if (-not $SkipMailboxCount) {
    try { $allMailboxes = @(Get-EXOMailbox -ResultSize Unlimited -Properties MailboxPlan -ErrorAction Stop) }
    catch { Write-Warning "Could not count mailboxes per plan: $($_.Exception.Message)"; $allMailboxes = @() }
    foreach ($group in ($allMailboxes | Group-Object -Property { [string]$_.MailboxPlan })) { $mailboxCounts[$group.Name] = $group.Count }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($mailboxPlan in $plans) {
    $name = [string]$mailboxPlan.Name
    $casPlan = $casPlans[$name]
    $retainDays = $null
    if ("$($mailboxPlan.RetainDeletedItemsFor)" -match '^(\d+)\.') { $retainDays = [int]$Matches[1] }

    $changes = New-Object -TypeName System.Collections.Generic.List[string]
    $result = 'Report only'
    if ($SetDefaults) {
        $planParams = @{}
        if ($wantsRetention -and [string]$mailboxPlan.RetentionPolicy -ne $RetentionPolicy) { $planParams['RetentionPolicy'] = $RetentionPolicy; $changes.Add("RetentionPolicy = $RetentionPolicy") }
        if ($wantsDeletedItems -and $retainDays -ne $RetainDeletedItemsDays) { $planParams['RetainDeletedItemsFor'] = $deletedItemsSpan; $changes.Add("RetainDeletedItemsFor = $deletedItemsSpan") }
        $casParams = @{}
        if ($DisablePopImap -and ([bool]$casPlan.PopEnabled -or [bool]$casPlan.ImapEnabled)) { $casParams = @{ PopEnabled = $false; ImapEnabled = $false }; $changes.Add('POP/IMAP = disabled') }
        if ($changes.Count -eq 0) { $result = 'Nothing to do' }
        elseif ($PSCmdlet.ShouldProcess($name, ($changes -join '; '))) {
            try {
                if ($planParams.Count -gt 0) { Set-MailboxPlan -Identity $name @planParams -ErrorAction Stop }
                if ($casParams.Count -gt 0) { Set-CASMailboxPlan -Identity $name @casParams -ErrorAction Stop }
                $result = 'Updated'
            }
            catch { $result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not update plan '$name': $($_.Exception.Message)" }
        }
        else { $result = 'Not confirmed' }
    }

    $results.Add([PSCustomObject]@{
            PlanName                   = $name
            DisplayName                = [string]$mailboxPlan.DisplayName
            IsDefault                  = [bool]$mailboxPlan.IsDefault
            MailboxCount               = $(if ($SkipMailboxCount) { $null } else { [int]$mailboxCounts[$name] })
            ProhibitSendReceiveQuotaGB = ConvertTo-Size -Size $mailboxPlan.ProhibitSendReceiveQuota
            ProhibitSendQuotaGB        = ConvertTo-Size -Size $mailboxPlan.ProhibitSendQuota
            IssueWarningQuotaGB        = ConvertTo-Size -Size $mailboxPlan.IssueWarningQuota
            RetentionPolicy            = [string]$mailboxPlan.RetentionPolicy
            RoleAssignmentPolicy       = [string]$mailboxPlan.RoleAssignmentPolicy
            MaxSendSizeMB              = ConvertTo-Size -Size $mailboxPlan.MaxSendSize -Unit MB
            MaxReceiveSizeMB           = ConvertTo-Size -Size $mailboxPlan.MaxReceiveSize -Unit MB
            RetainDeletedItemsDays     = $retainDays
            ActiveSyncEnabled          = [bool]$casPlan.ActiveSyncEnabled
            PopEnabled                 = [bool]$casPlan.PopEnabled
            ImapEnabled                = [bool]$casPlan.ImapEnabled
            OwaMailboxPolicy           = [string]$casPlan.OwaMailboxPolicy
            Changes                    = ($changes -join '; ')
            Result                     = $result
        })
}

if ($results.Count -eq 0) { Write-Warning 'No mailbox plans were found; nothing to export.'; return }
$results | Sort-Object -Property MailboxCount -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$popImapPlans = @($results | Where-Object { $_.PopEnabled -or $_.ImapEnabled }).Count

Write-Host "Mailbox plan summary ($($results.Count) plans)" -ForegroundColor Cyan
if (-not $SkipMailboxCount) { Write-Host ('  Mailboxes counted            : {0}' -f ($results | Measure-Object -Property MailboxCount -Sum).Sum) }
Write-Host ('  Plans with POP or IMAP on    : {0}' -f $popImapPlans) -ForegroundColor $(if ($popImapPlans -gt 0) { 'Yellow' } else { 'Green' })
if ($SetDefaults) { Write-Host ('  Plans updated                : {0}' -f @($results | Where-Object { $_.Result -eq 'Updated' }).Count) -ForegroundColor Green }
Write-Host '  Plan settings apply to NEW mailboxes only; see .NOTES for aligning existing mailboxes.' -ForegroundColor Gray
Write-Host ('  Report                       : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
