<#
.SYNOPSIS
    Reports the Microsoft Purview audit configuration and can switch unified audit log ingestion on.
.DESCRIPTION
    Reads the unified audit log ingestion state (Get-AdminAuditLogConfig), the organisation-wide mailbox auditing
    default (Get-OrganizationConfig AuditDisabled) and the audit bypass accounts (Get-MailboxAuditBypassAssociation)
    in an Exchange Online session, then lists audit retention policies (Get-UnifiedAuditLogRetentionPolicy) in a
    Security & Compliance session. Writes Setting/Value/Status/Recommendation rows to a CSV plus a second CSV with the
    retention policies. With -EnableAuditing it enables organization customization when needed and turns ingestion on.
.PARAMETER EnableAuditing
    Turn unified audit log ingestion on when it is disabled. Without this switch the script only reports.
.PARAMETER SkipBypassCheck
    Skip Get-MailboxAuditBypassAssociation, which enumerates every recipient and is slow in large tenants.
.PARAMETER OutputPath
    Path of the settings CSV. Defaults to .\Reports\PurviewAuditConfiguration_yyyyMMdd-HHmm.csv; retention policies are written next to it as <base>_RetentionPolicies.csv.
.PARAMETER PassThru
    Also emit the Setting/Value rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewAuditConfiguration.ps1
    Reports ingestion state, mailbox auditing default, bypass accounts and retention policies with recommendations.
.EXAMPLE
    PS> .\Get-PurviewAuditConfiguration.ps1 -EnableAuditing -WhatIf
    Shows the changes that would enable unified audit log ingestion without applying them.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Online View-Only Organization Management to report (Organization Management for -EnableAuditing);
                  Purview Audit Logs or Organization Configuration role to read audit retention policies
    Category    : Audit log scenarios
    Changes     : Optional (-EnableAuditing)
    Notes       : Audit retention policies require Audit (Premium) (Microsoft 365 E5 / E5 Compliance or the add-on); without
                  it the cmdlet returns nothing or fails and the script only warns. After ingestion is enabled it can take up
                  to 60 minutes before searches return records. AuditDisabled = True suspends auditing for every mailbox.
.LINK
    https://learn.microsoft.com/purview/audit-log-enable-disable
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-unifiedauditlogretentionpolicy
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$EnableAuditing,

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

function New-SettingRow {
    <# Shapes one Setting/Value row; the recommendation is only kept when the setting needs attention. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Setting,

        [Parameter()]
        [AllowNull()]
        $Value,

        [Parameter()]
        [bool]$IsOk = $true,

        [Parameter()]
        [string]$Recommendation = ''
    )
    return [PSCustomObject]@{
        Setting        = $Setting
        Value          = [string]$Value
        Status         = $(if ($IsOk) { 'OK' } else { 'Review' })
        Recommendation = $(if ($IsOk) { '' } else { $Recommendation })
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewAuditConfiguration_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$retentionPath = [System.IO.Path]::ChangeExtension($OutputPath, $null) + '_RetentionPolicies.csv'

try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }
try {
    $auditConfig = Get-AdminAuditLogConfig -ErrorAction Stop
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
}
catch {
    throw "Unable to read the Exchange Online audit configuration: $($_.Exception.Message)"
}
$ingestionEnabled = ($auditConfig.UnifiedAuditLogIngestionEnabled -eq $true)
$mailboxAuditingOn = ($orgConfig.AuditDisabled -ne $true)

$ingestionAdvice = 'Enable unified audit log ingestion (re-run with -EnableAuditing); no user or admin activity is searchable until then.'
$auditDisabledAdvice = 'Run Set-OrganizationConfig -AuditDisabled $false; while True, mailbox auditing on by default is suspended for all mailboxes.'
$bypassAdvice = 'Review each bypass account; nothing these accounts do in any mailbox is written to the mailbox audit log.'
$retentionAdvice = 'No audit retention policies: Audit (Standard) keeps 180 days. With Audit (Premium), create policies to keep selected records up to 10 years.'

$settings = New-Object -TypeName System.Collections.Generic.List[object]
$settings.Add((New-SettingRow -Setting 'UnifiedAuditLogIngestionEnabled' -Value $ingestionEnabled -IsOk $ingestionEnabled -Recommendation $ingestionAdvice))
$settings.Add((New-SettingRow -Setting 'UnifiedAuditLogFirstOptInDate' -Value $auditConfig.UnifiedAuditLogFirstOptInDate))
$settings.Add((New-SettingRow -Setting 'OrganizationAuditDisabled' -Value $orgConfig.AuditDisabled -IsOk $mailboxAuditingOn -Recommendation $auditDisabledAdvice))

$bypassAccounts = @()
if (-not $SkipBypassCheck) {
    Write-Progress -Activity 'Reading audit configuration' -Status 'Enumerating mailbox audit bypass associations (slow in large tenants)' -PercentComplete 50
    try {
        $bypassAccounts = @(Get-MailboxAuditBypassAssociation -ResultSize Unlimited -ErrorAction Stop | Where-Object { $_.AuditBypassEnabled -eq $true })
    }
    catch {
        Write-Warning "Could not read mailbox audit bypass associations: $($_.Exception.Message)"
    }
    Write-Progress -Activity 'Reading audit configuration' -Completed
    $bypassNames = @($bypassAccounts | ForEach-Object { $_.Name }) -join '; '
    $settings.Add((New-SettingRow -Setting 'MailboxAuditBypassAccounts' -Value $bypassNames -IsOk ($bypassAccounts.Count -eq 0) -Recommendation $bypassAdvice))
}

$retentionPolicies = @()
try {
    Connect-ExchangeIfNeeded -Compliance
    $retentionPolicies = @(Get-UnifiedAuditLogRetentionPolicy -ErrorAction Stop | Sort-Object -Property Priority)
}
catch {
    Write-Warning "Could not read audit retention policies (requires Audit (Premium) and the Audit Logs role): $($_.Exception.Message)"
}
$retentionRows = foreach ($policy in $retentionPolicies) {
    [PSCustomObject]@{
        Name              = [string]$policy.Name
        Priority          = $policy.Priority
        Description       = [string]$policy.Description
        RetentionDuration = [string]$policy.RetentionDuration
        RecordTypes       = (@($policy.RecordTypes) -join '; ')
        Operations        = (@($policy.Operations) -join '; ')
        UserIds           = (@($policy.UserIds) -join '; ')
        Enabled           = $policy.Enabled
    }
}
$settings.Add((New-SettingRow -Setting 'AuditRetentionPolicies' -Value $retentionPolicies.Count -IsOk ($retentionPolicies.Count -gt 0) -Recommendation $retentionAdvice))

if ($EnableAuditing -and -not $ingestionEnabled) {
    try {
        # A dehydrated organisation rejects Set-AdminAuditLogConfig until customization is enabled (one-time, irreversible).
        if ($orgConfig.IsDehydrated -eq $true -and $PSCmdlet.ShouldProcess('Exchange Online organization', 'Enable-OrganizationCustomization')) {
            Enable-OrganizationCustomization -ErrorAction Stop
        }
        if ($PSCmdlet.ShouldProcess('Exchange Online organization', 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true')) {
            Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ErrorAction Stop
            $ingestionEnabled = $true
            Write-Host 'Unified audit log ingestion enabled; records appear in searches within about 60 minutes.' -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to enable unified audit log ingestion: $($_.Exception.Message)" -ErrorAction Continue
    }
}
elseif ($EnableAuditing) { Write-Host 'Unified audit log ingestion is already enabled; nothing to change.' -ForegroundColor Green }

$settings | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if (@($retentionRows).Count -gt 0) { $retentionRows | Export-Csv -Path $retentionPath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'Purview audit configuration summary' -ForegroundColor Cyan
Write-Host ('  Unified audit log ingestion  : {0}' -f $(if ($ingestionEnabled) { 'Enabled' } else { 'DISABLED' }))
Write-Host ('  Mailbox auditing org default : {0}' -f $(if ($mailboxAuditingOn) { 'Enabled' } else { 'DISABLED (AuditDisabled = True)' }))
Write-Host ('  Audit bypass accounts        : {0}' -f $(if ($SkipBypassCheck) { 'skipped' } else { $bypassAccounts.Count }))
Write-Host ('  Audit retention policies     : {0}' -f $retentionPolicies.Count)
$reviewItems = @($settings | Where-Object { $_.Status -ne 'OK' })
if ($reviewItems.Count -gt 0) {
    Write-Host '  Recommendations:' -ForegroundColor Yellow
    foreach ($item in $reviewItems) { Write-Host ('    - {0}: {1}' -f $item.Setting, $item.Recommendation) }
}
Write-Host ('  Report                       : {0}' -f $OutputPath)
if (@($retentionRows).Count -gt 0) { Write-Host ('  Retention policies           : {0}' -f $retentionPath) }

if ($PassThru) { $settings }
#endregion Main
