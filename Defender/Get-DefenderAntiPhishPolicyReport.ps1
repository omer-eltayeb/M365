<#
.SYNOPSIS
    Reports every anti-phishing policy with its scope, phishing threshold, impersonation, spoof and DMARC settings.
.DESCRIPTION
    Joins Get-AntiPhishPolicy with Get-AntiPhishRule (custom policies) and Get-EOPProtectionPolicyRule (Standard and
    Strict preset policies) to show how each policy is applied - type, rule state, priority and recipient scope -
    together with the phishing email threshold, mailbox intelligence, user and domain impersonation protection,
    spoof intelligence, DMARC handling, safety tips and unauthenticated sender indicators. A Flags column calls out
    weak settings: threshold 1, impersonation protection or spoof intelligence off, DMARC not honored, inactive policy.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderAntiPhishPolicies_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderAntiPhishPolicyReport.ps1
    Writes one row per anti-phishing policy to .\Reports\ and lists the flagged policies in the console.
.EXAMPLE
    PS> .\Get-DefenderAntiPhishPolicyReport.ps1 -PassThru | Where-Object { $_.State -like 'Enabled*' } | Format-Table Name, PolicyType, Scope, PhishThresholdLevel, Flags -Wrap
    Shows the active policies, who they apply to and what is flagged.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report
    Category    : Defender for Office 365 policies
    Changes     : No
    Notes       : The phishing threshold, impersonation protection and mailbox intelligence protection need Defender for
                  Office 365 Plan 1 or 2; EOP-only tenants only have the spoof, DMARC and safety tip settings, so the
                  impersonation flags are expected there. Microsoft recommends threshold 3 (Standard) or 4 (Strict).
.LINK
    https://learn.microsoft.com/defender-office-365/anti-phishing-policies-about
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-antiphishpolicy
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
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

function Get-PolicyBinding {
    <# Finds the rule that applies a policy (custom rule, preset security policy rule or built-in protection rule) and
       returns how the policy is applied: PolicyType, Priority, State and the recipient scope as readable text. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Policy,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Rules,

        [Parameter(Mandatory = $true)]
        [string]$LinkProperty,

        [Parameter()]
        [string[]]$ConditionNames = @('SentTo', 'SentToMemberOf', 'RecipientDomainIs')
    )
    $name = [string]$Policy.Name
    $policyType = 'Custom'
    if ([bool]$Policy.IsDefault) { $policyType = 'Default' }
    elseif ([bool]$Policy.IsBuiltInProtection -or $name -eq 'Built-In Protection Policy') { $policyType = 'Built-in protection' }
    elseif ($name -like 'Strict Preset Security Policy*') { $policyType = 'Preset (Strict)' }
    elseif ($name -like 'Standard Preset Security Policy*') { $policyType = 'Preset (Standard)' }

    $rule = $Rules | Where-Object { [string]$_.$LinkProperty -eq $name } | Select-Object -First 1
    $scopeParts = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($propertyName in (@($ConditionNames) + @($ConditionNames | ForEach-Object { "ExceptIf$_" }))) {
        $values = @($rule.$propertyName | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($values.Count -gt 0) { $scopeParts.Add(('{0}: {1}' -f $propertyName, ($values -join ', '))) }
    }
    $state = 'No rule (not applied)'
    $scope = 'Not applied'
    if ($policyType -eq 'Default') {
        $state = 'Enabled (always on)'
        $scope = 'Everyone not matched by another policy'
    }
    elseif ($null -ne $rule) {
        $state = [string]$rule.State
        if ($policyType -eq 'Built-in protection') { $scopeParts.Insert(0, 'Everyone not matched by another policy') }
        elseif ($scopeParts.Count -eq 0) { $scopeParts.Add('Everyone') }
        $scope = ($scopeParts -join ' | ')
    }
    return [PSCustomObject]@{
        PolicyType = $policyType
        Priority   = $(if ($null -ne $rule) { [int]$rule.Priority } else { $null })
        State      = $state
        Scope      = $scope
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderAntiPhishPolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try {
    $policies = @(Get-AntiPhishPolicy -ErrorAction Stop)
    $rules = @(Get-AntiPhishRule -ErrorAction Stop)
}
catch { throw "Failed to read anti-phishing policies: $($_.Exception.Message)" }
# Preset security policies are applied by their own rule objects, not by anti-phish rules.
try { $rules += @(Get-EOPProtectionPolicyRule -ErrorAction Stop) }
catch { Write-Warning "Preset security policy rules could not be read; preset policies will show no scope: $($_.Exception.Message)" }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in $policies) {
    $binding = Get-PolicyBinding -Policy $policy -Rules $rules -LinkProperty 'AntiPhishPolicy'
    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ([int]$policy.PhishThresholdLevel -le 1) { $flags.Add('Phishing threshold 1 (Standard); Microsoft recommends 3 or 4') }
    if (-not [bool]$policy.EnableTargetedUserProtection) { $flags.Add('User impersonation protection off') }
    if (-not [bool]$policy.EnableOrganizationDomainsProtection) { $flags.Add('Domain impersonation protection off for owned domains') }
    if (-not [bool]$policy.EnableMailboxIntelligenceProtection) { $flags.Add('Mailbox intelligence protection off') }
    if (-not [bool]$policy.EnableSpoofIntelligence) { $flags.Add('Spoof intelligence off') }
    if (-not [bool]$policy.HonorDmarcPolicy) { $flags.Add('Sender DMARC policy not honored') }
    if (-not [bool]$policy.Enabled -or $binding.State -notlike 'Enabled*') { $flags.Add('Policy not active') }

    $rows.Add([PSCustomObject]@{
            Name                                = [string]$policy.Name
            PolicyType                          = $binding.PolicyType
            IsDefault                           = [bool]$policy.IsDefault
            Enabled                             = [bool]$policy.Enabled
            State                               = $binding.State
            Priority                            = $binding.Priority
            Scope                               = $binding.Scope
            PhishThresholdLevel                 = [int]$policy.PhishThresholdLevel
            ImpersonationProtectionState        = [string]$policy.ImpersonationProtectionState
            EnableMailboxIntelligence           = [bool]$policy.EnableMailboxIntelligence
            EnableMailboxIntelligenceProtection = [bool]$policy.EnableMailboxIntelligenceProtection
            MailboxIntelligenceProtectionAction = [string]$policy.MailboxIntelligenceProtectionAction
            EnableTargetedUserProtection        = [bool]$policy.EnableTargetedUserProtection
            TargetedUsersToProtectCount         = @($policy.TargetedUsersToProtect | Where-Object { $null -ne $_ }).Count
            TargetedUserProtectionAction        = [string]$policy.TargetedUserProtectionAction
            EnableTargetedDomainsProtection     = [bool]$policy.EnableTargetedDomainsProtection
            EnableOrganizationDomainsProtection = [bool]$policy.EnableOrganizationDomainsProtection
            TargetedDomainProtectionAction      = [string]$policy.TargetedDomainProtectionAction
            EnableSpoofIntelligence             = [bool]$policy.EnableSpoofIntelligence
            AuthenticationFailAction            = [string]$policy.AuthenticationFailAction
            HonorDmarcPolicy                    = [bool]$policy.HonorDmarcPolicy
            DmarcRejectAction                   = [string]$policy.DmarcRejectAction
            DmarcQuarantineAction               = [string]$policy.DmarcQuarantineAction
            EnableFirstContactSafetyTips        = [bool]$policy.EnableFirstContactSafetyTips
            EnableSimilarUsersSafetyTips        = [bool]$policy.EnableSimilarUsersSafetyTips
            EnableSimilarDomainsSafetyTips      = [bool]$policy.EnableSimilarDomainsSafetyTips
            EnableUnusualCharactersSafetyTips   = [bool]$policy.EnableUnusualCharactersSafetyTips
            EnableViaTag                        = [bool]$policy.EnableViaTag
            EnableUnauthenticatedSender         = [bool]$policy.EnableUnauthenticatedSender
            SpoofQuarantineTag                  = [string]$policy.SpoofQuarantineTag
            WhenChanged                         = $policy.WhenChanged
            Flags                               = ($flags -join '; ')
        })
}

# Evaluation order: Strict preset, Standard preset, custom rules by priority, default policy last.
$typeRank = @{ 'Preset (Strict)' = 0; 'Preset (Standard)' = 1; 'Custom' = 2; 'Built-in protection' = 3; 'Default' = 4 }
$rows = @($rows | Sort-Object -Property @{ Expression = { $typeRank[$_.PolicyType] } }, Priority)
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$active = @($rows | Where-Object { $_.State -like 'Enabled*' })
$flagged = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Flags) })

Write-Host ''
Write-Host 'Anti-phishing policy summary' -ForegroundColor Cyan
Write-Host ('  Policies            : {0} ({1} active: {2})' -f $rows.Count, $active.Count, (($active | ForEach-Object { $_.Name }) -join ', '))
Write-Host ('  Policies with flags : {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $flagged) {
    Write-Host ('    {0} [{1}]: {2}' -f $row.Name, $row.PolicyType, $row.Flags)
}
Write-Host ('  Report              : {0}' -f $OutputPath)

if ($PassThru) {
    $rows
}
#endregion Main
