<#
.SYNOPSIS
    Reports every outbound spam policy with its sender scope, automatic forwarding mode, recipient limits and notifications.
.DESCRIPTION
    Joins Get-HostedOutboundSpamFilterPolicy with Get-HostedOutboundSpamFilterRule so each row shows how the policy is
    applied - type, rule state, priority and sender scope (From, FromMemberOf, SenderDomainIs and the exceptions) -
    together with the automatic external forwarding mode (explained in plain words), the external, internal and daily
    recipient limits, the action when a limit is reached, the Bcc copy of suspicious outbound mail and the legacy
    notification recipients. Flags mark policies that allow automatic forwarding, rely on the service default limits
    (0) or only alert instead of restricting a sender that hits the limit. Read-only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderOutboundSpamPolicies_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderOutboundSpamPolicyReport.ps1
    Writes one row per outbound spam policy to .\Reports\ and lists the flagged policies in the console.
.EXAMPLE
    PS> .\Get-DefenderOutboundSpamPolicyReport.ps1 -PassThru | Where-Object { $_.AutoForwardingMode -eq 'On' } | Select-Object Name, Scope
    Shows which policies allow automatic external forwarding and which senders they apply to.
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
    Notes       : Outbound spam policies belong to Exchange Online Protection (EOP-only tenants included) and are not part
                  of the Standard or Strict preset security policies. Microsoft recommends AutoForwardingMode Off,
                  RecipientLimitExternalPerHour 500, RecipientLimitInternalPerHour 1000, RecipientLimitPerDay 1000
                  (Strict: 400/800/800) and ActionWhenThresholdReached BlockUser. The value 0 means the service default
                  applies. The Bcc setting only works in the default policy; the alert policy "User restricted from
                  sending email" already notifies admins, so NotifyOutboundSpam is largely redundant.
.LINK
    https://learn.microsoft.com/defender-office-365/outbound-spam-policies-configure
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-hostedoutboundspamfilterpolicy
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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderOutboundSpamPolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try {
    $policies = @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop)
    $rules = @(Get-HostedOutboundSpamFilterRule -ErrorAction Stop)
}
catch { throw "Failed to read outbound spam policies: $($_.Exception.Message)" }

# Automatic has meant "blocked" since 2020, but Microsoft notes its behaviour can differ by organization; Off is explicit.
$forwardingText = @{
    Automatic = 'System-controlled - currently blocks automatic external forwarding (same as Off); set Off to make it explicit'
    Off       = 'Automatic external forwarding is blocked; the sender receives a non-delivery report'
    On        = 'Automatic external forwarding is ALLOWED - mailbox forwarding and inbox rules can send mail outside the tenant'
}
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in $policies) {
    $binding = Get-PolicyBinding -Policy $policy -Rules $rules -LinkProperty 'HostedOutboundSpamFilterPolicy' -ConditionNames @('From', 'FromMemberOf', 'SenderDomainIs')
    $mode = [string]$policy.AutoForwardingMode
    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ($mode -eq 'On') { $flags.Add('Automatic external forwarding allowed') }
    if ($mode -eq 'Automatic') { $flags.Add('Forwarding mode Automatic (system-controlled); Microsoft recommends Off') }
    $zeroLimits = @(foreach ($limit in 'RecipientLimitExternalPerHour', 'RecipientLimitInternalPerHour', 'RecipientLimitPerDay') { if ([int]$policy.$limit -eq 0) { $limit } })
    if ($zeroLimits.Count -gt 0) { $flags.Add(('No explicit limit (service default) for {0}' -f ($zeroLimits -join ', '))) }
    if ([string]$policy.ActionWhenThresholdReached -eq 'Alert') { $flags.Add('Limit reached only raises an alert; Microsoft recommends BlockUser') }
    if ([bool]$policy.BccSuspiciousOutboundMail -and -not [bool]$policy.IsDefault) { $flags.Add('Bcc of suspicious mail only works in the default policy') }
    if ($binding.State -notlike 'Enabled*') { $flags.Add('Policy not applied to anyone') }

    $rows.Add([PSCustomObject]@{
            Name                                      = [string]$policy.Name
            PolicyType                                = $binding.PolicyType
            IsDefault                                 = [bool]$policy.IsDefault
            State                                     = $binding.State
            Priority                                  = $binding.Priority
            Scope                                     = $binding.Scope
            AutoForwardingMode                        = $mode
            AutoForwardingEffect                      = $(if ($forwardingText.ContainsKey($mode)) { $forwardingText[$mode] } else { $mode })
            RecipientLimitExternalPerHour             = [int]$policy.RecipientLimitExternalPerHour
            RecipientLimitInternalPerHour             = [int]$policy.RecipientLimitInternalPerHour
            RecipientLimitPerDay                      = [int]$policy.RecipientLimitPerDay
            ActionWhenThresholdReached                = [string]$policy.ActionWhenThresholdReached
            BccSuspiciousOutboundMail                 = [bool]$policy.BccSuspiciousOutboundMail
            BccSuspiciousOutboundAdditionalRecipients = (@($policy.BccSuspiciousOutboundAdditionalRecipients) -join ';')
            NotifyOutboundSpam                        = [bool]$policy.NotifyOutboundSpam
            NotifyOutboundSpamRecipients              = (@($policy.NotifyOutboundSpamRecipients) -join ';')
            RecommendedPolicyType                     = [string]$policy.RecommendedPolicyType
            WhenChanged                               = $policy.WhenChanged
            Flags                                     = ($flags -join '; ')
        })
}

# Custom rules by priority first, default policy last.
$rows = @($rows | Sort-Object -Property @{ Expression = { if ($_.PolicyType -eq 'Default') { 1 } else { 0 } } }, Priority)
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$active = @($rows | Where-Object { $_.State -like 'Enabled*' })
$forwardingAllowed = @($active | Where-Object { $_.AutoForwardingMode -eq 'On' })
$forwardingText = $(if ($forwardingAllowed.Count -gt 0) { ($forwardingAllowed | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Scope }) -join '; ' } else { 'none' })
$flagged = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Flags) })

Write-Host ''
Write-Host 'Outbound spam policy summary' -ForegroundColor Cyan
Write-Host ('  Policies                   : {0} ({1} active)' -f $rows.Count, $active.Count)
Write-Host ('  Allowing auto-forwarding   : {0}' -f $forwardingText) -ForegroundColor $(if ($forwardingAllowed.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host ('  Policies with flags        : {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $flagged) { Write-Host ('    {0} [{1}]: {2}' -f $row.Name, $row.PolicyType, $row.Flags) }
Write-Host ('  Report                     : {0}' -f $OutputPath)

if ($PassThru) { $rows }
#endregion Main
