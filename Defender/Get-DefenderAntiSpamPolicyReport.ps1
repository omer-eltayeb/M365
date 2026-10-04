<#
.SYNOPSIS
    Reports every inbound anti-spam policy with its scope, verdict actions, bulk threshold, ZAP, allow/block lists and ASF settings.
.DESCRIPTION
    Joins Get-HostedContentFilterPolicy with Get-HostedContentFilterRule (custom policies) and Get-EOPProtectionPolicyRule
    (Standard and Strict presets) so each row shows how the policy is applied - type, rule state, priority, recipient
    scope - plus the actions for spam, high confidence spam, phishing, high confidence phishing and bulk mail, the bulk
    threshold, quarantine retention, zero-hour auto purge, intra-organization filtering, allowed and blocked sender
    lists, the Advanced Spam Filter (ASF) settings that are on or in test mode, region and language blocking and the
    test mode action. Flags mark allow lists (filter bypass), bulk threshold above 6, ZAP off and unquarantined phish.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderAntiSpamPolicies_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderAntiSpamPolicyReport.ps1
    Writes one row per anti-spam policy to .\Reports\ and lists the flagged policies in the console.
.EXAMPLE
    PS> .\Get-DefenderAntiSpamPolicyReport.ps1 -PassThru | Where-Object { $_.AllowedSenderDomainsCount -gt 0 } | Select-Object Name, Scope, AllowedSenderDomains
    Shows which policies whitelist whole sender domains and who those policies apply to.
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
    Notes       : Anti-spam policies are part of Exchange Online Protection, so this works in EOP-only tenants too.
                  Microsoft recommends BulkThreshold 6 (Standard) or 5 (Strict), Quarantine for phishing and high
                  confidence spam, 30 days retention and no allowed sender domains (use the Tenant Allow/Block List
                  instead). The quarantine policies behind each verdict are reported by Get-DefenderQuarantinePolicies.ps1.
.LINK
    https://learn.microsoft.com/defender-office-365/anti-spam-policies-configure
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-hostedcontentfilterpolicy
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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderAntiSpamPolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try {
    $policies = @(Get-HostedContentFilterPolicy -ErrorAction Stop)
    $rules = @(Get-HostedContentFilterRule -ErrorAction Stop)
}
catch { throw "Failed to read anti-spam policies: $($_.Exception.Message)" }
# Preset security policies are applied by their own rule objects, not by anti-spam rules.
try { $rules += @(Get-EOPProtectionPolicyRule -ErrorAction Stop) }
catch { Write-Warning "Preset security policy rules could not be read; preset policies will show no scope: $($_.Exception.Message)" }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in $policies) {
    $binding = Get-PolicyBinding -Policy $policy -Rules $rules -LinkProperty 'HostedContentFilterPolicy'
    $allowedSenders = @($policy.AllowedSenders | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    $allowedDomains = @($policy.AllowedSenderDomains | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    # ASF settings are Off, On or Test; MarkAsSpamBulkMail is the bulk filter itself and is expected to be On.
    $asfProperties = @($policy.PSObject.Properties | Where-Object { ($_.Name -like 'MarkAsSpam*' -or $_.Name -like 'IncreaseScoreWith*') -and $_.Name -ne 'MarkAsSpamBulkMail' })
    $asfEnabled = @($asfProperties | Where-Object { [string]$_.Value -in @('On', 'Test') } | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value })

    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ($allowedDomains.Count -gt 0 -or $allowedSenders.Count -gt 0) { $flags.Add(('{0} allowed domain(s) and {1} allowed sender(s) bypass filters' -f $allowedDomains.Count, $allowedSenders.Count)) }
    if ([int]$policy.BulkThreshold -gt 6) { $flags.Add(('Bulk threshold {0} (Microsoft recommends 6 or lower)' -f $policy.BulkThreshold)) }
    if (-not [bool]$policy.SpamZapEnabled -or -not [bool]$policy.PhishZapEnabled) { $flags.Add('Zero-hour auto purge disabled for spam and/or phishing') }
    if ([string]$policy.HighConfidencePhishAction -ne 'Quarantine') { $flags.Add('High confidence phishing not quarantined') }
    if ($binding.State -notlike 'Enabled*') { $flags.Add('Policy not applied to anyone') }

    $rows.Add([PSCustomObject]@{
            Name                      = [string]$policy.Name
            PolicyType                = $binding.PolicyType
            IsDefault                 = [bool]$policy.IsDefault
            State                     = $binding.State
            Priority                  = $binding.Priority
            Scope                     = $binding.Scope
            SpamAction                = [string]$policy.SpamAction
            HighConfidenceSpamAction  = [string]$policy.HighConfidenceSpamAction
            PhishSpamAction           = [string]$policy.PhishSpamAction
            HighConfidencePhishAction = [string]$policy.HighConfidencePhishAction
            BulkSpamAction            = [string]$policy.BulkSpamAction
            BulkThreshold             = [int]$policy.BulkThreshold
            QuarantineRetentionPeriod = [int]$policy.QuarantineRetentionPeriod
            SpamZapEnabled            = [bool]$policy.SpamZapEnabled
            PhishZapEnabled           = [bool]$policy.PhishZapEnabled
            IntraOrgFilterState       = [string]$policy.IntraOrgFilterState
            AllowedSendersCount       = $allowedSenders.Count
            AllowedSenders            = (($allowedSenders | Select-Object -First 20) -join ';')
            AllowedSenderDomainsCount = $allowedDomains.Count
            AllowedSenderDomains      = (($allowedDomains | Select-Object -First 20) -join ';')
            BlockedSendersCount       = @($policy.BlockedSenders | Where-Object { $null -ne $_ }).Count
            BlockedSenderDomainsCount = @($policy.BlockedSenderDomains | Where-Object { $null -ne $_ }).Count
            AsfEnabledCount           = $asfEnabled.Count
            AsfEnabledSettings        = ($asfEnabled -join ';')
            EnableRegionBlockList     = [bool]$policy.EnableRegionBlockList
            RegionBlockList           = (@($policy.RegionBlockList) -join ';')
            EnableLanguageBlockList   = [bool]$policy.EnableLanguageBlockList
            TestModeAction            = [string]$policy.TestModeAction
            WhenChanged               = $policy.WhenChanged
            Flags                     = ($flags -join '; ')
        })
}

# Evaluation order: Strict preset, Standard preset, custom rules by priority, default policy last.
$typeRank = @{ 'Preset (Strict)' = 0; 'Preset (Standard)' = 1; 'Custom' = 2; 'Built-in protection' = 3; 'Default' = 4 }
$rows = @($rows | Sort-Object -Property @{ Expression = { $typeRank[$_.PolicyType] } }, Priority)
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$active = @($rows | Where-Object { $_.State -like 'Enabled*' })
$flagged = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Flags) })

Write-Host ''
Write-Host 'Inbound anti-spam policy summary' -ForegroundColor Cyan
Write-Host ('  Policies                 : {0} ({1} active: {2})' -f $rows.Count, $active.Count, (($active | ForEach-Object { $_.Name }) -join ', '))
Write-Host ('  Policies with flags      : {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $flagged) { Write-Host ('    {0} [{1}]: {2}' -f $row.Name, $row.PolicyType, $row.Flags) }
Write-Host ('  Report                   : {0}' -f $OutputPath)

if ($PassThru) { $rows }
#endregion Main
