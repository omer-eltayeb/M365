<#
.SYNOPSIS
    Reports whether the Standard, Strict and Built-in protection preset security policies are on and who they cover.
.DESCRIPTION
    Reads the preset security policy rules with Get-EOPProtectionPolicyRule (anti-spam, anti-malware and anti-phishing
    part of the Standard and Strict presets), Get-ATPProtectionPolicyRule (Safe Links and Safe Attachments part) and
    Get-ATPBuiltInProtectionRule (Built-in protection exceptions). One row per preset and component shows the rule
    state, priority, included users, groups and domains, the exceptions and the policy objects the rule applies.
    The script also counts the custom anti-phishing, anti-spam, anti-malware, Safe Links and Safe Attachments policies
    and prints recommendations (Standard for everyone, Strict for admins and other priority accounts). Read-only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderPresetSecurityPolicies_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderPresetSecurityPolicyStatus.ps1
    Shows the state and scope of each preset security policy and writes the CSV to .\Reports\.
.EXAMPLE
    PS> .\Get-DefenderPresetSecurityPolicyStatus.ps1 -PassThru | Where-Object { $_.State -ne 'Enabled' }
    Lists the preset components that are disabled, not configured or not available in the tenant.
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
    Notes       : The Defender for Office 365 rows (Safe Links, Safe Attachments, Built-in protection) need Defender for
                  Office 365 Plan 1 or 2; EOP-only tenants only have the EOP rows. A preset rule without conditions applies
                  to all recipients. Precedence: Strict, Standard, custom policies by priority, then Built-in protection
                  (Safe Links and Safe Attachments) or the default policies for everyone else.
.LINK
    https://learn.microsoft.com/defender-office-365/preset-security-policies
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-eopprotectionpolicyrule
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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderPresetSecurityPolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$expectedRules = @(
    @{ Preset = 'Standard'; Component = 'EOP'; Command = 'Get-EOPProtectionPolicyRule' }
    @{ Preset = 'Strict'; Component = 'EOP'; Command = 'Get-EOPProtectionPolicyRule' }
    @{ Preset = 'Standard'; Component = 'Defender for Office 365'; Command = 'Get-ATPProtectionPolicyRule' }
    @{ Preset = 'Strict'; Component = 'Defender for Office 365'; Command = 'Get-ATPProtectionPolicyRule' }
    @{ Preset = 'Built-in protection'; Component = 'Defender for Office 365'; Command = 'Get-ATPBuiltInProtectionRule' }
)
$linkProperties = @('AntiPhishPolicy', 'HostedContentFilterPolicy', 'MalwareFilterPolicy', 'SafeLinksPolicy', 'SafeAttachmentPolicy')
$ruleCache = @{}
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($expected in $expectedRules) {
    $command = $expected.Command
    if (-not $ruleCache.ContainsKey($command)) {
        # A missing cmdlet means the tenant has no Defender for Office 365 licence (or the admin lacks the role).
        $ruleCache[$command] = $null
        if ($null -eq (Get-Command -Name $command -ErrorAction SilentlyContinue)) {
            Write-Warning "$command is not available in this tenant (Defender for Office 365 Plan 1 or 2 required)."
        }
        else {
            try { $ruleCache[$command] = @(& $command -ErrorAction Stop) }
            catch { Write-Warning "$command failed: $($_.Exception.Message)" }
        }
    }
    $rule = $null
    if ($null -ne $ruleCache[$command]) {
        if ($expected.Preset -eq 'Built-in protection') { $rule = $ruleCache[$command] | Select-Object -First 1 }
        else { $rule = $ruleCache[$command] | Where-Object { $_.Name -like "$($expected.Preset) Preset Security Policy*" } | Select-Object -First 1 }
    }

    $state = 'Not configured'
    $appliesTo = 'Nobody - the preset has never been turned on'
    if ($null -eq $ruleCache[$command]) {
        $state = 'Not available'
        $appliesTo = 'Cmdlet not available in this tenant'
    }
    elseif ($null -ne $rule) {
        $state = [string]$rule.State
        $included = @(@($rule.SentTo) + @($rule.SentToMemberOf) + @($rule.RecipientDomainIs) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($state -ne 'Enabled') { $appliesTo = 'Nobody - rule is disabled' }
        elseif ($expected.Preset -eq 'Built-in protection') { $appliesTo = 'Everyone not covered by a preset or custom policy' }
        elseif ($included.Count -eq 0) { $appliesTo = 'All recipients' }
        else { $appliesTo = 'Specific recipients' }
    }
    $exceptions = @(foreach ($name in 'ExceptIfSentTo', 'ExceptIfSentToMemberOf', 'ExceptIfRecipientDomainIs') {
            $values = @($rule.$name | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
            if ($values.Count -gt 0) { '{0}: {1}' -f $name, ($values -join ', ') }
        })
    $linked = @(foreach ($name in $linkProperties) { if (-not [string]::IsNullOrWhiteSpace([string]$rule.$name)) { '{0}={1}' -f $name, $rule.$name } })

    $rows.Add([PSCustomObject]@{
            Preset          = $expected.Preset
            Component       = $expected.Component
            RuleName        = $(if ($null -ne $rule) { [string]$rule.Name } else { $null })
            State           = $state
            Priority        = $(if ($null -ne $rule) { [int]$rule.Priority } else { $null })
            AppliesTo       = $appliesTo
            IncludedUsers   = (@($rule.SentTo) -join ';')
            IncludedGroups  = (@($rule.SentToMemberOf) -join ';')
            IncludedDomains = (@($rule.RecipientDomainIs) -join ';')
            Exceptions      = ($exceptions -join ' | ')
            LinkedPolicies  = ($linked -join ';')
            WhenChanged     = $(if ($null -ne $rule) { $rule.WhenChanged } else { $null })
        })
}

# Custom policies are evaluated after the presets, so they only matter for recipients outside the preset scopes.
$policySources = @(
    @{ Kind = 'Anti-phishing'; Command = 'Get-AntiPhishPolicy' }
    @{ Kind = 'Anti-spam'; Command = 'Get-HostedContentFilterPolicy' }
    @{ Kind = 'Anti-malware'; Command = 'Get-MalwareFilterPolicy' }
    @{ Kind = 'Safe Links'; Command = 'Get-SafeLinksPolicy' }
    @{ Kind = 'Safe Attachments'; Command = 'Get-SafeAttachmentPolicy' }
)
$customPolicies = New-Object -TypeName System.Collections.Generic.List[string]
foreach ($source in $policySources) {
    if ($null -eq (Get-Command -Name $source.Command -ErrorAction SilentlyContinue)) { continue }
    try {
        foreach ($policy in @(& $source.Command -ErrorAction Stop)) {
            $isManaged = [bool]$policy.IsDefault -or [bool]$policy.IsBuiltInProtection -or $policy.Name -like '* Preset Security Policy*' -or $policy.Name -eq 'Built-In Protection Policy'
            if (-not $isManaged) { $customPolicies.Add(('{0}: {1}' -f $source.Kind, $policy.Name)) }
        }
    }
    catch { Write-Warning "$($source.Command) failed; the custom policy check is incomplete: $($_.Exception.Message)" }
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$recommendations = New-Object -TypeName System.Collections.Generic.List[string]
foreach ($preset in 'Standard', 'Strict') {
    $presetRows = @($rows | Where-Object { $_.Preset -eq $preset -and $_.State -ne 'Not available' })
    $enabledRows = @($presetRows | Where-Object { $_.State -eq 'Enabled' })
    if ($enabledRows.Count -eq 0) {
        if ($preset -eq 'Standard') { $recommendations.Add('Turn on the Standard preset for all recipients: it applies the Microsoft recommended baseline and Microsoft keeps its settings current.') }
        else { $recommendations.Add('Turn on the Strict preset for admins, executives and other priority accounts (specific users or a group).') }
    }
    elseif ($preset -eq 'Standard' -and @($enabledRows | Where-Object { $_.AppliesTo -eq 'All recipients' }).Count -eq 0) {
        $recommendations.Add('The Standard preset only covers specific recipients; consider applying it to all recipients so nobody falls back to the default policies.')
    }
    if ($enabledRows.Count -gt 0 -and $enabledRows.Count -lt $presetRows.Count) {
        $states = ($presetRows | ForEach-Object { '{0}={1}' -f $_.Component, $_.State }) -join ', '
        $recommendations.Add(('{0} preset: the EOP and Defender for Office 365 rules differ ({1}); recipients only get part of the preset.' -f $preset, $states))
    }
}
if (@($rows | Where-Object { $_.Preset -eq 'Built-in protection' -and -not [string]::IsNullOrWhiteSpace($_.Exceptions) }).Count -gt 0) {
    $recommendations.Add('Built-in protection has exceptions; those recipients get no Safe Links or Safe Attachments unless a preset or custom policy includes them.')
}
if ($customPolicies.Count -gt 0) {
    $recommendations.Add(('{0} custom policy(ies) exist; presets take precedence, so they only apply outside the preset scopes. Check whether they are still needed.' -f $customPolicies.Count))
}

Write-Host ''
Write-Host 'Preset security policy status' -ForegroundColor Cyan
foreach ($row in $rows) {
    $colour = switch ($row.State) { 'Enabled' { 'Green' } 'Disabled' { 'Yellow' } default { 'DarkYellow' } }
    Write-Host ('  {0,-20} {1,-24}: {2,-14} {3}' -f $row.Preset, $row.Component, $row.State, $row.AppliesTo) -ForegroundColor $colour
}
Write-Host ('  Custom policies      : {0}' -f $customPolicies.Count)
foreach ($custom in ($customPolicies | Select-Object -First 10)) { Write-Host ('    {0}' -f $custom) }
if ($recommendations.Count -gt 0) {
    Write-Host '  Recommendations' -ForegroundColor Yellow
    foreach ($recommendation in $recommendations) { Write-Host ('    - {0}' -f $recommendation) }
}
Write-Host ('  Report               : {0}' -f $OutputPath)

if ($PassThru) { $rows }
#endregion Main
