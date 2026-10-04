<#
.SYNOPSIS
    Reports every Safe Attachments policy with its scope and action, plus the global SharePoint, OneDrive, Teams and Safe Documents settings.
.DESCRIPTION
    Joins Get-SafeAttachmentPolicy with Get-SafeAttachmentRule (custom policies), Get-ATPProtectionPolicyRule (Standard
    and Strict presets) and Get-ATPBuiltInProtectionRule (Built-in protection) so each policy row shows how it is
    applied - type, rule state, priority, recipient scope - plus whether scanning is enabled, the unknown malware
    response (Block, Replace, DynamicDelivery or Allow, which the portal calls Monitor), redirect settings and the
    quarantine policy. Get-AtpPolicyForO365 supplies the tenant-wide Safe Attachments for SharePoint, OneDrive and
    Teams and Safe Documents settings. Weak settings are flagged in the CSV and the console. Read-only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderSafeAttachmentsPolicies_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderSafeAttachmentsReport.ps1
    Writes one row per Safe Attachments policy to .\Reports\ and prints the global settings and flags.
.EXAMPLE
    PS> .\Get-DefenderSafeAttachmentsReport.ps1 -PassThru | Where-Object { $_.Action -ne 'Block' } | Select-Object Name, PolicyType, Action, Scope
    Shows the policies that do not block malware outright and who they apply to.
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
    Notes       : Safe Attachments requires Defender for Office 365 Plan 1 or 2; in EOP-only tenants the cmdlets do not
                  exist and the script stops with an error. Safe Documents additionally needs Microsoft 365 E5/A5 Security.
                  The former ActionOnError setting is retired - the response is applied when scanning times out or fails.
.LINK
    https://learn.microsoft.com/defender-office-365/safe-attachments-about
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-safeattachmentpolicy
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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderSafeAttachmentsPolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try {
    $policies = @(Get-SafeAttachmentPolicy -ErrorAction Stop)
    $rules = @(Get-SafeAttachmentRule -ErrorAction Stop)
}
catch { throw "Failed to read Safe Attachments policies (Defender for Office 365 Plan 1 or 2 is required): $($_.Exception.Message)" }
# Preset and Built-in protection policies are applied by these rules, not by Safe Attachments rules.
foreach ($command in 'Get-ATPProtectionPolicyRule', 'Get-ATPBuiltInProtectionRule') {
    try { $rules += @(& $command -ErrorAction Stop) }
    catch { Write-Warning "$command could not be read; preset or built-in policies will show no scope: $($_.Exception.Message)" }
}
$atpGlobal = $null
try { $atpGlobal = Get-AtpPolicyForO365 -ErrorAction Stop | Select-Object -First 1 }
catch { Write-Warning "Get-AtpPolicyForO365 failed; the tenant-wide Safe Attachments settings are not reported: $($_.Exception.Message)" }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in $policies) {
    $binding = Get-PolicyBinding -Policy $policy -Rules $rules -LinkProperty 'SafeAttachmentPolicy'
    $action = [string]$policy.Action
    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if (-not [bool]$policy.Enable) { $flags.Add('Scanning off (Enable = False) - attachments are not detonated') }
    elseif ($action -in @('Allow', 'Monitor')) { $flags.Add('Monitor only (Action Allow) - malware is still delivered') }
    if ([bool]$policy.Redirect -and [string]::IsNullOrWhiteSpace([string]$policy.RedirectAddress)) { $flags.Add('Redirect enabled without a redirect address') }
    if ($binding.State -notlike 'Enabled*') { $flags.Add('Policy not applied to anyone') }

    $rows.Add([PSCustomObject]@{
            Name                  = [string]$policy.Name
            PolicyType            = $binding.PolicyType
            State                 = $binding.State
            Priority              = $binding.Priority
            Scope                 = $binding.Scope
            Enable                = [bool]$policy.Enable
            Action                = $action
            Redirect              = [bool]$policy.Redirect
            RedirectAddress       = [string]$policy.RedirectAddress
            QuarantineTag         = [string]$policy.QuarantineTag
            RecommendedPolicyType = [string]$policy.RecommendedPolicyType
            WhenChanged           = $policy.WhenChanged
            Flags                 = ($flags -join '; ')
        })
}

# Evaluation order: Strict preset, Standard preset, custom rules by priority, Built-in protection last.
$typeRank = @{ 'Preset (Strict)' = 0; 'Preset (Standard)' = 1; 'Custom' = 2; 'Built-in protection' = 3; 'Default' = 4 }
$rows = @($rows | Sort-Object -Property @{ Expression = { $typeRank[$_.PolicyType] } }, Priority)
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$everyonePolicies = @($rows | Where-Object { $_.State -eq 'Enabled' -and $_.Enable -and ($_.Scope -eq 'Everyone' -or $_.Scope -like 'ExceptIf*') })
$builtIn = @($rows | Where-Object { $_.PolicyType -eq 'Built-in protection' }) | Select-Object -First 1
$flagged = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Flags) })

Write-Host ''
Write-Host 'Safe Attachments policy summary' -ForegroundColor Cyan
Write-Host ('  Policies                    : {0} ({1} applied)' -f $rows.Count, @($rows | Where-Object { $_.State -like 'Enabled*' }).Count)
Write-Host ('  Applied to everyone         : {0}' -f $(if ($everyonePolicies.Count -gt 0) { ($everyonePolicies | ForEach-Object { $_.Name }) -join ', ' } else { 'none' }))
Write-Host ('  Built-in protection         : {0}' -f $(if ($null -ne $builtIn) { '{0} (Action {1})' -f $builtIn.Scope, $builtIn.Action } else { 'rule not found' }))
if ($null -ne $atpGlobal) {
    $spoTeams = [bool]$atpGlobal.EnableATPForSPOTeamsODB
    $safeDocs = [bool]$atpGlobal.EnableSafeDocs
    Write-Host ('  SharePoint/OneDrive/Teams   : {0}' -f $(if ($spoTeams) { 'On' } else { 'OFF' })) -ForegroundColor $(if ($spoTeams) { 'Green' } else { 'Yellow' })
    Write-Host ('  Safe Documents              : {0}' -f $(if ($safeDocs) { 'On' } else { 'OFF' })) -ForegroundColor $(if ($safeDocs) { 'Green' } else { 'Yellow' })
    Write-Host ('  Safe Documents click-through: {0}' -f $(if ([bool]$atpGlobal.AllowSafeDocsOpen) { 'Allowed' } else { 'Not allowed' }))
    if (-not $spoTeams) { Write-Warning 'Safe Attachments for SharePoint, OneDrive and Teams is off (Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true); uploaded files are not detonated.' }
    if (-not $safeDocs) { Write-Warning 'Safe Documents is off (Set-AtpPolicyForO365 -EnableSafeDocs $true); Protected View files are not scanned by Defender. Needs Microsoft 365 E5/A5 Security.' }
    if ([bool]$atpGlobal.AllowSafeDocsOpen) { Write-Warning 'Users can leave Protected View even when Safe Documents identified the file as malicious (AllowSafeDocsOpen).' }
}
Write-Host ('  Policies with flags         : {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $flagged) {
    Write-Host ('    {0} [{1}]: {2}' -f $row.Name, $row.PolicyType, $row.Flags)
}
if ($null -ne $builtIn -and $builtIn.Scope -like '*ExceptIf*') {
    Write-Warning "Built-in protection has exceptions ($($builtIn.Scope)); those recipients have no Safe Attachments protection unless another policy includes them."
}
Write-Host ('  Report                      : {0}' -f $OutputPath)

if ($PassThru) { $rows }
#endregion Main
