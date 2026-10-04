<#
.SYNOPSIS
    Reports every Safe Links policy with its scope and URL protection settings, and shows who is only covered by Built-in protection.
.DESCRIPTION
    Joins Get-SafeLinksPolicy with Get-SafeLinksRule (custom policies), Get-ATPProtectionPolicyRule (Standard and Strict
    presets) and Get-ATPBuiltInProtectionRule (Built-in protection) so each policy row shows how it is applied - type,
    rule state, priority, recipient scope - plus the email, Teams and Office apps protection, real-time URL scanning,
    wait-for-scan delivery, URL rewriting, click tracking, click-through, internal sender coverage and excluded URLs.
    Flags mark policies that allow click-through, do not rewrite URLs, skip internal mail or are not applied; the
    console warns when no Standard/Strict preset or custom policy covers all recipients. Read-only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderSafeLinksPolicies_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderSafeLinksReport.ps1
    Writes one row per Safe Links policy to .\Reports\ and prints the coverage summary and flags.
.EXAMPLE
    PS> .\Get-DefenderSafeLinksReport.ps1 -PassThru | Where-Object { $_.AllowClickThrough } | Select-Object Name, PolicyType, Scope
    Shows which policies (and therefore which recipients) can bypass the Safe Links warning page.
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
    Notes       : Safe Links requires Defender for Office 365 Plan 1 or 2; in EOP-only tenants the cmdlets do not exist
                  and the script stops with an error. The Office apps, click tracking and click-through settings moved
                  from Get-AtpPolicyForO365 into the policies, so the global object is not read. Built-in protection
                  covers everyone else, but without URL rewriting or internal mail coverage and with click-through allowed.
.LINK
    https://learn.microsoft.com/defender-office-365/safe-links-about
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-safelinkspolicy
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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderSafeLinksPolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try {
    $policies = @(Get-SafeLinksPolicy -ErrorAction Stop)
    $rules = @(Get-SafeLinksRule -ErrorAction Stop)
}
catch { throw "Failed to read Safe Links policies (Defender for Office 365 Plan 1 or 2 is required): $($_.Exception.Message)" }
# Preset and Built-in protection policies are applied by these rules, not by Safe Links rules.
foreach ($command in 'Get-ATPProtectionPolicyRule', 'Get-ATPBuiltInProtectionRule') {
    try { $rules += @(& $command -ErrorAction Stop) }
    catch { Write-Warning "$command could not be read; preset or built-in policies will show no scope: $($_.Exception.Message)" }
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in $policies) {
    $binding = Get-PolicyBinding -Policy $policy -Rules $rules -LinkProperty 'SafeLinksPolicy'
    $excluded = @($policy.DoNotRewriteUrls | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })

    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ([bool]$policy.AllowClickThrough) { $flags.Add('Users can click through to the original URL') }
    if ([bool]$policy.DisableUrlRewrite) { $flags.Add('URLs not rewritten (time-of-click protection only in supported Outlook clients)') }
    if (-not [bool]$policy.EnableSafeLinksForEmail) { $flags.Add('Email protection off') }
    if (-not [bool]$policy.ScanUrls) { $flags.Add('Real-time URL scanning off') }
    if (-not [bool]$policy.EnableForInternalSenders) { $flags.Add('Internal messages not covered') }
    if ($excluded.Count -gt 0) { $flags.Add(('{0} URL(s) excluded from rewriting' -f $excluded.Count)) }
    if ($binding.State -notlike 'Enabled*') { $flags.Add('Policy not applied to anyone') }

    $rows.Add([PSCustomObject]@{
            Name                       = [string]$policy.Name
            PolicyType                 = $binding.PolicyType
            State                      = $binding.State
            Priority                   = $binding.Priority
            Scope                      = $binding.Scope
            EnableSafeLinksForEmail    = [bool]$policy.EnableSafeLinksForEmail
            EnableSafeLinksForTeams    = [bool]$policy.EnableSafeLinksForTeams
            EnableSafeLinksForOffice   = [bool]$policy.EnableSafeLinksForOffice
            TrackClicks                = [bool]$policy.TrackClicks
            AllowClickThrough          = [bool]$policy.AllowClickThrough
            ScanUrls                   = [bool]$policy.ScanUrls
            EnableForInternalSenders   = [bool]$policy.EnableForInternalSenders
            DeliverMessageAfterScan    = [bool]$policy.DeliverMessageAfterScan
            DisableUrlRewrite          = [bool]$policy.DisableUrlRewrite
            DoNotRewriteUrlsCount      = $excluded.Count
            DoNotRewriteUrls           = ($excluded -join ';')
            EnableOrganizationBranding = [bool]$policy.EnableOrganizationBranding
            CustomNotificationText     = [string]$policy.CustomNotificationText
            WhenChanged                = $policy.WhenChanged
            Flags                      = ($flags -join '; ')
        })
}
# Evaluation order: Strict preset, Standard preset, custom rules by priority, Built-in protection last.
$typeRank = @{ 'Preset (Strict)' = 0; 'Preset (Standard)' = 1; 'Custom' = 2; 'Built-in protection' = 3; 'Default' = 4 }
$rows = @($rows | Sort-Object -Property @{ Expression = { $typeRank[$_.PolicyType] } }, Priority)
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# A rule without include conditions (scope 'Everyone' or exceptions only) reaches every recipient.
$everyonePolicies = @($rows | Where-Object { $_.State -eq 'Enabled' -and ($_.Scope -eq 'Everyone' -or $_.Scope -like 'ExceptIf*') })
$everyoneText = $(if ($everyonePolicies.Count -gt 0) { ($everyonePolicies | ForEach-Object { $_.Name }) -join ', ' } else { 'none' })
$builtIn = @($rows | Where-Object { $_.PolicyType -eq 'Built-in protection' }) | Select-Object -First 1
$flagged = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Flags) })

Write-Host ''
Write-Host 'Safe Links policy summary' -ForegroundColor Cyan
Write-Host ('  Policies              : {0} ({1} applied)' -f $rows.Count, @($rows | Where-Object { $_.State -like 'Enabled*' }).Count)
Write-Host ('  Applied to everyone   : {0}' -f $everyoneText) -ForegroundColor $(if ($everyonePolicies.Count -gt 0) { 'Green' } else { 'Yellow' })
Write-Host ('  Built-in protection   : {0}' -f $(if ($null -ne $builtIn) { $builtIn.Scope } else { 'rule not found' }))
Write-Host ('  Policies with flags   : {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $flagged) { Write-Host ('    {0} [{1}]: {2}' -f $row.Name, $row.PolicyType, $row.Flags) }
Write-Host ('  Report                : {0}' -f $OutputPath)
if ($everyonePolicies.Count -eq 0) {
    Write-Warning 'No preset or custom Safe Links policy applies to all recipients; everyone not explicitly included only gets Built-in protection (no URL rewriting, internal mail not covered).'
}
if ($null -ne $builtIn -and $builtIn.Scope -like '*ExceptIf*') {
    Write-Warning "Built-in protection has exceptions ($($builtIn.Scope)); those recipients have no Safe Links protection unless another policy includes them."
}

if ($PassThru) { $rows }
#endregion Main
