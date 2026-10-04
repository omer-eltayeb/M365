<#
.SYNOPSIS
    Documents Microsoft Purview Communication Compliance policies and their rules (reviewers, sampling, conditions).
.DESCRIPTION
    Connects to Security & Compliance PowerShell, reads every policy with Get-SupervisoryReviewPolicyV2 and the rules
    of each policy with Get-SupervisoryReviewRule -Policy. Policies are exported with their reviewers, priority, state
    and distribution status; rules with their (truncated) condition, sampling rate, content sources and status. Policies
    without reviewers and rules with a 0 % sampling rate are flagged. Writes two CSV files and prints a summary.
.PARAMETER ConditionLength
    Maximum number of characters of the rule condition kept in the CSV (default 300).
.PARAMETER OutputPath
    Path of the policies CSV. Defaults to .\Reports\PurviewCommunicationCompliance_yyyyMMdd-HHmm.csv; rules are written next to it as <base>_Rules.csv.
.PARAMETER PassThru
    Also emit the policy rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewCommunicationCompliancePolicies.ps1
    Exports policies and rules to .\Reports and prints the policies that have no reviewers or sample nothing.
.EXAMPLE
    PS> .\Get-PurviewCommunicationCompliancePolicies.ps1 -OutputPath C:\Baselines\CC\Policies.csv -ConditionLength 1000 -Verbose
    Keeps a baseline with longer rule conditions.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Communication Compliance or Communication Compliance Admins role group (Supervisory Review Administrator role) in Microsoft Purview
    Category    : Risk, compliance & roles
    Changes     : No
    Notes       : Communication Compliance needs Microsoft 365 E5, E5 Compliance, the E5 Insider Risk Management add-on or the
                  Communication Compliance add-on. The cmdlets are only imported when the account holds one of the role groups;
                  the script stops with a clear message otherwise. Message content and alerts are never exported, only the
                  configuration. Conditions are stored as a single query string and are truncated to -ConditionLength.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-supervisoryreviewpolicyv2
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-supervisoryreviewrule
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(50, 10000)]
    [int]$ConditionLength = 300,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewCommunicationCompliance_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$rulesPath = [System.IO.Path]::ChangeExtension($OutputPath, $null) + '_Rules.csv'

try {
    Connect-ExchangeIfNeeded -Compliance
}
catch {
    throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)"
}
if ($null -eq (Get-Command -Name Get-SupervisoryReviewPolicyV2 -ErrorAction SilentlyContinue)) {
    throw ('Get-SupervisoryReviewPolicyV2 is not available in this session. Communication Compliance needs Microsoft 365 E5 / E5 Compliance ' +
        'licensing and membership in the Communication Compliance or Communication Compliance Admins role group.')
}
try {
    $policies = @(Get-SupervisoryReviewPolicyV2 -ErrorAction Stop)
}
catch {
    throw "Get-SupervisoryReviewPolicyV2 failed: $($_.Exception.Message)"
}

$policyRows = New-Object -TypeName System.Collections.Generic.List[object]
$ruleRows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($policy in $policies) {
    $index++
    Write-Progress -Activity 'Reading communication compliance policies' -Status $policy.Name -PercentComplete (100 * $index / $policies.Count)
    $rules = @()
    try {
        $rules = @(Get-SupervisoryReviewRule -Policy $policy.Name -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not read the rules of policy '$($policy.Name)': $($_.Exception.Message)"
    }
    foreach ($rule in $rules) {
        $condition = [string]$rule.Condition
        $ruleRows.Add([PSCustomObject]@{
                Policy         = [string]$policy.Name
                Name           = [string]$rule.Name
                Condition      = $condition.Substring(0, [math]::Min($ConditionLength, $condition.Length))
                SamplingRate   = $rule.SamplingRate
                ContentSources = (@($rule.ContentSources) -join '; ')
                Status         = [string]$rule.Status
                Flag           = $(if ([string]$rule.SamplingRate -eq '0') { 'ZeroSampling' } else { '' })
            })
    }
    $reviewers = @($policy.Reviewers | Where-Object { $null -ne $_ })
    $flags = @()
    if ($reviewers.Count -eq 0) { $flags += 'NoReviewers' }
    if ($policy.Enabled -eq $false) { $flags += 'Disabled' }
    if (@($rules | Where-Object { [string]$_.SamplingRate -eq '0' }).Count -gt 0) { $flags += 'ZeroSamplingRule' }
    $policyRows.Add([PSCustomObject]@{
            Name               = [string]$policy.Name
            Enabled            = $policy.Enabled
            Comment            = [string]$policy.Comment
            Reviewers          = ($reviewers -join '; ')
            ReviewerCount      = $reviewers.Count
            Priority           = $policy.Priority
            RuleCount          = $rules.Count
            WhenCreated        = $policy.WhenCreated
            WhenChanged        = $policy.WhenChanged
            DistributionStatus = [string]$policy.DistributionStatus
            Flag               = ($flags -join '; ')
        })
}
Write-Progress -Activity 'Reading communication compliance policies' -Completed

if ($policyRows.Count -gt 0) {
    $policyRows | Sort-Object -Property Priority, Name | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No communication compliance policies were returned.'
}
if ($ruleRows.Count -gt 0) {
    $ruleRows | Sort-Object -Property Policy, Name | Export-Csv -Path $rulesPath -NoTypeInformation -Encoding UTF8
}

Write-Host ''
Write-Host 'Communication compliance summary' -ForegroundColor Cyan
Write-Host ('  Policies      : {0}  (enabled {1})' -f $policyRows.Count, @($policyRows | Where-Object { $_.Enabled -eq $true }).Count)
Write-Host ('  Rules         : {0}' -f $ruleRows.Count)
Write-Host ('  No reviewers  : {0}' -f @($policyRows | Where-Object { $_.Flag -like '*NoReviewers*' }).Count) -ForegroundColor Yellow
Write-Host ('  0 % sampling  : {0} rule(s)' -f @($ruleRows | Where-Object { $_.Flag -eq 'ZeroSampling' }).Count) -ForegroundColor Yellow
foreach ($flagged in ($policyRows | Where-Object { $_.Flag })) { Write-Host ('  Review        : {0} -> {1}' -f $flagged.Name, $flagged.Flag) -ForegroundColor Yellow }
if ($policyRows.Count -gt 0) { Write-Host ('  Policies CSV  : {0}' -f $OutputPath) }
if ($ruleRows.Count -gt 0) { Write-Host ('  Rules CSV     : {0}' -f $rulesPath) }

if ($PassThru) {
    $policyRows
}
#endregion Main
