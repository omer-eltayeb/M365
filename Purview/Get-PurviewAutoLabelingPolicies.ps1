<#
.SYNOPSIS
    Documents Microsoft Purview auto-labeling policies and their rules to CSV and JSON.
.DESCRIPTION
    Connects to Security & Compliance PowerShell and documents every service-side auto-labeling policy
    (Get-AutoSensitivityLabelPolicy) and rule (Get-AutoSensitivityLabelRule): the label each policy applies (resolved
    via Get-Label), mode, locations, priority, distribution status, and each rule's sensitive information conditions
    flattened to text (nested groups included). Writes AutoLabelPolicies.csv, AutoLabelRules.csv and the raw objects as
    JSON into -OutputFolder; flags simulations older than -MaxSimulationDays, policies without rules and disabled rules.
.PARAMETER OutputFolder
    Folder that receives the four export files. Defaults to .\PurviewAutoLabelExport_yyyyMMdd-HHmm\ (created if missing).
.PARAMETER MaxSimulationDays
    Policies in simulation (Mode TestWithNotifications or TestWithoutNotifications) last changed more than this many days ago are flagged. Default 30.
.PARAMETER PassThru
    Also emit the shaped policy objects to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewAutoLabelingPolicies.ps1
    Exports all auto-labeling policies and rules to .\PurviewAutoLabelExport_<timestamp>\ and prints a summary.
.EXAMPLE
    PS> .\Get-PurviewAutoLabelingPolicies.ps1 -OutputFolder C:\Docs\Purview\AutoLabel -MaxSimulationDays 14 -PassThru | Where-Object { $_.InSimulation }
    Exports into a fixed folder, flags simulations unchanged for more than two weeks and lists the policies still in simulation.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Compliance Administrator, Compliance Data Administrator or Information Protection Admin; Global Reader is sufficient
    Category    : Information protection
    Changes     : No
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). Service-side auto-labeling needs
                  Microsoft 365 E5, E5 Compliance or Information Protection and Governance licensing. Simulation age is
                  measured from WhenChanged, so a simulation that was recently edited is not flagged.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-autosensitivitylabelpolicy
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-autosensitivitylabelrule
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$MaxSimulationDays = 30,

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

function ConvertTo-SensitiveInfoString {
    <# Flattens ContentContainsSensitiveInformation into "Name (min 1, max 5, conf High); ..." and recurses into groups. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Condition
    )
    $parts = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($item in @($Condition)) {
        if ($null -eq $item) { continue }
        if ($item -is [string]) { $parts.Add($item); continue }
        # Conditions arrive as hashtables or PSObjects depending on the module version; a JSON round trip normalises them.
        if ($item -is [System.Collections.IDictionary]) { $item = $item | ConvertTo-Json -Depth 10 | ConvertFrom-Json }
        if ($null -ne $item.PSObject.Properties['groups']) {
            foreach ($group in @($item.groups)) {
                foreach ($key in 'sensitivetypes', 'labels', 'trainableclassifiers') {
                    $text = ConvertTo-SensitiveInfoString -Condition $group.$key
                    if (-not [string]::IsNullOrWhiteSpace($text)) { $parts.Add($text) }
                }
            }
            continue
        }
        if ([string]::IsNullOrWhiteSpace([string]$item.name)) { continue }
        $details = @()
        if (-not [string]::IsNullOrWhiteSpace([string]$item.mincount)) { $details += "min $($item.mincount)" }
        if (-not [string]::IsNullOrWhiteSpace([string]$item.maxcount) -and [string]$item.maxcount -ne '-1') { $details += "max $($item.maxcount)" }
        if (-not [string]::IsNullOrWhiteSpace([string]$item.confidencelevel)) { $details += "conf $($item.confidencelevel)" }
        if ($details.Count -gt 0) { $parts.Add(('{0} ({1})' -f $item.name, ($details -join ', '))) } else { $parts.Add([string]$item.name) }
    }
    return ($parts -join '; ')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('PurviewAutoLabelExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$OutputFolder = (Resolve-Path -Path $OutputFolder).Path

try {
    Connect-ExchangeIfNeeded -Compliance
    Write-Verbose 'Retrieving auto-labeling policies, rules and sensitivity labels.'
    $policies = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)
    $rules = @(Get-AutoSensitivityLabelRule -ErrorAction Stop)
    $labels = @(Get-Label -ErrorAction Stop)
}
catch {
    throw "Unable to connect to Security & Compliance PowerShell or read the auto-labeling configuration: $($_.Exception.Message)"
}

# ApplySensitivityLabel may hold the label GUID or its name, so index labels by every identifier.
$labelNames = @{}
foreach ($label in $labels) {
    foreach ($key in @($label.Guid, $label.ImmutableId, $label.Name | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
        $labelNames[([string]$key).ToLowerInvariant()] = [string]$label.DisplayName
    }
}

$now = Get-Date
$policyRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in ($policies | Sort-Object -Property Priority)) {
    $labelName = [string]$policy.ApplySensitivityLabel
    if ($labelNames.ContainsKey($labelName.ToLowerInvariant())) { $labelName = $labelNames[$labelName.ToLowerInvariant()] }
    $policyRules = @($rules | Where-Object { [string]$_.ParentPolicyName -eq [string]$policy.Name })
    $disabledRules = @($policyRules | Where-Object { $_.Disabled }).Count
    $inSimulation = ([string]$policy.Mode -like 'Test*')
    $simulationDays = $null
    if ($inSimulation -and $null -ne $policy.WhenChanged) { $simulationDays = [int][math]::Floor(($now - [datetime]$policy.WhenChanged).TotalDays) }
    $issues = @()
    if ($simulationDays -gt $MaxSimulationDays) { $issues += "In simulation for $simulationDays days" }
    if (-not $policy.Enabled) { $issues += 'Policy disabled' }
    if ($policyRules.Count -eq 0) { $issues += 'No rules' } elseif ($disabledRules -gt 0) { $issues += "$disabledRules disabled rule(s)" }
    if ([string]::IsNullOrWhiteSpace($labelName)) { $issues += 'No label to apply' }

    $policyRows.Add([PSCustomObject]@{
            Name               = [string]$policy.Name
            Guid               = [string]$policy.Guid
            Enabled            = [bool]$policy.Enabled
            Mode               = [string]$policy.Mode
            InSimulation       = $inSimulation
            SimulationDays     = $simulationDays
            Label              = $labelName
            Priority           = $policy.Priority
            OverwriteLabel     = [bool]$policy.OverwriteLabel
            ExchangeLocation   = (@($policy.ExchangeLocation | ForEach-Object { [string]$_ }) -join ';')
            SharePointLocation = (@($policy.SharePointLocation | ForEach-Object { [string]$_ }) -join ';')
            OneDriveLocation   = (@($policy.OneDriveLocation | ForEach-Object { [string]$_ }) -join ';')
            RuleCount          = $policyRules.Count
            DisabledRuleCount  = $disabledRules
            DistributionStatus = [string]$policy.DistributionStatus
            Comment            = [string]$policy.Comment
            WhenCreated        = $policy.WhenCreated
            WhenChanged        = $policy.WhenChanged
            Issues             = ($issues -join '; ')
        })
}

$ruleRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($rule in ($rules | Sort-Object -Property ParentPolicyName, Priority)) {
    $ruleRows.Add([PSCustomObject]@{
            Name                         = [string]$rule.Name
            ParentPolicyName             = [string]$rule.ParentPolicyName
            Disabled                     = [bool]$rule.Disabled
            Priority                     = $rule.Priority
            Workload                     = (@($rule.Workload) -join ';')
            SensitiveInformation         = ConvertTo-SensitiveInfoString -Condition $rule.ContentContainsSensitiveInformation
            ExceptIfSensitiveInformation = ConvertTo-SensitiveInfoString -Condition $rule.ExceptIfContentContainsSensitiveInformation
        })
}

if ($policyRows.Count -gt 0) { $policyRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'AutoLabelPolicies.csv') -NoTypeInformation -Encoding UTF8 }
if ($ruleRows.Count -gt 0) { $ruleRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'AutoLabelRules.csv') -NoTypeInformation -Encoding UTF8 }
try {
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText((Join-Path -Path $OutputFolder -ChildPath 'AutoLabelPolicies.json'), (ConvertTo-Json -InputObject @($policies) -Depth 10), $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path -Path $OutputFolder -ChildPath 'AutoLabelRules.json'), (ConvertTo-Json -InputObject @($rules) -Depth 10), $utf8NoBom)
}
catch {
    Write-Warning "CSV files were written but the raw JSON export failed: $($_.Exception.Message)"
}

$flagged = @($policyRows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Issues) })
Write-Host ''
Write-Host 'Auto-labeling export summary' -ForegroundColor Cyan
Write-Host ('  Policies       : {0} ({1} enabled, {2} in simulation)' -f $policyRows.Count, @($policyRows | Where-Object { $_.Enabled }).Count, @($policyRows | Where-Object { $_.InSimulation }).Count)
Write-Host ('  Rules          : {0} ({1} disabled)' -f $ruleRows.Count, @($ruleRows | Where-Object { $_.Disabled }).Count)
Write-Host ('  Flagged        : {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $flagged) { Write-Host ('    {0}: {1}' -f $row.Name, $row.Issues) -ForegroundColor Yellow }
Write-Host ('  Output folder  : {0}' -f $OutputFolder)

if ($PassThru) {
    $policyRows
}
#endregion Main
