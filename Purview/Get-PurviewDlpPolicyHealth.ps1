<#
.SYNOPSIS
    Checks every Purview DLP policy for configuration problems and reports findings with a severity.
.DESCRIPTION
    Connects to Security & Compliance PowerShell, reads all DLP policies (Get-DlpCompliancePolicy -DistributionDetail)
    and rules (Get-DlpComplianceRule) and evaluates each policy for: Disabled, InTestModeTooLong (test mode and not
    changed for more than -TestModeMaxDays), NoLocations, NoRules, AllRulesDisabled, RulesWithoutActions (enabled
    audit-only rules), NoIncidentReport (no enabled rule generates an incident report or alert) and DistributionError.
    Each finding is one row with Severity High/Medium/Low; policies without findings get a single Healthy row.
    Writes a CSV and prints a console summary. The script is read-only.
.PARAMETER PolicyName
    Wildcard filter on the policy name (default * = all policies).
.PARAMETER TestModeMaxDays
    Days a policy may stay in test mode (TestWithNotifications / TestWithoutNotifications) before it is flagged. Default 30.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewDlpPolicyHealth_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the finding rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewDlpPolicyHealth.ps1
    Evaluates all DLP policies, writes the findings CSV and prints the summary.
.EXAMPLE
    PS> .\Get-PurviewDlpPolicyHealth.ps1 -PolicyName 'PCI*' -TestModeMaxDays 14 -PassThru | Where-Object { $_.Severity -eq 'High' }
    Shows only high-severity findings for the PCI policies, flagging test mode after 14 days.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Compliance Administrator, Compliance Data Administrator or a role group with View-Only DLP Compliance Management
    Category    : Data loss prevention
    Changes     : No
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). The service does not record when the
                  mode last changed, so InTestModeTooLong uses WhenChanged as the closest available proxy.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-dlpcompliancepolicy
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyName = '*',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$TestModeMaxDays = 30,

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

function Test-RuleHasAction {
    <# True when the rule configures at least one enforcement or notification action; audit-only rules return false. #>
    param([Parameter(Mandatory = $true)]$Rule, [Parameter(Mandatory = $true)][string[]]$ActionProperties)
    foreach ($name in $ActionProperties) {
        $value = $Rule.$name
        if ($null -eq $value) { continue }
        if ($value -is [bool]) { if ($value) { return $true } else { continue } }
        if (@($value | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) { return $true }
    }
    return $false
}

function New-HealthRow {
    <# Shapes one finding (or the Healthy marker) for a policy into the report row. #>
    param([Parameter(Mandatory = $true)]$Policy, [Parameter(Mandatory = $true)][int]$RuleCount, [Parameter(Mandatory = $true)][int]$EnabledRuleCount,
        [Parameter(Mandatory = $true)][string]$Finding, [Parameter(Mandatory = $true)][string]$Severity, [Parameter()][string]$Detail)
    [PSCustomObject]@{
        PolicyName         = [string]$Policy.Name
        Mode               = [string]$Policy.Mode
        Enabled            = [bool]$Policy.Enabled
        Priority           = $Policy.Priority
        Workloads          = [string]$Policy.Workload
        RuleCount          = $RuleCount
        EnabledRuleCount   = $EnabledRuleCount
        DistributionStatus = [string]$Policy.DistributionStatus
        WhenChanged        = $Policy.WhenChanged
        Finding            = $Finding
        Severity           = $Severity
        Detail             = $Detail
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewDlpPolicyHealth_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try {
    $policies = @(Get-DlpCompliancePolicy -DistributionDetail -ErrorAction Stop | Where-Object { $_.Name -like $PolicyName })
    $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
}
catch { throw "Failed to retrieve DLP policies or rules: $($_.Exception.Message)" }

# Properties that make a rule do something beyond logging the match.
$actionProperties = 'BlockAccess', 'NotifyUser', 'GenerateIncidentReport', 'GenerateAlert', 'EncryptRMSTemplate', 'SetHeader', 'RemoveHeader', 'Moderate',
'RedirectMessageTo', 'ApplyHtmlDisclaimer', 'PrependSubject', 'AddRecipients', 'EndpointDlpRestrictions', 'EndpointDlpBrowserRestrictions', 'RestrictBrowserAccess'
$locationProperties = 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'TeamsLocation', 'EndpointDlpLocation',
'OnPremisesScannerDlpLocation', 'ThirdPartyAppDlpLocation', 'PowerBIDlpLocation'

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($policy in ($policies | Sort-Object -Property Priority)) {
    $index++
    Write-Progress -Activity 'Evaluating DLP policies' -Status $policy.Name -PercentComplete (($index / $policies.Count) * 100)
    $policyRules = @($rules | Where-Object { $_.ParentPolicyName -eq $policy.Name })
    $enabledRules = @($policyRules | Where-Object { -not $_.Disabled })
    $findings = New-Object -TypeName System.Collections.Generic.List[object]

    if ($policy.Mode -eq 'Disable' -or -not $policy.Enabled) {
        $findings.Add(@{ Finding = 'Disabled'; Severity = 'Medium'; Detail = 'The policy is disabled and protects nothing.' })
    }
    elseif ($policy.Mode -like 'Test*' -and $null -ne $policy.WhenChanged) {
        $ageDays = [int]((Get-Date) - [datetime]$policy.WhenChanged).TotalDays
        if ($ageDays -gt $TestModeMaxDays) {
            $findings.Add(@{ Finding = 'InTestModeTooLong'; Severity = 'Medium'; Detail = ('Mode {0}; last changed {1} days ago.' -f $policy.Mode, $ageDays) })
        }
    }
    $locationCount = 0
    foreach ($name in $locationProperties) { $locationCount += @($policy.$name | Where-Object { $null -ne $_ }).Count }
    if ($locationCount -eq 0) {
        $findings.Add(@{ Finding = 'NoLocations'; Severity = 'High'; Detail = 'No workload locations are selected, so the policy applies nowhere.' })
    }
    if ($policyRules.Count -eq 0) {
        $findings.Add(@{ Finding = 'NoRules'; Severity = 'High'; Detail = 'The policy contains no rules.' })
    }
    elseif ($enabledRules.Count -eq 0) {
        $findings.Add(@{ Finding = 'AllRulesDisabled'; Severity = 'High'; Detail = ('All {0} rule(s) are disabled.' -f $policyRules.Count) })
    }
    $silentRules = @($enabledRules | Where-Object { -not (Test-RuleHasAction -Rule $_ -ActionProperties $actionProperties) })
    if ($silentRules.Count -gt 0) {
        $findings.Add(@{ Finding = 'RulesWithoutActions'; Severity = 'Low'; Detail = ('Audit-only rules: {0}' -f (($silentRules | ForEach-Object { $_.Name }) -join '; ')) })
    }
    $reportingRules = @($enabledRules | Where-Object { @(@($_.GenerateIncidentReport) + @($_.GenerateAlert) | Where-Object { $_ }).Count -gt 0 })
    if ($enabledRules.Count -gt 0 -and $reportingRules.Count -eq 0) {
        $findings.Add(@{ Finding = 'NoIncidentReport'; Severity = 'Low'; Detail = 'No enabled rule generates an incident report or alert; matches are only visible in Activity explorer.' })
    }
    $distributionErrors = @(@($policy.DistributionResults) | Where-Object { $null -ne $_ -and ([string]$_) -match 'Error|Fail' } | ForEach-Object { [string]$_ })
    if ($policy.DistributionStatus -eq 'Error' -or $distributionErrors.Count -gt 0) {
        $findings.Add(@{ Finding = 'DistributionError'; Severity = 'High'; Detail = ('Status {0}. {1}' -f $policy.DistributionStatus, ($distributionErrors -join ' | ')).Trim() })
    }

    if ($findings.Count -eq 0) { $findings.Add(@{ Finding = 'Healthy'; Severity = 'None'; Detail = '' }) }
    foreach ($finding in $findings) {
        $results.Add((New-HealthRow -Policy $policy -RuleCount $policyRules.Count -EnabledRuleCount $enabledRules.Count -Finding $finding.Finding -Severity $finding.Severity -Detail $finding.Detail))
    }
}
Write-Progress -Activity 'Evaluating DLP policies' -Completed

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning ('No DLP policies match "{0}".' -f $PolicyName) }

$issues = @($results | Where-Object { $_.Finding -ne 'Healthy' })
Write-Host 'Purview DLP policy health summary' -ForegroundColor Cyan
Write-Host ('  Policies evaluated : {0} ({1} healthy)' -f $policies.Count, @($results | Where-Object { $_.Finding -eq 'Healthy' }).Count)
foreach ($severity in 'High', 'Medium', 'Low') {
    $count = @($issues | Where-Object { $_.Severity -eq $severity }).Count
    Write-Host ('  {0,-7} findings    : {1}' -f $severity, $count) -ForegroundColor (@{ High = 'Red'; Medium = 'Yellow'; Low = 'Gray' }[$severity])
}
if ($issues.Count -gt 0) {
    Write-Host '  By finding         :'
    foreach ($group in ($issues | Group-Object -Property Finding | Sort-Object -Property Count -Descending)) {
        Write-Host ('    {0,5}  {1}' -f $group.Count, $group.Name)
    }
    Write-Host '  High severity      :'
    foreach ($issue in ($issues | Where-Object { $_.Severity -eq 'High' } | Select-Object -First 15)) {
        Write-Host ('    {0} - {1}: {2}' -f $issue.PolicyName, $issue.Finding, $issue.Detail) -ForegroundColor Red
    }
}
Write-Host ('  Report             : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
