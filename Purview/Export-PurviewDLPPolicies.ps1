<#
.SYNOPSIS
    Documents Microsoft Purview DLP policies and their rules to CSV and JSON.
.DESCRIPTION
    Connects to Security & Compliance PowerShell and reads every DLP policy (Get-DlpCompliancePolicy) and rule
    (Get-DlpComplianceRule). Policy rows show mode, status, workload locations (Exchange, SharePoint, OneDrive,
    Teams, Endpoint, on-premises scanner, third-party apps) and the number of rules. Rule rows flatten the
    sensitive information conditions - both the simple list and the groups/sensitivetypes shape - into readable
    text such as "Credit Card Number (min 1, conf High); U.S. Social Security Number (SSN) (min 1)", together with
    the blocking, notification and incident report settings.
    Writes DlpPolicies.csv, DlpRules.csv plus the raw objects as DlpPolicies.json and DlpRules.json into
    -OutputFolder. Policies still in test mode are called out with a warning. The script is read-only.
.PARAMETER OutputFolder
    Folder that receives the four export files. Defaults to .\PurviewDlpExport_yyyyMMdd-HHmm\ (created if missing).
.PARAMETER PassThru
    Also emit the shaped rule objects (one per DLP rule) to the pipeline.
.EXAMPLE
    PS> .\Export-PurviewDLPPolicies.ps1
    Exports all DLP policies and rules to .\PurviewDlpExport_<timestamp>\ and prints a summary.
.EXAMPLE
    PS> .\Export-PurviewDLPPolicies.ps1 -OutputFolder C:\Docs\Purview\DLP -Verbose
    Exports into a fixed folder, for example before a policy change so you have a baseline to compare against.
.EXAMPLE
    PS> .\Export-PurviewDLPPolicies.ps1 -PassThru | Where-Object { $_.BlockAccess } | Select-Object ParentPolicyName, Name, SensitiveInformation
    Lists the rules that block access and the conditions that trigger them.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Compliance Administrator, Compliance Data Administrator or Global Reader
    Category    : Data loss prevention
    Changes     : No
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession), not an Exchange Online one.
                  The flattened SensitiveInformation column omits And/Or operators between groups; the raw JSON export
                  keeps the complete condition structure. Run Get-DlpCompliancePolicy -DistributionDetail when a policy
                  shows a DistributionStatus other than Success to see the per-workload error.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-dlpcompliancepolicy
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-dlpcompliancerule
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

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

function Get-PropertyValue {
    <# Reads a key or property case-insensitively from a hashtable or object; the DLP condition shapes mix both. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]$key -eq $Name) { return $InputObject[$key] }
        }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function ConvertTo-SensitiveInfoString {
    <# Flattens ContentContainsSensitiveInformation into "Name (min 1, max 5, conf High); ..." and recurses into groups/sensitivetypes. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Condition
    )
    $parts = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($item in @($Condition)) {
        if ($null -eq $item) { continue }
        $groups = Get-PropertyValue -InputObject $item -Name 'groups'
        if ($null -ne $groups) {
            foreach ($group in @($groups)) {
                $members = @()
                foreach ($key in 'sensitivetypes', 'labels', 'trainableclassifiers') {
                    $members += @(Get-PropertyValue -InputObject $group -Name $key)
                }
                $text = ConvertTo-SensitiveInfoString -Condition $members
                if (-not [string]::IsNullOrWhiteSpace($text)) { $parts.Add($text) }
            }
            continue
        }
        $name = [string](Get-PropertyValue -InputObject $item -Name 'name')
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $details = New-Object -TypeName System.Collections.Generic.List[string]
        $minCount = [string](Get-PropertyValue -InputObject $item -Name 'mincount')
        $maxCount = [string](Get-PropertyValue -InputObject $item -Name 'maxcount')
        $confidence = [string](Get-PropertyValue -InputObject $item -Name 'confidencelevel')
        if (-not [string]::IsNullOrWhiteSpace($minCount)) { $details.Add("min $minCount") }
        if (-not [string]::IsNullOrWhiteSpace($maxCount) -and $maxCount -ne '-1') { $details.Add("max $maxCount") }
        if (-not [string]::IsNullOrWhiteSpace($confidence)) { $details.Add("conf $confidence") }
        if ($details.Count -gt 0) { $parts.Add(('{0} ({1})' -f $name, ($details -join ', '))) } else { $parts.Add($name) }
    }
    return ($parts -join '; ')
}

function ConvertTo-LocationString {
    <# Joins a policy location collection with ';', collapsing to 'All' when the collection contains All. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Location
    )
    $names = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($item in @($Location)) {
        if ($null -eq $item) { continue }
        $name = $null
        if ($null -ne $item.PSObject.Properties['Name']) { $name = [string]$item.Name }
        if ([string]::IsNullOrWhiteSpace($name)) { $name = [string]$item }
        if (-not [string]::IsNullOrWhiteSpace($name)) { $names.Add($name) }
    }
    if ($names.Count -eq 0) { return $null }
    if ($names -contains 'All') { return 'All' }
    return ($names -join ';')
}

function Export-JsonFile {
    <# Serialises the raw objects to UTF-8 JSON without a BOM so any tooling can consume the file. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    $json = ConvertTo-Json -InputObject @($InputObject) -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('PurviewDlpExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
$OutputFolder = (Resolve-Path -Path $OutputFolder).Path

try {
    Connect-ExchangeIfNeeded -Compliance
}
catch {
    throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)"
}

Write-Verbose 'Retrieving DLP policies.'
try {
    $policies = @(Get-DlpCompliancePolicy -ErrorAction Stop)
}
catch {
    throw "Failed to retrieve DLP policies: $($_.Exception.Message)"
}
Write-Verbose 'Retrieving DLP rules.'
try {
    $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
}
catch {
    throw "Failed to retrieve DLP rules: $($_.Exception.Message)"
}

$policyRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in ($policies | Sort-Object -Property Priority)) {
    $policyRows.Add([PSCustomObject]@{
            Name                         = [string]$policy.Name
            Guid                         = [string]$policy.Guid
            Mode                         = [string]$policy.Mode
            Enabled                      = [bool]$policy.Enabled
            Priority                     = $policy.Priority
            Workload                     = (@($policy.Workload | ForEach-Object { [string]$_ }) -join ';')
            DistributionStatus           = [string]$policy.DistributionStatus
            RuleCount                    = @($rules | Where-Object { $_.ParentPolicyName -eq $policy.Name }).Count
            ExchangeLocation             = ConvertTo-LocationString -Location $policy.ExchangeLocation
            SharePointLocation           = ConvertTo-LocationString -Location $policy.SharePointLocation
            OneDriveLocation             = ConvertTo-LocationString -Location $policy.OneDriveLocation
            TeamsLocation                = ConvertTo-LocationString -Location $policy.TeamsLocation
            EndpointDlpLocation          = ConvertTo-LocationString -Location $policy.EndpointDlpLocation
            OnPremisesScannerDlpLocation = ConvertTo-LocationString -Location $policy.OnPremisesScannerDlpLocation
            ThirdPartyAppDlpLocation     = ConvertTo-LocationString -Location $policy.ThirdPartyAppDlpLocation
            Comment                      = [string]$policy.Comment
            WhenCreated                  = $policy.WhenCreated
            WhenChanged                  = $policy.WhenChanged
        })
}

$ruleRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($rule in ($rules | Sort-Object -Property ParentPolicyName, Priority)) {
    $policyTip = [string]$rule.NotifyPolicyTipCustomText
    if (-not [string]::IsNullOrWhiteSpace($policyTip)) { $policyTip = ($policyTip -replace '\s+', ' ').Trim() }

    $ruleRows.Add([PSCustomObject]@{
            Name                         = [string]$rule.Name
            ParentPolicyName             = [string]$rule.ParentPolicyName
            Disabled                     = [bool]$rule.Disabled
            Priority                     = $rule.Priority
            SensitiveInformation         = ConvertTo-SensitiveInfoString -Condition $rule.ContentContainsSensitiveInformation
            ExceptIfSensitiveInformation = ConvertTo-SensitiveInfoString -Condition $rule.ExceptIfContentContainsSensitiveInformation
            AccessScope                  = [string]$rule.AccessScope
            BlockAccess                  = [bool]$rule.BlockAccess
            BlockAccessScope             = [string]$rule.BlockAccessScope
            NotifyUser                   = (@($rule.NotifyUser | ForEach-Object { [string]$_ }) -join ';')
            NotifyPolicyTipCustomText    = $policyTip
            GenerateIncidentReport       = (@($rule.GenerateIncidentReport | ForEach-Object { [string]$_ }) -join ';')
            ReportSeverityLevel          = [string]$rule.ReportSeverityLevel
            IncidentReportContent        = (@($rule.IncidentReportContent | ForEach-Object { [string]$_ }) -join ';')
            WhenChanged                  = $rule.WhenChanged
        })
}

$policyCsv = Join-Path -Path $OutputFolder -ChildPath 'DlpPolicies.csv'
$ruleCsv = Join-Path -Path $OutputFolder -ChildPath 'DlpRules.csv'
if ($policyRows.Count -gt 0) { $policyRows | Export-Csv -Path $policyCsv -NoTypeInformation -Encoding UTF8 }
if ($ruleRows.Count -gt 0) { $ruleRows | Export-Csv -Path $ruleCsv -NoTypeInformation -Encoding UTF8 }
try {
    Export-JsonFile -InputObject $policies -Path (Join-Path -Path $OutputFolder -ChildPath 'DlpPolicies.json')
    Export-JsonFile -InputObject $rules -Path (Join-Path -Path $OutputFolder -ChildPath 'DlpRules.json')
}
catch {
    Write-Warning "CSV files were written but the raw JSON export failed: $($_.Exception.Message)"
}

$testModePolicies = @($policyRows | Where-Object { $_.Mode -like 'Test*' })
$blockingRules = @($ruleRows | Where-Object { $_.BlockAccess -and -not $_.Disabled })

Write-Host ''
Write-Host 'DLP export summary' -ForegroundColor Cyan
Write-Host ('  Policies                 : {0}' -f $policyRows.Count)
foreach ($group in ($policyRows | Group-Object -Property Mode | Sort-Object -Property Name)) {
    Write-Host ('    {0,-24}: {1}' -f $group.Name, $group.Count)
}
Write-Host ('  Rules                    : {0} ({1} disabled)' -f $ruleRows.Count, @($ruleRows | Where-Object { $_.Disabled }).Count)
Write-Host ('  Active rules blocking    : {0}' -f $blockingRules.Count)
Write-Host ('  Output folder            : {0}' -f $OutputFolder)
if ($testModePolicies.Count -gt 0) {
    Write-Warning ('{0} DLP policy(ies) are still in test mode and do not enforce anything: {1}' -f $testModePolicies.Count, (($testModePolicies | Select-Object -ExpandProperty Name) -join ', '))
}

if ($PassThru) {
    $ruleRows
}
#endregion Main
