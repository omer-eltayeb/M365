<#
.SYNOPSIS
    Inventories sensitive information types (SITs), their rule packages and the DLP / auto-labeling rules that use them.
.DESCRIPTION
    Connects to Security & Compliance PowerShell and lists every sensitive information type (Get-DlpSensitiveInformationType)
    with publisher, Microsoft or Custom origin, kind, recommended confidence and its rule package
    (Get-DlpSensitiveInformationTypeRulePackage). Every DLP rule condition (ContentContainsSensitiveInformation and ExceptIf...,
    including nested groups) and optionally every auto-labeling rule is scanned so each SIT lists the rules that reference it.
    -ExportCustomPackages writes each custom rule package to an XML file next to the CSV. Writes a CSV and prints a summary.
    The script is read-only.
.PARAMETER Name
    Wildcard filter on the SIT name (default * = all).
.PARAMETER OnlyCustom
    Return only custom SITs (those outside the built-in Microsoft Rule Package).
.PARAMETER OnlyUnused
    Return only SITs that no DLP rule (and, with -IncludeAutoLabel, no auto-labeling rule) references.
.PARAMETER IncludeAutoLabel
    Also scan auto-labeling policy rules (Get-AutoSensitivityLabelRule) for SIT references.
.PARAMETER ExportCustomPackages
    Export every custom rule package (SerializedClassificationRuleCollection) as an XML file in the report folder.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewSensitiveInfoTypes_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewSensitiveInfoTypes.ps1
    Lists all SITs with the DLP rules that use them and writes the CSV.
.EXAMPLE
    PS> .\Get-PurviewSensitiveInfoTypes.ps1 -OnlyCustom -IncludeAutoLabel -ExportCustomPackages -Verbose
    Reports the custom SITs including auto-labeling usage and backs up the custom rule packages as XML.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Compliance Administrator, Compliance Data Administrator or Global Reader
    Category    : Data loss prevention
    Changes     : No
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). Built-in SITs carry the all-zero
                  RulePackId; everything else (including Microsoft.SCCManaged.CustomRulePack, which holds SITs created in the
                  portal) is reported as Custom. Exported XML can be re-imported with Set-DlpSensitiveInformationTypeRulePackage.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-dlpsensitiveinformationtype
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Name = '*',

    [Parameter()]
    [switch]$OnlyCustom,

    [Parameter()]
    [switch]$OnlyUnused,

    [Parameter()]
    [switch]$IncludeAutoLabel,

    [Parameter()]
    [switch]$ExportCustomPackages,

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

function Get-PropertyValue {
    <# Reads a key or property case-insensitively from a hashtable or object; DLP condition shapes mix both. #>
    param([Parameter()][AllowNull()]$InputObject, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) { if ([string]$key -eq $Name) { return $InputObject[$key] } }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-SitReference {
    <# Emits every SIT name or id referenced by a ContentContainsSensitiveInformation condition, recursing into groups. #>
    param([Parameter()][AllowNull()]$Condition)
    foreach ($item in @($Condition)) {
        if ($null -eq $item) { continue }
        $groups = Get-PropertyValue -InputObject $item -Name 'groups'
        if ($null -ne $groups) {
            foreach ($group in @($groups)) { Get-SitReference -Condition (Get-PropertyValue -InputObject $group -Name 'sensitivetypes') }
            continue
        }
        foreach ($key in 'name', 'id') {
            $value = [string](Get-PropertyValue -InputObject $item -Name $key)
            if (-not [string]::IsNullOrWhiteSpace($value)) { $value }
        }
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewSensitiveInfoTypes_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try {
    $sits = @(Get-DlpSensitiveInformationType -ErrorAction Stop | Where-Object { $_.Name -like $Name })
    $packages = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    $ruleSets = @(@{ Kind = 'DLP'; Rules = @(Get-DlpComplianceRule -ErrorAction Stop) })
    if ($IncludeAutoLabel) { $ruleSets += @{ Kind = 'AutoLabel'; Rules = @(Get-AutoSensitivityLabelRule -ErrorAction Stop) } }
}
catch { throw "Failed to retrieve sensitive information types, rule packages or rules: $($_.Exception.Message)" }
# Usage map keyed by lower-case SIT name or id -> "Kind: Policy/Rule" labels.
$usage = @{}
foreach ($ruleSet in $ruleSets) {
    foreach ($rule in $ruleSet.Rules) {
        $references = @(Get-SitReference -Condition $rule.ContentContainsSensitiveInformation) + @(Get-SitReference -Condition $rule.ExceptIfContentContainsSensitiveInformation)
        foreach ($reference in ($references | Select-Object -Unique)) {
            $key = $reference.ToLowerInvariant()
            if (-not $usage.ContainsKey($key)) { $usage[$key] = New-Object -TypeName System.Collections.Generic.List[string] }
            $usage[$key].Add(('{0}: {1}/{2}' -f $ruleSet.Kind, $rule.ParentPolicyName, $rule.Name))
        }
    }
}
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($sit in $sits) {
    $isCustom = ([string]$sit.RulePackId -ne '00000000-0000-0000-0000-000000000000')
    $usedBy = @(@($usage[([string]$sit.Name).ToLowerInvariant()]) + @($usage[([string]$sit.Id).ToLowerInvariant()]) | Where-Object { $_ } | Select-Object -Unique)
    if (($OnlyCustom -and -not $isCustom) -or ($OnlyUnused -and $usedBy.Count -gt 0)) { continue }
    $package = $packages | Where-Object { [string]$_.Identity -eq $sit.RulePackId -or [string]$_.Name -eq $sit.RulePackId -or [string]$_.Guid -eq $sit.RulePackId } | Select-Object -First 1
    $description = [string]$sit.Description
    if ($description.Length -gt 200) { $description = $description.Substring(0, 197) + '...' }
    $results.Add([PSCustomObject]@{
            Name                  = [string]$sit.Name
            Publisher             = [string]$sit.Publisher
            Type                  = $(if ($isCustom) { 'Custom' } else { 'Microsoft' })
            Kind                  = [string]$sit.Type
            RecommendedConfidence = $sit.RecommendedConfidence
            Id                    = [string]$sit.Id
            RulePackId            = [string]$sit.RulePackId
            RulePackName          = [string]$package.RuleCollectionName
            UsedByRuleCount       = $usedBy.Count
            UsedByRules           = ($usedBy -join '; ')
            Description           = $description
        })
}
$results = @($results | Sort-Object -Property Type, Name)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No sensitive information types match the given filters.' }

$exported = New-Object -TypeName System.Collections.Generic.List[string]
if ($ExportCustomPackages) {
    foreach ($package in ($packages | Where-Object { $_.RuleCollectionName -ne 'Microsoft Rule Package' })) {
        try {
            $bytes = $package.SerializedClassificationRuleCollection
            if ($bytes -is [string]) { $bytes = [Convert]::FromBase64String($bytes) }
            $xmlPath = Join-Path -Path $outputFolder -ChildPath (('RulePackage_{0}.xml' -f $package.RuleCollectionName) -replace '[\\/:*?"<>|]', '_')
            [System.IO.File]::WriteAllBytes($xmlPath, [byte[]]$bytes)
            $exported.Add($xmlPath)
        }
        catch { Write-Warning ('Could not export rule package {0}: {1}' -f $package.RuleCollectionName, $_.Exception.Message) }
    }
}

Write-Host 'Purview sensitive information type summary' -ForegroundColor Cyan
$customCount = @($results | Where-Object { $_.Type -eq 'Custom' }).Count
Write-Host ('  SITs reported : {0} ({1} Microsoft, {2} Custom)' -f $results.Count, ($results.Count - $customCount), $customCount)
$unusedCount = @($results | Where-Object { $_.UsedByRuleCount -eq 0 }).Count
Write-Host ('  Referenced    : {0} used by at least one rule, {1} unused' -f ($results.Count - $unusedCount), $unusedCount)
Write-Host ('  Rule packages : {0}' -f $packages.Count)
foreach ($package in $packages) {
    Write-Host ('    {0} | {1} | v{2} | {3}' -f $package.RuleCollectionName, $package.Publisher, $package.Version, $package.Identity)
}
foreach ($path in $exported) { Write-Host ('  Exported      : {0}' -f $path) -ForegroundColor Green }
Write-Host ('  Report        : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
