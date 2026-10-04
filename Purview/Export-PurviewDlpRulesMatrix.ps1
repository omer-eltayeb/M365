<#
.SYNOPSIS
    Exports a one-row-per-rule matrix of all Purview DLP rules with their conditions, exceptions and actions.
.DESCRIPTION
    Connects to Security & Compliance PowerShell, reads every DLP policy and rule (Get-DlpCompliancePolicy,
    Get-DlpComplianceRule) and flattens each rule into readable text: sensitive information types as "Name (min-max,
    confidence)" including nested groups, the common conditions (AccessScope, extensions, recipient domains, password
    protection, content properties, FromScope), the names of all ExceptIf* exceptions and every configured action (block
    access and scope, notifications, policy tip, incident report, alert, encryption, header, moderation, redirect, endpoint
    restrictions, browser restriction, override options). Writes a CSV and optionally an HTML table. Read-only.
.PARAMETER HtmlPath
    Optional path of an HTML version of the matrix (ConvertTo-Html).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewDlpRulesMatrix_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the rule rows to the pipeline.
.EXAMPLE
    PS> .\Export-PurviewDlpRulesMatrix.ps1
    Exports all DLP rules to .\Reports\PurviewDlpRulesMatrix_<timestamp>.csv.
.EXAMPLE
    PS> .\Export-PurviewDlpRulesMatrix.ps1 -HtmlPath C:\Docs\DLP\RulesMatrix.html -PassThru | Where-Object { $_.HasOverride }
    Writes CSV and HTML and lists the rules that let users override the policy tip.
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
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). The Conditions column omits the And/Or
                  operators between SIT groups and covers the most common predicates only. Policy tips are truncated to 80 chars.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-dlpcompliancerule
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string]$HtmlPath,

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

function ConvertTo-ValueText {
    <# Joins a scalar, collection or dictionary into "a, b" text; null, empty and $false become '' so callers can skip them. #>
    param([Parameter()][AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { if ($Value) { return 'True' } else { return '' } }
    if ($Value -is [System.Collections.IDictionary]) { return (@($Value.Keys | ForEach-Object { '{0}={1}' -f $_, $Value[$_] }) -join ', ') }
    return (@(@($Value) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ }) -join ', ')
}

function ConvertTo-SitText {
    <# Flattens ContentContainsSensitiveInformation into "Name (min-max, confidence); ..." and recurses into groups. #>
    param([Parameter()][AllowNull()]$Condition)
    $parts = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($item in @($Condition)) {
        if ($null -eq $item) { continue }
        $groups = Get-PropertyValue -InputObject $item -Name 'groups'
        if ($null -ne $groups) {
            foreach ($group in @($groups)) {
                foreach ($key in 'sensitivetypes', 'labels', 'trainableclassifiers') {
                    $text = ConvertTo-SitText -Condition (Get-PropertyValue -InputObject $group -Name $key)
                    if ($text) { $parts.Add($text) }
                }
            }
            continue
        }
        $name = [string](Get-PropertyValue -InputObject $item -Name 'name')
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $min = [string](Get-PropertyValue -InputObject $item -Name 'mincount')
        $max = [string](Get-PropertyValue -InputObject $item -Name 'maxcount')
        if ([string]::IsNullOrWhiteSpace($max) -or $max -eq '-1') { $max = 'Any' }
        $confidence = [string](Get-PropertyValue -InputObject $item -Name 'confidencelevel')
        if ([string]::IsNullOrWhiteSpace($confidence)) {
            # Newer rules store numeric minconfidence/maxconfidence instead of a Low/Medium/High level.
            $confidence = ('{0}-{1}' -f (Get-PropertyValue -InputObject $item -Name 'minconfidence'), (Get-PropertyValue -InputObject $item -Name 'maxconfidence')).Trim('-')
        }
        $parts.Add(('{0} ({1}-{2}, {3})' -f $name, $(if ($min) { $min } else { '1' }), $max, $confidence).Replace(', )', ')'))
    }
    return ($parts -join '; ')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewDlpRulesMatrix_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
foreach ($path in @($OutputPath, $HtmlPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    $outputFolder = Split-Path -Path $path -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
        New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
    }
}

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try {
    $policies = @(Get-DlpCompliancePolicy -ErrorAction Stop)
    $rules = @(Get-DlpComplianceRule -ErrorAction Stop)
}
catch { throw "Failed to retrieve DLP policies or rules: $($_.Exception.Message)" }
$policyModes = @{}
foreach ($policy in $policies) { $policyModes[[string]$policy.Name] = [string]$policy.Mode }

$conditionLabels = [ordered]@{ AccessScope = 'AccessScope'; ContentExtensionMatchesWords = 'Extensions'; RecipientDomainIs = 'RecipientDomain'
    DocumentIsPasswordProtected = 'PasswordProtected'; ContentPropertyContainsWords = 'ContentProperty'; FromScope = 'FromScope' }
$actionLabels = [ordered]@{ NotifyUser = 'NotifyUser'; NotifyPolicyTipCustomText = 'PolicyTip'; GenerateIncidentReport = 'IncidentReport'
    IncidentReportContent = 'ReportContent'; ReportSeverityLevel = 'Severity'; GenerateAlert = 'Alert'; EncryptRMSTemplate = 'Encrypt'; SetHeader = 'SetHeader'
    Moderate = 'Moderate'; RedirectMessageTo = 'RedirectTo'; RestrictBrowserAccess = 'RestrictBrowser'; NotifyAllowOverride = 'AllowOverride' }

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($rule in ($rules | Sort-Object -Property ParentPolicyName, Priority)) {
    $conditions = New-Object -TypeName System.Collections.Generic.List[string]
    $sitText = ConvertTo-SitText -Condition $rule.ContentContainsSensitiveInformation
    if ($sitText) { $conditions.Add("SIT: $sitText") }
    foreach ($name in $conditionLabels.Keys) {
        $text = ConvertTo-ValueText -Value $rule.$name
        if ($text) { $conditions.Add(('{0}: {1}' -f $conditionLabels[$name], $text)) }
    }
    $exceptions = @($rule.PSObject.Properties | Where-Object { $_.Name -like 'ExceptIf*' -and (ConvertTo-ValueText -Value $_.Value) } | ForEach-Object { $_.Name })
    $actions = New-Object -TypeName System.Collections.Generic.List[string]
    if ($rule.BlockAccess) { $actions.Add(('BlockAccess ({0})' -f $(if ($rule.BlockAccessScope) { $rule.BlockAccessScope } else { 'All' }))) }
    foreach ($name in $actionLabels.Keys) {
        $text = ConvertTo-ValueText -Value $rule.$name
        if ($name -eq 'NotifyPolicyTipCustomText' -and $text.Length -gt 80) { $text = $text.Substring(0, 77) + '...' }
        if ($text -and $text -ne 'None') { $actions.Add(('{0}: {1}' -f $actionLabels[$name], $text)) }
    }
    $endpoint = @(foreach ($restriction in @($rule.EndpointDlpRestrictions)) {
            if ($null -ne $restriction) { '{0}:{1}' -f (Get-PropertyValue -InputObject $restriction -Name 'Setting'), (Get-PropertyValue -InputObject $restriction -Name 'Value') }
        })
    if ($endpoint.Count -gt 0) { $actions.Add('Endpoint: ' + ($endpoint -join ', ')) }

    $results.Add([PSCustomObject]@{
            Policy      = [string]$rule.ParentPolicyName
            Mode        = [string]$policyModes[[string]$rule.ParentPolicyName]
            Rule        = [string]$rule.Name
            Disabled    = [bool]$rule.Disabled
            Priority    = $rule.Priority
            Workloads   = [string]$rule.Workload
            Conditions  = ($conditions -join ' | ')
            Exceptions  = ($exceptions -join '; ')
            Actions     = ($actions -join ' | ')
            HasOverride = [bool](ConvertTo-ValueText -Value $rule.NotifyAllowOverride)
        })
}

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No DLP rules were found in this tenant.' }
if (-not [string]::IsNullOrWhiteSpace($HtmlPath) -and $results.Count -gt 0) {
    $title = 'Purview DLP rules matrix - {0:yyyy-MM-dd HH:mm}' -f (Get-Date)
    $style = '<style>body{font-family:Segoe UI,Arial;font-size:12px}table{border-collapse:collapse}th,td{border:1px solid #ccc;padding:4px;vertical-align:top}th{background:#0078d4;color:#fff}</style>'
    $results | ConvertTo-Html -Title $title -Head $style -PreContent ('<h2>{0}</h2><p>{1} rules in {2} policies</p>' -f $title, $results.Count, $policies.Count) |
        Out-File -FilePath $HtmlPath -Encoding UTF8
}

Write-Host 'Purview DLP rules matrix summary' -ForegroundColor Cyan
Write-Host ('  Policies / rules : {0} / {1}' -f $policies.Count, $results.Count)
Write-Host ('  Disabled rules   : {0}' -f @($results | Where-Object { $_.Disabled }).Count)
Write-Host ('  Blocking rules   : {0}' -f @($results | Where-Object { $_.Actions -like 'BlockAccess*' }).Count)
Write-Host ('  With override    : {0}' -f @($results | Where-Object { $_.HasOverride }).Count)
Write-Host ('  Report           : {0}' -f $OutputPath)
if (-not [string]::IsNullOrWhiteSpace($HtmlPath)) { Write-Host ('  HTML             : {0}' -f $HtmlPath) }

if ($PassThru) { $results }
#endregion Main
