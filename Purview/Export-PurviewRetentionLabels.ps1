<#
.SYNOPSIS
    Documents Microsoft Purview retention labels, their file plan descriptors and where each label is published or auto-applied.
.DESCRIPTION
    Connects to Security & Compliance PowerShell and reads every retention label (Get-ComplianceTag) together with all
    retention policies and rules (Get-RetentionCompliancePolicy / Get-RetentionComplianceRule). For each label the
    FilePlanMetadata JSON is parsed into Department, Category, SubCategory, Authority, Citation and ReferenceId
    columns, the retention duration is converted to years, and the rules are scanned to list the policies that publish
    the label (PublishComplianceTag) or auto-apply it (ApplyComplianceTag, with the KQL or sensitive-info condition
    type). Writes RetentionLabels.csv plus RetentionLabels.json into -OutputFolder and flags labels that are neither
    published nor auto-applied and record labels that delete content without any disposition reviewer. Read-only.
.PARAMETER OutputFolder
    Folder that receives RetentionLabels.csv and RetentionLabels.json. Defaults to .\PurviewRetentionLabelsExport_yyyyMMdd-HHmm\.
.PARAMETER PassThru
    Also emit the shaped label objects to the pipeline.
.EXAMPLE
    PS> .\Export-PurviewRetentionLabels.ps1
    Exports all retention labels to .\PurviewRetentionLabelsExport_<timestamp>\ and prints a summary.
.EXAMPLE
    PS> .\Export-PurviewRetentionLabels.ps1 -OutputFolder C:\Docs\Purview\Labels -PassThru | Where-Object { $_.Flags -match 'NotPublished' } | Select-Object Name, RetentionAction, RetentionYears
    Exports into a fixed folder and lists the labels that users can never see because no policy publishes or auto-applies them.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Retention Management or View-Only Retention Management role (Compliance Administrator, Records Management
                  or Global Reader role groups) in Security & Compliance PowerShell
    Category    : Retention & records management
    Changes     : No
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). Rules reference labels by GUID or
                  name depending on how they were created; both forms are matched. Auto-apply rules based on trainable
                  classifiers or cloud attachments carry no ContentMatchQuery and are reported with the condition type
                  'Other'. Regulatory record labels cannot be removed from content once applied. The raw JSON export
                  keeps every property, including the complete FilePlanMetadata and MultiStageReviewProperty strings.
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/get-compliancetag
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/get-retentioncompliancerule
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

function ConvertTo-RetentionYearCount {
    <# Converts a RetentionDuration (days or Unlimited) into years with one decimal; $null when unlimited or empty. #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Duration)
    $days = 0
    if (-not [int]::TryParse([string]$Duration, [ref]$days) -or $days -le 0) { return $null }
    return [math]::Round($days / 365, 1)
}

function Test-LabelReference {
    <# True when a PublishComplianceTag / ApplyComplianceTag value (GUIDs or names, comma separated) references the label. #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()]$Value,
        [Parameter(Mandatory = $true)]$Label
    )
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }
    if (-not [string]::IsNullOrWhiteSpace([string]$Label.Guid) -and $text -match [regex]::Escape([string]$Label.Guid)) { return $true }
    return (@($text -split ',' | ForEach-Object { $_.Trim() }) -contains [string]$Label.Name)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('PurviewRetentionLabelsExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$OutputFolder = (Resolve-Path -Path $OutputFolder).Path

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try { $labels = @(Get-ComplianceTag -ErrorAction Stop) }
catch { throw "Failed to retrieve retention labels: $($_.Exception.Message)" }
try {
    $policies = @(Get-RetentionCompliancePolicy -ErrorAction Stop)
    $rules = @(Get-RetentionComplianceRule -ErrorAction Stop)
}
catch { throw "Failed to retrieve retention policies and rules: $($_.Exception.Message)" }

# Pre-compute the policy name and condition type of every rule so the per-label scan stays cheap.
$policyNameByGuid = @{}
foreach ($policy in $policies) { $policyNameByGuid[[string]$policy.Guid] = [string]$policy.Name }
$ruleInfo = foreach ($rule in $rules) {
    $policyName = [string]$rule.Policy
    if ($policyNameByGuid.ContainsKey($policyName)) { $policyName = $policyNameByGuid[$policyName] }
    $condition = 'Other'
    if (-not [string]::IsNullOrWhiteSpace([string]$rule.ContentMatchQuery)) { $condition = 'KQL' }
    elseif (@($rule.ContentContainsSensitiveInformation).Count -gt 0) { $condition = 'SensitiveInfo' }
    [PSCustomObject]@{ PolicyName = $policyName; Publish = $rule.PublishComplianceTag; Apply = $rule.ApplyComplianceTag; Condition = $condition }
}

$labelRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($label in ($labels | Sort-Object -Property Name)) {
    $filePlan = @{}
    if (-not [string]::IsNullOrWhiteSpace([string]$label.FilePlanMetadata)) {
        try {
            foreach ($setting in @(([string]$label.FilePlanMetadata | ConvertFrom-Json -ErrorAction Stop).Settings)) {
                if ($null -ne $setting -and -not [string]::IsNullOrWhiteSpace([string]$setting.Key)) { $filePlan[[string]$setting.Key] = [string]$setting.Value }
            }
        }
        catch { Write-Warning "Label '$($label.Name)': could not parse FilePlanMetadata: $($_.Exception.Message)" }
    }

    $publishedIn = @($ruleInfo | Where-Object { Test-LabelReference -Value $_.Publish -Label $label } | ForEach-Object { $_.PolicyName } | Sort-Object -Unique)
    $autoRules = @($ruleInfo | Where-Object { Test-LabelReference -Value $_.Apply -Label $label })
    $hasReviewers = (-not [string]::IsNullOrWhiteSpace(([string](@($label.ReviewerEmail) -join ';'))))
    $hasMultiStage = ([string]$label.MultiStageReviewProperty -match 'Stage')
    $action = [string]$label.RetentionAction

    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ($publishedIn.Count -eq 0 -and $autoRules.Count -eq 0) { $flags.Add('NotPublished') }
    if ([bool]$label.IsRecordLabel -and $action -match 'Delete' -and -not $hasReviewers -and -not $hasMultiStage) { $flags.Add('RecordDeletesWithoutReview') }
    if ([string]::IsNullOrWhiteSpace($action)) { $flags.Add('ClassifyOnly') }

    $labelRows.Add([PSCustomObject]@{
            Name                = [string]$label.Name
            Guid                = [string]$label.Guid
            Comment             = [string]$label.Comment
            RetentionAction     = $action
            RetentionDuration   = [string]$label.RetentionDuration
            RetentionYears      = ConvertTo-RetentionYearCount -Duration $label.RetentionDuration
            RetentionType       = [string]$label.RetentionType
            EventType           = [string]$label.EventType
            IsRecordLabel       = [bool]$label.IsRecordLabel
            Regulatory          = [bool]$label.Regulatory
            ReviewerEmail       = (@($label.ReviewerEmail) -join ';')
            HasMultiStageReview = $hasMultiStage
            FilePlanDepartment  = $filePlan['FilePlanPropertyDepartment']
            FilePlanCategory    = $filePlan['FilePlanPropertyCategory']
            FilePlanSubCategory = $filePlan['FilePlanPropertySubcategory']
            FilePlanAuthority   = $filePlan['FilePlanPropertyAuthority']
            FilePlanCitation    = $filePlan['FilePlanPropertyCitation']
            FilePlanReferenceId = $filePlan['FilePlanPropertyReferenceId']
            PublishedIn         = ($publishedIn -join ';')
            AutoAppliedBy       = (@($autoRules | ForEach-Object { $_.PolicyName } | Sort-Object -Unique) -join ';')
            AutoApplyConditions = (@($autoRules | ForEach-Object { $_.Condition } | Sort-Object -Unique) -join ';')
            Flags               = ($flags -join ';')
            WhenCreated         = $label.WhenCreated
            WhenChanged         = $label.WhenChanged
        })
}

if ($labelRows.Count -gt 0) { $labelRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'RetentionLabels.csv') -NoTypeInformation -Encoding UTF8 }
# Raw JSON keeps every property the cmdlet returns; written without a BOM so any tooling can read it.
try {
    $json = ConvertTo-Json -InputObject @($labels) -Depth 10
    [System.IO.File]::WriteAllText((Join-Path -Path $OutputFolder -ChildPath 'RetentionLabels.json'), $json, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
}
catch { Write-Warning "The CSV was written but the raw JSON export failed: $($_.Exception.Message)" }

$notPublished = @($labelRows | Where-Object { $_.Flags -match 'NotPublished' }).Count
$noReview = @($labelRows | Where-Object { $_.Flags -match 'RecordDeletesWithoutReview' }).Count
$recordCount = @($labelRows | Where-Object { $_.IsRecordLabel }).Count
Write-Host "`nRetention label export summary" -ForegroundColor Cyan
Write-Host ('  Retention labels                : {0} ({1} record, {2} regulatory)' -f $labelRows.Count, $recordCount, @($labelRows | Where-Object { $_.Regulatory }).Count)
Write-Host ('  Published by a label policy     : {0}' -f @($labelRows | Where-Object { $_.PublishedIn }).Count)
Write-Host ('  Auto-applied by a policy        : {0}' -f @($labelRows | Where-Object { $_.AutoAppliedBy }).Count)
Write-Host ('  Not published or auto-applied   : {0}' -f $notPublished) -ForegroundColor $(if ($notPublished -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Record labels deleting unreviewed: {0}' -f $noReview) -ForegroundColor $(if ($noReview -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Output folder                   : {0}' -f $OutputFolder)

if ($PassThru) {
    $labelRows
}
#endregion Main
