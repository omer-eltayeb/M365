<#
.SYNOPSIS
    Documents Microsoft Purview retention policies and their retention rules to CSV and JSON.
.DESCRIPTION
    Connects to Security & Compliance PowerShell and reads every retention policy with Get-RetentionCompliancePolicy
    -DistributionDetail (the only way to get accurate location and distribution values) plus every retention rule with
    Get-RetentionComplianceRule. Policies are flattened to one row with all workload locations and exceptions, adaptive
    scopes, preservation lock and distribution status; rules get the resolved policy name, duration (days and years),
    action and conditions. Writes RetentionPolicies.csv, RetentionRules.csv and the raw objects as JSON into
    -OutputFolder, then flags preservation-locked, disabled, delete-only and distribution-error policies. Read-only.
.PARAMETER OutputFolder
    Folder that receives the four export files. Defaults to .\PurviewRetentionExport_yyyyMMdd-HHmm\ (created if missing).
.PARAMETER PassThru
    Also emit the shaped policy objects (one per retention policy) to the pipeline.
.EXAMPLE
    PS> .\Export-PurviewRetentionPolicies.ps1
    Exports all retention policies and rules to .\PurviewRetentionExport_<timestamp>\ and prints a summary.
.EXAMPLE
    PS> .\Export-PurviewRetentionPolicies.ps1 -OutputFolder C:\Docs\Purview\Retention -PassThru | Where-Object { $_.Flags } | Select-Object Name, Flags
    Exports into a fixed folder and lists only the policies that need attention (locked, disabled, delete-only, errors).
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
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). -DistributionDetail makes the
                  call noticeably slower in tenants with many policies. Policies for Teams private channels, Viva Engage
                  and Copilot live in Get-AppRetentionCompliancePolicy and are not included. RetentionDuration is in days;
                  RetentionYears is a one-decimal convenience value (blank for Unlimited). A preservation-locked policy
                  (RestrictiveRetention) can never be disabled, shortened or deleted.
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/get-retentioncompliancepolicy
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

function ConvertTo-LocationString {
    <# Joins a policy location collection with ';', collapsing to 'All' when the collection contains All. #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Location)
    $names = @(foreach ($item in @($Location)) {
            if ($null -eq $item) { continue }
            if ($null -ne $item.PSObject.Properties['Name'] -and -not [string]::IsNullOrWhiteSpace([string]$item.Name)) { [string]$item.Name } else { [string]$item }
        })
    if ($names.Count -eq 0) { return $null }
    if ($names -contains 'All') { return 'All' }
    return ($names -join ';')
}

function ConvertTo-RetentionYearCount {
    <# Converts a RetentionDuration (days or Unlimited) into years with one decimal; $null when unlimited or empty. #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$Duration)
    $days = 0
    if (-not [int]::TryParse([string]$Duration, [ref]$days) -or $days -le 0) { return $null }
    return [math]::Round($days / 365, 1)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('PurviewRetentionExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$OutputFolder = (Resolve-Path -Path $OutputFolder).Path

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try { $policies = @(Get-RetentionCompliancePolicy -DistributionDetail -ErrorAction Stop) }
catch { throw "Failed to retrieve retention policies: $($_.Exception.Message)" }
try { $rules = @(Get-RetentionComplianceRule -ErrorAction Stop) }
catch { throw "Failed to retrieve retention rules: $($_.Exception.Message)" }

# Rules reference their policy by GUID; resolve to the policy name and group them per policy.
$policyNameByGuid = @{}
foreach ($policy in $policies) { $policyNameByGuid[[string]$policy.Guid] = [string]$policy.Name }
$rulesByPolicy = @{}
$ruleRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($rule in ($rules | Sort-Object -Property Name)) {
    $policyName = [string]$rule.Policy
    if ($policyNameByGuid.ContainsKey($policyName)) { $policyName = $policyNameByGuid[$policyName] }
    if (-not $rulesByPolicy.ContainsKey($policyName)) { $rulesByPolicy[$policyName] = New-Object -TypeName System.Collections.Generic.List[object] }
    $rulesByPolicy[$policyName].Add($rule)
    $ruleRows.Add([PSCustomObject]@{
            Name                         = [string]$rule.Name
            Guid                         = [string]$rule.Guid
            Policy                       = $policyName
            RetentionDuration            = [string]$rule.RetentionDuration
            RetentionYears               = ConvertTo-RetentionYearCount -Duration $rule.RetentionDuration
            RetentionDurationDisplayHint = [string]$rule.RetentionDurationDisplayHint
            RetentionComplianceAction    = [string]$rule.RetentionComplianceAction
            ExpirationDateOption         = [string]$rule.ExpirationDateOption
            ContentMatchQuery            = [string]$rule.ContentMatchQuery
            ApplyComplianceTag           = [string]$rule.ApplyComplianceTag
            PublishComplianceTag         = [string]$rule.PublishComplianceTag
            Disabled                     = [bool]$rule.Disabled
        })
}

$policyRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in ($policies | Sort-Object -Property Name)) {
    $policyRules = @()
    if ($rulesByPolicy.ContainsKey([string]$policy.Name)) { $policyRules = @($rulesByPolicy[[string]$policy.Name]) }
    $actions = @($policyRules | ForEach-Object { [string]$_.RetentionComplianceAction } | Where-Object { $_ } | Sort-Object -Unique)
    $distributionText = (@($policy.DistributionResults | ForEach-Object { [string]$_ }) -join ' | ')
    if ($distributionText.Length -gt 500) { $distributionText = $distributionText.Substring(0, 500) + '...' }
    $adaptiveScopes = ConvertTo-LocationString -Location $policy.AdaptiveScopeLocation

    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ($policy.RestrictiveRetention) { $flags.Add('PreservationLock') }
    if (-not $policy.Enabled -or [string]$policy.Mode -eq 'PendingDeletion') { $flags.Add('Disabled') }
    if ([string]$policy.DistributionStatus -eq 'Error') { $flags.Add('DistributionError') }
    if ($actions.Count -gt 0 -and @($actions | Where-Object { $_ -ne 'Delete' }).Count -eq 0) { $flags.Add('DeleteOnly') }
    if ($policyRules.Count -eq 0) { $flags.Add('NoRules') }

    $policyRows.Add([PSCustomObject]@{
            Name                          = [string]$policy.Name
            Guid                          = [string]$policy.Guid
            Enabled                       = [bool]$policy.Enabled
            Mode                          = [string]$policy.Mode
            Workload                      = (@($policy.Workload) -join ';')
            AdaptiveScopes                = $adaptiveScopes
            ExchangeLocation              = ConvertTo-LocationString -Location $policy.ExchangeLocation
            ExchangeLocationException     = ConvertTo-LocationString -Location $policy.ExchangeLocationException
            SharePointLocation            = ConvertTo-LocationString -Location $policy.SharePointLocation
            SharePointLocationException   = ConvertTo-LocationString -Location $policy.SharePointLocationException
            OneDriveLocation              = ConvertTo-LocationString -Location $policy.OneDriveLocation
            OneDriveLocationException     = ConvertTo-LocationString -Location $policy.OneDriveLocationException
            ModernGroupLocation           = ConvertTo-LocationString -Location $policy.ModernGroupLocation
            ModernGroupLocationException  = ConvertTo-LocationString -Location $policy.ModernGroupLocationException
            TeamsChannelLocation          = ConvertTo-LocationString -Location $policy.TeamsChannelLocation
            TeamsChannelLocationException = ConvertTo-LocationString -Location $policy.TeamsChannelLocationException
            TeamsChatLocation             = ConvertTo-LocationString -Location $policy.TeamsChatLocation
            TeamsChatLocationException    = ConvertTo-LocationString -Location $policy.TeamsChatLocationException
            PublicFolderLocation          = ConvertTo-LocationString -Location $policy.PublicFolderLocation
            RuleCount                     = $policyRules.Count
            RetentionActions              = ($actions -join ';')
            PreservationLock              = [bool]$policy.RestrictiveRetention
            DistributionStatus            = [string]$policy.DistributionStatus
            DistributionResults           = $distributionText
            Flags                         = ($flags -join ';')
            WhenCreated                   = $policy.WhenCreated
            WhenChanged                   = $policy.WhenChanged
        })
}

if ($policyRows.Count -gt 0) { $policyRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'RetentionPolicies.csv') -NoTypeInformation -Encoding UTF8 }
if ($ruleRows.Count -gt 0) { $ruleRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'RetentionRules.csv') -NoTypeInformation -Encoding UTF8 }
# Raw JSON keeps every property the cmdlets return; written without a BOM so any tooling can read it.
try {
    $utf8NoBom = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText((Join-Path -Path $OutputFolder -ChildPath 'RetentionPolicies.json'), (ConvertTo-Json -InputObject @($policies) -Depth 10), $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path -Path $OutputFolder -ChildPath 'RetentionRules.json'), (ConvertTo-Json -InputObject @($rules) -Depth 10), $utf8NoBom)
}
catch { Write-Warning "CSV files were written but the raw JSON export failed: $($_.Exception.Message)" }

$errorCount = @($policyRows | Where-Object { $_.DistributionStatus -eq 'Error' }).Count
Write-Host "`nRetention policy export summary" -ForegroundColor Cyan
Write-Host ('  Retention policies   : {0} ({1} adaptive)' -f $policyRows.Count, @($policyRows | Where-Object { $_.AdaptiveScopes }).Count)
Write-Host ('  Retention rules      : {0}' -f $ruleRows.Count)
Write-Host ('  Preservation locked  : {0}' -f @($policyRows | Where-Object { $_.PreservationLock }).Count)
Write-Host ('  Disabled policies    : {0}' -f @($policyRows | Where-Object { -not $_.Enabled }).Count)
Write-Host ('  Delete-only policies : {0}' -f @($policyRows | Where-Object { $_.Flags -match 'DeleteOnly' }).Count)
Write-Host ('  Distribution errors  : {0}' -f $errorCount) -ForegroundColor $(if ($errorCount -gt 0) { 'Red' } else { 'Green' })
Write-Host ('  Output folder        : {0}' -f $OutputFolder)

if ($PassThru) {
    $policyRows
}
#endregion Main
