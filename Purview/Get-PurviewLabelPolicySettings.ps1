<#
.SYNOPSIS
    Builds a settings matrix of every sensitivity label policy (mandatory labeling, default labels, scopes, distribution).
.DESCRIPTION
    Reads every label policy (Get-LabelPolicy) from Security & Compliance PowerShell and flattens the "[key, value]"
    pairs of its Settings property into one row per policy: mandatory labeling, default label and Outlook default
    label (GUIDs resolved to display names via Get-Label), downgrade justification, attachment action, hidden label
    bar, Outlook exemption, custom permissions and the Power BI, site/group and Teamwork mandatory switches, together
    with the published labels, the Exchange / SharePoint / OneDrive / Microsoft 365 Groups scopes (All or scoped count),
    WhenChanged and DistributionStatus. Flags policies without mandatory labeling or default label, disabled policies
    and distribution errors. The script is read-only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewLabelPolicySettings_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the policy rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewLabelPolicySettings.ps1
    Exports the settings matrix of all label policies and prints the flagged policies.
.EXAMPLE
    PS> .\Get-PurviewLabelPolicySettings.ps1 -PassThru | Where-Object { -not $_.Mandatory } | Select-Object Name, Labels, ExchangeLocation
    Lists the policies that do not enforce mandatory labeling and whom they target.
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
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). Settings not present in a policy are
                  reported as False / empty, which is also the service default. Several users can be covered by more than one
                  policy; the policy with the highest priority order wins for conflicting settings. DistributionStatus Pending
                  is normal for up to 24 hours after a change and is not flagged; use Get-LabelPolicy -Identity for DistributionResults.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-labelpolicy
.LINK
    https://learn.microsoft.com/purview/sensitivity-labels-office-apps
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

function ConvertTo-SettingsTable {
    <# Converts the "[key, value]" strings found in the Settings property of a label policy into a hashtable. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Settings
    )
    $table = @{}
    foreach ($entry in @($Settings)) {
        if ($null -eq $entry) { continue }
        if ([string]$entry -match '^\s*\[\s*([^,\]]+?)\s*,\s*(.*?)\s*\]\s*$') { $table[$Matches[1]] = $Matches[2] }
    }
    return $table
}

function ConvertTo-ScopeString {
    <# Returns 'All', 'None' or '<n> scoped' for a policy location collection. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Location
    )
    $names = @(foreach ($item in @($Location)) { if ($null -ne $item) { [string]$item } })
    if ($names -contains 'All') { return 'All' }
    if ($names.Count -eq 0) { return 'None' }
    return ('{0} scoped' -f $names.Count)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewLabelPolicySettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-ExchangeIfNeeded -Compliance
    Write-Verbose 'Retrieving label policies and sensitivity labels.'
    $policies = @(Get-LabelPolicy -ErrorAction Stop)
    $labels = @(Get-Label -ErrorAction Stop)
}
catch {
    throw "Unable to connect to Security & Compliance PowerShell or read the label policies: $($_.Exception.Message)"
}

# Settings reference labels by GUID and policies list them by name; index both so everything resolves to a display name.
$labelNames = @{}
foreach ($label in $labels) {
    foreach ($key in @($label.Guid, $label.ImmutableId, $label.Name)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$key)) { $labelNames[([string]$key).ToLowerInvariant()] = [string]$label.DisplayName }
    }
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in ($policies | Sort-Object -Property Name)) {
    $settings = ConvertTo-SettingsTable -Settings $policy.Settings
    $resolved = @{}
    foreach ($key in 'defaultlabelid', 'outlookdefaultlabel') {
        $value = [string]$settings[$key]
        if ([string]::IsNullOrWhiteSpace($value) -or $value -eq 'None') { $resolved[$key] = $null }
        elseif ($labelNames.ContainsKey($value.ToLowerInvariant())) { $resolved[$key] = $labelNames[$value.ToLowerInvariant()] }
        else { $resolved[$key] = $value }
    }
    $policyLabels = @($policy.Labels | ForEach-Object { $name = [string]$_; if ($labelNames.ContainsKey($name.ToLowerInvariant())) { $labelNames[$name.ToLowerInvariant()] } else { $name } })
    $mandatory = ([string]$settings['mandatory'] -eq 'True')
    $status = [string]$policy.DistributionStatus

    $issues = @()
    if (-not $policy.Enabled) { $issues += 'Disabled' }
    if (-not $mandatory) { $issues += 'No mandatory labeling' }
    if ($null -eq $resolved['defaultlabelid']) { $issues += 'No default label' }
    if ($policyLabels.Count -eq 0) { $issues += 'No labels' }
    if (-not [string]::IsNullOrWhiteSpace($status) -and $status -notin 'Success', 'Pending') { $issues += "Distribution: $status" }

    $rows.Add([PSCustomObject]@{
            Name                          = [string]$policy.Name
            Enabled                       = [bool]$policy.Enabled
            Mode                          = [string]$policy.Mode
            LabelCount                    = $policyLabels.Count
            Labels                        = ($policyLabels -join ';')
            ExchangeLocation              = ConvertTo-ScopeString -Location $policy.ExchangeLocation
            SharePointLocation            = ConvertTo-ScopeString -Location $policy.SharePointLocation
            OneDriveLocation              = ConvertTo-ScopeString -Location $policy.OneDriveLocation
            ModernGroupLocation           = ConvertTo-ScopeString -Location $policy.ModernGroupLocation
            Mandatory                     = $mandatory
            DefaultLabel                  = $resolved['defaultlabelid']
            RequireDowngradeJustification = ([string]$settings['requiredowngradejustification'] -eq 'True')
            OutlookDefaultLabel           = $resolved['outlookdefaultlabel']
            AttachmentAction              = [string]$settings['attachmentaction']
            HideBarByDefault              = ([string]$settings['hidebarbydefault'] -eq 'True')
            DisableMandatoryInOutlook     = ([string]$settings['disablemandatoryinoutlook'] -eq 'True')
            EnableCustomPermissions       = ([string]$settings['enablecustompermissions'] -eq 'True')
            PowerBIMandatory              = ([string]$settings['powerbimandatory'] -eq 'True')
            SiteAndGroupMandatory         = ([string]$settings['siteandgroupmandatory'] -eq 'True')
            TeamworkMandatory             = ([string]$settings['teamworkmandatory'] -eq 'True')
            WhenChanged                   = $policy.WhenChanged
            DistributionStatus            = $status
            Issues                        = ($issues -join '; ')
        })
}

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No label policies were found in this tenant.' }

$flagged = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Issues) })
Write-Host ''
Write-Host 'Label policy settings summary' -ForegroundColor Cyan
Write-Host ('  Policies             : {0} ({1} enabled)' -f $rows.Count, @($rows | Where-Object { $_.Enabled }).Count)
Write-Host ('  Mandatory labeling   : {0}' -f @($rows | Where-Object { $_.Mandatory }).Count)
Write-Host ('  With default label   : {0}' -f @($rows | Where-Object { $null -ne $_.DefaultLabel }).Count)
Write-Host ('  Distribution errors  : {0}' -f @($rows | Where-Object { $_.Issues -like '*Distribution:*' }).Count)
Write-Host ('  Flagged policies     : {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $flagged) { Write-Host ('    {0}: {1}' -f $row.Name, $row.Issues) -ForegroundColor Yellow }
Write-Host ('  Report               : {0}' -f $OutputPath)

if ($PassThru) {
    $rows
}
#endregion Main
