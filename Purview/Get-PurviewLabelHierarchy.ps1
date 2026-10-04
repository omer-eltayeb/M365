<#
.SYNOPSIS
    Prints the sensitivity label tree (parents and sub-labels) and exports it with publishing status to CSV.
.DESCRIPTION
    Reads every sensitivity label (Get-Label) and label policy (Get-LabelPolicy) from Security & Compliance PowerShell,
    rebuilds the parent / sub-label tree from ParentId and prints it as an indented console tree with priority, scope
    (ContentType), encryption, content marking and disabled state. Each label becomes a CSV row with depth, full path,
    the policies that publish it (Labels and ScopedLabels) and an Issues column flagging unpublished labels, disabled
    labels, parents whose sub-labels are all disabled, and sub-labels whose parent no longer exists. Read-only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewLabelHierarchy_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the label rows to the pipeline (in tree order).
.EXAMPLE
    PS> .\Get-PurviewLabelHierarchy.ps1
    Prints the label tree, writes .\Reports\PurviewLabelHierarchy_<timestamp>.csv and summarises the flagged labels.
.EXAMPLE
    PS> .\Get-PurviewLabelHierarchy.ps1 -PassThru | Where-Object { $_.Issues -like '*Unpublished*' } | Select-Object Path, Priority, Guid
    Lists the labels that no label policy publishes - users cannot see or apply them.
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
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). Encryption and marking are derived
                  from the action types in LabelActions (Get-Label -IncludeDetailedLabelActions shows per-action settings).
                  A parent with sub-labels cannot itself be applied, hence the flag when all its sub-labels are disabled.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-label
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-labelpolicy
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

function Test-IsSubLabel {
    <# True when the label carries a real ParentId (top-level labels have an empty GUID). #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] $Label)
    return (-not [string]::IsNullOrWhiteSpace([string]$Label.ParentId) -and [string]$Label.ParentId -ne [guid]::Empty.ToString())
}

function Add-LabelNode {
    <# Emits one row for the label, prints its tree line and recurses into its sub-labels in priority order. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Label,

        [Parameter()]
        [int]$Depth = 0,

        [Parameter()]
        [string]$ParentPath = '',

        [Parameter()]
        [string]$ParentName = ''
    )
    $id = [string]$Label.Guid
    $path = $(if ($Depth -eq 0) { [string]$Label.DisplayName } else { '{0} / {1}' -f $ParentPath, $Label.DisplayName })
    $children = @()
    if ($childrenByParent.ContainsKey($id)) { $children = @($childrenByParent[$id] | Sort-Object -Property Priority) }
    $policyNames = @()
    foreach ($key in @(([string]$Label.Name).ToLowerInvariant(), $id.ToLowerInvariant())) {
        if ($policiesByLabel.ContainsKey($key)) { $policyNames += $policiesByLabel[$key] }
    }
    $policyNames = @($policyNames | Sort-Object -Unique)

    $actionTypes = @()
    foreach ($action in @($Label.LabelActions)) {
        if ([string]::IsNullOrWhiteSpace([string]$action)) { continue }
        try { $actionTypes += ([string]([string]$action | ConvertFrom-Json -ErrorAction Stop).Type).ToLowerInvariant() }
        catch { Write-Warning "Label '$($Label.DisplayName)': could not parse a LabelActions entry: $($_.Exception.Message)" }
    }
    $encryption = ($actionTypes -contains 'encrypt')
    $marking = (@($actionTypes | Where-Object { $_ -in 'applycontentmarking', 'applywatermarking', 'applydynamicwatermarking' }).Count -gt 0)

    $issues = @()
    if ($policyNames.Count -eq 0) { $issues += 'Unpublished' }
    if ($Label.Disabled) { $issues += 'Disabled' }
    if ($children.Count -gt 0 -and @($children | Where-Object { -not $_.Disabled }).Count -eq 0) { $issues += 'Parent without enabled sub-labels' }
    if ($Depth -eq 0 -and (Test-IsSubLabel -Label $Label)) { $issues += 'Orphan: parent label not found' }

    $rows.Add([PSCustomObject]@{
            Label               = [string]$Label.DisplayName
            Name                = [string]$Label.Name
            Parent              = $(if ($Depth -gt 0) { $ParentName } else { $null })
            Depth               = $Depth
            Path                = $path
            Priority            = $Label.Priority
            ContentType         = (@($Label.ContentType) -join ';')
            Encryption          = $encryption
            Marking             = $marking
            Disabled            = [bool]$Label.Disabled
            SubLabelCount       = $children.Count
            PublishedInPolicies = ($policyNames -join ';')
            Guid                = $id
            Issues              = ($issues -join '; ')
        })

    $tagPairs = @(@('encryption', $encryption), @('marking', $marking), @('DISABLED', [bool]$Label.Disabled), @('UNPUBLISHED', ($policyNames.Count -eq 0)))
    $tags = @($tagPairs | Where-Object { $_[1] } | ForEach-Object { $_[0] })
    $tagText = $(if ($tags.Count -gt 0) { '; ' + ($tags -join ', ') } else { '' })
    $line = '{0}- {1}  [priority {2}; {3}{4}]' -f ('    ' * $Depth), $Label.DisplayName, $Label.Priority, (@($Label.ContentType) -join ','), $tagText
    Write-Host $line -ForegroundColor $(if ($issues.Count -gt 0) { 'Yellow' } else { 'Gray' })

    foreach ($child in $children) {
        Add-LabelNode -Label $child -Depth ($Depth + 1) -ParentPath $path -ParentName ([string]$Label.DisplayName)
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewLabelHierarchy_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-ExchangeIfNeeded -Compliance
    Write-Verbose 'Retrieving sensitivity labels and label policies.'
    $labels = @(Get-Label -ErrorAction Stop)
    $policies = @(Get-LabelPolicy -ErrorAction Stop)
}
catch {
    throw "Unable to connect to Security & Compliance PowerShell or read the labels: $($_.Exception.Message)"
}

$labelIds = @($labels | ForEach-Object { [string]$_.Guid })
$childrenByParent = @{}
foreach ($label in ($labels | Where-Object { Test-IsSubLabel -Label $_ })) {
    $parentId = [string]$label.ParentId
    if (-not $childrenByParent.ContainsKey($parentId)) { $childrenByParent[$parentId] = New-Object -TypeName System.Collections.Generic.List[object] }
    $childrenByParent[$parentId].Add($label)
}

# Policies list labels by name (Labels) and sub-labels in ScopedLabels; index both, by name and by GUID, to be safe.
$policiesByLabel = @{}
foreach ($policy in $policies) {
    foreach ($entry in (@($policy.Labels) + @($policy.ScopedLabels))) {
        $key = ([string]$entry).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        if (-not $policiesByLabel.ContainsKey($key)) { $policiesByLabel[$key] = @() }
        if ($policiesByLabel[$key] -notcontains [string]$policy.Name) { $policiesByLabel[$key] += [string]$policy.Name }
    }
}

# Roots are top-level labels plus orphaned sub-labels whose parent no longer exists.
$roots = @($labels | Where-Object { -not (Test-IsSubLabel -Label $_) -or $labelIds -notcontains [string]$_.ParentId } | Sort-Object -Property Priority)
$rows = New-Object -TypeName System.Collections.Generic.List[object]
Write-Host ''
Write-Host 'Sensitivity label hierarchy' -ForegroundColor Cyan
foreach ($root in $roots) { Add-LabelNode -Label $root }

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No sensitivity labels were found in this tenant.' }

$subLabelCount = @($rows | Where-Object { $_.Depth -gt 0 }).Count
$flagged = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Issues) })
Write-Host ''
Write-Host 'Label hierarchy summary' -ForegroundColor Cyan
Write-Host ('  Labels                     : {0} ({1} top-level, {2} sub-labels, {3} policies)' -f $rows.Count, ($rows.Count - $subLabelCount), $subLabelCount, $policies.Count)
Write-Host ('  Unpublished                : {0}' -f @($rows | Where-Object { $_.Issues -like '*Unpublished*' }).Count)
Write-Host ('  Disabled                   : {0}' -f @($rows | Where-Object { $_.Disabled }).Count)
Write-Host ('  Parents without sub-labels : {0}' -f @($rows | Where-Object { $_.Issues -like '*Parent without*' }).Count)
Write-Host ('  Orphaned sub-labels        : {0}' -f @($rows | Where-Object { $_.Issues -like '*Orphan*' }).Count)
Write-Host ('  Flagged labels             : {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Report                     : {0}' -f $OutputPath)

if ($PassThru) {
    $rows
}
#endregion Main
