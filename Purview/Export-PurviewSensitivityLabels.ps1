<#
.SYNOPSIS
    Documents Microsoft Purview sensitivity labels and label policies to CSV and JSON.
.DESCRIPTION
    Connects to Security & Compliance PowerShell and reads every sensitivity label (Get-Label) and label policy
    (Get-LabelPolicy). For each label the script resolves the parent label name, parses the LabelActions JSON to
    report whether encryption, content marking or group/site protection is configured, and lists the distinct
    action types. For each policy it flattens the Settings pairs and surfaces mandatory labelling, the default
    label (resolved to its display name) and the downgrade-justification setting.
    Writes SensitivityLabels.csv, LabelPolicies.csv plus the raw objects as SensitivityLabels.json and
    LabelPolicies.json into -OutputFolder. The script is read-only.
.PARAMETER OutputFolder
    Folder that receives the four export files. Defaults to .\PurviewLabelsExport_yyyyMMdd-HHmm\ (created if missing).
.PARAMETER PassThru
    Also emit the shaped label objects (one per sensitivity label) to the pipeline.
.EXAMPLE
    PS> .\Export-PurviewSensitivityLabels.ps1
    Exports labels and policies to .\PurviewLabelsExport_<timestamp>\ and prints a summary.
.EXAMPLE
    PS> .\Export-PurviewSensitivityLabels.ps1 -OutputFolder C:\Docs\Purview\Labels -Verbose
    Exports into a fixed folder - handy for keeping a dated copy of the label taxonomy in source control.
.EXAMPLE
    PS> .\Export-PurviewSensitivityLabels.ps1 -PassThru | Where-Object { $_.EncryptionEnabled } | Select-Object DisplayName, ParentLabel, Priority
    Lists the labels that apply encryption.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Compliance Administrator, Compliance Data Administrator, Information Protection Reader or Global Reader
    Category    : Information protection
    Changes     : No
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession), not an Exchange Online one.
                  Government clouds need Connect-IPPSSession -ConnectionUri for their endpoint before running the script.
                  LabelActions only lists the configured action types; run Get-Label -IncludeDetailedLabelActions when you
                  need the full per-action settings (the raw JSON export already contains everything the cmdlet returns).
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

function ConvertTo-SettingsTable {
    <# Converts the "[key, value]" strings found in the Settings property of labels and policies into a hashtable. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Settings
    )
    $table = @{}
    foreach ($entry in @($Settings)) {
        if ($null -eq $entry) { continue }
        if ([string]$entry -match '^\s*\[\s*([^,\]]+?)\s*,\s*(.*?)\s*\]\s*$') {
            $table[$Matches[1]] = $Matches[2]
        }
    }
    return $table
}

function ConvertTo-SettingsString {
    <# Flattens a settings hashtable into "key=value; key=value" sorted by key. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Table
    )
    return (($Table.Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, $Table[$_] }) -join '; ')
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
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('PurviewLabelsExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

Write-Verbose 'Retrieving sensitivity labels.'
try {
    $labels = @(Get-Label -ErrorAction Stop)
}
catch {
    throw "Failed to retrieve sensitivity labels: $($_.Exception.Message)"
}
Write-Verbose 'Retrieving label policies.'
try {
    $policies = @(Get-LabelPolicy -ErrorAction Stop)
}
catch {
    throw "Failed to retrieve label policies: $($_.Exception.Message)"
}

# Guid -> DisplayName lookup used for parent labels and policy default labels.
$labelNameById = @{}
foreach ($label in $labels) {
    if ($null -ne $label.Guid) { $labelNameById[[string]$label.Guid] = [string]$label.DisplayName }
}

$labelRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($label in ($labels | Sort-Object -Property Priority)) {
    $actionTypes = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($action in @($label.LabelActions)) {
        if ([string]::IsNullOrWhiteSpace([string]$action)) { continue }
        try {
            $parsed = [string]$action | ConvertFrom-Json -ErrorAction Stop
            $type = [string]$parsed.Type
            if (-not [string]::IsNullOrWhiteSpace($type) -and -not $actionTypes.Contains($type.ToLowerInvariant())) {
                $actionTypes.Add($type.ToLowerInvariant())
            }
        }
        catch {
            Write-Warning "Label '$($label.DisplayName)': could not parse a LabelActions entry: $($_.Exception.Message)"
        }
    }

    $parentId = [string]$label.ParentId
    $isSubLabel = (-not [string]::IsNullOrWhiteSpace($parentId) -and $parentId -ne [guid]::Empty.ToString())
    $parentLabel = $null
    if ($isSubLabel) {
        if ($labelNameById.ContainsKey($parentId)) { $parentLabel = $labelNameById[$parentId] } else { $parentLabel = $parentId }
    }
    $labelSettings = ConvertTo-SettingsTable -Settings $label.Settings

    $labelRows.Add([PSCustomObject]@{
            DisplayName           = [string]$label.DisplayName
            Name                  = [string]$label.Name
            Guid                  = [string]$label.Guid
            Priority              = $label.Priority
            IsSubLabel            = $isSubLabel
            ParentLabel           = $parentLabel
            ParentId              = $(if ($isSubLabel) { $parentId } else { $null })
            ContentType           = (@($label.ContentType) -join ';')
            Workload              = (@($label.Workload) -join ';')
            Disabled              = [bool]$label.Disabled
            EncryptionEnabled     = ($actionTypes -contains 'encrypt')
            ContentMarkingEnabled = (($actionTypes -contains 'applycontentmarking') -or ($actionTypes -contains 'applywatermarking') -or ($actionTypes -contains 'applydynamicwatermarking'))
            GroupSiteProtection   = (($actionTypes -contains 'protectgroup') -or ($actionTypes -contains 'protectsite'))
            ActionTypes           = ($actionTypes -join ';')
            Tooltip               = [string]$label.Tooltip
            Settings              = ConvertTo-SettingsString -Table $labelSettings
            WhenCreated           = $label.WhenCreated
            WhenChanged           = $label.WhenChanged
        })
}

$policyRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in ($policies | Sort-Object -Property Name)) {
    $settings = ConvertTo-SettingsTable -Settings $policy.Settings
    $defaultLabelId = [string]$settings['defaultlabelid']
    $defaultLabel = $null
    if (-not [string]::IsNullOrWhiteSpace($defaultLabelId) -and $defaultLabelId -ne 'None') {
        if ($labelNameById.ContainsKey($defaultLabelId)) { $defaultLabel = $labelNameById[$defaultLabelId] } else { $defaultLabel = $defaultLabelId }
    }
    $policyLabels = @($policy.Labels | ForEach-Object { [string]$_ })

    $policyRows.Add([PSCustomObject]@{
            Name                          = [string]$policy.Name
            Guid                          = [string]$policy.Guid
            Enabled                       = [bool]$policy.Enabled
            Mode                          = [string]$policy.Mode
            LabelCount                    = $policyLabels.Count
            Labels                        = ($policyLabels -join ';')
            Mandatory                     = ([string]$settings['mandatory'] -eq 'True')
            DefaultLabel                  = $defaultLabel
            DefaultLabelId                = $(if ([string]::IsNullOrWhiteSpace($defaultLabelId)) { $null } else { $defaultLabelId })
            RequireDowngradeJustification = ([string]$settings['requiredowngradejustification'] -eq 'True')
            ExchangeLocation              = ConvertTo-LocationString -Location $policy.ExchangeLocation
            SharePointLocation            = ConvertTo-LocationString -Location $policy.SharePointLocation
            OneDriveLocation              = ConvertTo-LocationString -Location $policy.OneDriveLocation
            ModernGroupLocation           = ConvertTo-LocationString -Location $policy.ModernGroupLocation
            Settings                      = ConvertTo-SettingsString -Table $settings
            WhenCreated                   = $policy.WhenCreated
            WhenChanged                   = $policy.WhenChanged
        })
}

$labelCsv = Join-Path -Path $OutputFolder -ChildPath 'SensitivityLabels.csv'
$policyCsv = Join-Path -Path $OutputFolder -ChildPath 'LabelPolicies.csv'
if ($labelRows.Count -gt 0) { $labelRows | Export-Csv -Path $labelCsv -NoTypeInformation -Encoding UTF8 }
if ($policyRows.Count -gt 0) { $policyRows | Export-Csv -Path $policyCsv -NoTypeInformation -Encoding UTF8 }
try {
    Export-JsonFile -InputObject $labels -Path (Join-Path -Path $OutputFolder -ChildPath 'SensitivityLabels.json')
    Export-JsonFile -InputObject $policies -Path (Join-Path -Path $OutputFolder -ChildPath 'LabelPolicies.json')
}
catch {
    Write-Warning "CSV files were written but the raw JSON export failed: $($_.Exception.Message)"
}

$subLabelCount = @($labelRows | Where-Object { $_.IsSubLabel }).Count
$encryptedCount = @($labelRows | Where-Object { $_.EncryptionEnabled }).Count
$disabledCount = @($labelRows | Where-Object { $_.Disabled }).Count
$enabledPolicyCount = @($policyRows | Where-Object { $_.Enabled }).Count
$mandatoryPolicyCount = @($policyRows | Where-Object { $_.Mandatory }).Count

Write-Host ''
Write-Host 'Sensitivity label export summary' -ForegroundColor Cyan
Write-Host ('  Labels                 : {0} ({1} top-level, {2} sub-labels)' -f $labelRows.Count, ($labelRows.Count - $subLabelCount), $subLabelCount)
Write-Host ('  Labels with encryption : {0}' -f $encryptedCount)
Write-Host ('  Labels disabled        : {0}' -f $disabledCount)
Write-Host ('  Label policies         : {0} ({1} enabled, {2} mandatory)' -f $policyRows.Count, $enabledPolicyCount, $mandatoryPolicyCount)
Write-Host ('  Output folder          : {0}' -f $OutputFolder)

if ($PassThru) {
    $labelRows
}
#endregion Main
