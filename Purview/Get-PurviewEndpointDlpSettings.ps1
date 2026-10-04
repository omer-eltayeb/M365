<#
.SYNOPSIS
    Documents the tenant-wide Endpoint DLP settings (exclusions, restricted apps and browsers, service domains, device groups).
.DESCRIPTION
    Connects to Security & Compliance PowerShell and reads Get-PolicyConfig | Select-Object -ExpandProperty
    EndpointDlpGlobalSettings, the Setting/Value list behind Purview > Data loss prevention > Settings > Endpoint settings.
    JSON values (restricted apps, printer / removable media / network share / site groups, VPN settings, evidence store,
    quarantine parameters) are flattened into readable "key=value" text with arrays counted and their first items shown.
    Settings that exist in the product but are not configured are listed as "(not configured)" so the report is complete.
    Writes a CSV, optionally the parsed settings as JSON (-ExportJson), and prints a summary. The script is read-only.
.PARAMETER ExportJson
    Also write the parsed settings as a JSON file next to the CSV (same name, .json extension).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewEndpointDlpSettings_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewEndpointDlpSettings.ps1
    Exports all Endpoint DLP global settings to CSV and prints the summary.
.EXAMPLE
    PS> .\Get-PurviewEndpointDlpSettings.ps1 -ExportJson -PassThru | Where-Object { $_.Setting -eq 'UnallowedApp' }
    Writes CSV and JSON and shows the restricted apps.
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
    Notes       : Opens a Security & Compliance PowerShell session (Connect-IPPSSession). Endpoint DLP needs Microsoft 365 E5 /
                  E5 Compliance (or equivalent) and devices onboarded to Microsoft Defender for Endpoint. The setting names are
                  the internal ones used by the service; the portal shows friendlier labels (for example "File path exclusions").
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-policyconfig
.LINK
    https://learn.microsoft.com/purview/dlp-configure-endpoint-settings
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$ExportJson,

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

function ConvertTo-FlatText {
    <# Flattens a parsed JSON value: objects become "key=value; ...", arrays become "[N] first, second, third ...". #>
    param([Parameter()][AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string] -or $Value -is [datetime] -or $Value -is [decimal] -or $Value.GetType().IsPrimitive) { return [string]$Value }
    if ($Value -is [System.Collections.IList]) {
        $items = @($Value | ForEach-Object { ConvertTo-FlatText -Value $_ })
        $preview = (@($items | Select-Object -First 3) -join ', ')
        if ($items.Count -gt 3) { $preview += ' ...' }
        return ('[{0}] {1}' -f $items.Count, $preview)
    }
    $pairs = foreach ($property in $Value.PSObject.Properties) { '{0}={1}' -f $property.Name, (ConvertTo-FlatText -Value $property.Value) }
    return ($pairs -join '; ')
}

function Get-SettingTotal {
    <# Sums ItemCount over one or more setting names for the summary lines. #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory = $true)][string[]]$Names)
    return [int](($Rows | Where-Object { $Names -contains $_.Setting } | Measure-Object -Property ItemCount -Sum).Sum)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewEndpointDlpSettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

try { $entries = @(Get-PolicyConfig -ErrorAction Stop | Select-Object -ExpandProperty EndpointDlpGlobalSettings -ErrorAction Stop) }
catch { throw "Failed to read EndpointDlpGlobalSettings from Get-PolicyConfig: $($_.Exception.Message)" }

# Settings the service knows about; those missing from the tenant are reported as not configured.
$knownSettings = 'PathExclusion', 'MacPathExclusion', 'UnallowedApp', 'UnallowedBluetoothApp', 'UnallowedBrowser', 'UnallowedCloudSyncApp', 'CloudAppMode',
'CloudAppRestrictionList', 'BusinessJustificationList', 'AdvancedClassificationEnabled', 'BandwidthLimitEnabled', 'DailyBandwidthLimitInMB',
'NetworkShareEnforcementEnabled', 'serverDlpEnabled', 'PrinterGroups', 'RemovableMediaGroups', 'NetworkShareGroups', 'SiteGroups', 'DlpAppGroups',
'DlpPrinterGroups', 'VPNSettings', 'EvidenceStoreSettings', 'QuarantineParameters'

$results = New-Object -TypeName System.Collections.Generic.List[object]
$parsedEntries = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($entry in $entries) {
    if ($null -eq $entry) { continue }
    $raw = [string]$entry.Value
    $parsed = $raw
    $itemCount = 1
    if ($raw -match '^\s*[\[{]') {
        try {
            $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($parsed -is [System.Collections.IList]) { $itemCount = @($parsed).Count }
        }
        catch { Write-Verbose ('{0}: value is not valid JSON, kept as text.' -f $entry.Setting) }
    }
    $parsedEntries.Add([PSCustomObject]@{ Setting = [string]$entry.Setting; Value = $parsed })
    $results.Add([PSCustomObject]@{
            Setting   = [string]$entry.Setting
            ItemCount = $itemCount
            Value     = (ConvertTo-FlatText -Value $parsed)
            RawValue  = $raw
        })
}
foreach ($name in $knownSettings) {
    if (@($results | Where-Object { $_.Setting -eq $name }).Count -eq 0) {
        $results.Add([PSCustomObject]@{ Setting = $name; ItemCount = 0; Value = '(not configured)'; RawValue = '' })
    }
}
$results = @($results | Sort-Object -Property Setting)
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$jsonPath = $null
if ($ExportJson) {
    $jsonPath = [System.IO.Path]::ChangeExtension($OutputPath, '.json')
    $json = ConvertTo-Json -InputObject @($parsedEntries) -Depth 15
    [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false))
}

# First flattened value per setting, for the single-value settings shown in the summary.
$valueBySetting = @{}
foreach ($row in $results) { if (-not $valueBySetting.ContainsKey($row.Setting)) { $valueBySetting[$row.Setting] = $row.Value } }
Write-Host 'Purview Endpoint DLP settings summary' -ForegroundColor Cyan
Write-Host ('  Configured settings    : {0} of {1} known ({2} entries)' -f @($results | Where-Object { $_.ItemCount -gt 0 }).Count, $knownSettings.Count, $entries.Count)
Write-Host ('  File path exclusions   : {0} (Windows + macOS)' -f (Get-SettingTotal -Rows $results -Names 'PathExclusion', 'MacPathExclusion'))
Write-Host ('  Restricted apps        : {0} apps, {1} Bluetooth apps, {2} cloud sync apps' -f (Get-SettingTotal -Rows $results -Names 'UnallowedApp'),
    (Get-SettingTotal -Rows $results -Names 'UnallowedBluetoothApp'), (Get-SettingTotal -Rows $results -Names 'UnallowedCloudSyncApp'))
Write-Host ('  Unallowed browsers     : {0}' -f (Get-SettingTotal -Rows $results -Names 'UnallowedBrowser'))
Write-Host ('  Service domains        : mode {0}, {1} domain entries' -f $valueBySetting['CloudAppMode'], (Get-SettingTotal -Rows $results -Names 'CloudAppRestrictionList'))
$groupCounts = foreach ($names in @(@('PrinterGroups', 'DlpPrinterGroups'), @('RemovableMediaGroups'), @('NetworkShareGroups'), @('SiteGroups'), @('DlpAppGroups'))) {
    Get-SettingTotal -Rows $results -Names $names
}
Write-Host ('  Device / site groups   : {0} printer, {1} removable media, {2} network share, {3} site, {4} app groups' -f $groupCounts)
Write-Host ('  Advanced classification: {0}; bandwidth limit: {1} ({2} MB/day); network share enforcement: {3}' -f $valueBySetting['AdvancedClassificationEnabled'],
    $valueBySetting['BandwidthLimitEnabled'], $valueBySetting['DailyBandwidthLimitInMB'], $valueBySetting['NetworkShareEnforcementEnabled'])
Write-Host ('  Report                 : {0}' -f $OutputPath)
if ($jsonPath) { Write-Host ('  JSON                   : {0}' -f $jsonPath) }

if ($PassThru) { $results }
#endregion Main
