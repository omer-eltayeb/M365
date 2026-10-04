<#
.SYNOPSIS
    Reports failed Defender Vulnerability Management security configuration checks with impact, risk, remediation and affected device counts.
.DESCRIPTION
    Runs an Advanced Hunting query through Microsoft Graph (POST v1.0 /security/runHuntingQuery) that takes the non-compliant,
    applicable rows of DeviceTvmSecureConfigurationAssessment, joins DeviceTvmSecureConfigurationAssessmentKB for the configuration
    name, category, impact score, risk description and remediation options, and summarises one row per configuration (DeviceCount,
    up to 10 sample devices) ordered by impact and devices. -PerDevice returns one row per device and failed check instead.
    Writes a CSV and prints the recommendations per category and the highest-impact items.
.PARAMETER Days
    Timespan passed to the API (1-30, default 7). The TVM tables are snapshots, so the value does not filter them.
.PARAMETER Category
    Restricts the output to one configuration category: Application, OS, Network, Accounts or 'Security controls'.
.PARAMETER MinimumDevices
    Hides configurations failing on fewer devices than this (default 1). Ignored with -PerDevice.
.PARAMETER PerDevice
    Returns one row per DeviceName and failed configuration instead of the aggregated view.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderSecurityRecommendations_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderSecurityRecommendations.ps1 -MinimumDevices 10
    Exports every failed configuration check affecting at least 10 devices, highest impact first.
.EXAMPLE
    PS> .\Get-DefenderSecurityRecommendations.ps1 -Category 'Security controls' -PerDevice -OutputPath C:\Temp\SecurityControlsGaps.csv -Verbose
    Lists, per device, the failed security-control checks such as antivirus, ASR or firewall settings.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access.
    Category    : Advanced hunting (Graph)
    Changes     : No
    Notes       : Advanced hunting caps results per query (10,000 rows in the portal, 100,000 through the API); -Days maps to the Timespan
                  property (P<n>D). -PerDevice without -Category easily exceeds the cap in large tenants. ConfigurationImpact is the
                  1-10 weight of the check in the configuration score. Needs Defender for Endpoint Plan 2 or the Defender Vulnerability
                  Management add-on.
.LINK
    https://learn.microsoft.com/graph/api/security-security-runhuntingquery
.LINK
    https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsecureconfigurationassessment-table
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$Days = 7,

    [Parameter()]
    [ValidateSet('Application', 'OS', 'Network', 'Accounts', 'Security controls')]
    [string]$Category,

    [Parameter()]
    [ValidateRange(1, 1000000)]
    [int]$MinimumDevices = 1,

    [Parameter()]
    [switch]$PerDevice,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-GraphIfNeeded {
    <# Connects to Microsoft Graph only when there is no usable session for the required scopes. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )
    $context = Get-MgContext
    $missingScopes = @()
    if ($null -ne $context) {
        $missingScopes = @($Scopes | Where-Object { $context.Scopes -notcontains $_ })
    }
    if ($null -eq $context -or $missingScopes.Count -gt 0) {
        Write-Verbose "Connecting to Microsoft Graph with scopes: $($Scopes -join ', ')"
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
    }
    else {
        Write-Verbose "Reusing existing Microsoft Graph session for $($context.Account)."
    }
}

function Invoke-GraphPaged {
    <# GET helper that follows @odata.nextLink and returns every item in 'value'. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Headers
    )
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $requestParams = @{ Method = 'GET'; Uri = $nextLink; OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($null -ne $Headers) { $requestParams['Headers'] = $Headers }
        $response = Invoke-MgGraphRequest @requestParams
        if ($null -ne $response.PSObject.Properties['value']) {
            foreach ($item in $response.value) { $results.Add($item) }
        }
        elseif ($null -ne $response) {
            $results.Add($response)
        }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}

function Invoke-HuntingQuery {
    <# Runs an Advanced Hunting KQL query through Microsoft Graph and returns the result rows. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$Days = 7
    )
    $body = @{ Query = $Query; Timespan = ('P{0}D' -f $Days) }
    $response = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
    if ($null -eq $response.results) { return @() }
    return @($response.results)
}

function ConvertTo-ReportRow {
    <# Copies one hunting result row into a PSCustomObject in projection order: dynamic arrays joined with '; ', ISO timestamps as UTC [datetime]. #>
    param([Parameter(Mandatory = $true)][object]$Row)
    $shaped = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [array]) { $value = @($value | ForEach-Object { if ($_ -is [string] -or $_ -is [ValueType]) { [string]$_ } else { $_ | ConvertTo-Json -Compress } }) -join '; ' }
        elseif ($value -is [string] -and $value -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') { $value = [datetime]::Parse($value, [cultureinfo]::InvariantCulture, 'AdjustToUniversal') }
        $shaped[$property.Name] = $value
    }
    return [PSCustomObject]$shaped
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderSecurityRecommendations_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('ThreatHunting.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$categoryFilter = ''
if (-not [string]::IsNullOrWhiteSpace($Category)) { $categoryFilter = "| where ConfigurationCategory =~ '{0}'" -f $Category }
$shape = @"
| summarize DeviceCount=dcount(DeviceId), Devices=make_set(DeviceName, 10) by ConfigurationId, ConfigurationName, ConfigurationCategory,
    ConfigurationSubcategory, ConfigurationImpact, RiskDescription, RemediationOptions
| where DeviceCount >= $MinimumDevices
| order by ConfigurationImpact desc, DeviceCount desc
"@
if ($PerDevice) {
    $shape = '| project DeviceName, DeviceId, OSPlatform, ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationSubcategory,'
    $shape += " ConfigurationImpact, RiskDescription, RemediationOptions`n| order by DeviceName asc, ConfigurationImpact desc"
}
$query = @"
DeviceTvmSecureConfigurationAssessment
| where IsCompliant == 0 and IsApplicable == 1
| join kind=inner (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationDescription, RiskDescription,
    ConfigurationCategory, ConfigurationSubcategory, ConfigurationImpact, RemediationOptions, Tags) on ConfigurationId
$categoryFilter
$shape
"@
Write-Verbose "Running query:`n$query"
try { $rows = @(Invoke-HuntingQuery -Query $query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }
if ($rows.Count -eq 0) { Write-Warning 'No failed configuration checks matched the filters; nothing exported.'; return }
$report = @(foreach ($row in $rows) { ConvertTo-ReportRow -Row $row })
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$unit = if ($PerDevice) { 'failed check(s) across {0} device(s)' -f @($report | Select-Object -ExpandProperty DeviceName -Unique).Count } else { 'security recommendation(s)' }
Write-Host ('Defender security recommendations: {0} {1}' -f $report.Count, $unit) -ForegroundColor Cyan
$categoryParts = foreach ($group in ($report | Group-Object -Property ConfigurationCategory | Sort-Object -Property Count -Descending)) { '{0} {1}' -f $group.Count, $group.Name }
Write-Host ('  By category: {0}' -f (@($categoryParts) -join ' | ')) -ForegroundColor Yellow
if ($PerDevice) {
    Write-Host '  Devices with the most failed checks:' -ForegroundColor Yellow
    foreach ($group in ($report | Group-Object -Property DeviceName | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
        Write-Host ('    {0,5} check(s)  {1}' -f $group.Count, $group.Name)
    }
}
else {
    Write-Host '  Highest impact recommendations:' -ForegroundColor Yellow
    foreach ($row in ($report | Select-Object -First 10)) {
        Write-Host ('    impact {0,4}  {1,6} device(s)  [{2}] {3}' -f $row.ConfigurationImpact, $row.DeviceCount, $row.ConfigurationCategory, $row.ConfigurationName)
    }
}
if ($rows.Count -ge 100000) { Write-Warning 'The result hit the 100,000-row API cap and is truncated; add -Category or raise -MinimumDevices.' }
Write-Host ('  Report -> {0}' -f $OutputPath)
if ($PassThru) { $report }
#endregion Main
