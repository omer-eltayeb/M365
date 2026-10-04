<#
.SYNOPSIS
    Reports vulnerable software found by Defender Vulnerability Management: CVEs per software version with CVSS, exploit availability and device counts.
.DESCRIPTION
    Runs an Advanced Hunting query through Microsoft Graph (POST v1.0 /security/runHuntingQuery) that joins DeviceTvmSoftwareVulnerabilities
    with DeviceTvmSoftwareVulnerabilitiesKB and summarises one row per CVE and software version (DeviceCount, up to 10 sample devices,
    severity, CVSS, exploit flag, published date, recommended update) ordered by affected devices; -PerDevice returns one row per device,
    software version and CVE instead. A second tenant-wide query feeds the summary with the devices that carry a critical, exploitable CVE.
.PARAMETER Days
    Timespan passed to the API (1-30, default 7). The TVM tables are snapshots without a Timestamp, so the value does not filter them.
.PARAMETER Severity
    One or more of Critical, High, Medium, Low. Default: all severities.
.PARAMETER OnlyExploitable
    Returns only CVEs for which a public exploit is known (IsExploitAvailable == true).
.PARAMETER SoftwareName
    Case-insensitive 'contains' match on SoftwareName, for example chrome or java.
.PARAMETER MinimumDevices
    Hides CVE rows affecting fewer devices than this (default 1). Ignored with -PerDevice.
.PARAMETER PerDevice
    Returns one row per DeviceName, software version and CVE instead of the aggregated view.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderVulnerableSoftware_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderVulnerableSoftware.ps1 -Severity Critical, High -OnlyExploitable
    Exports critical and high CVEs with a known exploit, one row per CVE and software version, with the devices affected.
.EXAMPLE
    PS> .\Get-DefenderVulnerableSoftware.ps1 -SoftwareName chrome -PerDevice -OutputPath C:\Temp\ChromeCves.csv -PassThru | Group-Object -Property DeviceName
    Lists every Chrome CVE per device and groups the rows per device in the pipeline.
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
                  property (P<n>D). -PerDevice without -SoftwareName or -Severity easily exceeds the cap in large tenants. Needs MDE Plan 2 or the MDVM add-on.
.LINK
    https://learn.microsoft.com/graph/api/security-security-runhuntingquery
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$Days = 7,

    [Parameter()]
    [ValidateSet('Critical', 'High', 'Medium', 'Low')]
    [string[]]$Severity = @(),

    [Parameter()]
    [switch]$OnlyExploitable,

    [Parameter()]
    [string]$SoftwareName,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderVulnerableSoftware_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('ThreatHunting.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$filters = @()
if ($Severity.Count -gt 0) { $filters += "| where VulnerabilitySeverityLevel in~ ('{0}')" -f ($Severity -join "', '") }
if ($OnlyExploitable) { $filters += '| where IsExploitAvailable == true' }
# Backslash and single quote are escaped so the user value is a safe KQL string literal.
if (-not [string]::IsNullOrWhiteSpace($SoftwareName)) { $filters += "| where SoftwareName contains '{0}'" -f $SoftwareName.Replace('\', '\\').Replace("'", "\'") }
$shape = @"
| summarize DeviceCount=dcount(DeviceId), Devices=make_set(DeviceName, 10) by CveId, SoftwareVendor, SoftwareName, SoftwareVersion,
    VulnerabilitySeverityLevel, CvssScore, IsExploitAvailable, PublishedDate, RecommendedSecurityUpdate
| where DeviceCount >= $MinimumDevices
| order by DeviceCount desc
"@
if ($PerDevice) {
    $shape = '| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, CvssScore,'
    $shape += " IsExploitAvailable, PublishedDate, RecommendedSecurityUpdate`n| order by CvssScore desc, DeviceName asc"
}
$query = @"
DeviceTvmSoftwareVulnerabilities
| join kind=inner (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable, VulnerabilitySeverityLevel, PublishedDate) on CveId
$($filters -join "`n")
$shape
"@
Write-Verbose "Running query:`n$query"
try { $rows = @(Invoke-HuntingQuery -Query $query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }
if ($rows.Count -eq 0) { Write-Warning 'No vulnerabilities matched the filters; nothing exported.'; return }
$report = @(foreach ($row in $rows) { ConvertTo-ReportRow -Row $row })
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$exposureQuery = @"
DeviceTvmSoftwareVulnerabilities | where VulnerabilitySeverityLevel == 'Critical'
| join kind=inner (DeviceTvmSoftwareVulnerabilitiesKB | where IsExploitAvailable == true | project CveId) on CveId
| summarize CriticalExploitableCves=dcount(CveId) by DeviceName | order by CriticalExploitableCves desc
"@
try { $exposedDevices = @(Invoke-HuntingQuery -Query $exposureQuery -Days $Days) }
catch { Write-Warning "Could not compute the critical exploitable exposure: $($_.Exception.Message)"; $exposedDevices = @() }

Write-Host ('Defender vulnerable software: {0} row(s){1}' -f $report.Count, $(if ($PerDevice) { ' (per device)' } else { ' (per CVE and software version)' })) -ForegroundColor Cyan
Write-Host $(if ($PerDevice) { '  Highest CVSS rows:' } else { '  Top CVEs by affected devices:' }) -ForegroundColor Yellow
foreach ($cve in ($report | Select-Object -First 10)) {
    $tail = if ($PerDevice) { $cve.DeviceName } else { '{0} device(s)' -f $cve.DeviceCount }
    Write-Host ('    {0,-16} {1,-8} CVSS {2,4}  {3,-40} {4}' -f $cve.CveId, $cve.VulnerabilitySeverityLevel, $cve.CvssScore, $cve.SoftwareName, $tail)
}
Write-Host ('  Devices with at least one critical CVE that has a public exploit (tenant-wide): {0}' -f $exposedDevices.Count) -ForegroundColor Yellow
foreach ($device in ($exposedDevices | Select-Object -First 5)) { Write-Host ('    {0,5} CVE(s)  {1}' -f $device.CriticalExploitableCves, $device.DeviceName) }
Write-Host ('  Report -> {0}' -f $OutputPath)
if ($PassThru) { $report }
#endregion Main
