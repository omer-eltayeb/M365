<#
.SYNOPSIS
    Exports the Defender Vulnerability Management software inventory with device counts, versions in use and end-of-support status.
.DESCRIPTION
    Runs an Advanced Hunting query through Microsoft Graph (POST v1.0 /security/runHuntingQuery) over DeviceTvmSoftwareInventory and
    summarises one row per vendor and product: DeviceCount, up to 20 versions seen, end-of-support status and date, ordered by the
    number of devices. -PerDevice returns one row per device and software version instead. -SoftwareName narrows the search and
    -OnlyEndOfSupport keeps products or versions that are already, or soon will be, out of support. Writes a CSV and prints a summary
    of the end-of-support software.
.PARAMETER Days
    Timespan passed to the API (1-30, default 7). The TVM tables are snapshots without a Timestamp, so the value does not filter them.
.PARAMETER SoftwareName
    Case-insensitive 'contains' match on SoftwareName, for example office, java or 7-zip.
.PARAMETER OnlyEndOfSupport
    Keeps only rows whose EndOfSupportStatus is EOS Version, EOS Software, Upcoming EOS Version or Upcoming EOS Software.
.PARAMETER PerDevice
    Returns one row per DeviceName, software and version (DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName,
    SoftwareVersion, EndOfSupportStatus, EndOfSupportDate) instead of the aggregated view.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderSoftwareInventory_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderSoftwareInventory.ps1
    Exports every software product with the number of devices and versions in use, and prints the end-of-support summary.
.EXAMPLE
    PS> .\Get-DefenderSoftwareInventory.ps1 -OnlyEndOfSupport -PerDevice -OutputPath C:\Temp\EosSoftwareByDevice.csv -PassThru | Group-Object -Property DeviceName
    Lists each device that still runs end-of-support software, one row per software version, grouped per device in the pipeline.
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
                  property (P<n>D). -PerDevice without -SoftwareName or -OnlyEndOfSupport easily exceeds the cap. End-of-support data is
                  only available for Windows software. Needs Defender for Endpoint Plan 2 or the Defender Vulnerability Management add-on.
.LINK
    https://learn.microsoft.com/graph/api/security-security-runhuntingquery
.LINK
    https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsoftwareinventory-table
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$Days = 7,

    [Parameter()]
    [string]$SoftwareName,

    [Parameter()]
    [switch]$OnlyEndOfSupport,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderSoftwareInventory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('ThreatHunting.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# Backslash and single quote are escaped so the user value is a safe KQL string literal.
$filters = @()
if (-not [string]::IsNullOrWhiteSpace($SoftwareName)) { $filters += "| where SoftwareName contains '{0}'" -f $SoftwareName.Replace('\', '\\').Replace("'", "\'") }
if ($OnlyEndOfSupport) { $filters += "| where EndOfSupportStatus has 'EOS'" }
$shape = @"
| summarize DeviceCount=dcount(DeviceId), Versions=make_set(SoftwareVersion, 20), EndOfSupport=any(EndOfSupportStatus), EndOfSupportDate=any(EndOfSupportDate) by SoftwareVendor, SoftwareName
| order by DeviceCount desc
"@
$statusColumn = 'EndOfSupport'
if ($PerDevice) {
    $shape = "| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate`n| order by SoftwareName asc, DeviceName asc"
    $statusColumn = 'EndOfSupportStatus'
}
$query = @"
DeviceTvmSoftwareInventory
$($filters -join "`n")
$shape
"@
Write-Verbose "Running query:`n$query"
try { $rows = @(Invoke-HuntingQuery -Query $query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }
if ($rows.Count -eq 0) { Write-Warning 'No software matched the filters; nothing exported.'; return }
$report = @(foreach ($row in $rows) { ConvertTo-ReportRow -Row $row })
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# 'EOS ...' means support already ended; 'Upcoming EOS ...' is announced for the next six months.
$eosRows = @($report | Where-Object { $_.$statusColumn -like '*EOS*' })
$alreadyEos = @($eosRows | Where-Object { $_.$statusColumn -like 'EOS*' }).Count
$unit = if ($PerDevice) { 'device software row(s)' } else { 'software product(s)' }
Write-Host ('Defender software inventory: {0} {1}, {2} end of support ({3} already out of support, {4} upcoming)' -f $report.Count, $unit,
    $eosRows.Count, $alreadyEos, ($eosRows.Count - $alreadyEos)) -ForegroundColor Cyan
Write-Host '  Top end-of-support software:' -ForegroundColor Yellow
if ($PerDevice) {
    foreach ($group in ($eosRows | Group-Object -Property SoftwareName | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
        Write-Host ('    {0,5} row(s)  {1}' -f $group.Count, $group.Name)
    }
}
else {
    foreach ($row in ($eosRows | Select-Object -First 10)) {
        Write-Host ('    {0,5} device(s)  {1} {2}  [{3}, {4:yyyy-MM-dd}]' -f $row.DeviceCount, $row.SoftwareVendor, $row.SoftwareName, $row.EndOfSupport, $row.EndOfSupportDate)
    }
}
if ($rows.Count -ge 100000) { Write-Warning 'The result hit the 100,000-row API cap and is truncated; add -SoftwareName or -OnlyEndOfSupport.' }
Write-Host ('  Report -> {0}' -f $OutputPath)
if ($PassThru) { $report }
#endregion Main
