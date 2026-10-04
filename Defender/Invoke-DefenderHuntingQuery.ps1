<#
.SYNOPSIS
    Runs any Advanced Hunting KQL query against Microsoft Defender XDR through Microsoft Graph and exports the rows to CSV.
.DESCRIPTION
    Generic runner for ad-hoc and saved hunts: pass the KQL inline with -Query or point -QueryFile at a .kql file, pick the
    timespan with -Days, and the script POSTs the query to v1.0 /security/runHuntingQuery, prints the result schema (column
    names and the value types seen in the results), writes every row to CSV and optionally emits the rows to the pipeline.
    -ShowTables lists the main Advanced Hunting tables by product area, which is handy while drafting queries.
.PARAMETER Query
    KQL query text; multi-line here-strings are fine.
.PARAMETER QueryFile
    Path to a text file (typically .kql) that contains the query. The whole file is sent as-is.
.PARAMETER Days
    Timespan of the query in days (1-30, default 7). The service applies the shorter of this window and any Timestamp filter in the query.
.PARAMETER ShowTables
    Lists the main Advanced Hunting tables grouped by product area, then exits without connecting to Graph.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderHuntingQuery_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the result rows to the pipeline.
.EXAMPLE
    PS> .\Invoke-DefenderHuntingQuery.ps1 -Query 'DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId | project DeviceName, OSPlatform, SensorHealthState' -Days 3
    Runs the query over the last 3 days, prints the schema and exports the rows to .\Reports.
.EXAMPLE
    PS> .\Invoke-DefenderHuntingQuery.ps1 -QueryFile .\Hunts\LolbinDownloads.kql -Days 30 -OutputPath C:\Temp\Lolbin.csv -PassThru | Group-Object -Property DeviceName
    Runs a saved hunt over the full 30-day window, exports it and groups the rows per device in the pipeline.
.EXAMPLE
    PS> .\Invoke-DefenderHuntingQuery.ps1 -ShowTables
    Prints the device, vulnerability management, email, identity, cloud app, alert and Entra ID sign-in tables.
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
    Notes       : Advanced hunting caps results per query (10,000 rows in the portal, 100,000 through the API) and keeps 30 days of
                  data; -Days maps to the Timespan property (P<n>D). Dynamic columns (arrays) are joined with '; ' in the CSV. Tables
                  only return data for the Defender products deployed in the tenant; the Entra ID sign-in tables need Entra ID P2.
.LINK
    https://learn.microsoft.com/graph/api/security-security-runhuntingquery
.LINK
    https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(DefaultParameterSetName = 'Query')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Query', Position = 0)]
    [string]$Query,

    [Parameter(Mandatory = $true, ParameterSetName = 'QueryFile')]
    [string]$QueryFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'Tables')]
    [switch]$ShowTables,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$Days = 7,

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
if ($ShowTables) {
    $tableGroups = [ordered]@{
        'Endpoint (Defender for Endpoint)'      = 'DeviceInfo, DeviceEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceRegistryEvents, DeviceImageLoadEvents'
        'Vulnerability management (snapshots)'  = 'DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities (+KB), DeviceTvmSecureConfigurationAssessment (+KB)'
        'Email (Defender for Office 365)'       = 'EmailEvents, EmailUrlInfo, EmailAttachmentInfo, EmailPostDeliveryEvents, UrlClickEvents'
        'Identity (Defender for Identity)'      = 'IdentityLogonEvents, IdentityQueryEvents, IdentityDirectoryEvents'
        'Cloud apps (Defender for Cloud Apps)'  = 'CloudAppEvents'
        'Alerts (all Defender products)'        = 'AlertInfo, AlertEvidence'
        'Entra ID sign-ins (Entra ID P2)'       = 'EntraIdSignInEvents, EntraIdSpnSignInEvents (replace AADSignInEventsBeta and AADSpnSignInEventsBeta, retired on 2026-10-19)'
    }
    foreach ($area in $tableGroups.Keys) { [PSCustomObject]@{ Area = $area; Tables = $tableGroups[$area] } }
    return
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderHuntingQuery_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if ($PSCmdlet.ParameterSetName -eq 'QueryFile') {
    $Query = Get-Content -Path $QueryFile -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($Query)) { throw "Query file '$QueryFile' is empty." }
}

try { Connect-GraphIfNeeded -Scopes @('ThreatHunting.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

Write-Verbose ("Running query with a {0}-day timespan:`n{1}" -f $Days, $Query)
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
try { $rows = @(Invoke-HuntingQuery -Query $Query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }
$stopwatch.Stop()
if ($rows.Count -eq 0) { Write-Warning ('The query returned no rows for the last {0} day(s); nothing exported.' -f $Days); return }

# The helper returns rows only, so the schema is read from the results: column order from the first row, type from the first non-null value.
$columns = @($rows[0].PSObject.Properties | Select-Object -ExpandProperty Name)
$schema = foreach ($column in $columns) {
    $sample = $null
    foreach ($row in $rows) { if ($null -ne $row.$column) { $sample = $row.$column; break } }
    $typeName = 'Unknown (all null)'
    if ($sample -is [array]) { $typeName = 'Dynamic' }
    elseif ($sample -is [string] -and $sample -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') { $typeName = 'DateTime' }
    elseif ($null -ne $sample) { $typeName = $sample.GetType().Name }
    [PSCustomObject]@{ Column = $column; Type = $typeName }
}
$report = foreach ($row in $rows) { ConvertTo-ReportRow -Row $row }
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ('Advanced hunting query finished in {0:N1} s: {1} row(s), {2} column(s), timespan {3} day(s)' -f $stopwatch.Elapsed.TotalSeconds, $rows.Count, $columns.Count, $Days) -ForegroundColor Cyan
if ($rows.Count -ge 100000) { Write-Warning 'The result hit the 100,000-row API cap and is truncated; narrow the query or the timespan.' }
Write-Host '  Schema:' -ForegroundColor Yellow
foreach ($entry in $schema) { Write-Host ('    {0,-40} {1}' -f $entry.Column, $entry.Type) }
Write-Host ('  Report -> {0}' -f $OutputPath)

if ($PassThru) { $report }
#endregion Main
