<#
.SYNOPSIS
    Trends Microsoft Defender XDR alerts over time: volume by severity, source, category and title, MTTR and false-positive rate.
.DESCRIPTION
    Reads every alert created in the last -DaysBack days from GET /security/alerts_v2 (server-side $filter on createdDateTime,
    $select of the trend fields only) and writes two CSV files: <base>_Daily.csv (or _Weekly.csv) with one row per period and
    the alert counts per severity, and the main report with a breakdown per dimension (Total, Severity, ServiceSource, Category,
    top 20 Title): alert count, share, resolved count, mean hours to resolve (resolvedDateTime - createdDateTime) and the
    false-positive rate among classified alerts. The console prints the headline numbers and the most recent periods.
.PARAMETER DaysBack
    Number of days to look back based on createdDateTime. Default 30, maximum 365.
.PARAMETER GroupBy
    Period size of the trend file: Day (default) or Week (weeks start on Monday).
.PARAMETER OutputPath
    Path of the breakdown CSV. Defaults to .\Reports\DefenderAlertsTrend_yyyyMMdd-HHmm.csv; the period file is written next to it.
.PARAMETER PassThru
    Also emits the breakdown rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderAlertsTrend.ps1
    Exports the daily alert counts and the breakdown for the last 30 days and prints the summary.
.EXAMPLE
    PS> .\Get-DefenderAlertsTrend.ps1 -DaysBack 180 -GroupBy Week -OutputPath C:\Temp\AlertTrend.csv -Verbose
    Builds a six-month weekly trend for a management report.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityAlert.Read.All (delegated); Security Reader, Security Operator or Security Administrator in Defender XDR.
    Category    : Defender XDR alerts & incidents
    Changes     : No
    Notes       : Mean time to resolve only counts alerts that carry resolvedDateTime; the false-positive rate is computed over
                  alerts classified as falsePositive, truePositive or informationalExpectedActivity. 365 days can mean tens of
                  thousands of alerts in large tenants, so paging takes a while. Alert titles are a good input for tuning rules.
.LINK
    https://learn.microsoft.com/graph/api/security-list-alerts_v2
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [Parameter()]
    [ValidateSet('Day', 'Week')]
    [string]$GroupBy = 'Day',

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

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Get-DimensionBreakdown {
    <# Groups the shaped alerts by one property and returns count, share, mean hours to resolve and false-positive rate per group. #>
    param([Parameter(Mandatory = $true)][object[]]$Alerts, [Parameter(Mandatory = $true)][string]$Property, [int]$Top = 0)
    $groups = @($Alerts | Group-Object -Property $Property | Sort-Object -Property Count -Descending)
    if ($Top -gt 0) { $groups = @($groups | Select-Object -First $Top) }
    foreach ($group in $groups) {
        $resolved = @($group.Group | Where-Object { $null -ne $_.HoursToResolve })
        $classified = @($group.Group | Where-Object { $_.Classification -in @('falsePositive', 'truePositive', 'informationalExpectedActivity') })
        $falsePositives = @($classified | Where-Object { $_.Classification -eq 'falsePositive' }).Count
        $meanHours = $null; if ($resolved.Count -gt 0) { $meanHours = [math]::Round(($resolved | Measure-Object -Property HoursToResolve -Average).Average, 1) }
        $falsePositiveRate = $null; if ($classified.Count -gt 0) { $falsePositiveRate = [math]::Round(($falsePositives / $classified.Count) * 100, 1) }
        [PSCustomObject]@{
            Dimension = $Property; Name = $group.Name; Alerts = $group.Count; Percent = [math]::Round(($group.Count / $Alerts.Count) * 100, 1); Resolved = $resolved.Count
            MeanHoursToResolve = $meanHours; Classified = $classified.Count; FalsePositives = $falsePositives; FalsePositiveRatePercent = $falsePositiveRate
        }
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderAlertsTrend_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$periodFileName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + $(if ($GroupBy -eq 'Week') { '_Weekly.csv' } else { '_Daily.csv' })
$periodPath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($OutputPath), $periodFileName)

try { Connect-GraphIfNeeded -Scopes @('SecurityAlert.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
$select = '$select=id,title,severity,status,serviceSource,category,createdDateTime,resolvedDateTime,classification'
$uri = 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=100&{0}&$filter=createdDateTime ge {1}' -f $select, $since
try { $alerts = @(Invoke-GraphPaged -Uri $uri) }
catch { throw "Failed to read alerts from Microsoft Defender XDR: $($_.Exception.Message)" }
if ($alerts.Count -eq 0) { Write-Warning ('No alerts were created in the last {0} days; nothing to report.' -f $DaysBack); return }

$shaped = foreach ($alert in $alerts) {
    $created = ConvertTo-UtcDateTime -Value $alert.createdDateTime
    $resolvedAt = ConvertTo-UtcDateTime -Value $alert.resolvedDateTime
    $hours = $null
    if ($null -ne $created -and $null -ne $resolvedAt -and $resolvedAt -ge $created) { $hours = [math]::Round(($resolvedAt - $created).TotalHours, 2) }
    [PSCustomObject]@{
        Scope = 'All alerts'; Title = $alert.title; Severity = [string]$alert.severity; Status = $alert.status; ServiceSource = [string]$alert.serviceSource; Category = [string]$alert.category
        Classification = [string]$alert.classification; Created = $created; HoursToResolve = $hours
    }
}
$shaped = @($shaped | Where-Object { $null -ne $_.Created })

# Pre-create every period in the window so quiet days show as zero rows instead of gaps in a chart.
$periodDays = $(if ($GroupBy -eq 'Week') { 7 } else { 1 })
$periodStart = [datetime]::UtcNow.Date.AddDays(-$DaysBack)
if ($GroupBy -eq 'Week') { $periodStart = $periodStart.AddDays(-(([int]$periodStart.DayOfWeek + 6) % 7)) }
$periods = [ordered]@{}
for ($day = $periodStart; $day -le [datetime]::UtcNow.Date; $day = $day.AddDays($periodDays)) {
    $periods[$day.ToString('yyyy-MM-dd')] = [PSCustomObject]@{ Date = $day; Informational = 0; Low = 0; Medium = 0; High = 0; Total = 0 }
}
$textInfo = [System.Globalization.CultureInfo]::InvariantCulture.TextInfo
foreach ($item in $shaped) {
    $bucket = $item.Created.Date
    if ($GroupBy -eq 'Week') { $bucket = $bucket.AddDays(-(([int]$bucket.DayOfWeek + 6) % 7)) }
    $key = $bucket.ToString('yyyy-MM-dd')
    if (-not $periods.Contains($key)) { $periods[$key] = [PSCustomObject]@{ Date = $bucket; Informational = 0; Low = 0; Medium = 0; High = 0; Total = 0 } }
    $severityName = $textInfo.ToTitleCase($item.Severity)
    if ($null -ne $periods[$key].PSObject.Properties[$severityName]) { $periods[$key].$severityName++ }
    $periods[$key].Total++
}
$periodRows = @($periods.Values | Sort-Object -Property Date)
$periodRows | Export-Csv -Path $periodPath -NoTypeInformation -Encoding UTF8
$breakdown = @(
    Get-DimensionBreakdown -Alerts $shaped -Property 'Scope'
    Get-DimensionBreakdown -Alerts $shaped -Property 'Severity'
    Get-DimensionBreakdown -Alerts $shaped -Property 'ServiceSource'
    Get-DimensionBreakdown -Alerts $shaped -Property 'Category'
    Get-DimensionBreakdown -Alerts $shaped -Property 'Title' -Top 20
)
$breakdown | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$total = $breakdown[0]
Write-Host ('Defender XDR alert trend (last {0} days, grouped by {1})' -f $DaysBack, $GroupBy.ToLower()) -ForegroundColor Cyan
Write-Host ('  Alerts {0} | Resolved {1} | Mean hours to resolve {2} | False-positive rate {3}% of {4} classified' -f $total.Alerts, $total.Resolved,
    $total.MeanHoursToResolve, $total.FalsePositiveRatePercent, $total.Classified)
Write-Host '  By severity (alerts | mean hours to resolve | false-positive rate):' -ForegroundColor Yellow
foreach ($row in ($breakdown | Where-Object { $_.Dimension -eq 'Severity' })) {
    Write-Host ('    {0,-14}: {1,6} | {2,8} h | {3,5} %' -f $row.Name, $row.Alerts, $row.MeanHoursToResolve, $row.FalsePositiveRatePercent)
}
Write-Host ('  Last {0} periods (date | info | low | medium | high | total):' -f [math]::Min(10, $periodRows.Count)) -ForegroundColor Yellow
foreach ($row in ($periodRows | Select-Object -Last 10)) {
    Write-Host ('    {0:yyyy-MM-dd} | {1,5} | {2,5} | {3,6} | {4,5} | {5,6}' -f $row.Date, $row.Informational, $row.Low, $row.Medium, $row.High, $row.Total)
}
Write-Host '  Top alert titles:' -ForegroundColor Yellow
foreach ($row in ($breakdown | Where-Object { $_.Dimension -eq 'Title' } | Select-Object -First 5)) { Write-Host ('    {0,5} x {1}' -f $row.Alerts, $row.Name) }
Write-Host ('  Breakdown -> {0} | Periods -> {1}' -f $OutputPath, $periodPath)

if ($PassThru) { $breakdown }
#endregion Main
