<#
.SYNOPSIS
    Summarises Microsoft 365 adoption per workload (active vs inactive users and the daily active-user trend) from the Graph usage reports.
.DESCRIPTION
    Downloads the active vs inactive user counts per service (/reports/getOffice365ServicesUserCounts) and the daily active
    users per workload (/reports/getOffice365ActiveUserCounts) for the selected period. Outputs one summary row per workload
    (Office 365 overall, Exchange, OneDrive, SharePoint, Skype for Business, Yammer/Viva Engage, Teams) with active, inactive
    and total users, the adoption percentage and the change in daily active users from the first to the last day of the
    period. The daily series is written to <OutputPath base>_Daily.csv and a console bar chart shows adoption per workload.
.PARAMETER Period
    Report period: D7, D30, D90 or D180 (days). Default D30.
.PARAMETER OutputPath
    Path of the summary CSV file. Defaults to .\Reports\M365WorkloadAdoption_<Period>_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the summary objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365WorkloadAdoptionSummary.ps1
    Prints a 30-day adoption bar chart per workload and writes the summary and daily CSV files to .\Reports.
.EXAMPLE
    PS> .\Get-M365WorkloadAdoptionSummary.ps1 -Period D180 -OutputPath C:\Temp\Adoption.csv -PassThru | Sort-Object -Property AdoptionPercent
    Uses the 180-day report, writes C:\Temp\Adoption.csv and C:\Temp\Adoption_Daily.csv and returns the rows sorted by adoption.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Reports.Read.All (delegated); Reports Reader or Global Reader role
    Category    : Usage & adoption reports
    Changes     : No
    Notes       : Adoption = active / (active + inactive) licensed users for the period as counted by Microsoft. Report data lags
                  about 48 hours, so the last daily value is for the report refresh date, not today. Skype for Business Online is
                  retired and normally shows zero users. Aggregate reports are not affected by the concealed-names setting.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getoffice365servicesusercounts
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getoffice365activeusercounts
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period = 'D30',

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

function Get-UsageReportCsv {
    <# Downloads a Microsoft Graph usage report (CSV) and imports it. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportFunction,

        [Parameter(Mandatory = $true)]
        [string]$Period
    )
    $uri = 'https://graph.microsoft.com/v1.0/reports/{0}(period=''{1}'')' -f $ReportFunction, $Period
    $tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('{0}_{1}.csv' -f $ReportFunction, [guid]::NewGuid())
    try {
        Invoke-MgGraphRequest -Method GET -Uri $uri -OutputFilePath $tempCsv -ErrorAction Stop
        return @(Import-Csv -Path $tempCsv)
    }
    finally {
        if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue }
    }
}

function ConvertTo-ReportObject {
    <# Converts a raw report row to PascalCase properties; empty cells become $null, True/False/Yes/No [bool], whole numbers [int64] (not in Name/Id columns), "...Date" columns [datetime]. #>
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Row
    )
    $props = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        $name = $property.Name -replace '[^A-Za-z0-9]', ''
        [string]$text = $property.Value
        $number = [int64]0; $date = [datetime]::MinValue
        if ([string]::IsNullOrEmpty($text)) { $props[$name] = $null }
        elseif ($text -in @('True', 'False', 'Yes', 'No')) { $props[$name] = ($text -eq 'True' -or $text -eq 'Yes') }
        elseif ($property.Name -notmatch 'Name$|Id$' -and [int64]::TryParse($text, [ref]$number)) { $props[$name] = $number }
        elseif ($property.Name -like '*Date*' -and [datetime]::TryParse($text, [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date)) { $props[$name] = $date }
        else { $props[$name] = $text }
    }
    return [PSCustomObject]$props
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365WorkloadAdoption_{0}_{1}.csv' -f $Period, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
# Path.Combine tolerates an empty folder (bare file name in -OutputPath) where Join-Path would throw.
$dailyOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_Daily.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All')
    Write-Verbose "Downloading getOffice365ServicesUserCounts and getOffice365ActiveUserCounts for period $Period."
    $servicesReport = @(Get-UsageReportCsv -ReportFunction 'getOffice365ServicesUserCounts' -Period $Period)
    $dailyReport = @(Get-UsageReportCsv -ReportFunction 'getOffice365ActiveUserCounts' -Period $Period)
}
catch {
    throw "Failed to retrieve the active user reports from Microsoft Graph: $($_.Exception.Message)"
}
if ($servicesReport.Count -eq 0) { throw 'The services user counts report returned no data; the tenant may have no licensed users yet.' }

# Workload names as spelled in the report columns; property names drop the spaces (SkypeForBusinessActive, ...).
$workloads = @('Office 365', 'Exchange', 'OneDrive', 'SharePoint', 'Skype For Business', 'Yammer', 'Teams')
$services = ConvertTo-ReportObject -Row $servicesReport[0]
$daily = @($dailyReport | ForEach-Object { ConvertTo-ReportObject -Row $_ } | Sort-Object -Property ReportDate |
    Select-Object -Property ReportDate, Office365, Exchange, OneDrive, SharePoint, SkypeForBusiness, Yammer, Teams)
if ($daily.Count -gt 0) { $daily | Export-Csv -Path $dailyOutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'The daily active user counts report returned no rows; trend columns will be empty.' }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($workload in $workloads) {
    $key = $workload.Replace(' ', '')
    $active = [int64]$services.($key + 'Active')
    $inactive = [int64]$services.($key + 'Inactive')
    $adoptionPercent = 0; if (($active + $inactive) -gt 0) { $adoptionPercent = [math]::Round(($active / ($active + $inactive)) * 100, 1) }
    $firstDay = $null; $lastDay = $null; $trend = $null; $firstDate = $null; $lastDate = $null
    if ($daily.Count -gt 0) {
        $firstDay = [int64]$daily[0].$key
        $lastDay = [int64]$daily[-1].$key
        $trend = $lastDay - $firstDay
        $firstDate = $daily[0].ReportDate; $lastDate = $daily[-1].ReportDate
    }
    $rows.Add([PSCustomObject]@{
            Workload          = $workload
            ActiveUsers       = $active
            InactiveUsers     = $inactive
            TotalUsers        = $active + $inactive
            AdoptionPercent   = $adoptionPercent
            FirstDayActive    = $firstDay
            LastDayActive     = $lastDay
            TrendFirstToLast  = $trend
            FirstReportDate   = $firstDate
            LastReportDate    = $lastDate
            ReportRefreshDate = $services.ReportRefreshDate
            Period            = $Period
        })
}
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ('Microsoft 365 workload adoption ({0}, refreshed {1:yyyy-MM-dd})' -f $Period, $services.ReportRefreshDate) -ForegroundColor Cyan
Write-Host ('  {0,-20} {1,7}  {2,-50} {3,9} {4,9} {5,7}' -f 'Workload', 'Adopt %', ('0 %' + (' ' * 42) + '100 %'), 'Active', 'Inactive', 'Trend')
foreach ($row in $rows) {
    # One '#' per two percent, so a full bar is 50 characters wide.
    $bar = '#' * [int][math]::Round($row.AdoptionPercent / 2)
    $trendText = 'n/a'; if ($null -ne $row.TrendFirstToLast) { $trendText = '{0:+#;-#;0}' -f $row.TrendFirstToLast }
    Write-Host ('  {0,-20} {1,7}  {2,-50} {3,9} {4,9} {5,7}' -f $row.Workload, $row.AdoptionPercent, $bar, $row.ActiveUsers, $row.InactiveUsers, $trendText)
}
Write-Host '  Trend = daily active users on the last day minus the first day of the period.'
Write-Host ('  Summary CSV : {0}' -f $OutputPath)
if ($daily.Count -gt 0) { Write-Host ('  Daily CSV   : {0}' -f $dailyOutputPath) }

if ($PassThru) { $rows }
#endregion Main
