<#
.SYNOPSIS
    Reports which Teams client platforms (Windows, Mac, web, iOS, Android, ...) every user has used and finds web-only and mobile-only users.
.DESCRIPTION
    Downloads the Microsoft Graph usage report /reports/getTeamsDeviceUsageUserDetail(period='D30') as CSV and reshapes every
    row into one boolean column per platform plus Platforms (the joined list), PlatformCount, WebOnly (no desktop or mobile
    client, often a sign that the Teams desktop app is not deployed), MobileOnly and UsesDesktopClient. -IncludeDistribution
    also downloads getTeamsDeviceUsageDistributionUserCounts and prints the tenant-wide user counts per platform.
    The console summary shows platform adoption and the number of web-only, mobile-only and inactive users.
.PARAMETER Period
    Usage report period: D7, D30, D90 or D180. Default D30.
.PARAMETER Filter
    Export all users (default) or only WebOnly, MobileOnly or Inactive (no platform used in the period) users.
.PARAMETER IncludeDistribution
    Also download the distribution report and print the number of users per platform as counted by Microsoft.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsDeviceUsage_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsDeviceUsageReport.ps1
    Exports the platforms used by every user in the last 30 days and shows the adoption per platform.
.EXAMPLE
    PS> .\Get-TeamsDeviceUsageReport.ps1 -Period D90 -Filter WebOnly -IncludeDistribution -OutputPath C:\Temp\TeamsWebOnly.csv -Verbose
    Lists users who only used Teams in the browser during the last 90 days, a good target list for a desktop client rollout.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Reports.Read.All (delegated). The Reports Reader, Global Reader or Teams Administrator role is enough.
    Category    : Teams apps, settings & usage
    Changes     : No
    Notes       : Usage report data lags about 48 hours behind real time. If "Display concealed user, group, and site names in all
                  reports" is enabled (Microsoft 365 admin center > Settings > Org settings > Reports) the UPN column contains hashes.
                  A platform counts as used when the user signed in from it at least once in the period; Windows Phone is kept for
                  completeness only. Deleted accounts stay in the report with IsDeleted = True.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getteamsdeviceusageuserdetail
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getteamsdeviceusagedistributionusercounts
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period = 'D30',

    [Parameter()]
    [ValidateSet('All', 'WebOnly', 'MobileOnly', 'Inactive')]
    [string]$Filter = 'All',

    [Parameter()]
    [switch]$IncludeDistribution,

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

function Get-GraphReportCsv {
    <# Downloads a usage report (Graph answers with a redirect to a CSV) into a temp file and imports it. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    $tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('GraphReport_{0}.csv' -f [guid]::NewGuid().ToString('N'))
    try {
        Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputFilePath $tempCsv -ErrorAction Stop
        return @(Import-Csv -Path $tempCsv -Encoding UTF8)
    }
    finally {
        if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue }
    }
}

function Get-ReportValue {
    <# Returns a report column value by name (header spacing differences are ignored); $null when the column is missing or empty. #>
    param([Parameter(Mandatory = $true)][object]$Row, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $script:reportColumns) {
        $script:reportColumns = @{}
        foreach ($column in $Row.PSObject.Properties.Name) { $script:reportColumns[($column -replace '\s+', ' ')] = $column }
    }
    $actualName = $script:reportColumns[($Name -replace '\s+', ' ')]
    if ($null -eq $actualName -or [string]::IsNullOrWhiteSpace([string]$Row.$actualName)) { return $null }
    return $Row.$actualName
}

function Get-ReportDate {
    <# Converts a report date column (yyyy-MM-dd) to a UTC [datetime]; $null when empty. #>
    param([Parameter(Mandatory = $true)][object]$Row, [Parameter(Mandatory = $true)][string]$Name)
    $value = Get-ReportValue -Row $Row -Name $Name
    if ($null -eq $value) { return $null }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { return $parsed.ToUniversalTime() }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsDeviceUsage_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('Reports.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
Write-Progress -Activity 'Teams device usage report' -Status "Downloading getTeamsDeviceUsageUserDetail(period='$Period')"
try { $report = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getTeamsDeviceUsageUserDetail(period='$Period')") }
catch { throw "Failed to download the Teams device usage report: $($_.Exception.Message)" }

# Report column -> output column suffix; the order also drives the Platforms list.
$platformColumns = [ordered]@{
    'Used Windows' = 'Windows'; 'Used Mac' = 'Mac'; 'Used Linux' = 'Linux'; 'Used Chrome OS' = 'ChromeOS'
    'Used Web' = 'Web'; 'Used iOS' = 'iOS'; 'Used Android Phone' = 'Android'; 'Used Windows Phone' = 'WindowsPhone'
}
$desktopPlatforms = @('Windows', 'Mac', 'Linux', 'ChromeOS')
$mobilePlatforms = @('iOS', 'Android', 'WindowsPhone')
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($entry in $report) {
    $counter++
    if ($counter % 250 -eq 0) { Write-Progress -Activity 'Teams device usage report' -Status "Processing $counter of $($report.Count) users" -PercentComplete ([int](($counter / $report.Count) * 100)) }
    $row = [ordered]@{
        UserPrincipalName = Get-ReportValue -Row $entry -Name 'User Principal Name'
        UserId            = Get-ReportValue -Row $entry -Name 'User Id'
        LastActivityDate  = Get-ReportDate -Row $entry -Name 'Last Activity Date'
        IsLicensed        = ((Get-ReportValue -Row $entry -Name 'Is Licensed') -eq 'Yes')
        IsDeleted         = ((Get-ReportValue -Row $entry -Name 'Is Deleted') -eq 'True')
    }
    $used = @()
    foreach ($column in $platformColumns.Keys) {
        $flag = ((Get-ReportValue -Row $entry -Name $column) -eq 'Yes')
        $row['Used' + $platformColumns[$column]] = $flag
        if ($flag) { $used += $platformColumns[$column] }
    }
    $row['Platforms'] = $used -join ';'
    $row['PlatformCount'] = $used.Count
    $row['UsesDesktopClient'] = (@($used | Where-Object { $desktopPlatforms -contains $_ }).Count -gt 0)
    $row['WebOnly'] = ($used.Count -eq 1 -and $used[0] -eq 'Web')
    $row['MobileOnly'] = ($used.Count -gt 0 -and @($used | Where-Object { $mobilePlatforms -notcontains $_ }).Count -eq 0)
    $row['ReportRefreshDate'] = Get-ReportDate -Row $entry -Name 'Report Refresh Date'
    $rows.Add([PSCustomObject]$row)
}
Write-Progress -Activity 'Teams device usage report' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'PlatformCount'; Descending = $true }, UserPrincipalName)
switch ($Filter) {
    'WebOnly' { $output = @($output | Where-Object { $_.WebOnly }) }
    'MobileOnly' { $output = @($output | Where-Object { $_.MobileOnly }) }
    'Inactive' { $output = @($output | Where-Object { $_.PlatformCount -eq 0 }) }
}
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No users to export (the report is empty or nobody matches -Filter); no CSV was written.' }

$activeRows = @($rows | Where-Object { $_.PlatformCount -gt 0 })
Write-Host ''
Write-Host "Teams device usage summary ($Period)" -ForegroundColor Cyan
Write-Host ('  Users in report / with activity : {0} / {1}' -f $rows.Count, $activeRows.Count)
Write-Host '  Platform adoption (users):'
foreach ($suffix in $platformColumns.Values) {
    $platformUsers = @($rows | Where-Object { $_.('Used' + $suffix) }).Count
    if ($platformUsers -gt 0) { Write-Host ('    {0,-14} {1,7}' -f $suffix, $platformUsers) }
}
Write-Host ('  Web-only users                  : {0}' -f @($rows | Where-Object { $_.WebOnly }).Count) -ForegroundColor Yellow
Write-Host ('  Mobile-only users               : {0}' -f @($rows | Where-Object { $_.MobileOnly }).Count) -ForegroundColor Yellow
Write-Host ('  Licensed users without activity : {0}' -f @($rows | Where-Object { $_.IsLicensed -and -not $_.IsDeleted -and $_.PlatformCount -eq 0 }).Count) -ForegroundColor Yellow
if ($IncludeDistribution) {
    try {
        $script:reportColumns = $null   # the distribution report has its own headers
        $distribution = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getTeamsDeviceUsageDistributionUserCounts(period='$Period')") | Select-Object -First 1
        Write-Host '  Microsoft distribution counts (users per platform):'
        foreach ($name in @('Windows', 'Mac', 'Linux', 'Chrome OS', 'Web', 'iOS', 'Android Phone', 'Windows Phone')) {
            Write-Host ('    {0,-14} {1,7}' -f $name, [int][string](Get-ReportValue -Row $distribution -Name $name))
        }
    }
    catch { Write-Warning "Could not download the distribution report: $($_.Exception.Message)" }
}
Write-Host ('  Rows exported                   : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
