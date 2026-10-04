<#
.SYNOPSIS
    Reports SharePoint Online storage consumption per site and flags dormant sites, optionally including OneDrive.
.DESCRIPTION
    Downloads the Microsoft Graph usage report /reports/getSharePointSiteUsageDetail(period='D30') as CSV and
    shapes every site into one row with storage in GB, percentage of the allocated quota, file and page view
    counters, the last activity date and an IsDormant flag (no activity for -DaysInactive days, or never).
    With -IncludeOneDrive the OneDrive report /reports/getOneDriveUsageAccountDetail is appended with the
    Template set to OneDrive. Exports the rows to CSV and prints the total storage, the top 10 sites by
    storage and the number of dormant sites.
.PARAMETER Period
    Usage report period: D7, D30, D90 or D180. Default D30. Activity counters are totals for the period.
.PARAMETER DaysInactive
    Number of days without activity after which a site is flagged IsDormant. Default 90.
.PARAMETER Top
    Keep only the N largest sites by StorageUsedGB after the other filters. Default 0 = keep all.
.PARAMETER OnlyDormant
    Export only sites flagged IsDormant.
.PARAMETER IncludeOneDrive
    Also download the OneDrive usage account detail report and append personal sites (Template = OneDrive).
.PARAMETER IncludeDeleted
    Keep sites the report marks as deleted (they still consume storage until purged from the recycle bin).
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOSiteStorage_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOSiteStorageReport.ps1
    Exports every active SharePoint site with its storage usage and flags sites with no activity for 90 days.
.EXAMPLE
    PS> .\Get-SPOSiteStorageReport.ps1 -Period D90 -IncludeOneDrive -Top 50 -OutputPath C:\Temp\TopStorage.csv -Verbose
    Uses the 90-day report, adds OneDrive accounts and keeps the 50 largest sites and OneDrives.
.EXAMPLE
    PS> .\Get-SPOSiteStorageReport.ps1 -OnlyDormant -DaysInactive 180 -PassThru | Where-Object { $_.StorageUsedGB -gt 10 }
    Lists sites idle for 180 days or more and pipes the ones above 10 GB for review.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Reports.Read.All (delegated). The Reports Reader or Global Reader role is enough to read usage reports.
    Category    : SharePoint & OneDrive (Graph)
    Changes     : No
    Notes       : Usage report data lags about 48 hours behind real time. If "Display concealed user, group, and site names
                  in all reports" is enabled (Microsoft 365 admin center > Settings > Org settings > Reports), Site URL
                  and owner names are hashed; Site Id and all counters stay intact. The tenant-wide storage quota and the
                  real-time per-site usage are visible in the SharePoint admin center (Active sites). Storage Allocated
                  for group-connected and communication sites usually reflects the tenant-level per-site limit, so
                  PercentOfAllocated is small by design. The OneDrive report has no Site Id or page view counters.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getsharepointsiteusagedetail
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getonedriveusageaccountdetail
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period = 'D30',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [ValidateRange(0, 1000000)]
    [int]$Top = 0,

    [Parameter()]
    [switch]$OnlyDormant,

    [Parameter()]
    [switch]$IncludeOneDrive,

    [Parameter()]
    [switch]$IncludeDeleted,

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
    <# Returns a report column value, or $null when the row or column is missing (report schemas change over time) or empty. #>
    param(
        [Parameter()]
        [object]$Row,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if ($null -eq $Row) { return $null }
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) { return $null }
    return $property.Value
}

function ConvertTo-ReportNumber {
    <# Parses a numeric report column culture-independently; returns [double] (or [int64] with -AsInt64) and $null when missing. #>
    param(
        [Parameter()]
        [object]$Row,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter()]
        [switch]$AsInt64
    )
    $value = Get-ReportValue -Row $Row -Name $Name
    if ($null -eq $value) { return $null }
    $number = 0.0
    if (-not [double]::TryParse([string]$value, [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number)) { return $null }
    if ($AsInt64) { return [int64]$number }
    return $number
}

function ConvertTo-ReportDate {
    <# Converts a report date (yyyy-MM-dd) to a UTC [datetime]; $null when empty. #>
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}

function ConvertTo-SiteRecord {
    <# Shapes one SharePoint or OneDrive report row into the common output object. #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Row,

        [Parameter(Mandatory = $true)]
        [int]$DormantAfterDays,

        [Parameter()]
        [string]$TemplateOverride
    )
    $today = [datetime]::UtcNow.Date
    $lastActivity = ConvertTo-ReportDate -Value (Get-ReportValue -Row $Row -Name 'Last Activity Date')
    $daysSinceLastActivity = $null
    if ($null -ne $lastActivity) { $daysSinceLastActivity = [int](($today - $lastActivity.Date).TotalDays) }
    $usedBytes = ConvertTo-ReportNumber -Row $Row -Name 'Storage Used (Byte)'
    $allocatedBytes = ConvertTo-ReportNumber -Row $Row -Name 'Storage Allocated (Byte)'
    $usedGB = $null
    $allocatedGB = $null
    $percentOfAllocated = $null
    if ($null -ne $usedBytes) { $usedGB = [math]::Round($usedBytes / 1GB, 2) }
    if ($null -ne $allocatedBytes) { $allocatedGB = [math]::Round($allocatedBytes / 1GB, 2) }
    if ($null -ne $usedBytes -and $allocatedBytes -gt 0) { $percentOfAllocated = [math]::Round(($usedBytes / $allocatedBytes) * 100, 2) }
    $template = $TemplateOverride
    if ([string]::IsNullOrWhiteSpace($template)) { $template = Get-ReportValue -Row $Row -Name 'Root Web Template' }

    return [PSCustomObject]@{
        SiteUrl               = Get-ReportValue -Row $Row -Name 'Site URL'
        SiteId                = Get-ReportValue -Row $Row -Name 'Site Id'
        OwnerDisplayName      = Get-ReportValue -Row $Row -Name 'Owner Display Name'
        OwnerPrincipalName    = Get-ReportValue -Row $Row -Name 'Owner Principal Name'
        Template              = $template
        IsDeleted             = ((Get-ReportValue -Row $Row -Name 'Is Deleted') -eq 'True')
        LastActivityDate      = $lastActivity
        DaysSinceLastActivity = $daysSinceLastActivity
        FileCount             = ConvertTo-ReportNumber -Row $Row -Name 'File Count' -AsInt64
        ActiveFileCount       = ConvertTo-ReportNumber -Row $Row -Name 'Active File Count' -AsInt64
        PageViewCount         = ConvertTo-ReportNumber -Row $Row -Name 'Page View Count' -AsInt64
        StorageUsedGB         = $usedGB
        StorageAllocatedGB    = $allocatedGB
        PercentOfAllocated    = $percentOfAllocated
        IsDormant             = (($null -eq $daysSinceLastActivity) -or ($daysSinceLastActivity -ge $DormantAfterDays))
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPOSiteStorage_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

Write-Verbose "Downloading the SharePoint site usage report for period $Period."
try {
    $siteRows = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getSharePointSiteUsageDetail(period='$Period')")
}
catch {
    throw "Failed to download the SharePoint site usage report: $($_.Exception.Message)"
}
$refreshDate = Get-ReportValue -Row ($siteRows | Select-Object -First 1) -Name 'Report Refresh Date'
Write-Verbose "SharePoint report contains $($siteRows.Count) rows (refresh date: $refreshDate)."

$oneDriveRows = @()
if ($IncludeOneDrive) {
    Write-Verbose "Downloading the OneDrive usage account report for period $Period."
    try {
        $oneDriveRows = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='$Period')")
    }
    catch {
        throw "Failed to download the OneDrive usage account report: $($_.Exception.Message)"
    }
    Write-Verbose "OneDrive report contains $($oneDriveRows.Count) rows."
}

$records = New-Object -TypeName System.Collections.Generic.List[object]
$totalRows = $siteRows.Count + $oneDriveRows.Count
$counter = 0
foreach ($row in $siteRows) {
    $counter++
    if ($counter % 100 -eq 0) { Write-Progress -Activity 'Shaping site rows' -Status "$counter of $totalRows" -PercentComplete ([int](($counter / $totalRows) * 100)) }
    $records.Add((ConvertTo-SiteRecord -Row $row -DormantAfterDays $DaysInactive))
}
foreach ($row in $oneDriveRows) {
    $counter++
    if ($counter % 100 -eq 0) { Write-Progress -Activity 'Shaping site rows' -Status "$counter of $totalRows" -PercentComplete ([int](($counter / $totalRows) * 100)) }
    $records.Add((ConvertTo-SiteRecord -Row $row -DormantAfterDays $DaysInactive -TemplateOverride 'OneDrive'))
}
Write-Progress -Activity 'Shaping site rows' -Completed

$allSites = @($records)
if (-not $IncludeDeleted) { $allSites = @($allSites | Where-Object { -not $_.IsDeleted }) }
$output = $allSites
if ($OnlyDormant) { $output = @($output | Where-Object { $_.IsDormant }) }
$output = @($output | Sort-Object -Property StorageUsedGB -Descending)
if ($Top -gt 0) { $output = @($output | Select-Object -First $Top) }

if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No sites matched the selected filters; no CSV was written.'
}

$totalGB = ($allSites | Where-Object { $null -ne $_.StorageUsedGB } | Measure-Object -Property StorageUsedGB -Sum).Sum
if ($null -eq $totalGB) { $totalGB = 0 }
$dormantCount = @($allSites | Where-Object { $_.IsDormant }).Count
$topSites = @($allSites | Sort-Object -Property StorageUsedGB -Descending | Select-Object -First 10)
Write-Host ''
Write-Host 'SharePoint storage summary' -ForegroundColor Cyan
Write-Host ('  Report period / refresh date : {0} / {1}' -f $Period, $refreshDate)
Write-Host ('  Sites in report              : {0} (OneDrive included: {1}; deleted included: {2})' -f $allSites.Count, $IncludeOneDrive.IsPresent, $IncludeDeleted.IsPresent)
Write-Host ('  Total storage used           : {0:N2} GB' -f $totalGB)
Write-Host ('  Dormant sites (>= {0} days)   : {1}' -f $DaysInactive, $dormantCount) -ForegroundColor Yellow
if ($topSites.Count -gt 0) {
    Write-Host '  Top 10 sites by storage:'
    foreach ($site in $topSites) {
        Write-Host ('    {0,12:N2} GB  {1}' -f $site.StorageUsedGB, $site.SiteUrl)
    }
}
Write-Host ('  Rows exported                : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
