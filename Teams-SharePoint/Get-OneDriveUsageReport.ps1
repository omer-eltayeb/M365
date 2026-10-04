<#
.SYNOPSIS
    Reports OneDrive storage and activity per account and flags dormant OneDrives and OneDrives of deleted users.
.DESCRIPTION
    Downloads the Microsoft Graph usage report /reports/getOneDriveUsageAccountDetail(period='D30') as CSV and shapes every
    OneDrive into one row with owner, site URL, file counts, storage used and allocated in GB, percentage used,
    LastActivityDate, DaysSinceLastActivity, IsDormant (no activity for -DaysInactive days or never) and IsOrphaned (the
    owner account is deleted; the OneDrive is kept for the retention period and then purged). -IncludeTrend adds the
    tenant-wide storage trend from getOneDriveUsageStorage. Exports to CSV and prints the total storage, the top 10 OneDrives
    and the dormant / orphaned counts.
.PARAMETER Period
    Usage report period: D7, D30, D90 or D180. Default D30. File counts are totals for the period.
.PARAMETER DaysInactive
    OneDrives without activity for this many days (or ever) are flagged IsDormant. Default 180.
.PARAMETER Top
    Keep only the N largest OneDrives by StorageUsedGB after the other filters. Default 0 = keep all.
.PARAMETER OnlyDormant
    Export only OneDrives flagged IsDormant.
.PARAMETER OnlyOrphaned
    Export only OneDrives flagged IsOrphaned (owner deleted).
.PARAMETER IncludeTrend
    Also download the tenant-wide OneDrive storage report and print the first / last value of the period.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\OneDriveUsage_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-OneDriveUsageReport.ps1
    Exports every OneDrive with storage and activity figures and flags the ones idle for 180 days.
.EXAMPLE
    PS> .\Get-OneDriveUsageReport.ps1 -Period D180 -OnlyOrphaned -IncludeTrend -OutputPath C:\Temp\OrphanedOneDrives.csv -Verbose
    Lists the OneDrives whose owner has been deleted (storage that is about to be purged or should be reassigned) and prints the storage trend.
.EXAMPLE
    PS> .\Get-OneDriveUsageReport.ps1 -OnlyDormant -DaysInactive 365 -Top 50 -PassThru | Where-Object { $_.StorageUsedGB -gt 5 }
    The 50 largest OneDrives untouched for a year, filtered to the ones above 5 GB.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Reports.Read.All (delegated). The Reports Reader or Global Reader role is enough to read usage reports.
    Category    : SharePoint & OneDrive (Graph)
    Changes     : No
    Notes       : Usage report data lags about 48 hours behind real time. If "Display concealed user, group, and site names in all
                  reports" is enabled (Microsoft 365 admin center > Settings > Org settings > Reports), owner names and site URLs
                  are hashed. Deleted users' OneDrives are retained for the period set in the SharePoint admin center
                  (Settings > OneDrive > Retention, default 30 days) before they are purged.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getonedriveusageaccountdetail
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getonedriveusagestorage
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()] [ValidateSet('D7', 'D30', 'D90', 'D180')] [string]$Period = 'D30',
    [Parameter()] [ValidateRange(1, 3650)] [int]$DaysInactive = 180,
    [Parameter()] [ValidateRange(0, 1000000)] [int]$Top = 0,
    [Parameter()] [switch]$OnlyDormant,
    [Parameter()] [switch]$OnlyOrphaned,
    [Parameter()] [switch]$IncludeTrend,
    [Parameter()] [string]$OutputPath,
    [Parameter()] [switch]$PassThru
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
    param([Parameter(Mandatory = $true)] [string]$Uri)
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
    <# Returns a report column as text, [int64] (-AsNumber) or UTC [datetime] (-AsDate); $null when the column is missing, empty or unparsable (report schemas change over time). #>
    param([Parameter(Mandatory = $true)] [object]$Row, [Parameter(Mandatory = $true)] [string]$Name, [Parameter()] [switch]$AsNumber, [Parameter()] [switch]$AsDate)
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) { return $null }
    $text = ([string]$property.Value).Trim()
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    if ($AsNumber) {
        $number = 0.0
        if ([double]::TryParse($text, [System.Globalization.NumberStyles]::Any, $culture, [ref]$number)) { return [int64]$number }
        return $null
    }
    if ($AsDate) {
        $date = [datetime]::MinValue
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        if ([datetime]::TryParse($text, $culture, $styles, [ref]$date)) { return $date }
        return $null
    }
    return $text
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath ('OneDriveUsage_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
try { Connect-GraphIfNeeded -Scopes @('Reports.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

Write-Verbose "Downloading the OneDrive usage account detail report for period $Period."
try { $rows = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageAccountDetail(period='$Period')") }
catch { throw "Failed to download the OneDrive usage report: $($_.Exception.Message)" }
$refreshDate = $null
if ($rows.Count -gt 0) { $refreshDate = Get-ReportValue -Row $rows[0] -Name 'Report Refresh Date' }
Write-Verbose "Report contains $($rows.Count) rows (refresh date: $refreshDate)."

$today = [datetime]::UtcNow.Date
$records = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($row in $rows) {
    $counter++
    if ($counter % 200 -eq 0) { Write-Progress -Activity 'Shaping OneDrive rows' -Status "$counter of $($rows.Count)" -PercentComplete ([int](($counter / $rows.Count) * 100)) }
    $lastActivity = Get-ReportValue -Row $row -Name 'Last Activity Date' -AsDate
    $daysSince = $null
    if ($null -ne $lastActivity) { $daysSince = [int](($today - $lastActivity.Date).TotalDays) }
    $usedBytes = Get-ReportValue -Row $row -Name 'Storage Used (Byte)' -AsNumber
    $allocatedBytes = Get-ReportValue -Row $row -Name 'Storage Allocated (Byte)' -AsNumber
    $percentUsed = $null
    if ($null -ne $usedBytes -and $allocatedBytes -gt 0) { $percentUsed = [math]::Round(($usedBytes / $allocatedBytes) * 100, 2) }
    $isDeleted = ((Get-ReportValue -Row $row -Name 'Is Deleted') -eq 'True')
    $records.Add([PSCustomObject]@{
            Owner                 = Get-ReportValue -Row $row -Name 'Owner Display Name'
            OwnerUpn              = Get-ReportValue -Row $row -Name 'Owner Principal Name'
            SiteUrl               = Get-ReportValue -Row $row -Name 'Site URL'
            IsDeleted             = $isDeleted
            LastActivityDate      = $lastActivity
            DaysSinceLastActivity = $daysSince
            FileCount             = Get-ReportValue -Row $row -Name 'File Count' -AsNumber
            ActiveFileCount       = Get-ReportValue -Row $row -Name 'Active File Count' -AsNumber
            StorageUsedGB         = $(if ($null -ne $usedBytes) { [math]::Round($usedBytes / 1GB, 2) })
            StorageAllocatedGB    = $(if ($null -ne $allocatedBytes) { [math]::Round($allocatedBytes / 1GB, 2) })
            PercentUsed           = $percentUsed
            IsDormant             = (($null -eq $daysSince) -or ($daysSince -ge $DaysInactive))
            IsOrphaned            = $isDeleted
            ReportPeriod          = Get-ReportValue -Row $row -Name 'Report Period'
        })
}
Write-Progress -Activity 'Shaping OneDrive rows' -Completed

$allAccounts = @($records)
$output = $allAccounts
if ($OnlyDormant) { $output = @($output | Where-Object { $_.IsDormant }) }
if ($OnlyOrphaned) { $output = @($output | Where-Object { $_.IsOrphaned }) }
$output = @($output | Sort-Object -Property StorageUsedGB -Descending)
if ($Top -gt 0) { $output = @($output | Select-Object -First $Top) }
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No OneDrives matched the selected filters; no CSV was written.' }

$sized = @($allAccounts | Where-Object { $null -ne $_.StorageUsedGB })
$totalGB = [double]($sized | Measure-Object -Property StorageUsedGB -Sum).Sum
$dormant = @($sized | Where-Object { $_.IsDormant })
$orphaned = @($sized | Where-Object { $_.IsOrphaned })
Write-Host 'OneDrive usage summary' -ForegroundColor Cyan
Write-Host ('  Report period / refresh date : {0} / {1}' -f $Period, $refreshDate)
Write-Host ('  OneDrives in report          : {0}; total storage used: {1:N2} GB' -f $allAccounts.Count, $totalGB)
Write-Host ('  Dormant (>= {0} days)        : {1} ({2:N2} GB)' -f $DaysInactive, $dormant.Count, [double]($dormant | Measure-Object -Property StorageUsedGB -Sum).Sum) -ForegroundColor Yellow
Write-Host ('  Orphaned (owner deleted)     : {0} ({1:N2} GB)' -f $orphaned.Count, [double]($orphaned | Measure-Object -Property StorageUsedGB -Sum).Sum) -ForegroundColor Yellow
Write-Host '  Top 10 OneDrives by storage:'
foreach ($account in ($allAccounts | Sort-Object -Property StorageUsedGB -Descending | Select-Object -First 10)) { Write-Host ('    {0,10:N2} GB  {1}' -f $account.StorageUsedGB, $account.OwnerUpn) }
if ($IncludeTrend) {
    try {
        $trend = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getOneDriveUsageStorage(period='$Period')" | Sort-Object -Property 'Report Date')
        $firstDay = $trend | Select-Object -First 1
        $lastDay = $trend | Select-Object -Last 1
        $firstGB = [double](Get-ReportValue -Row $firstDay -Name 'Storage Used (Byte)' -AsNumber) / 1GB
        $lastGB = [double](Get-ReportValue -Row $lastDay -Name 'Storage Used (Byte)' -AsNumber) / 1GB
        $firstDate = Get-ReportValue -Row $firstDay -Name 'Report Date'
        $lastDate = Get-ReportValue -Row $lastDay -Name 'Report Date'
        Write-Host ('  Tenant OneDrive storage trend: {0:N2} GB on {1} -> {2:N2} GB on {3} (change {4:N2} GB)' -f $firstGB, $firstDate, $lastGB, $lastDate, ($lastGB - $firstGB))
    }
    catch { Write-Warning "Could not download the OneDrive storage trend: $($_.Exception.Message)" }
}
Write-Host ('  Rows exported                : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
