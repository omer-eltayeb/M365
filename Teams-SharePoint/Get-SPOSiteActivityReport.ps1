<#
.SYNOPSIS
    Reports SharePoint activity per user (files viewed, synced, shared internally and externally, pages visited) and flags inactive users and heavy external sharers.
.DESCRIPTION
    Downloads the Microsoft Graph usage report /reports/getSharePointActivityUserDetail(period='D30') as CSV and shapes every
    user into one row with PascalCase counters, LastActivityDate, DaysSinceLastActivity, IsInactive (no activity for
    -DaysInactive days or never), IsHeavyExternalSharer (more than -ExternalShareThreshold files shared externally) and
    IsLicensed. -IncludeTotals adds the tenant-wide totals from getSharePointActivityFileCounts and getSharePointActivityPages.
    Exports the rows to CSV and prints the active share, the inactive licensed users and the top external sharers.
.PARAMETER Period
    Usage report period: D7, D30, D90 or D180. Default D30. Counters are totals for the period.
.PARAMETER DaysInactive
    Users without SharePoint activity for this many days (or ever) are flagged IsInactive. Default 30.
.PARAMETER ExternalShareThreshold
    Users who shared more than this many files externally in the period are flagged IsHeavyExternalSharer. Default 10.
.PARAMETER OnlyInactive
    Export only users flagged IsInactive.
.PARAMETER IncludeDeleted
    Keep users the report marks as deleted. They are excluded by default.
.PARAMETER IncludeTotals
    Also download the tenant-wide file activity and page visit reports and print their period totals.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOUserActivity_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOSiteActivityReport.ps1
    Exports the 30-day SharePoint activity of every user and flags the ones idle for 30 days.
.EXAMPLE
    PS> .\Get-SPOSiteActivityReport.ps1 -Period D90 -DaysInactive 60 -ExternalShareThreshold 25 -IncludeTotals -OutputPath C:\Temp\SPOActivity.csv
    Uses the 90-day report, flags users idle for 60+ days and users who shared more than 25 files externally, and prints tenant totals.
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
                  reports" is enabled (Microsoft 365 admin center > Settings > Org settings > Reports), user principal names are
                  hashed; counters stay intact. "Shared externally" counts files shared with people outside the organization.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getsharepointactivityuserdetail
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getsharepointactivityfilecounts
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()] [ValidateSet('D7', 'D30', 'D90', 'D180')] [string]$Period = 'D30',
    [Parameter()] [ValidateRange(1, 3650)] [int]$DaysInactive = 30,
    [Parameter()] [ValidateRange(0, 1000000)] [int]$ExternalShareThreshold = 10,
    [Parameter()] [switch]$OnlyInactive,
    [Parameter()] [switch]$IncludeDeleted,
    [Parameter()] [switch]$IncludeTotals,
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
    $OutputPath = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath ('SPOUserActivity_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
try { Connect-GraphIfNeeded -Scopes @('Reports.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

Write-Verbose "Downloading the SharePoint activity user detail report for period $Period."
try { $rows = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getSharePointActivityUserDetail(period='$Period')") }
catch { throw "Failed to download the SharePoint activity report: $($_.Exception.Message)" }
$refreshDate = $null
if ($rows.Count -gt 0) { $refreshDate = Get-ReportValue -Row $rows[0] -Name 'Report Refresh Date' }
Write-Verbose "Report contains $($rows.Count) rows (refresh date: $refreshDate)."

$today = [datetime]::UtcNow.Date
$records = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($row in $rows) {
    $counter++
    if ($counter % 200 -eq 0) { Write-Progress -Activity 'Shaping user rows' -Status "$counter of $($rows.Count)" -PercentComplete ([int](($counter / $rows.Count) * 100)) }
    $lastActivity = Get-ReportValue -Row $row -Name 'Last Activity Date' -AsDate
    $daysSince = $null
    if ($null -ne $lastActivity) { $daysSince = [int](($today - $lastActivity.Date).TotalDays) }
    $sharedExternally = Get-ReportValue -Row $row -Name 'Shared Externally File Count' -AsNumber
    $assignedProducts = Get-ReportValue -Row $row -Name 'Assigned Products'
    $records.Add([PSCustomObject]@{
            UserPrincipalName         = Get-ReportValue -Row $row -Name 'User Principal Name'
            IsDeleted                 = ((Get-ReportValue -Row $row -Name 'Is Deleted') -eq 'True')
            DeletedDate               = Get-ReportValue -Row $row -Name 'Deleted Date' -AsDate
            LastActivityDate          = $lastActivity
            DaysSinceLastActivity     = $daysSince
            IsInactive                = (($null -eq $daysSince) -or ($daysSince -ge $DaysInactive))
            ViewedOrEditedFileCount   = Get-ReportValue -Row $row -Name 'Viewed Or Edited File Count' -AsNumber
            SyncedFileCount           = Get-ReportValue -Row $row -Name 'Synced File Count' -AsNumber
            SharedInternallyFileCount = Get-ReportValue -Row $row -Name 'Shared Internally File Count' -AsNumber
            SharedExternallyFileCount = $sharedExternally
            IsHeavyExternalSharer     = ($null -ne $sharedExternally -and $sharedExternally -gt $ExternalShareThreshold)
            VisitedPageCount          = Get-ReportValue -Row $row -Name 'Visited Page Count' -AsNumber
            IsLicensed                = (-not [string]::IsNullOrWhiteSpace($assignedProducts))
            AssignedProducts          = $assignedProducts
            ReportPeriod              = Get-ReportValue -Row $row -Name 'Report Period'
        })
}
Write-Progress -Activity 'Shaping user rows' -Completed

$allUsers = @($records)
if (-not $IncludeDeleted) { $allUsers = @($allUsers | Where-Object { -not $_.IsDeleted }) }
$output = $allUsers
if ($OnlyInactive) { $output = @($output | Where-Object { $_.IsInactive }) }
$output = @($output | Sort-Object -Property SharedExternallyFileCount, ViewedOrEditedFileCount -Descending)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No users matched the selected filters; no CSV was written.' }

$activeCount = @($allUsers | Where-Object { -not $_.IsInactive }).Count
$activePercent = 0
if ($allUsers.Count -gt 0) { $activePercent = [math]::Round(($activeCount / $allUsers.Count) * 100, 1) }
$inactiveLicensed = @($allUsers | Where-Object { $_.IsInactive -and $_.IsLicensed }).Count
$heavySharers = @($allUsers | Where-Object { $_.IsHeavyExternalSharer } | Sort-Object -Property SharedExternallyFileCount -Descending)
Write-Host 'SharePoint user activity summary' -ForegroundColor Cyan
Write-Host ('  Report period / refresh date   : {0} / {1}' -f $Period, $refreshDate)
Write-Host ('  Users in report                : {0} (deleted included: {1})' -f $allUsers.Count, $IncludeDeleted.IsPresent)
Write-Host ('  Active within {0,3} days         : {1} ({2}%)' -f $DaysInactive, $activeCount, $activePercent)
Write-Host ('  Inactive licensed users        : {0}' -f $inactiveLicensed) -ForegroundColor Yellow
Write-Host ('  Users sharing > {0} files externally : {1}' -f $ExternalShareThreshold, $heavySharers.Count) -ForegroundColor Yellow
foreach ($user in ($heavySharers | Select-Object -First 10)) { Write-Host ('    {0,6} files  {1}' -f $user.SharedExternallyFileCount, $user.UserPrincipalName) }
if ($IncludeTotals) {
    try {
        $fileRows = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getSharePointActivityFileCounts(period='$Period')")
        $pageRows = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getSharePointActivityPages(period='$Period')")
        $totals = foreach ($column in 'Viewed Or Edited', 'Synced', 'Shared Internally', 'Shared Externally') {
            '{0}: {1:N0}' -f $column, ($fileRows | ForEach-Object { Get-ReportValue -Row $_ -Name $column -AsNumber } | Where-Object { $null -ne $_ } | Measure-Object -Sum).Sum
        }
        $pageVisits = ($pageRows | ForEach-Object { Get-ReportValue -Row $_ -Name 'Visited Page Count' -AsNumber } | Where-Object { $null -ne $_ } | Measure-Object -Sum).Sum
        Write-Host ('  Tenant file activity ({0})    : {1}' -f $Period, ($totals -join ', '))
        Write-Host ('  Tenant page visits ({0})      : {1:N0}' -f $Period, $pageVisits)
    }
    catch { Write-Warning "Could not download the tenant-wide activity totals: $($_.Exception.Message)" }
}
Write-Host ('  Rows exported                  : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
