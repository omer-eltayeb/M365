<#
.SYNOPSIS
    Reports Microsoft 365 user activity per workload from the Graph usage reports and flags inactive licensed users.
.DESCRIPTION
    Downloads the active user detail usage report (/reports/getOffice365ActiveUserDetail) for the selected period
    and outputs one row per user with the license flag and last activity date for Exchange, OneDrive, SharePoint,
    Skype for Business, Yammer (Viva Engage) and Teams, the most recent activity across all workloads, the licensed
    workloads without recent activity and an IsInactive flag. Prints adoption per workload and reclaim candidates.
.PARAMETER Period
    Report period: D7, D30, D90 or D180 (days). Default D30.
.PARAMETER DaysInactive
    Days without activity in any workload after which a user is flagged IsInactive. Default 30.
.PARAMETER OnlyInactive
    Export only users flagged IsInactive (the console summary still covers every user in the report).
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365ActiveUsers_<Period>_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the user objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365ActiveUsersReport.ps1
    Exports the last 30 days of activity for every user and prints adoption per workload.
.EXAMPLE
    PS> .\Get-M365ActiveUsersReport.ps1 -Period D90 -DaysInactive 60 -OnlyInactive -OutputPath C:\Temp\Inactive.csv -Verbose
    Exports only users without any activity for 60 days, based on the 90-day report.
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
    Notes       : Report data lags about 48 hours; dates are UTC days. An empty activity date means no activity in the
                  selected period, so pick a -Period of at least -DaysInactive days. Names and UPNs appear as hashes when
                  "Display concealed user, group, and site names in all reports" is on (admin center > Org settings > Reports).
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getoffice365activeuserdetail
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
    [int]$DaysInactive = 30,

    [Parameter()]
    [switch]$OnlyInactive,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365ActiveUsers_{0}_{1}.csv' -f $Period, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All')
    Write-Verbose "Downloading getOffice365ActiveUserDetail for period $Period."
    $report = @(Get-UsageReportCsv -ReportFunction 'getOffice365ActiveUserDetail' -Period $Period)
}
catch {
    throw "Failed to retrieve the active user detail report from Microsoft Graph: $($_.Exception.Message)"
}

# Workload names as spelled in the report columns; output property names drop the spaces (SkypeForBusinessLicensed, ...).
$workloads = @('Exchange', 'OneDrive', 'SharePoint', 'Skype For Business', 'Yammer', 'Teams')
$today = [datetime]::UtcNow.Date
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($row in $report) {
    $counter++
    if ($counter % 250 -eq 0) { Write-Progress -Activity 'Shaping users' -Status "$counter of $($report.Count)" -PercentComplete ([int](($counter / $report.Count) * 100)) }
    $r = ConvertTo-ReportObject -Row $row
    $props = [ordered]@{
        UserPrincipalName = $r.UserPrincipalName
        DisplayName       = $r.DisplayName
        IsDeleted         = [bool]$r.IsDeleted
        DeletedDate       = $r.DeletedDate
        AssignedProducts  = $r.AssignedProducts
    }
    $licensed = New-Object -TypeName System.Collections.Generic.List[string]
    $inactive = New-Object -TypeName System.Collections.Generic.List[string]
    $lastAny = $null
    foreach ($workload in $workloads) {
        $key = $workload.Replace(' ', '')
        $hasLicense = [bool]$r.('Has' + $key + 'License')
        $lastActivity = $r.($key + 'LastActivityDate')
        $props[$key + 'Licensed'] = $hasLicense
        $props[$key + 'LastActivityDate'] = $lastActivity
        if ($hasLicense) { $licensed.Add($key) }
        if ($null -ne $lastActivity -and ($null -eq $lastAny -or $lastActivity -gt $lastAny)) { $lastAny = $lastActivity }
        if ($hasLicense -and ($null -eq $lastActivity -or ($today - $lastActivity).TotalDays -ge $DaysInactive)) { $inactive.Add($key) }
    }
    $daysSince = $null; if ($null -ne $lastAny) { $daysSince = [int](($today - $lastAny).TotalDays) }
    $props['LicensedWorkloads'] = ($licensed -join ';')
    $props['LastActivityAnyWorkload'] = $lastAny
    $props['DaysSinceLastActivity'] = $daysSince
    $props['InactiveWorkloads'] = ($inactive -join ';')
    $props['IsInactive'] = ($null -eq $lastAny -or $daysSince -ge $DaysInactive)
    $props['LicensedButNeverActive'] = ($licensed.Count -gt 0 -and $null -eq $lastAny)
    $props['ReportRefreshDate'] = $r.ReportRefreshDate
    $rows.Add([PSCustomObject]$props)
}
Write-Progress -Activity 'Shaping users' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'IsInactive'; Descending = $true }, UserPrincipalName)
if ($OnlyInactive) { $output = @($output | Where-Object { $_.IsInactive }) }
if ($output.Count -eq 0) { Write-Warning 'No rows matched the selected filters; the CSV will be empty.' }
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Deleted users stay in the CSV but are excluded from the percentages.
$current = @($rows | Where-Object { -not $_.IsDeleted })
$activeUsers = @($current | Where-Object { $null -ne $_.LastActivityAnyWorkload })
$inactiveUsers = @($current | Where-Object { $_.IsInactive })
$reclaim = @($inactiveUsers | Where-Object { -not [string]::IsNullOrEmpty($_.LicensedWorkloads) })
$neverActive = @($current | Where-Object { $_.LicensedButNeverActive })
$activePercent = 0; if ($current.Count -gt 0) { $activePercent = [math]::Round(($activeUsers.Count / $current.Count) * 100, 1) }
Write-Host ('Microsoft 365 active users ({0})' -f $Period) -ForegroundColor Cyan
Write-Host ('  Users in report (current / deleted) : {0} / {1}' -f $current.Count, ($rows.Count - $current.Count))
Write-Host ('  Active in period                    : {0} ({1} %)' -f $activeUsers.Count, $activePercent)
Write-Host ('  {0,-36}: {1}' -f ('Inactive for {0}+ days' -f $DaysInactive), $inactiveUsers.Count) -ForegroundColor Yellow
Write-Host ('  Licensed and inactive (reclaim)     : {0} (never active: {1})' -f $reclaim.Count, $neverActive.Count) -ForegroundColor Yellow
Write-Host ('  {0,-20} {1,9} {2,8} {3,9}' -f 'Workload', 'Licensed', 'Active', 'Percent')
foreach ($workload in $workloads) {
    $key = $workload.Replace(' ', '')
    $licensedCount = @($current | Where-Object { $_.($key + 'Licensed') }).Count
    $activeCount = @($current | Where-Object { $null -ne $_.($key + 'LastActivityDate') }).Count
    $percent = 0; if ($licensedCount -gt 0) { $percent = [math]::Round(($activeCount / $licensedCount) * 100, 1) }
    Write-Host ('  {0,-20} {1,9} {2,8} {3,7} %' -f $workload, $licensedCount, $activeCount, $percent)
}
Write-Host ('  CSV : {0}' -f $OutputPath)

if ($PassThru) { $output }
#endregion Main
