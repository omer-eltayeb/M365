<#
.SYNOPSIS
    Reports Microsoft 365 Apps, Project and Visio activations per user and device platform from the Graph usage reports.
.DESCRIPTION
    Downloads the Microsoft 365 activations user detail report (/reports/getOffice365ActivationsUserDetail) and outputs one
    row per user and product with the activations on Windows, Mac, iOS and Android, desktop, mobile and total counts, the
    shared computer activation flag and a NearLimit flag for users who used up the device allowance. -IncludeCounts merges
    /reports/getOffice365ActivationsUserCounts and getOffice365ActivationCounts into <OutputPath base>_Counts.csv.
.PARAMETER ProductType
    Export only rows for this product type, for example "Microsoft 365 Apps for enterprise", Project or Visio (wildcards allowed).
.PARAMETER IncludeCounts
    Also export the per-product totals: assigned and activated users, shared computer activations and activations per platform.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365Activations_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the activation objects (and, with -IncludeCounts, the per-product objects) to the pipeline.
.EXAMPLE
    PS> .\Get-M365ActivationsReport.ps1
    Exports every user activation and prints users, activations and near-limit users per product.
.EXAMPLE
    PS> .\Get-M365ActivationsReport.ps1 -ProductType 'Microsoft 365 Apps*' -IncludeCounts -OutputPath C:\Temp\Activations.csv
    Exports only Microsoft 365 Apps activations and writes C:\Temp\Activations_Counts.csv with assigned vs activated users.
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
    Notes       : The activation reports are snapshots without a period parameter; data lags about 48 hours. A license allows
                  5 PCs or Macs, 5 tablets and 5 phones; the report pools tablets and phones, so the mobile part of NearLimit is
                  indicative. Only users with at least one activation are listed; licensed users who never activated appear only
                  as AssignedUsers minus ActivatedUsers in the -IncludeCounts file. Names are hashed when concealed names are on.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getoffice365activationsuserdetail
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ProductType,

    [Parameter()]
    [switch]$IncludeCounts,

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
    <# Downloads a Microsoft Graph usage report (CSV) and imports it; the activation reports take no period parameter. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportFunction,

        [Parameter()]
        [string]$Period
    )
    $uri = 'https://graph.microsoft.com/v1.0/reports/{0}' -f $ReportFunction
    if (-not [string]::IsNullOrEmpty($Period)) { $uri = '{0}(period=''{1}'')' -f $uri, $Period }
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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365Activations_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$countsOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_Counts.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

$userCountsReport = @(); $deviceCountsReport = @()
try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All')
    Write-Verbose 'Downloading getOffice365ActivationsUserDetail.'
    $report = @(Get-UsageReportCsv -ReportFunction 'getOffice365ActivationsUserDetail')
    if ($IncludeCounts) { $userCountsReport = @(Get-UsageReportCsv -ReportFunction 'getOffice365ActivationsUserCounts') }
    if ($IncludeCounts) { $deviceCountsReport = @(Get-UsageReportCsv -ReportFunction 'getOffice365ActivationCounts') }
}
catch {
    throw "Failed to retrieve the activation reports from Microsoft Graph: $($_.Exception.Message)"
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($row in $report) {
    $counter++
    if ($counter % 250 -eq 0) { Write-Progress -Activity 'Shaping activations' -Status "$counter of $($report.Count)" -PercentComplete ([int](($counter / $report.Count) * 100)) }
    $r = ConvertTo-ReportObject -Row $row
    $desktop = [int64]$r.Windows + [int64]$r.Mac
    $mobile = [int64]$r.iOS + [int64]$r.Android + [int64]$r.Windows10Mobile
    $rows.Add([PSCustomObject]@{
            UserPrincipalName  = $r.UserPrincipalName
            DisplayName        = $r.DisplayName
            ProductType        = $r.ProductType
            LastActivatedDate  = $r.LastActivatedDate
            WindowsActivations = [int64]$r.Windows
            MacActivations     = [int64]$r.Mac
            IosActivations     = [int64]$r.iOS
            AndroidActivations = [int64]$r.Android
            SharedComputer     = [bool]$r.ActivatedOnSharedComputer
            DesktopActivations = $desktop
            MobileActivations  = $mobile
            TotalActivations   = $desktop + $mobile
            NearLimit          = ($desktop -ge 5 -or $mobile -ge 5) # a license covers 5 PCs/Macs, 5 tablets and 5 phones
            ReportRefreshDate  = $r.ReportRefreshDate
        })
}
Write-Progress -Activity 'Shaping activations' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'TotalActivations'; Descending = $true }, UserPrincipalName)
if (-not [string]::IsNullOrWhiteSpace($ProductType)) { $output = @($output | Where-Object { $_.ProductType -like $ProductType }) }
if ($output.Count -eq 0) { Write-Warning 'No rows matched the selected filter; the CSV will be empty.' }
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Per-product totals: assigned vs activated users come from one report, activations per platform from the other.
$counts = New-Object -TypeName System.Collections.Generic.List[object]
$deviceCounts = @($deviceCountsReport | ForEach-Object { ConvertTo-ReportObject -Row $_ })
foreach ($userCount in ($userCountsReport | ForEach-Object { ConvertTo-ReportObject -Row $_ })) {
    $devices = $deviceCounts | Where-Object { $_.ProductType -eq $userCount.ProductType } | Select-Object -First 1
    $assigned = [int64]$userCount.Assigned; $activated = [int64]$userCount.Activated
    $activatedPercent = 0; if ($assigned -gt 0) { $activatedPercent = [math]::Round(($activated / $assigned) * 100, 1) }
    $counts.Add([PSCustomObject]@{
            ProductType              = $userCount.ProductType
            AssignedUsers            = $assigned
            ActivatedUsers           = $activated
            NotActivatedUsers        = [math]::Max(0, $assigned - $activated)
            ActivatedPercent         = $activatedPercent
            SharedComputerActivation = [int64]$userCount.SharedComputerActivation
            WindowsActivations       = [int64]$devices.Windows
            MacActivations           = [int64]$devices.Mac
            IosActivations           = [int64]$devices.iOS
            AndroidActivations       = [int64]$devices.Android
            ReportRefreshDate        = $userCount.ReportRefreshDate
        })
}
if ($counts.Count -gt 0) { $counts | Export-Csv -Path $countsOutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host 'Microsoft 365 activations (snapshot)' -ForegroundColor Cyan
Write-Host ('  Activation rows (user x product)    : {0}' -f $rows.Count)
Write-Host ('  Users with at least one activation  : {0}' -f @($rows | Select-Object -Property UserPrincipalName -Unique).Count)
foreach ($group in ($rows | Group-Object -Property ProductType | Sort-Object -Property Count -Descending)) {
    $activations = [int64]($group.Group | Measure-Object -Property TotalActivations -Sum).Sum
    Write-Host ('    {0,-34}: {1} users, {2} activations, {3} near limit' -f $group.Name, $group.Count, $activations, @($group.Group | Where-Object { $_.NearLimit }).Count) -ForegroundColor Yellow
}
foreach ($c in $counts) {
    Write-Host ('    {0,-34}: {1} assigned, {2} activated ({3} %), {4} never activated' -f
        $c.ProductType, $c.AssignedUsers, $c.ActivatedUsers, $c.ActivatedPercent, $c.NotActivatedUsers) -ForegroundColor Yellow
}
Write-Host ('  CSV : {0}' -f $OutputPath)
if ($counts.Count -gt 0) { Write-Host ('  Counts CSV : {0}' -f $countsOutputPath) }

if ($PassThru) { $output }
if ($PassThru -and $counts.Count -gt 0) { $counts }
#endregion Main
