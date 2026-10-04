<#
.SYNOPSIS
    Reports Purview content searches with status, item counts and size, optionally with per-location statistics and a result preview.
.DESCRIPTION
    Lists compliance searches (all, by -Name wildcard, or for one eDiscovery (Standard) case with -Case) and re-reads each one
    with Get-ComplianceSearch -Identity to get the statistics. -IncludeLocationStatistics parses SuccessResults into
    <base>_Locations.csv (one row per mailbox or site). -Preview creates a preview action (New-ComplianceSearchAction -Preview)
    for each completed search, waits for it, and parses the sample items into <base>_Preview.csv. Only -Preview changes
    anything (a preview action is added to the search); it is wrapped in ShouldProcess.
.PARAMETER Name
    Search name or wildcard pattern, for example 'HR-*'. Default: every search you can see.
.PARAMETER Case
    Name of an eDiscovery (Standard) case; only its searches are reported.
.PARAMETER IncludeLocationStatistics
    Also write per-location item counts and sizes to <base>_Locations.csv.
.PARAMETER Preview
    Create (or reuse) a preview action per completed search and write the sample items to <base>_Preview.csv.
.PARAMETER TimeoutMinutes
    Maximum time to wait for each preview action to complete (default 15).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewContentSearchResults_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the search objects to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewContentSearchResults.ps1 -Case 'Legal 7' -IncludeLocationStatistics -Verbose
    Exports the searches of one case plus a per-mailbox / per-site breakdown of the hits.
.EXAMPLE
    PS> .\Get-PurviewContentSearchResults.ps1 -Name 'HR-Case-42' -Preview -Confirm:$false
    Creates a preview action for the search and saves the sampled items (sender, subject, size, received time) to CSV.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : eDiscovery Manager role group (Compliance Search role; the Preview role for -Preview) in Security & Compliance PowerShell
    Category    : eDiscovery & content search
    Changes     : Optional (-Preview)
    Notes       : Search statistics are estimates until an export runs. A preview is a sample of up to 1,000 items (at most 100 per
                  location); an existing <name>_Preview action is reused and may be older than the latest search run.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-compliancesearch
.LINK
    https://learn.microsoft.com/powershell/module/exchange/new-compliancesearchaction
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string]$Name,

    [Parameter()]
    [string]$Case,

    [Parameter()]
    [switch]$IncludeLocationStatistics,

    [Parameter()]
    [switch]$Preview,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$TimeoutMinutes = 15,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-ExchangeIfNeeded {
    <# Connects to Exchange Online (or Security & Compliance PowerShell) only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Compliance
    )
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($Compliance) {
        $active = @($connections | Where-Object { $_.ConnectionUri -like '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Security & Compliance PowerShell.'
            Connect-IPPSSession -ErrorAction Stop
        }
    }
    else {
        $active = @($connections | Where-Object { $_.ConnectionUri -notlike '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewContentSearchResults_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$basePath = $OutputPath -replace '\.[^.\\/]+$', ''

try { Connect-ExchangeIfNeeded -Compliance } catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

$listParams = @{ ResultSize = 'Unlimited'; ErrorAction = 'Stop' }
if ($Case) { $listParams['Case'] = $Case }
try { $searches = @(Get-ComplianceSearch @listParams) } catch { throw "Failed to list compliance searches: $($_.Exception.Message)" }
if ($Name) { $searches = @($searches | Where-Object { $_.Name -like $Name }) }
if ($searches.Count -eq 0) { Write-Warning 'No compliance searches matched the given filters.' }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$locationRows = New-Object -TypeName System.Collections.Generic.List[object]
$previewRows = New-Object -TypeName System.Collections.Generic.List[object]
$previewPattern = 'Location: (?<Location>[^;]*); Sender: (?<Sender>.*?); Subject: (?<Subject>.*?); Type: (?<Type>[^;]*); Size: (?<Size>\d+); Received Time: (?<Received>[^;}]*)'
$index = 0
foreach ($summary in $searches) {
    $index++
    Write-Progress -Activity 'Reading content searches' -Status ('{0} of {1}: {2}' -f $index, $searches.Count, $summary.Name) -PercentComplete ([int](($index / $searches.Count) * 100))
    # The list view omits statistics such as Items, Size and SuccessResults; reading by identity returns the full object.
    try { $search = Get-ComplianceSearch -Identity $summary.Identity -ErrorAction Stop }
    catch { Write-Warning ("Could not read the search '{0}': {1}" -f $summary.Name, $_.Exception.Message); continue }

    $query = [string]$search.ContentMatchQuery
    if ($query.Length -gt 300) { $query = $query.Substring(0, 300) + '...' }
    $errors = [string]$search.Errors
    if ($errors.Length -gt 300) { $errors = $errors.Substring(0, 300) + '...' }
    $results.Add([PSCustomObject]@{
            Name                 = [string]$search.Name
            Case                 = [string]$search.CaseName
            Status               = [string]$search.Status
            Items                = [long]$search.Items
            SizeGB               = [math]::Round([double]$search.Size / 1GB, 2)
            CreatedBy            = [string]$search.CreatedBy
            JobStartTime         = $search.JobStartTime
            JobEndTime           = $search.JobEndTime
            ContentMatchQuery    = $query
            ExchangeLocation     = (@($search.ExchangeLocation) -join '; ')
            SharePointLocation   = (@($search.SharePointLocation) -join '; ')
            PublicFolderLocation = (@($search.PublicFolderLocation) -join '; ')
            Errors               = $errors
        })

    if ($IncludeLocationStatistics) {
        # SuccessResults lists every location as "{Location: <mailbox or site>, Item count: <n>, Total size: <bytes>}".
        foreach ($hit in [regex]::Matches([string]$search.SuccessResults, 'Location: (.+?), Item count: (\d+), Total size: (\d+)')) {
            $locationRows.Add([PSCustomObject]@{
                    SearchName = [string]$search.Name
                    Location   = $hit.Groups[1].Value
                    ItemCount  = [long]$hit.Groups[2].Value
                    SizeMB     = [math]::Round([double]$hit.Groups[3].Value / 1MB, 2)
                })
        }
    }
    if (-not $Preview) { continue }
    if ($search.Status -ne 'Completed' -or [long]$search.Items -eq 0) { Write-Warning ("Preview skipped for '{0}': status {1}, {2} items." -f $search.Name, $search.Status, $search.Items); continue }

    $actionName = '{0}_Preview' -f $search.Name
    $action = Get-ComplianceSearchAction -Identity $actionName -ErrorAction SilentlyContinue
    if ($null -eq $action) {
        if (-not $PSCmdlet.ShouldProcess($search.Name, 'Create a preview action (New-ComplianceSearchAction -Preview)')) { continue }
        try { $action = New-ComplianceSearchAction -SearchName $search.Name -Preview -Confirm:$false -ErrorAction Stop }
        catch { Write-Warning ("Could not create the preview action for '{0}': {1}" -f $search.Name, $_.Exception.Message); continue }
    }
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while (@('Completed', 'Failed', 'PartiallySucceeded') -notcontains [string]$action.Status -and (Get-Date) -lt $deadline) {
        Write-Progress -Activity 'Reading content searches' -Status ('{0} of {1}: waiting for {2} ({3})' -f $index, $searches.Count, $actionName, $action.Status)
        Start-Sleep -Seconds 15
        try { $action = Get-ComplianceSearchAction -Identity $actionName -ErrorAction Stop } catch { Write-Warning ("Polling '{0}' failed: {1}" -f $actionName, $_.Exception.Message) }
    }
    if ([string]$action.Status -ne 'Completed') { Write-Warning ("Preview action '{0}' did not complete (status {1})." -f $actionName, $action.Status); continue }
    try { $details = Get-ComplianceSearchAction -Identity $actionName -Details -ErrorAction Stop }
    catch { Write-Warning ("Could not read the preview results of '{0}': {1}" -f $actionName, $_.Exception.Message); continue }
    foreach ($hit in [regex]::Matches([string]$details.Results, $previewPattern)) {
        $row = [ordered]@{ SearchName = [string]$search.Name }
        foreach ($field in 'Location', 'Sender', 'Subject', 'Type') { $row[$field] = $hit.Groups[$field].Value.Trim() }
        $row['SizeKB'] = [math]::Round([double]$hit.Groups['Size'].Value / 1KB, 1)
        $row['ReceivedTime'] = $null
        try { $row['ReceivedTime'] = [datetime]$hit.Groups['Received'].Value.Trim() } catch { Write-Verbose ("Unparsed received time: {0}" -f $hit.Groups['Received'].Value) }
        $previewRows.Add([PSCustomObject]$row)
    }
}
Write-Progress -Activity 'Reading content searches' -Completed

$results = @($results | Sort-Object -Property Case, Name)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
if ($locationRows.Count -gt 0) { $locationRows | Export-Csv -Path ($basePath + '_Locations.csv') -NoTypeInformation -Encoding UTF8 }
if ($previewRows.Count -gt 0) { $previewRows | Export-Csv -Path ($basePath + '_Preview.csv') -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'Content search summary' -ForegroundColor Cyan
Write-Host ('  Searches        : {0}' -f $results.Count)
foreach ($group in ($results | Group-Object -Property Status | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,5}  {1}' -f $group.Count, $group.Name)
}
Write-Host ('  Items (total)   : {0:N0} in {1:N2} GB' -f (($results | Measure-Object -Property Items -Sum).Sum), (($results | Measure-Object -Property SizeGB -Sum).Sum))
if ($results.Count -gt 0) { Write-Host ('  Report          : {0}' -f $OutputPath) }
if ($locationRows.Count -gt 0) { Write-Host ('  Location rows   : {0} -> {1}' -f $locationRows.Count, ($basePath + '_Locations.csv')) }
if ($previewRows.Count -gt 0) { Write-Host ('  Preview rows    : {0} -> {1}' -f $previewRows.Count, ($basePath + '_Preview.csv')) }

if ($PassThru) {
    $results
}
#endregion Main
