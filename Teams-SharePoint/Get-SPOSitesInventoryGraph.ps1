<#
.SYNOPSIS
    Inventories every SharePoint site in the tenant through Microsoft Graph, optionally with library count and storage used.
.DESCRIPTION
    Pages through /sites/getAllSites (application permission) and falls back to /sites?$search=* for delegated sessions.
    Each site becomes one row with Name, WebUrl, SiteId, Created, LastModified, IsPersonalSite, Hostname and IsRoot.
    -IncludeDrives adds the number of document libraries and the storage used from /sites/{id}/drives (quota.used).
    Personal sites (OneDrive) are excluded unless -IncludePersonalSites is used; -NameFilter narrows by display name or URL.
    Exports to CSV and prints the totals, the newest sites and (with -IncludeDrives) the largest sites.
.PARAMETER IncludeDrives
    Call /sites/{id}/drives for every site (100 ms pause) and add DriveCount and StorageUsedGB.
.PARAMETER IncludePersonalSites
    Also export OneDrive personal sites (isPersonalSite = true). Only available with getAllSites (application permission).
.PARAMETER NameFilter
    Wildcard applied to the display name and the web URL, for example 'Project*' or '*/sites/HR*'.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOSitesInventory_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOSitesInventoryGraph.ps1
    Exports every non-personal site with its id, URL and dates.
.EXAMPLE
    PS> .\Get-SPOSitesInventoryGraph.ps1 -IncludeDrives -NameFilter 'Project*' -OutputPath C:\Temp\ProjectSites.csv -Verbose
    Lists the project sites with their library count and storage used, largest first.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Sites.Read.All. getAllSites is application-only (app-only session); a delegated session falls back to the
                  site search, which returns only the sites the signed-in user can access and no personal sites.
    Category    : SharePoint & OneDrive (Graph)
    Changes     : No
    Notes       : Graph does not expose the site template (STS#3, GROUP#0, SITEPAGEPUBLISHING#0, ...); use the SharePoint Online
                  module (Get-SPOSite) or the usage report (Get-SPOSiteStorageReport.ps1, Root Web Template) for that. Every
                  library of a site reports the site collection quota, so StorageUsedGB is the site value, not a sum.
.LINK
    https://learn.microsoft.com/graph/api/site-getallsites
.LINK
    https://learn.microsoft.com/graph/api/site-search
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()] [switch]$IncludeDrives,
    [Parameter()] [switch]$IncludePersonalSites,
    [Parameter()] [string]$NameFilter,
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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath ('SPOSitesInventory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
try { Connect-GraphIfNeeded -Scopes @('Sites.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$siteSelect = '$select=id,displayName,name,webUrl,createdDateTime,lastModifiedDateTime,isPersonalSite,root,siteCollection'
$source = 'getAllSites'
try { $sites = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites/getAllSites?$siteSelect") }
catch {
    # getAllSites is application-only; a delegated session gets 403/404, so fall back to the site search (no personal sites).
    Write-Verbose "getAllSites is not available in this session ($($_.Exception.Message)); falling back to /sites?`$search=*."
    $source = 'site search'
    if ($IncludePersonalSites) { Write-Warning 'The site search does not return personal sites; -IncludePersonalSites needs an app-only session.' }
    try { $sites = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites?`$search=*&$siteSelect") }
    catch { throw "Failed to list the sites: $($_.Exception.Message)" }
}
Write-Verbose "Retrieved $($sites.Count) sites from $source."
if (-not $IncludePersonalSites) { $sites = @($sites | Where-Object { $_.isPersonalSite -ne $true }) }
if (-not [string]::IsNullOrWhiteSpace($NameFilter)) { $sites = @($sites | Where-Object { $_.displayName -like $NameFilter -or $_.webUrl -like $NameFilter }) }

$records = New-Object -TypeName System.Collections.Generic.List[object]
$siteCounter = 0
foreach ($site in $sites) {
    $siteCounter++
    $driveCount = $null
    $storageUsedGB = $null
    if ($IncludeDrives) {
        if ($siteCounter % 20 -eq 0) { Write-Progress -Activity 'Reading document libraries' -Status "$siteCounter of $($sites.Count)" -PercentComplete ([int](($siteCounter / $sites.Count) * 100)) }
        try {
            $drives = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/drives?`$select=id,name,driveType,quota")
            $driveCount = $drives.Count
            # every library reports the site collection quota, so take the maximum instead of summing
            $usedBytes = ($drives | ForEach-Object { [int64]$_.quota.used } | Measure-Object -Maximum).Maximum
            if ($null -ne $usedBytes) { $storageUsedGB = [math]::Round($usedBytes / 1GB, 2) }
        }
        catch { Write-Warning "Could not read the libraries of '$($site.webUrl)': $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 100
    }
    $hostname = $site.siteCollection.hostname
    if ([string]::IsNullOrEmpty($hostname)) { $hostname = ([uri]$site.webUrl).Host }
    $records.Add([PSCustomObject]@{
            Name           = $site.displayName
            WebUrl         = $site.webUrl
            SiteId         = $site.id
            Created        = $(if ($site.createdDateTime) { [datetime]$site.createdDateTime })
            LastModified   = $(if ($site.lastModifiedDateTime) { [datetime]$site.lastModifiedDateTime })
            IsPersonalSite = ($site.isPersonalSite -eq $true)
            Hostname       = $hostname
            IsRoot         = ($null -ne $site.root)
            DriveCount     = $driveCount
            StorageUsedGB  = $storageUsedGB
        })
}
Write-Progress -Activity 'Reading document libraries' -Completed

$output = @($records | Sort-Object -Property WebUrl)
if ($IncludeDrives) { $output = @($records | Sort-Object -Property StorageUsedGB -Descending) }
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No sites matched the selected filters; no CSV was written.' }

$personalCount = @($output | Where-Object { $_.IsPersonalSite }).Count
$rootCount = @($output | Where-Object { $_.IsRoot }).Count
$hostnameCount = @($output | Group-Object -Property Hostname).Count
Write-Host 'SharePoint sites inventory summary' -ForegroundColor Cyan
Write-Host ('  Source / sites exported   : {0} / {1} (personal: {2}, root sites: {3}, hostnames: {4})' -f $source, $output.Count, $personalCount, $rootCount, $hostnameCount)
Write-Host '  Newest sites:'
foreach ($site in ($output | Sort-Object -Property Created -Descending | Select-Object -First 5)) { Write-Host ('    {0:yyyy-MM-dd}  {1}' -f $site.Created, $site.WebUrl) }
if ($IncludeDrives) {
    $withDrives = @($output | Where-Object { $null -ne $_.DriveCount })
    $totalGB = [double]($withDrives | Measure-Object -Property StorageUsedGB -Sum).Sum
    Write-Host ('  Total storage used        : {0:N2} GB in {1} libraries' -f $totalGB, [int]($withDrives | Measure-Object -Property DriveCount -Sum).Sum)
    Write-Host '  Largest sites:'
    foreach ($site in ($output | Select-Object -First 5)) { Write-Host ('    {0,10:N2} GB  {1}' -f $site.StorageUsedGB, $site.WebUrl) }
}
Write-Host ('  Rows exported             : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
