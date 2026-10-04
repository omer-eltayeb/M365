<#
.SYNOPSIS
    Finds the largest files in SharePoint sites or OneDrive accounts, optionally with the storage consumed by their version history.
.DESCRIPTION
    Enumerates the document libraries of the selected sites (-SiteUrl, -SiteId, -AllSites) and/or the OneDrive of the
    given users (-UserPrincipalName) with the delta API (/drives/{id}/root/delta) and keeps files of at least -MinSizeMB.
    The -Top largest files are exported with path, size, age, last editor and an IsArchiveCandidate flag (not modified for
    -OlderThanDays); -IncludeVersions adds VersionCount and VersionsGB from /drives/{id}/items/{id}/versions, the hidden
    storage consumer. Prints the total size, size by extension and the archiving candidates.
.PARAMETER SiteUrl
    One or more site collection URLs, for example https://contoso.sharepoint.com/sites/Marketing.
.PARAMETER SiteId
    One or more Graph site ids (hostname,siteCollectionId,webId), for example from Get-SPOSitesInventoryGraph.ps1.
.PARAMETER AllSites
    Scan every non-personal site in the tenant. Slow in large tenants; the script warns before it starts.
.PARAMETER UserPrincipalName
    One or more users whose OneDrive should be scanned (resolved with /users/{upn}/drive).
.PARAMETER MinSizeMB
    Minimum file size in MB. Default 500.
.PARAMETER Top
    Number of largest files to export. Default 100; 0 = export all files above -MinSizeMB.
.PARAMETER OlderThanDays
    Files not modified for this many days are flagged IsArchiveCandidate. Default 365.
.PARAMETER IncludeVersions
    Also read the version history of each exported file (one call per file, 100 ms pause) and add VersionCount / VersionsGB.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOLargeFiles_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOLargeFilesReport.ps1 -SiteUrl https://contoso.sharepoint.com/sites/Engineering -IncludeVersions
    Exports the 100 largest files (500 MB or more) of the Engineering site with the size of their version history.
.EXAMPLE
    PS> .\Get-SPOLargeFilesReport.ps1 -AllSites -MinSizeMB 1024 -Top 50 -OlderThanDays 730 -OutputPath C:\Temp\Huge.csv -Verbose
    Lists the 50 largest files above 1 GB in the tenant and flags the ones untouched for two years.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Sites.Read.All, Files.Read.All (delegated sees only sites and OneDrives the user can open; app-only recommended).
    Category    : SharePoint & OneDrive (Graph)
    Changes     : No
    Notes       : /sites/getAllSites is application-only, so with a delegated session -AllSites falls back to /sites?$search=*.
                  VersionsGB counts every stored version incl. the current one; trim it with library version limits or Intelligent Versioning.
.LINK
    https://learn.microsoft.com/graph/api/driveitem-list-versions
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()] [string[]]$SiteUrl,
    [Parameter()] [string[]]$SiteId,
    [Parameter()] [switch]$AllSites,
    [Parameter()] [string[]]$UserPrincipalName,
    [Parameter()] [ValidateRange(1, 10000000)] [double]$MinSizeMB = 500,
    [Parameter()] [ValidateRange(0, 1000000)] [int]$Top = 100,
    [Parameter()] [ValidateRange(1, 36500)] [int]$OlderThanDays = 365,
    [Parameter()] [switch]$IncludeVersions,
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

function Get-TargetSite {
    <# Resolves -SiteUrl / -SiteId to site objects, or lists every non-personal site (getAllSites is application-only; delegated sessions fall back to $search=*). #>
    param([Parameter()] [string[]]$SiteUrl, [Parameter()] [string[]]$SiteId, [Parameter()] [switch]$All)
    $sites = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($url in $SiteUrl) {
        $parsedUrl = [uri]$url
        $sitePath = $parsedUrl.AbsolutePath.TrimEnd('/')
        if (-not [string]::IsNullOrEmpty($sitePath)) { $sitePath = ":$sitePath" }
        $sites.Add((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$($parsedUrl.Host)$sitePath" -OutputType PSObject -ErrorAction Stop))
    }
    foreach ($id in $SiteId) { $sites.Add((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$id" -OutputType PSObject -ErrorAction Stop)) }
    if ($All) {
        $siteSelect = '$select=id,displayName,name,webUrl,isPersonalSite'
        try { $allSites = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites/getAllSites?$siteSelect" }
        catch { Write-Verbose 'getAllSites is application-only; using /sites?$search=*.'; $allSites = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites?`$search=*&$siteSelect" }
        foreach ($site in $allSites) { if ($site.isPersonalSite -ne $true) { $sites.Add($site) } }
    }
    return @($sites)
}

function Get-DriveItemList {
    <# Enumerates every item of a drive in one flat delta pass (no folder recursion); the last page carries @odata.deltaLink instead of @odata.nextLink. #>
    param([Parameter(Mandatory = $true)] [string]$DriveUri)
    $items = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = "$DriveUri/root/delta?`$select=id,name,size,file,folder,root,parentReference,webUrl,createdDateTime,lastModifiedDateTime,lastModifiedBy"
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject -ErrorAction Stop
        foreach ($item in @($page.value)) { if ($null -eq $item.root) { $items.Add($item) } }
        $nextLink = $page.'@odata.nextLink'
        Start-Sleep -Milliseconds 100
    }
    return $items
}
#endregion Helpers

#region Main
if (-not $AllSites -and -not $SiteUrl -and -not $SiteId -and -not $UserPrincipalName) { throw 'Specify -SiteUrl, -SiteId, -AllSites or -UserPrincipalName.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath ('SPOLargeFiles_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
try { Connect-GraphIfNeeded -Scopes @('Sites.Read.All', 'Files.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
if ($AllSites) { Write-Warning 'Scanning every document library in the tenant can take a long time; use -SiteUrl to narrow the scope.' }
try { $sites = @(Get-TargetSite -SiteUrl $SiteUrl -SiteId $SiteId -All:$AllSites) }
catch { throw "Failed to resolve the target sites: $($_.Exception.Message)" }

# Build one flat list of drives to scan: every library of every site, plus the OneDrive of every requested user.
$drives = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($site in $sites) {
    try { $siteDrives = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/drives?`$select=id,name") }
    catch { Write-Warning "Could not list the libraries of '$($site.webUrl)': $($_.Exception.Message)"; continue }
    foreach ($drive in $siteDrives) { $drives.Add([PSCustomObject]@{ Location = $site.displayName; LocationType = 'Site'; Library = $drive.name; DriveId = $drive.id }) }
}
foreach ($upn in $UserPrincipalName) {
    try { $drive = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$upn/drive?`$select=id,name" -OutputType PSObject -ErrorAction Stop }
    catch { Write-Warning "OneDrive of '$upn' is not available (not provisioned or no access): $($_.Exception.Message)"; continue }
    $drives.Add([PSCustomObject]@{ Location = $upn; LocationType = 'OneDrive'; Library = $drive.name; DriveId = $drive.id })
}

$records = New-Object -TypeName System.Collections.Generic.List[object]; $driveCounter = 0
foreach ($drive in $drives) {
    $driveCounter++
    Write-Progress -Activity 'Scanning libraries for large files' -Status "$driveCounter of $($drives.Count): $($drive.Library)" -PercentComplete ([int](($driveCounter / $drives.Count) * 100))
    try { $items = Get-DriveItemList -DriveUri "https://graph.microsoft.com/v1.0/drives/$($drive.DriveId)" }
    catch { Write-Warning "Could not enumerate '$($drive.Library)' in '$($drive.Location)': $($_.Exception.Message)"; continue }
    foreach ($item in $items) {
        if ($null -ne $item.folder -or ($item.size / 1MB) -lt $MinSizeMB) { continue }
        $lastModified = [datetime]$item.lastModifiedDateTime
        $daysSinceModified = [int]([datetime]::UtcNow - $lastModified.ToUniversalTime()).TotalDays
        $editorName = @($item.lastModifiedBy.user.email, $item.lastModifiedBy.user.displayName, $item.lastModifiedBy.application.displayName) | Where-Object { $_ } | Select-Object -First 1
        $records.Add([PSCustomObject]@{
                Location           = $drive.Location
                LocationType       = $drive.LocationType
                Library            = $drive.Library
                # parentReference.path is /drives/{id}/root:/Folder/Sub; keep the part after root: and append the name
                Path               = [uri]::UnescapeDataString(("$($item.parentReference.path)/$($item.name)" -replace '^.*?root:', ''))
                Name               = $item.name
                Extension          = [System.IO.Path]::GetExtension([string]$item.name).ToLowerInvariant()
                SizeGB             = [math]::Round($item.size / 1GB, 3)
                Created            = [datetime]$item.createdDateTime
                LastModified       = $lastModified
                LastModifiedBy     = $editorName
                DaysSinceModified  = $daysSinceModified
                IsArchiveCandidate = ($daysSinceModified -ge $OlderThanDays)
                VersionCount       = $null
                VersionsGB         = $null
                WebUrl             = $item.webUrl
                DriveId            = $drive.DriveId
                ItemId             = $item.id
            })
    }
}
Write-Progress -Activity 'Scanning libraries for large files' -Completed

$allLarge = @($records | Sort-Object -Property SizeGB -Descending)
$output = $allLarge
if ($Top -gt 0) { $output = @($allLarge | Select-Object -First $Top) }
if ($IncludeVersions) {
    $versionCounter = 0
    foreach ($record in $output) {
        $versionCounter++
        Write-Progress -Activity 'Reading version history' -Status "$versionCounter of $($output.Count): $($record.Name)" -PercentComplete ([int](($versionCounter / $output.Count) * 100))
        try { $versions = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/drives/$($record.DriveId)/items/$($record.ItemId)/versions?`$select=id,size") }
        catch { Write-Warning "Could not read the versions of '$($record.Path)': $($_.Exception.Message)"; continue }
        $record.VersionCount = $versions.Count
        $record.VersionsGB = [math]::Round([double]($versions | Measure-Object -Property size -Sum).Sum / 1GB, 3)
        Start-Sleep -Milliseconds 100
    }
    Write-Progress -Activity 'Reading version history' -Completed
}

if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning "No files of $MinSizeMB MB or more were found; no CSV was written." }

$archiveCandidates = @($allLarge | Where-Object { $_.IsArchiveCandidate })
$archiveGB = [double]($archiveCandidates | Measure-Object -Property SizeGB -Sum).Sum
Write-Host 'SharePoint / OneDrive large files summary' -ForegroundColor Cyan
Write-Host ('  Drives scanned (sites / OneDrives) : {0} / {1}' -f $sites.Count, $UserPrincipalName.Count)
Write-Host ('  Files >= {0} MB                     : {1} ({2:N2} GB)' -f $MinSizeMB, $allLarge.Count, [double]($allLarge | Measure-Object -Property SizeGB -Sum).Sum)
Write-Host ('  Not modified for {0}+ days          : {1} ({2:N2} GB) - archiving candidates' -f $OlderThanDays, $archiveCandidates.Count, $archiveGB) -ForegroundColor Yellow
if ($IncludeVersions) {
    $versionsGB = [double]($output | Where-Object { $null -ne $_.VersionsGB } | Measure-Object -Property VersionsGB -Sum).Sum
    Write-Host ('  Version history (exported files)   : {0:N2} GB - trim via library version limits or Intelligent Versioning' -f $versionsGB)
}
Write-Host '  Top 10 extensions by file count:'
foreach ($group in ($allLarge | Group-Object -Property Extension | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,-8} {1,6} files {2,12:N2} GB' -f $group.Name, $group.Count, [double]($group.Group | Measure-Object -Property SizeGB -Sum).Sum)
}
Write-Host ('  Rows exported                      : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
