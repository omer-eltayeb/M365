<#
.SYNOPSIS
    Inventories every file in the document libraries of one or more SharePoint sites with size, age, editor and sharing state.
.DESCRIPTION
    Resolves the target sites (-SiteUrl, -SiteId or -AllSites), lists their document libraries with /sites/{id}/drives
    and enumerates each library with the delta API (/drives/{id}/root/delta), which streams every item in flat pages
    without folder recursion. Each file becomes one row with library-relative path, extension, size, dates, last editor,
    web URL, sharing state and item id; -MinSizeMB and -OlderThanDays keep only large or stale files. Exports to CSV and
    prints the file count, total size, the top 10 extensions and the 10 largest files.
.PARAMETER SiteUrl
    One or more site collection URLs, for example https://contoso.sharepoint.com/sites/Marketing.
.PARAMETER SiteId
    One or more Graph site ids (hostname,siteCollectionId,webId), for example from Get-SPOSitesInventoryGraph.ps1.
.PARAMETER AllSites
    Enumerate every non-personal site in the tenant. Slow in large tenants; the script warns before it starts.
.PARAMETER IncludeFolders
    Also export folder rows (ItemType = Folder). By default only files are exported.
.PARAMETER MinSizeMB
    Keep only items of at least this size in MB. Default 0 = no size filter.
.PARAMETER OlderThanDays
    Keep only items whose last modification is at least this many days old. Default 0 = no age filter.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOSiteFiles_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOSiteFilesInventory.ps1 -SiteUrl https://contoso.sharepoint.com/sites/Marketing
    Exports every file in all document libraries of the Marketing site.
.EXAMPLE
    PS> .\Get-SPOSiteFilesInventory.ps1 -AllSites -MinSizeMB 100 -OlderThanDays 365 -OutputPath C:\Temp\StaleLargeFiles.csv -Verbose
    Finds files of 100 MB or more that nobody has modified for a year across all sites: candidates for archiving.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Sites.Read.All, Files.Read.All (delegated sees only sites the user can open; app-only recommended tenant-wide).
    Category    : SharePoint & OneDrive (Graph)
    Changes     : No
    Notes       : /sites/getAllSites is application-only, so with a delegated session -AllSites falls back to /sites?$search=*.
                  Delta pages are followed with a 100 ms pause; the SDK retries HTTP 429. Sensitivity labels are not in v1.0 delta.
.LINK
    https://learn.microsoft.com/graph/api/driveitem-delta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()] [string[]]$SiteUrl,
    [Parameter()] [string[]]$SiteId,
    [Parameter()] [switch]$AllSites,
    [Parameter()] [switch]$IncludeFolders,
    [Parameter()] [ValidateRange(0, 10000000)] [double]$MinSizeMB = 0,
    [Parameter()] [ValidateRange(0, 36500)] [int]$OlderThanDays = 0,
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
    $nextLink = "$DriveUri/root/delta?`$select=id,name,size,file,folder,root,parentReference,webUrl,createdDateTime,lastModifiedDateTime,lastModifiedBy,shared"
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
if (-not $AllSites -and -not $SiteUrl -and -not $SiteId) { throw 'Specify -SiteUrl, -SiteId or -AllSites.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath ('SPOSiteFiles_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
try { Connect-GraphIfNeeded -Scopes @('Sites.Read.All', 'Files.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
if ($AllSites) { Write-Warning 'Enumerating every document library in the tenant can take a long time; use -SiteUrl to narrow the scope.' }
try { $sites = @(Get-TargetSite -SiteUrl $SiteUrl -SiteId $SiteId -All:$AllSites) }
catch { throw "Failed to resolve the target sites: $($_.Exception.Message)" }

$records = New-Object -TypeName System.Collections.Generic.List[object]
$libraryCount = 0; $siteCounter = 0
foreach ($site in $sites) {
    $siteCounter++
    Write-Progress -Activity 'Enumerating document libraries' -Status "$siteCounter of $($sites.Count): $($site.displayName)" -PercentComplete ([int](($siteCounter / $sites.Count) * 100))
    try { $drives = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/drives?`$select=id,name") }
    catch { Write-Warning "Could not list the libraries of '$($site.webUrl)': $($_.Exception.Message)"; continue }
    foreach ($drive in $drives) {
        try { $items = Get-DriveItemList -DriveUri "https://graph.microsoft.com/v1.0/drives/$($drive.id)"; $libraryCount++ }
        catch { Write-Warning "Could not enumerate library '$($drive.name)' in '$($site.webUrl)': $($_.Exception.Message)"; continue }
        foreach ($item in $items) {
            $isFolder = ($null -ne $item.folder)
            if ($isFolder -and -not $IncludeFolders) { continue }
            if ($MinSizeMB -gt 0 -and ($item.size / 1MB) -lt $MinSizeMB) { continue }
            $lastModified = [datetime]$item.lastModifiedDateTime
            if ($OlderThanDays -gt 0 -and ([datetime]::UtcNow - $lastModified.ToUniversalTime()).TotalDays -lt $OlderThanDays) { continue }
            # first non-empty of: editor e-mail, editor display name, application name (system/app edits have no user)
            $editorName = @($item.lastModifiedBy.user.email, $item.lastModifiedBy.user.displayName, $item.lastModifiedBy.application.displayName) | Where-Object { $_ } | Select-Object -First 1
            $itemType = 'File'; $extension = ''
            if ($isFolder) { $itemType = 'Folder' } else { $extension = [System.IO.Path]::GetExtension([string]$item.name).ToLowerInvariant() }
            $records.Add([PSCustomObject]@{
                    Site           = $site.displayName
                    Library        = $drive.name
                    # parentReference.path is /drives/{id}/root:/Folder/Sub; keep the part after root: and append the name
                    Path           = [uri]::UnescapeDataString(("$($item.parentReference.path)/$($item.name)" -replace '^.*?root:', ''))
                    Name           = $item.name
                    ItemType       = $itemType
                    Extension      = $extension
                    SizeMB         = [math]::Round($item.size / 1MB, 2)
                    Created        = [datetime]$item.createdDateTime
                    LastModified   = $lastModified
                    LastModifiedBy = $editorName
                    WebUrl         = $item.webUrl
                    IsShared       = ($null -ne $item.shared)
                    SharedScope    = $item.shared.scope
                    ItemId         = $item.id
                })
        }
    }
}
Write-Progress -Activity 'Enumerating document libraries' -Completed

$output = @($records | Sort-Object -Property SizeMB -Descending)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No items matched the selected filters; no CSV was written.' }

$files = @($output | Where-Object { $_.ItemType -eq 'File' })
$totalGB = [double]($files | Measure-Object -Property SizeMB -Sum).Sum / 1024
Write-Host 'SharePoint file inventory summary' -ForegroundColor Cyan
Write-Host ('  Sites / libraries scanned : {0} / {1}; files matched: {2} ({3:N2} GB); folders: {4}' -f $sites.Count, $libraryCount, $files.Count, $totalGB, ($output.Count - $files.Count))
Write-Host '  Top 10 extensions by file count:'
foreach ($group in ($files | Group-Object -Property Extension | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,-8} {1,8} files {2,12:N2} GB' -f $group.Name, $group.Count, ([double]($group.Group | Measure-Object -Property SizeMB -Sum).Sum / 1024))
}
Write-Host '  Largest 10 files:'
foreach ($file in ($files | Select-Object -First 10)) { Write-Host ('    {0,10:N1} MB  {1}{2}' -f $file.SizeMB, $file.Library, $file.Path) }
Write-Host ('  Rows exported             : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
