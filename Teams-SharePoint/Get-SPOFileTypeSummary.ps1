<#
.SYNOPSIS
    Summarises the files stored in SharePoint sites by extension and by category (Office, PDF, media, archives, code, CAD).
.DESCRIPTION
    Enumerates the document libraries of the selected sites (-SiteUrl, -SiteId or -AllSites) with the delta API
    (/drives/{id}/root/delta) and aggregates every file on the fly, so even very large tenants fit in memory. The main CSV
    has one row per extension (FileCount, TotalGB, AvgSizeMB, LargestMB, Oldest/NewestModified, Category, IsExecutable,
    IsStale); <OutputPath>_Categories.csv rolls the extensions up into categories and flags executables and scripts,
    media above -LargeMediaGB and categories nobody has modified for -StaleDays days.
.PARAMETER SiteUrl
    One or more site collection URLs, for example https://contoso.sharepoint.com/sites/Marketing.
.PARAMETER SiteId
    One or more Graph site ids (hostname,siteCollectionId,webId), for example from Get-SPOSitesInventoryGraph.ps1.
.PARAMETER AllSites
    Scan every non-personal site in the tenant. Slow in large tenants; the script warns before it starts.
.PARAMETER LargeMediaGB
    Flag the Images, Video and Audio categories when their combined size exceeds this many GB. Default 1.
.PARAMETER StaleDays
    An extension or category is IsStale when its newest file was modified more than this many days ago. Default 365.
.PARAMETER OutputPath
    Path of the per-extension CSV. Defaults to .\Reports\SPOFileTypes_<timestamp>.csv; the category CSV sits next to it.
.PARAMETER PassThru
    Also emit the per-extension objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOFileTypeSummary.ps1 -SiteUrl https://contoso.sharepoint.com/sites/Engineering
    Shows what kind of files the Engineering site stores and how much space each type takes.
.EXAMPLE
    PS> .\Get-SPOFileTypeSummary.ps1 -AllSites -LargeMediaGB 50 -StaleDays 730 -OutputPath C:\Temp\FileTypes.csv -Verbose
    Tenant-wide breakdown; flags media above 50 GB and categories untouched for two years.
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
                  Categories are assigned by extension only; files without an extension are reported as (none) / Other.
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
    [Parameter()] [ValidateRange(0, 1000000)] [double]$LargeMediaGB = 1,
    [Parameter()] [ValidateRange(1, 36500)] [int]$StaleDays = 365,
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
    $nextLink = "$DriveUri/root/delta?`$select=id,name,size,file,folder,root,lastModifiedDateTime"
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
    $OutputPath = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath ('SPOFileTypes_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
$categoryPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_Categories.csv')

# Extension -> category lookup. Executables and scripts are flagged separately because they rarely belong in a document library.
$categoryMap = @{
    'Office documents' = '.doc .docx .docm .dot .dotx .xls .xlsx .xlsm .xlsb .csv .ppt .pptx .pptm .pps .ppsx .one .vsd .vsdx .pub .odt .ods .odp .rtf .txt .msg .eml'
    'PDF'              = '.pdf'
    'Images'           = '.jpg .jpeg .png .gif .bmp .tif .tiff .heic .svg .webp .psd .ai .ico .raw'
    'Video'            = '.mp4 .mov .avi .wmv .mkv .m4v .mpg .mpeg .webm .flv .3gp'
    'Audio'            = '.mp3 .wav .m4a .wma .aac .flac .ogg .opus'
    'Archives'         = '.zip .7z .rar .tar .gz .tgz .bz2 .iso .cab .vhd .vhdx .bak .pst .ost'
    'Code/Scripts'     = '.ps1 .psm1 .psd1 .bat .cmd .vbs .js .ts .py .sh .exe .msi .msix .dll .com .scr .jar .reg .hta .wsf .json .xml .yml .yaml .sql .html .css .cs .java .cpp .h .go .php'
    'CAD'              = '.dwg .dxf .dgn .rvt .rfa .ifc .step .stp .stl .skp .3dm .sldprt .sldasm .ipt .iam .nwd .nwc'
}
$executableExtensions = '.exe .msi .msix .dll .com .scr .bat .cmd .ps1 .psm1 .vbs .js .hta .wsf .jar .reg .sh' -split ' '
$extensionCategory = @{}
foreach ($category in $categoryMap.Keys) { foreach ($extension in ($categoryMap[$category] -split ' ')) { $extensionCategory[$extension] = $category } }

try { Connect-GraphIfNeeded -Scopes @('Sites.Read.All', 'Files.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
if ($AllSites) { Write-Warning 'Scanning every document library in the tenant can take a long time; use -SiteUrl to narrow the scope.' }
try { $sites = @(Get-TargetSite -SiteUrl $SiteUrl -SiteId $SiteId -All:$AllSites) }
catch { throw "Failed to resolve the target sites: $($_.Exception.Message)" }

$stats = @{}
$libraryCount = 0; $siteCounter = 0
foreach ($site in $sites) {
    $siteCounter++
    Write-Progress -Activity 'Aggregating file types' -Status "$siteCounter of $($sites.Count): $($site.displayName)" -PercentComplete ([int](($siteCounter / $sites.Count) * 100))
    try { $drives = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/drives?`$select=id,name") }
    catch { Write-Warning "Could not list the libraries of '$($site.webUrl)': $($_.Exception.Message)"; continue }
    foreach ($drive in $drives) {
        try { $items = Get-DriveItemList -DriveUri "https://graph.microsoft.com/v1.0/drives/$($drive.id)"; $libraryCount++ }
        catch { Write-Warning "Could not enumerate library '$($drive.name)' in '$($site.webUrl)': $($_.Exception.Message)"; continue }
        foreach ($item in $items) {
            if ($null -ne $item.folder) { continue }
            $extension = [System.IO.Path]::GetExtension([string]$item.name).ToLowerInvariant()
            if ([string]::IsNullOrEmpty($extension)) { $extension = '(none)' }
            $modified = ([datetime]$item.lastModifiedDateTime).ToUniversalTime()
            # key is named Files (not Count) because .Count on a hashtable is the number of its entries
            if (-not $stats.ContainsKey($extension)) { $stats[$extension] = @{ Files = 0; Bytes = [int64]0; Largest = [int64]0; Oldest = $modified; Newest = $modified } }
            $entry = $stats[$extension]
            $entry.Files++; $entry.Bytes += [int64]$item.size
            if ($item.size -gt $entry.Largest) { $entry.Largest = [int64]$item.size }
            if ($modified -lt $entry.Oldest) { $entry.Oldest = $modified }
            if ($modified -gt $entry.Newest) { $entry.Newest = $modified }
        }
    }
}
Write-Progress -Activity 'Aggregating file types' -Completed

$staleBefore = [datetime]::UtcNow.AddDays(-$StaleDays)
$output = foreach ($extension in $stats.Keys) {
    $entry = $stats[$extension]
    $category = $extensionCategory[$extension]
    if ($null -eq $category) { $category = 'Other' }
    [PSCustomObject]@{
        Extension      = $extension
        Category       = $category
        FileCount      = $entry.Files
        TotalGB        = [math]::Round($entry.Bytes / 1GB, 3)
        AvgSizeMB      = [math]::Round(($entry.Bytes / $entry.Files) / 1MB, 2)
        LargestMB      = [math]::Round($entry.Largest / 1MB, 2)
        OldestModified = $entry.Oldest
        NewestModified = $entry.Newest
        IsExecutable   = ($executableExtensions -contains $extension)
        IsStale        = ($entry.Newest -lt $staleBefore)
    }
}
$output = @($output | Sort-Object -Property TotalGB -Descending)
$mediaGB = [double]($output | Where-Object { $_.Category -in @('Images', 'Video', 'Audio') } | Measure-Object -Property TotalGB -Sum).Sum
$categories = foreach ($group in ($output | Group-Object -Property Category)) {
    $flags = @()
    if (@($group.Group | Where-Object { $_.IsExecutable }).Count -gt 0) { $flags += 'Executables/scripts present' }
    if ($group.Name -in @('Images', 'Video', 'Audio') -and $mediaGB -gt $LargeMediaGB) { $flags += ('Media total {0:N2} GB exceeds {1} GB' -f $mediaGB, $LargeMediaGB) }
    # Sort-Object instead of Measure-Object -Maximum: the latter does not handle [datetime] reliably on Windows PowerShell 5.1
    $newest = ($group.Group | Sort-Object -Property NewestModified -Descending | Select-Object -First 1).NewestModified
    [PSCustomObject]@{
        Category       = $group.Name
        FileCount      = ($group.Group | Measure-Object -Property FileCount -Sum).Sum
        TotalGB        = [math]::Round(($group.Group | Measure-Object -Property TotalGB -Sum).Sum, 3)
        TopExtensions  = (@($group.Group | Sort-Object -Property FileCount -Descending | Select-Object -First 5 | ForEach-Object { $_.Extension }) -join ' ')
        OldestModified = ($group.Group | Sort-Object -Property OldestModified | Select-Object -First 1).OldestModified
        NewestModified = $newest
        IsStale        = ($newest -lt $staleBefore)
        Flags          = ($flags -join '; ')
    }
}
$categories = @($categories | Sort-Object -Property TotalGB -Descending)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8; $categories | Export-Csv -Path $categoryPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No files were found in the selected sites; no CSV was written.' }

$totalFiles = [int64]($output | Measure-Object -Property FileCount -Sum).Sum
$totalGB = [double]($output | Measure-Object -Property TotalGB -Sum).Sum
$executableCount = [int64]($output | Where-Object { $_.IsExecutable } | Measure-Object -Property FileCount -Sum).Sum
Write-Host 'SharePoint file type summary' -ForegroundColor Cyan
Write-Host ('  Sites / libraries scanned : {0} / {1}; files: {2} ({3:N2} GB)' -f $sites.Count, $libraryCount, $totalFiles, $totalGB)
foreach ($row in $categories) { Write-Host ('    {0,-18} {1,9} files {2,10:N2} GB  stale: {3,-5} {4}' -f $row.Category, $row.FileCount, $row.TotalGB, $row.IsStale, $row.Flags) }
Write-Host ('  Executables / scripts     : {0} files; media: {1:N2} GB (threshold {2} GB)' -f $executableCount, $mediaGB, $LargeMediaGB) -ForegroundColor Yellow
Write-Host ('  Extensions / categories   : {0} -> {1}; {2} -> {3}' -f $output.Count, $OutputPath, $categories.Count, $categoryPath)

if ($PassThru) { $output }
#endregion Main
