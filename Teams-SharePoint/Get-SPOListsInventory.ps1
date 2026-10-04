<#
.SYNOPSIS
    Inventories the lists and libraries of SharePoint sites with template, visibility, content type settings and optional item and column counts.
.DESCRIPTION
    Resolves the target sites (-SiteUrl, -SiteId or -AllSites) and reads /sites/{id}/lists with the list and system facets.
    Each list becomes one row with Template (genericList, documentLibrary, survey, tasks, events, ...), Hidden, IsSystem,
    ContentTypesEnabled, dates and web URL. Hidden and system lists are skipped unless -IncludeHidden is used.
    -IncludeItemCounts pages through /lists/{id}/items (Graph has no $count for list items) up to -MaxCountPerList;
    -IncludeColumns reads /lists/{id}/columns and lists the custom (non-system) columns. Prints the totals per template.
.PARAMETER SiteUrl
    One or more site collection URLs, for example https://contoso.sharepoint.com/sites/Marketing.
.PARAMETER SiteId
    One or more Graph site ids (hostname,siteCollectionId,webId), for example from Get-SPOSitesInventoryGraph.ps1.
.PARAMETER AllSites
    Inventory every non-personal site in the tenant. Slow in large tenants; the script warns before it starts.
.PARAMETER IncludeHidden
    Also export hidden lists and system lists (User Information List, Style Library, workflow and app lists, ...).
.PARAMETER IncludeItemCounts
    Count the items of every list by paging through /items (200 per call) up to -MaxCountPerList.
.PARAMETER MaxCountPerList
    Stop counting at this many items and report "<n>+" instead. Default 5000 (the SharePoint list view threshold).
.PARAMETER IncludeColumns
    Read the columns of every list and add ColumnCount and the names of the custom columns.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOLists_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOListsInventory.ps1 -SiteUrl https://contoso.sharepoint.com/sites/Projects
    Lists the visible lists and libraries of the Projects site with their templates.
.EXAMPLE
    PS> .\Get-SPOListsInventory.ps1 -AllSites -IncludeItemCounts -IncludeColumns -OutputPath C:\Temp\Lists.csv -Verbose
    Tenant-wide inventory with item counts (capped at 5000) and custom column names, useful before a migration or clean-up.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Sites.Read.All (delegated sees only sites the user can open; app-only recommended tenant-wide).
    Category    : SharePoint & OneDrive (Graph)
    Changes     : No
    Notes       : /sites/getAllSites is application-only, so with a delegated session -AllSites falls back to /sites?$search=*.
                  Item counting costs one call per 200 items (100 ms pause); use -MaxCountPerList to bound it. Custom columns
                  are detected by column group (anything outside the built-in groups) and may include columns added by apps.
.LINK
    https://learn.microsoft.com/graph/api/list-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()] [string[]]$SiteUrl,
    [Parameter()] [string[]]$SiteId,
    [Parameter()] [switch]$AllSites,
    [Parameter()] [switch]$IncludeHidden,
    [Parameter()] [switch]$IncludeItemCounts,
    [Parameter()] [ValidateRange(1, 10000000)] [int]$MaxCountPerList = 5000,
    [Parameter()] [switch]$IncludeColumns,
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

function Get-ListItemCount {
    <# Counts list items page by page (Graph does not support $count on list items) and stops at -Max, returning "<Max>+" when the list is larger. #>
    param([Parameter(Mandatory = $true)] [string]$ListUri, [Parameter(Mandatory = $true)] [int]$Max)
    $count = 0
    $nextLink = "$ListUri/items?`$select=id"
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject -ErrorAction Stop
        $count += @($page.value).Count
        if ($count -ge $Max) { return "$Max+" }
        $nextLink = $page.'@odata.nextLink'
        Start-Sleep -Milliseconds 100
    }
    return $count
}
#endregion Helpers

#region Main
if (-not $AllSites -and -not $SiteUrl -and -not $SiteId) { throw 'Specify -SiteUrl, -SiteId or -AllSites.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath ('SPOLists_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
try { Connect-GraphIfNeeded -Scopes @('Sites.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
if ($AllSites) { Write-Warning 'Inventorying every site in the tenant can take a long time; use -SiteUrl to narrow the scope.' }
try { $sites = @(Get-TargetSite -SiteUrl $SiteUrl -SiteId $SiteId -All:$AllSites) }
catch { throw "Failed to resolve the target sites: $($_.Exception.Message)" }

# Built-in column groups; columns outside these groups (typically "Custom Columns") were added by site owners or apps.
$systemColumnGroups = @('_Hidden', 'Base Columns', 'Core Document Columns', 'Core Contact and Calendar Columns', 'Core Task and Issue Columns',
    'Content Feedback', 'Display Template Columns', 'Document and Record Management Columns', 'Enterprise Keywords Group', 'Extended Columns',
    'Page Layout Columns', 'Publishing Columns', 'Reports', 'Status Indicators', 'Translation Columns')
$listSelect = '$select=id,displayName,name,createdDateTime,lastModifiedDateTime,list,webUrl,system'
$records = New-Object -TypeName System.Collections.Generic.List[object]
$hiddenCount = 0; $siteCounter = 0
foreach ($site in $sites) {
    $siteCounter++
    Write-Progress -Activity 'Inventorying lists' -Status "$siteCounter of $($sites.Count): $($site.displayName)" -PercentComplete ([int](($siteCounter / $sites.Count) * 100))
    try { $lists = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/lists?$listSelect") }
    catch { Write-Warning "Could not list the lists of '$($site.webUrl)': $($_.Exception.Message)"; continue }
    foreach ($list in $lists) {
        $isSystem = ($null -ne $list.system)
        $isHidden = ($list.list.hidden -eq $true)
        if (($isSystem -or $isHidden) -and -not $IncludeHidden) { $hiddenCount++; continue }
        $listUri = "https://graph.microsoft.com/v1.0/sites/$($site.id)/lists/$($list.id)"
        $itemCount = $null; $columnCount = $null; $customColumns = $null
        if ($IncludeItemCounts) {
            try { $itemCount = Get-ListItemCount -ListUri $listUri -Max $MaxCountPerList }
            catch { Write-Warning "Could not count the items of '$($list.displayName)' in '$($site.webUrl)': $($_.Exception.Message)" }
        }
        if ($IncludeColumns) {
            try {
                $columns = @(Invoke-GraphPaged -Uri "$listUri/columns?`$select=name,displayName,columnGroup,readOnly")
                $columnCount = $columns.Count
                $customColumns = (@($columns | Where-Object { $_.readOnly -ne $true -and $systemColumnGroups -notcontains [string]$_.columnGroup } | ForEach-Object { $_.displayName }) -join '; ')
                Start-Sleep -Milliseconds 100
            }
            catch { Write-Warning "Could not read the columns of '$($list.displayName)' in '$($site.webUrl)': $($_.Exception.Message)" }
        }
        $records.Add([PSCustomObject]@{
                Site                = $site.displayName
                SiteUrl             = $site.webUrl
                List                = $list.displayName
                Template            = $list.list.template
                Hidden              = $isHidden
                IsSystem            = $isSystem
                ContentTypesEnabled = ($list.list.contentTypesEnabled -eq $true)
                ItemCount           = $itemCount
                ColumnCount         = $columnCount
                CustomColumns       = $customColumns
                Created             = $(if ($list.createdDateTime) { [datetime]$list.createdDateTime })
                LastModified        = $(if ($list.lastModifiedDateTime) { [datetime]$list.lastModifiedDateTime })
                WebUrl              = $list.webUrl
                ListId              = $list.id
            })
    }
}
Write-Progress -Activity 'Inventorying lists' -Completed

$output = @($records | Sort-Object -Property Site, List)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No lists matched the selected filters; no CSV was written.' }

Write-Host 'SharePoint lists inventory summary' -ForegroundColor Cyan
Write-Host ('  Sites scanned             : {0}; lists exported: {1}; hidden/system lists skipped: {2}' -f $sites.Count, $output.Count, $hiddenCount)
Write-Host '  Lists by template:'
foreach ($group in ($output | Group-Object -Property Template | Sort-Object -Property Count -Descending)) { Write-Host ('    {0,-22} {1,6}' -f $group.Name, $group.Count) }
if ($IncludeItemCounts) { Write-Host ('  Lists at or above {0} items : {1}' -f $MaxCountPerList, @($output | Where-Object { "$($_.ItemCount)" -like '*+' }).Count) -ForegroundColor Yellow }
Write-Host ('  Rows exported             : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
