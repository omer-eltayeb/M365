<#
.SYNOPSIS
    Reports every sharing link and direct permission on shared files and folders in SharePoint sites, flagging anonymous and external access.
.DESCRIPTION
    Enumerates the document libraries of the selected sites (-SiteUrl, -SiteId or -AllSites) with the delta API, keeps the
    items that carry the 'shared' facet and reads their permissions with /drives/{id}/items/{id}/permissions. Each permission
    becomes one row: link type and scope (anonymous, organization, users, existingAccess), roles, grantees, expiration,
    password / download protection, inheritance and IsExternal (guest #EXT# accounts, e-mail domains outside the verified or
    -InternalDomains list, anonymous links). Prints the anonymous links, external domains and most-shared items.
.PARAMETER SiteUrl
    One or more site collection URLs, for example https://contoso.sharepoint.com/sites/Marketing.
.PARAMETER SiteId
    One or more Graph site ids (hostname,siteCollectionId,webId), for example from Get-SPOSitesInventoryGraph.ps1.
.PARAMETER AllSites
    Scan every non-personal site in the tenant. Slow in large tenants; the script warns before it starts.
.PARAMETER InternalDomains
    Domains treated as internal. Defaults to the tenant's verified domains (/organization) or, when that call is not permitted,
    the signed-in account's domain; pass the list explicitly in multi-domain tenants or app-only sessions.
.PARAMETER OnlyAnonymous
    Export only "anyone with the link" (anonymous) sharing links.
.PARAMETER OnlyExternal
    Export only permissions flagged IsExternal (guests, external domains and anonymous links).
.PARAMETER IncludeInherited
    Also export permissions inherited from a parent folder or the library. By default only permissions set on the item itself are listed.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOSharedItems_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOSharedItemsReport.ps1 -SiteUrl https://contoso.sharepoint.com/sites/Finance
    Lists every sharing link and direct permission on shared items in the Finance site.
.EXAMPLE
    PS> .\Get-SPOSharedItemsReport.ps1 -AllSites -OnlyExternal -InternalDomains contoso.com, contoso.onmicrosoft.com -OutputPath C:\Temp\External.csv
    Tenant-wide list of items exposed to guests, external domains or anonymous links.
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
                  One permissions call per shared item with a 150 ms pause; the SDK retries HTTP 429. Items inside a shared
                  folder inherit its permissions and are hidden unless -IncludeInherited is used.
.LINK
    https://learn.microsoft.com/graph/api/driveitem-list-permissions
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()] [string[]]$SiteUrl,
    [Parameter()] [string[]]$SiteId,
    [Parameter()] [switch]$AllSites,
    [Parameter()] [string[]]$InternalDomains,
    [Parameter()] [switch]$OnlyAnonymous,
    [Parameter()] [switch]$OnlyExternal,
    [Parameter()] [switch]$IncludeInherited,
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
    $nextLink = "$DriveUri/root/delta?`$select=id,name,folder,root,parentReference,webUrl,shared"
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject -ErrorAction Stop
        foreach ($item in @($page.value)) { if ($null -eq $item.root) { $items.Add($item) } }
        $nextLink = $page.'@odata.nextLink'
        Start-Sleep -Milliseconds 100
    }
    return $items
}

function Get-GranteeInfo {
    <# Flattens grantedToV2 / grantedToIdentitiesV2 into "Name <email> [kind]" labels and detects external grantees (guest #EXT# logins or e-mail domains outside -InternalDomains). #>
    param([Parameter(Mandatory = $true)] [object]$Permission, [Parameter()] [string[]]$InternalDomains)
    $labels = New-Object -TypeName System.Collections.Generic.List[string]
    $externalDomains = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($identity in (@($Permission.grantedToV2) + @($Permission.grantedToIdentitiesV2) | Where-Object { $null -ne $_ })) {
        foreach ($kind in 'user', 'siteUser', 'group', 'siteGroup', 'application') {
            $actor = $identity.$kind
            if ($null -eq $actor) { continue }
            $label = [string]$actor.displayName
            if (-not [string]::IsNullOrEmpty($actor.email)) { $label += " <$($actor.email)>" }
            $labels.Add("$label [$kind]")
            $domain = ([string]$actor.email).Split('@')[-1].ToLowerInvariant()
            $isGuest = ([string]$actor.loginName -match '#ext#')
            if ($isGuest -and -not $domain) { $domain = '(guest)' }
            if ($domain -and ($isGuest -or $InternalDomains -notcontains $domain)) { $externalDomains.Add($domain) }
        }
    }
    return [PSCustomObject]@{ GrantedTo = ($labels -join '; '); ExternalDomains = (@($externalDomains | Select-Object -Unique) -join ', '); IsExternal = ($externalDomains.Count -gt 0) }
}
#endregion Helpers

#region Main
if (-not $AllSites -and -not $SiteUrl -and -not $SiteId) { throw 'Specify -SiteUrl, -SiteId or -AllSites.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath ('SPOSharedItems_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
try { Connect-GraphIfNeeded -Scopes @('Sites.Read.All', 'Files.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$domains = @($InternalDomains | ForEach-Object { $_.ToLowerInvariant() })
if ($domains.Count -eq 0) {
    # Reading /organization needs a directory read scope; without it fall back to the signed-in account's domain.
    try { $domains = @((Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains')[0].verifiedDomains | ForEach-Object { $_.name.ToLowerInvariant() }) }
    catch { $domains = @(([string](Get-MgContext).Account).Split('@')[-1].ToLowerInvariant()); Write-Warning "Verified domains not readable; only '$($domains[0])' is internal." }
}
Write-Verbose "Internal domains: $($domains -join ', ')"
if ($AllSites) { Write-Warning 'Scanning every document library in the tenant can take a long time; use -SiteUrl to narrow the scope.' }
try { $sites = @(Get-TargetSite -SiteUrl $SiteUrl -SiteId $SiteId -All:$AllSites) }
catch { throw "Failed to resolve the target sites: $($_.Exception.Message)" }

$linkAudience = @{ anonymous = '(anyone with the link)'; organization = '(anyone in the organization)'; existingAccess = '(people with existing access)' }
$records = New-Object -TypeName System.Collections.Generic.List[object]
$sharedItemCount = 0; $siteCounter = 0
foreach ($site in $sites) {
    $siteCounter++
    Write-Progress -Activity 'Reading sharing permissions' -Status "$siteCounter of $($sites.Count): $($site.displayName)" -PercentComplete ([int](($siteCounter / $sites.Count) * 100))
    try { $drives = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/drives?`$select=id,name") }
    catch { Write-Warning "Could not list the libraries of '$($site.webUrl)': $($_.Exception.Message)"; continue }
    foreach ($drive in $drives) {
        try { $sharedItems = @(Get-DriveItemList -DriveUri "https://graph.microsoft.com/v1.0/drives/$($drive.id)" | Where-Object { $null -ne $_.shared }) }
        catch { Write-Warning "Could not enumerate library '$($drive.name)' in '$($site.webUrl)': $($_.Exception.Message)"; continue }
        foreach ($item in $sharedItems) {
            $sharedItemCount++
            try { $permissions = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/drives/$($drive.id)/items/$($item.id)/permissions") }
            catch { Write-Warning "Could not read the permissions of '$($item.webUrl)': $($_.Exception.Message)"; continue }
            Start-Sleep -Milliseconds 150
            foreach ($permission in $permissions) {
                $inherited = ($null -ne $permission.inheritedFrom)
                if ($inherited -and -not $IncludeInherited) { continue }
                $linkScope = [string]$permission.link.scope
                $grantee = Get-GranteeInfo -Permission $permission -InternalDomains $domains
                $isExternal = ($grantee.IsExternal -or $linkScope -eq 'anonymous')
                if (($OnlyAnonymous -and $linkScope -ne 'anonymous') -or ($OnlyExternal -and -not $isExternal)) { continue }
                $grantedTo = $grantee.GrantedTo
                if ([string]::IsNullOrEmpty($grantedTo) -and $linkAudience.ContainsKey($linkScope)) { $grantedTo = $linkAudience[$linkScope] }
                $records.Add([PSCustomObject]@{
                        Site               = $site.displayName
                        Library            = $drive.name
                        Item               = $item.name
                        ItemType           = $(if ($null -ne $item.folder) { 'Folder' } else { 'File' })
                        # parentReference.path is /drives/{id}/root:/Folder/Sub; keep the part after root: and append the name
                        Path               = [uri]::UnescapeDataString(("$($item.parentReference.path)/$($item.name)" -replace '^.*?root:', ''))
                        WebUrl             = $item.webUrl
                        PermissionId       = $permission.id
                        LinkType           = $permission.link.type
                        LinkScope          = $linkScope
                        Roles              = (@($permission.roles) -join ',')
                        GrantedTo          = $grantedTo
                        ExternalDomains    = $grantee.ExternalDomains
                        IsExternal         = $isExternal
                        ExpirationDateTime = $(if ($permission.expirationDateTime) { [datetime]$permission.expirationDateTime })
                        HasPassword        = ($permission.hasPassword -eq $true)
                        PreventsDownload   = ($permission.link.preventsDownload -eq $true)
                        Inherited          = $inherited
                        ItemId             = $item.id
                    })
            }
        }
    }
}
Write-Progress -Activity 'Reading sharing permissions' -Completed

$output = @($records)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No sharing permissions matched the selected filters; no CSV was written.' }

$externalDomainList = $output | Where-Object { $_.ExternalDomains } | ForEach-Object { $_.ExternalDomains -split ', ' }
$externalCount = @($output | Where-Object { $_.IsExternal }).Count
Write-Host 'SharePoint sharing summary' -ForegroundColor Cyan
Write-Host ('  Sites scanned / shared items     : {0} / {1}; permissions exported: {2} (external: {3})' -f $sites.Count, $sharedItemCount, $output.Count, $externalCount)
Write-Host ('  Anonymous "anyone" links         : {0}' -f @($output | Where-Object { $_.LinkScope -eq 'anonymous' }).Count) -ForegroundColor Yellow
Write-Host '  External shares by domain (top 10):'
foreach ($group in ($externalDomainList | Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 10)) { Write-Host ('    {0,6}  {1}' -f $group.Count, $group.Name) }
Write-Host '  Items with the most permissions (top 5):'
foreach ($group in ($output | Group-Object -Property WebUrl | Sort-Object -Property Count -Descending | Select-Object -First 5)) { Write-Host ('    {0,6}  {1}' -f $group.Count, $group.Name) }
Write-Host ('  Rows exported                    : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
