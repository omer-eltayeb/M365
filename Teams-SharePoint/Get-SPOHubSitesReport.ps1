<#
.SYNOPSIS
    Reports every SharePoint Online hub site with its settings, join permissions, parent hub and associated sites.
.DESCRIPTION
    Reads all hubs with Get-SPOHubSite (title, URL, description, logo, join approval, permissions sync, navigation setting,
    principals allowed to join, hub-to-hub parent) and all site collections with Get-SPOSite -Limit All, then joins them on
    HubSiteId. Produces one row per associated site (with template, storage and last content change), one row per hub that
    has no associated sites and, with -IncludeUnassociated, one row per site that belongs to no hub. The summary shows the
    number of sites per hub, empty hubs and unassociated sites.
.PARAMETER TenantName
    Tenant name prefix, for example contoso for https://contoso-admin.sharepoint.com.
.PARAMETER IncludeUnassociated
    Also export sites that are not associated with any hub (RowType = Unassociated); their count is always printed.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOHubSites_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOHubSitesReport.ps1 -TenantName contoso
    Exports all hub associations and prints how many sites hang off each hub and which hubs are empty.
.EXAMPLE
    PS> .\Get-SPOHubSitesReport.ps1 -TenantName contoso -IncludeUnassociated -PassThru | Where-Object { $_.RowType -eq 'Unassociated' -and $_.TemplateId -eq 'SITEPAGEPUBLISHING#0' }
    Lists communication sites that are not attached to any hub, typical candidates for an intranet navigation clean-up.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x on Windows, Microsoft.Online.SharePoint.PowerShell
    Permissions : SharePoint Administrator role; Global Reader is sufficient for this read-only report.
    Category    : SharePoint administration (SPO module)
    Changes     : No
    Notes       : The SharePoint Online Management Shell runs on Windows only. A hub's own HubSiteId equals its hub ID, so the hub
                  itself is not counted as an associated site. An empty JoinPermissions column means anyone with a site can
                  associate it with the hub. OneDrive, redirect and system sites are excluded from the unassociated count.
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/get-spohubsite
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Online.SharePoint.PowerShell

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter()]
    [switch]$IncludeUnassociated,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-SpoIfNeeded {
    <# Connects to the SharePoint Online admin endpoint only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdminUrl
    )
    $connected = $false
    try { $null = Get-SPOTenant -ErrorAction Stop; $connected = $true } catch { $connected = $false }
    if (-not $connected) {
        Write-Verbose "Connecting to SharePoint Online admin center $AdminUrl."
        Connect-SPOService -Url $AdminUrl -ErrorAction Stop
    }
}

function ConvertTo-TemplateName {
    <# Maps a site template id to the name shown in the SharePoint admin center; unknown ids are returned unchanged. #>
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$Template
    )
    $names = @{
        'GROUP#0' = 'Team site (Microsoft 365 group)'; 'STS#3' = 'Team site (no group)'; 'STS#0' = 'Classic team site'
        'SITEPAGEPUBLISHING#0' = 'Communication site'; 'TEAMCHANNEL#0' = 'Teams private channel site'; 'TEAMCHANNEL#1' = 'Teams shared channel site'
        'SPSPERS#10' = 'OneDrive'; 'SPSMSITEHOST#0' = 'OneDrive host'; 'APPCATALOG#0' = 'App catalog'; 'SRCHCEN#0' = 'Search center'
        'POINTPUBLISHINGHUB#0' = 'PointPublishing hub'; 'POINTPUBLISHINGTOPIC#0' = 'PointPublishing topic'; 'EHS#1' = 'Classic team site (SPO configuration)'
        'REDIRECTSITE#0' = 'Redirect site'; 'BLANKINTERNET#0' = 'Classic publishing site'
    }
    if ($names.ContainsKey($Template)) { return $names[$Template] }
    return $Template
}

function ConvertTo-HubRow {
    <# Builds one output row from a hub (may be $null for unassociated sites) and a site (may be $null for empty hubs). #>
    param(
        [Parameter()]
        [string]$RowType,

        [Parameter()]
        [object]$Hub,

        [Parameter()]
        [object]$Site,

        [Parameter()]
        [hashtable]$HubsById
    )
    $parentHub = $null
    $joinPrincipals = $null
    if ($null -ne $Hub) {
        $parentId = [string]$Hub.ParentHubSiteId
        if ($HubsById.ContainsKey($parentId)) { $parentHub = $HubsById[$parentId].SiteUrl }
        $principals = @($Hub.Permissions) | Where-Object { $null -ne $_ } | ForEach-Object { if ([string]::IsNullOrWhiteSpace($_.DisplayName)) { $_.PrincipalName } else { $_.DisplayName } }
        $joinPrincipals = @($principals) -join '; '
    }
    $usedGB = $null
    $templateName = $null
    if ($null -ne $Site) {
        $usedGB = [math]::Round(([double]$Site.StorageUsageCurrent) / 1024, 2)
        $templateName = ConvertTo-TemplateName -Template ([string]$Site.Template)
    }
    # Property access on a $null hub or site yields $null, which keeps the unused half of the row empty.
    return [PSCustomObject]@{
        RowType                 = $RowType
        HubTitle                = $Hub.Title
        HubUrl                  = $Hub.SiteUrl
        HubId                   = $Hub.ID
        ParentHubUrl            = $parentHub
        HubDescription          = $Hub.Description
        LogoUrl                 = $Hub.LogoUrl
        RequiresJoinApproval    = $Hub.RequiresJoinApproval
        EnablePermissionsSync   = $Hub.EnablePermissionsSync
        HideNameInNavigation    = $Hub.HideNameInNavigation
        JoinPermissions         = $joinPrincipals
        SiteUrl                 = $Site.Url
        SiteTitle               = $Site.Title
        Template                = $templateName
        TemplateId              = $Site.Template
        StorageUsedGB           = $usedGB
        LastContentModifiedDate = $Site.LastContentModifiedDate
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPOHubSites_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-SpoIfNeeded -AdminUrl "https://$TenantName-admin.sharepoint.com"
    $hubs = @(Get-SPOHubSite -ErrorAction Stop)
    $sites = @(Get-SPOSite -Limit All -ErrorAction Stop)
}
catch {
    throw "Failed to read hub sites or site collections: $($_.Exception.Message)"
}
Write-Verbose "Found $($hubs.Count) hub sites and $($sites.Count) site collections."

$hubsById = @{}
foreach ($hub in $hubs) { $hubsById[[string]$hub.ID] = $hub }
$systemTemplates = @('REDIRECTSITE#0', 'SPSMSITEHOST#0', 'APPCATALOG#0', 'SRCHCEN#0', 'POINTPUBLISHINGHUB#0', 'POINTPUBLISHINGTOPIC#0')
$records = New-Object -TypeName System.Collections.Generic.List[object]
$unassociated = New-Object -TypeName System.Collections.Generic.List[object]
$associatedCount = @{}
$counter = 0
foreach ($site in $sites) {
    $counter++
    if ($counter % 200 -eq 0) { Write-Progress -Activity 'Matching sites to hubs' -Status "$counter of $($sites.Count)" -PercentComplete ([int](($counter / $sites.Count) * 100)) }
    $hubId = [string]$site.HubSiteId
    if ([string]::IsNullOrWhiteSpace($hubId) -or $hubId -eq [guid]::Empty.ToString()) {
        if ($systemTemplates -notcontains [string]$site.Template) { $unassociated.Add($site) }
        continue
    }
    if (-not $hubsById.ContainsKey($hubId)) { Write-Warning "$($site.Url) references unknown hub $hubId."; continue }
    $hub = $hubsById[$hubId]
    # The hub site carries its own hub ID; only other sites count as associated.
    if ($site.Url.TrimEnd('/') -eq ([string]$hub.SiteUrl).TrimEnd('/')) { continue }
    $associatedCount[$hubId] = 1 + [int]$associatedCount[$hubId]
    $records.Add((ConvertTo-HubRow -RowType 'AssociatedSite' -Hub $hub -Site $site -HubsById $hubsById))
}
Write-Progress -Activity 'Matching sites to hubs' -Completed
foreach ($hub in $hubs) {
    if (-not $associatedCount.ContainsKey([string]$hub.ID)) { $records.Add((ConvertTo-HubRow -RowType 'HubWithoutSites' -Hub $hub -Site $null -HubsById $hubsById)) }
}
if ($IncludeUnassociated) {
    foreach ($site in $unassociated) { $records.Add((ConvertTo-HubRow -RowType 'Unassociated' -Hub $null -Site $site -HubsById $hubsById)) }
}

$output = @($records | Sort-Object -Property RowType, HubTitle, SiteUrl)
if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No hub sites or associations were found; no CSV was written.'
}

Write-Host ''
Write-Host 'SharePoint hub sites summary' -ForegroundColor Cyan
Write-Host ('  Hub sites                 : {0}' -f $hubs.Count)
Write-Host ('  Hub-to-hub associations   : {0}' -f @($hubs | Where-Object { $hubsById.ContainsKey([string]$_.ParentHubSiteId) }).Count)
foreach ($hub in ($hubs | Sort-Object -Property Title)) {
    Write-Host ('    {0,5}  {1} ({2})' -f [int]$associatedCount[[string]$hub.ID], $hub.Title, $hub.SiteUrl)
}
Write-Host ('  Hubs without sites        : {0}' -f @($records | Where-Object { $_.RowType -eq 'HubWithoutSites' }).Count) -ForegroundColor Yellow
Write-Host ('  Sites not in any hub      : {0}' -f $unassociated.Count)
Write-Host ('  Rows exported             : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
