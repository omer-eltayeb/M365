<#
.SYNOPSIS
    Reports the external sharing configuration of every SharePoint Online site and flags sites configured more openly than the tenant.
.DESCRIPTION
    Enumerates all site collections with Get-SPOSite -Limit All and shapes one row per site with template, owner, effective
    and site-defined sharing capability (plus the admin center label), storage, lock state and last content change. With
    -Detailed every site is re-read with Get-SPOSite -Identity -Detailed to add the default link type and permission,
    Anyone-link expiration, domain restrictions, conditional access policy, sensitivity label and DenyAddAndCustomizePages.
    The tenant default from Get-SPOTenant drives the MoreOpenThanTenant flag. Exports to CSV and prints a summary per level.
.PARAMETER TenantName
    Tenant name prefix, for example contoso for https://contoso-admin.sharepoint.com.
.PARAMETER Detailed
    Re-read every site with Get-SPOSite -Identity -Detailed to fill the link, domain, policy and label columns (one call per site, slow in large tenants).
.PARAMETER OnlyExternalSharingEnabled
    Export only sites whose effective sharing capability is not Disabled.
.PARAMETER LabelMap
    Hashtable of sensitivity label GUID to label name used to resolve the SensitivityLabel column; without it the GUID is shown.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOSitesSharing_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOSitesSharingReport.ps1 -TenantName contoso
    Exports the sharing capability of every site and prints how many sites allow Anyone links, new guests, existing guests or no external sharing.
.EXAMPLE
    PS> .\Get-SPOSitesSharingReport.ps1 -TenantName contoso -Detailed -OnlyExternalSharingEnabled -OutputPath C:\Temp\ExternalSharing.csv -Verbose
    Lists only externally shareable sites with their default link settings, domain restrictions, conditional access policy and labels
    (pass -LabelMap with a GUID-to-name hashtable, for example built from Get-Label, to show label names instead of GUIDs).
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
    Notes       : The SharePoint Online Management Shell runs on Windows only. SharingCapability is the effective value (never
                  above the tenant level); SiteDefinedSharingCapability is the configured site value that becomes effective as
                  soon as the tenant level is raised, so MoreOpenThanTenant compares that one. OneDrive and redirect sites are skipped.
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/get-sposite
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/get-spotenant
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Online.SharePoint.PowerShell

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter()]
    [switch]$Detailed,

    [Parameter()]
    [switch]$OnlyExternalSharingEnabled,

    [Parameter()]
    [hashtable]$LabelMap,

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPOSitesSharing_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-SpoIfNeeded -AdminUrl "https://$TenantName-admin.sharepoint.com"
    $tenant = Get-SPOTenant -ErrorAction Stop
}
catch {
    throw "Failed to connect to the SharePoint Online admin center: $($_.Exception.Message)"
}

# Admin center labels and a strictness rank for the four SharingCapability values.
$sharingLevels = @{
    Disabled = 'Only people in your organization'; ExistingExternalUserSharingOnly = 'Existing guests'
    ExternalUserSharingOnly = 'New and existing guests'; ExternalUserAndGuestSharing = 'Anyone'
}
$sharingRank = @{ Disabled = 0; ExistingExternalUserSharingOnly = 1; ExternalUserSharingOnly = 2; ExternalUserAndGuestSharing = 3 }
$tenantSharing = [string]$tenant.SharingCapability
Write-Verbose "Tenant sharing capability: $tenantSharing."

try {
    $sites = @(Get-SPOSite -Limit All -ErrorAction Stop | Where-Object { $_.Template -ne 'REDIRECTSITE#0' })
}
catch {
    throw "Failed to enumerate site collections: $($_.Exception.Message)"
}
Write-Verbose "Found $($sites.Count) site collections."

$records = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($site in $sites) {
    $counter++
    Write-Progress -Activity 'Reading site sharing settings' -Status "$counter of $($sites.Count): $($site.Url)" -PercentComplete ([int](($counter / $sites.Count) * 100))
    if ($Detailed) {
        try {
            $site = Get-SPOSite -Identity $site.Url -Detailed -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not read detailed properties of $($site.Url); basic properties are used: $($_.Exception.Message)"
        }
    }
    $effective = [string]$site.SharingCapability
    $siteDefined = [string]$site.SiteDefinedSharingCapability
    if ([string]::IsNullOrWhiteSpace($siteDefined)) { $siteDefined = $effective }
    $groupId = [string]$site.GroupId
    if ($groupId -eq [guid]::Empty.ToString()) { $groupId = $null }
    $labelName = [string]$site.SensitivityLabel
    if ([string]::IsNullOrWhiteSpace($labelName) -or $labelName -eq [guid]::Empty.ToString()) { $labelName = $null }
    elseif ($null -ne $LabelMap -and $LabelMap.ContainsKey($labelName)) { $labelName = $LabelMap[$labelName] }
    $moreOpen = $false
    if ($sharingRank.ContainsKey($siteDefined) -and $sharingRank.ContainsKey($tenantSharing)) { $moreOpen = $sharingRank[$siteDefined] -gt $sharingRank[$tenantSharing] }

    # Detailed-only properties are $null on the basic site object, so the columns stay empty without -Detailed.
    $records.Add([PSCustomObject]@{
            Url                                         = $site.Url
            Title                                       = $site.Title
            Template                                    = ConvertTo-TemplateName -Template ([string]$site.Template)
            TemplateId                                  = $site.Template
            Owner                                       = $site.Owner
            GroupId                                     = $groupId
            IsTeamsConnected                            = [bool]$site.IsTeamsConnected
            SharingCapability                           = $effective
            SharingLevel                                = $sharingLevels[$effective]
            SiteDefinedSharingCapability                = $siteDefined
            MoreOpenThanTenant                          = $moreOpen
            DefaultSharingLinkType                      = $site.DefaultSharingLinkType
            DefaultLinkPermission                       = $site.DefaultLinkPermission
            AnonymousLinkExpirationInDays               = $site.AnonymousLinkExpirationInDays
            OverrideTenantAnonymousLinkExpirationPolicy = $site.OverrideTenantAnonymousLinkExpirationPolicy
            SharingDomainRestrictionMode                = $site.SharingDomainRestrictionMode
            SharingAllowedDomainList                    = $site.SharingAllowedDomainList
            ConditionalAccessPolicy                     = $site.ConditionalAccessPolicy
            SensitivityLabel                            = $labelName
            DenyAddAndCustomizePages                    = $site.DenyAddAndCustomizePages
            StorageUsedGB                               = [math]::Round(([double]$site.StorageUsageCurrent) / 1024, 2)
            StorageQuotaGB                              = [math]::Round(([double]$site.StorageQuota) / 1024, 2)
            LockState                                   = [string]$site.LockState
            LastContentModifiedDate                     = $site.LastContentModifiedDate
        })
}
Write-Progress -Activity 'Reading site sharing settings' -Completed

$output = @($records)
if ($OnlyExternalSharingEnabled) { $output = @($output | Where-Object { $_.SharingCapability -ne 'Disabled' }) }
$output = @($output | Sort-Object -Property Url)

if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No sites matched the selected filters; no CSV was written.'
}

Write-Host ''
Write-Host 'SharePoint site sharing summary' -ForegroundColor Cyan
Write-Host ('  Tenant default sharing     : {0} ({1})' -f $tenantSharing, $sharingLevels[$tenantSharing])
Write-Host ('  Sites evaluated            : {0} (detailed: {1})' -f $records.Count, $Detailed.IsPresent)
foreach ($group in ($records | Group-Object -Property SharingLevel | Sort-Object -Property Count -Descending)) { Write-Host ('    {0,-34} {1}' -f $group.Name, $group.Count) }
Write-Host ('  More open than tenant      : {0}' -f @($records | Where-Object { $_.MoreOpenThanTenant }).Count) -ForegroundColor Yellow
Write-Host ('  Rows exported              : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
