<#
.SYNOPSIS
    Reports the site collection administrators of every SharePoint Online site and flags sites without a human admin, external admins and admin sprawl.
.DESCRIPTION
    Enumerates site collections with Get-SPOSite -Limit All (OneDrive with -IncludeOneDrive, a subset with -SiteUrl) and reads
    the users of each site with Get-SPOUser -Site -Limit All, keeping those with IsSiteAdmin. Produces one row per admin
    assignment with the site, template, primary owner, admin login (cleaned to a UPN), display name, IsGroup (security group or
    admin role claim such as Company Administrator) and IsExternal (#ext# guest accounts), plus per-site findings: no human
    admin, external admin, more than -MaxAdmins admins. Exports to CSV and prints a summary.
.PARAMETER TenantName
    Tenant name prefix, for example contoso for https://contoso-admin.sharepoint.com.
.PARAMETER SiteUrl
    Only report these site collections; wildcards are allowed, for example https://contoso.sharepoint.com/sites/Proj*.
.PARAMETER IncludeOneDrive
    Also scan OneDrive personal sites (one call per OneDrive, slow in large tenants).
.PARAMETER MaxAdmins
    Sites with more site collection admins than this are flagged TooManyAdmins. Default 5.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOSiteCollectionAdmins_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOSiteCollectionAdminsReport.ps1 -TenantName contoso
    Lists every site collection admin of every site and prints the sites without a human admin or with external admins.
.EXAMPLE
    PS> .\Get-SPOSiteCollectionAdminsReport.ps1 -TenantName contoso -IncludeOneDrive -MaxAdmins 2 -PassThru | Where-Object { $_.Findings }
    Scans OneDrives as well and returns only the rows of sites with a finding, for example OneDrives with extra admins left over from offboarding.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x on Windows, Microsoft.Online.SharePoint.PowerShell
    Permissions : SharePoint Administrator role (Get-SPOUser reads the site user list through the admin endpoint); Global Reader may be denied on some sites.
    Category    : SharePoint administration (SPO module)
    Changes     : No
    Notes       : The SharePoint Online Management Shell runs on Windows only. One Get-SPOUser call per site; expect a few seconds
                  per site and throttling in very large tenants - narrow with -SiteUrl. Sites with LockState NoAccess and redirect
                  sites cannot be read and are reported as QueryFailed. For group-connected sites the group owners appear as a
                  single claim row (IsGroup = True); the individual owners live in Entra ID.
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/get-spouser
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Online.SharePoint.PowerShell

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter()]
    [string[]]$SiteUrl,

    [Parameter()]
    [switch]$IncludeOneDrive,

    [Parameter()]
    [ValidateRange(1, 1000)]
    [int]$MaxAdmins = 5,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPOSiteCollectionAdmins_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-SpoIfNeeded -AdminUrl "https://$TenantName-admin.sharepoint.com"
    $sites = @(Get-SPOSite -Limit All -ErrorAction Stop | Where-Object { $_.Template -ne 'REDIRECTSITE#0' })
    if ($IncludeOneDrive) { $sites += @(Get-SPOSite -IncludePersonalSite $true -Limit All -Filter "Url -like '-my.sharepoint.com/personal/'" -ErrorAction Stop) }
}
catch {
    throw "Failed to enumerate site collections: $($_.Exception.Message)"
}
if ($null -ne $SiteUrl -and $SiteUrl.Count -gt 0) {
    $sites = @($sites | Where-Object { $url = $_.Url; @($SiteUrl | Where-Object { $url -like $_ -or $url.TrimEnd('/') -eq $_.TrimEnd('/') }).Count -gt 0 })
}
Write-Verbose "Scanning $($sites.Count) site collections."

$records = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($site in $sites) {
    $counter++
    Write-Progress -Activity 'Reading site collection administrators' -Status "$counter of $($sites.Count): $($site.Url)" -PercentComplete ([int](($counter / $sites.Count) * 100))
    $template = ConvertTo-TemplateName -Template ([string]$site.Template)
    try {
        $admins = @(Get-SPOUser -Site $site.Url -Limit All -ErrorAction Stop | Where-Object { $_.IsSiteAdmin })
    }
    catch {
        Write-Warning "Could not read users of $($site.Url): $($_.Exception.Message)"
        $records.Add([PSCustomObject]@{
                SiteUrl = $site.Url; SiteTitle = $site.Title; Template = $template; PrimaryOwner = $site.Owner; Admin = $null; AdminDisplayName = $null
                AdminLoginName = $null; IsGroup = $null; IsExternal = $null; AdminCount = $null; Findings = 'QueryFailed: ' + $_.Exception.Message
            })
        continue
    }
    $humanAdmins = @($admins | Where-Object { -not $_.IsGroup })
    $findings = @()
    if ($humanAdmins.Count -eq 0) { $findings += 'NoHumanAdmin' }
    if (@($admins | Where-Object { $_.LoginName -like '*#ext#*' }).Count -gt 0) { $findings += 'ExternalAdmin' }
    if ($admins.Count -gt $MaxAdmins) { $findings += 'TooManyAdmins' }
    $siteFindings = $findings -join '; '
    if ($admins.Count -eq 0) {
        $records.Add([PSCustomObject]@{
                SiteUrl = $site.Url; SiteTitle = $site.Title; Template = $template; PrimaryOwner = $site.Owner; Admin = $null; AdminDisplayName = $null
                AdminLoginName = $null; IsGroup = $null; IsExternal = $null; AdminCount = 0; Findings = $siteFindings
            })
        continue
    }
    foreach ($admin in $admins) {
        # Claims-encoded logins (i:0#.f|membership|user@contoso.com, c:0t.c|tenant|<guid>) are reduced to the part after the last pipe.
        $loginName = [string]$admin.LoginName
        $cleanLogin = $loginName
        if ($cleanLogin.Contains('|')) { $cleanLogin = $cleanLogin.Substring($cleanLogin.LastIndexOf('|') + 1) }
        $records.Add([PSCustomObject]@{
                SiteUrl          = $site.Url
                SiteTitle        = $site.Title
                Template         = $template
                PrimaryOwner     = $site.Owner
                Admin            = $cleanLogin
                AdminDisplayName = $admin.DisplayName
                AdminLoginName   = $loginName
                IsGroup          = [bool]$admin.IsGroup
                IsExternal       = ($loginName -like '*#ext#*')
                AdminCount       = $admins.Count
                Findings         = $siteFindings
            })
    }
}
Write-Progress -Activity 'Reading site collection administrators' -Completed

$output = @($records | Sort-Object -Property SiteUrl, Admin)
if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No sites matched the selected filters; no CSV was written.'
}

$siteRows = @($output | Group-Object -Property SiteUrl | ForEach-Object { $_.Group[0] })
$distinctHumans = @($output | Where-Object { $_.IsGroup -eq $false } | Select-Object -ExpandProperty Admin -Unique).Count
Write-Host ''
Write-Host 'SharePoint site collection administrators summary' -ForegroundColor Cyan
Write-Host ('  Sites scanned                : {0} (OneDrive included: {1})' -f $sites.Count, $IncludeOneDrive.IsPresent)
Write-Host ('  Admin assignments            : {0} (distinct human admins: {1})' -f @($output | Where-Object { $null -ne $_.Admin }).Count, $distinctHumans)
Write-Host ('  Sites without a human admin  : {0}' -f @($siteRows | Where-Object { $_.Findings -like '*NoHumanAdmin*' }).Count) -ForegroundColor Yellow
Write-Host ('  Sites with external admins   : {0}' -f @($siteRows | Where-Object { $_.Findings -like '*ExternalAdmin*' }).Count) -ForegroundColor Yellow
Write-Host ('  Sites with more than {0,2} admins: {1}' -f $MaxAdmins, @($siteRows | Where-Object { $_.Findings -like '*TooManyAdmins*' }).Count) -ForegroundColor Yellow
Write-Host ('  Sites that could not be read : {0}' -f @($siteRows | Where-Object { $_.Findings -like 'QueryFailed*' }).Count)
Write-Host ('  Rows exported                : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
