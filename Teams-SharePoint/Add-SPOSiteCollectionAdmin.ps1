<#
.SYNOPSIS
    Grants (or with -Remove revokes) site collection administrator rights for an account on selected SharePoint Online sites or OneDrives.
.DESCRIPTION
    Builds a target list from -SiteUrl, a CSV (-InputCsv with Url and optional Admin columns) or every site collection
    (-AllSites, OneDrive personal sites with -IncludeOneDrive), checks the current state with Get-SPOUser -Site -LoginName and
    changes only the sites where it differs, using Set-SPOUser -IsSiteCollectionAdmin $true (or $false with -Remove). Nothing is
    changed unless -Apply is present and every change honours -WhatIf / -Confirm. A results CSV documents the outcome per site.
    Typical uses: give an eDiscovery or migration account access to every OneDrive, or remove a leaver from all sites.
.PARAMETER TenantName
    Tenant name prefix, for example contoso for https://contoso-admin.sharepoint.com.
.PARAMETER Admin
    UPN of the user (or login name of a security group) to add or remove. Required unless every CSV row has an Admin column value.
.PARAMETER SiteUrl
    One or more site collection or OneDrive URLs.
.PARAMETER InputCsv
    CSV with a Url column and an optional Admin column that overrides -Admin per row.
.PARAMETER AllSites
    Target every site collection returned by Get-SPOSite -Limit All (redirect sites excluded).
.PARAMETER IncludeOneDrive
    With -AllSites, also target every OneDrive personal site.
.PARAMETER Remove
    Revoke site collection admin rights instead of granting them.
.PARAMETER Apply
    Perform the changes. Without this switch the script only reports what would change.
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\SPOSiteCollectionAdminChanges_<timestamp>.csv.
.EXAMPLE
    PS> .\Add-SPOSiteCollectionAdmin.ps1 -TenantName contoso -Admin ediscovery.svc@contoso.com -AllSites -IncludeOneDrive
    Shows on which sites and OneDrives the account is not yet a site collection admin, without changing anything.
.EXAMPLE
    PS> .\Add-SPOSiteCollectionAdmin.ps1 -TenantName contoso -Admin ediscovery.svc@contoso.com -AllSites -IncludeOneDrive -Apply -Confirm:$false
    Grants the account site collection admin rights everywhere it is missing, without prompting per site.
.EXAMPLE
    PS> .\Add-SPOSiteCollectionAdmin.ps1 -TenantName contoso -Admin former.admin@contoso.com -InputCsv .\sites.csv -Remove -Apply
    Removes the account from the sites in the CSV after confirmation.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x on Windows, Microsoft.Online.SharePoint.PowerShell
    Permissions : SharePoint Administrator role.
    Category    : SharePoint administration (SPO module)
    Changes     : Yes
    Notes       : The SharePoint Online Management Shell runs on Windows only. One Get-SPOUser call plus one Set-SPOUser call per
                  site - expect several minutes for thousands of OneDrives. Sites with LockState NoAccess are reported as Failed.
                  Site collection admins see all content of the site; record the business reason and revoke the access afterwards.
                  For OneDrive, the owner stays the primary admin; a secondary admin can also be set per site in the admin center.
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/set-spouser
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Online.SharePoint.PowerShell

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter()]
    [string]$Admin,

    [Parameter()]
    [string[]]$SiteUrl,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$AllSites,

    [Parameter()]
    [switch]$IncludeOneDrive,

    [Parameter()]
    [switch]$Remove,

    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [string]$OutputPath
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
#endregion Helpers

#region Main
if (@('SiteUrl', 'InputCsv', 'AllSites' | Where-Object { $PSBoundParameters.ContainsKey($_) }).Count -eq 0) { throw 'Specify the target sites with -SiteUrl, -InputCsv or -AllSites.' }
if ([string]::IsNullOrWhiteSpace($Admin) -and -not $PSBoundParameters.ContainsKey('InputCsv')) { throw 'Specify the account with -Admin (or provide an Admin column in -InputCsv).' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPOSiteCollectionAdminChanges_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-SpoIfNeeded -AdminUrl "https://$TenantName-admin.sharepoint.com"
}
catch {
    throw "Failed to connect to the SharePoint Online admin center: $($_.Exception.Message)"
}

$targets = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($url in @($SiteUrl)) { if (-not [string]::IsNullOrWhiteSpace($url)) { $targets.Add([PSCustomObject]@{ Url = $url.TrimEnd('/'); Admin = $Admin }) } }
if ($PSBoundParameters.ContainsKey('InputCsv')) {
    foreach ($row in @(Import-Csv -Path $InputCsv)) {
        if ($null -eq $row.PSObject.Properties['Url']) { throw "The CSV '$InputCsv' needs a Url column (optional: Admin)." }
        $rowAdmin = $Admin
        if ($null -ne $row.PSObject.Properties['Admin'] -and -not [string]::IsNullOrWhiteSpace($row.Admin)) { $rowAdmin = $row.Admin.Trim() }
        $targets.Add([PSCustomObject]@{ Url = ([string]$row.Url).TrimEnd('/'); Admin = $rowAdmin })
    }
}
if ($AllSites) {
    try {
        $sites = @(Get-SPOSite -Limit All -ErrorAction Stop | Where-Object { $_.Template -ne 'REDIRECTSITE#0' })
        if ($IncludeOneDrive) { $sites += @(Get-SPOSite -IncludePersonalSite $true -Limit All -Filter "Url -like '-my.sharepoint.com/personal/'" -ErrorAction Stop) }
    }
    catch {
        throw "Failed to enumerate site collections: $($_.Exception.Message)"
    }
    foreach ($site in $sites) { $targets.Add([PSCustomObject]@{ Url = $site.Url.TrimEnd('/'); Admin = $Admin }) }
}
$action = if ($Remove) { 'Revoke' } else { 'Grant' }
Write-Verbose "$action site collection admin on $($targets.Count) sites."

$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($target in $targets) {
    $counter++
    Write-Progress -Activity "$action site collection admin" -Status "$counter of $($targets.Count): $($target.Url)" -PercentComplete ([int](($counter / $targets.Count) * 100))
    $result = [PSCustomObject]@{ SiteUrl = $target.Url; Admin = $target.Admin; Action = $action; Result = $null; Detail = $null }
    $results.Add($result)
    try {
        if ([string]::IsNullOrWhiteSpace($target.Admin)) { $result.Result = 'Skipped'; $result.Detail = 'No admin account given for this site'; continue }
        # Get-SPOUser throws when the account is not in the site user list, which simply means it is not an admin yet.
        $isAdmin = $false
        try { $isAdmin = [bool](Get-SPOUser -Site $target.Url -LoginName $target.Admin -ErrorAction Stop).IsSiteAdmin } catch { $isAdmin = $false }
        if ($isAdmin -eq (-not $Remove)) { $result.Result = 'AlreadyCompliant'; continue }
        if (-not $Apply) { $result.Result = 'WouldChange'; continue }
        $result.Result = 'SkippedByUser'
        if ($PSCmdlet.ShouldProcess($target.Url, "$action site collection admin rights for $($target.Admin)")) {
            Set-SPOUser -Site $target.Url -LoginName $target.Admin -IsSiteCollectionAdmin (-not $Remove) -ErrorAction Stop | Out-Null
            $result.Result = 'Changed'
        }
    }
    catch {
        $result.Result = 'Failed'
        $result.Detail = $_.Exception.Message
        Write-Warning "$($target.Url): $($_.Exception.Message)"
    }
}
Write-Progress -Activity "$action site collection admin" -Completed

$output = @($results)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'Site collection admin change summary' -ForegroundColor Cyan
Write-Host ('  Mode              : {0} ({1})' -f $action, $(if ($Apply) { 'APPLY' } else { 'report only, add -Apply to change' }))
Write-Host ('  Sites targeted    : {0}' -f $output.Count)
foreach ($group in ($output | Group-Object -Property Result | Sort-Object -Property Name)) { Write-Host ('  {0,-18}: {1}' -f $group.Name, $group.Count) }
Write-Host ('  Results exported  : {0} -> {1}' -f $output.Count, $OutputPath)
#endregion Main
