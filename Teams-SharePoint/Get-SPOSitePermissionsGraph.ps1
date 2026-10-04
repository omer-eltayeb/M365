<#
.SYNOPSIS
    Audits which applications hold Sites.Selected permissions on SharePoint sites, optionally with library-level permissions, and can grant or revoke app access.
.DESCRIPTION
    Reads /sites/{id}/permissions for the selected sites (-SiteUrl, -SiteId or -AllSites): every row is one application
    grant (AppName, AppId, Roles read/write/manage/fullcontrol/owner), the audit behind "which apps can reach this site".
    -IncludeLibraryPermissions also reads /drives/{id}/root/permissions of every document library (site groups, direct
    grants and sharing links) into <OutputPath>_LibraryPermissions.csv. The script is read-only unless -GrantAppAccess
    (POST /sites/{id}/permissions, PATCH for manage/fullcontrol) or -RevokePermissionId (DELETE) is used; both target
    exactly one site and support -WhatIf / -Confirm.
.PARAMETER SiteUrl
    One or more site collection URLs, for example https://contoso.sharepoint.com/sites/Marketing.
.PARAMETER SiteId
    One or more Graph site ids (hostname,siteCollectionId,webId), for example from Get-SPOSitesInventoryGraph.ps1.
.PARAMETER AllSites
    Audit every non-personal site in the tenant (report only). Slow in large tenants; the script warns before it starts.
.PARAMETER IncludeLibraryPermissions
    Also export the root permissions of every document library to <OutputPath>_LibraryPermissions.csv.
.PARAMETER GrantAppAccess
    Grant -Role on the single selected site to the application identified by -AppId / -AppDisplayName (Sites.Selected model).
.PARAMETER AppId
    Application (client) id of the app registration to grant access to.
.PARAMETER AppDisplayName
    Display name of the application; stored with the permission and shown in later audits.
.PARAMETER Role
    Role to grant: read, write, manage or fullcontrol. Default read.
.PARAMETER RevokePermissionId
    Id of a site permission (PermissionId column) to delete from the single selected site.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOSitePermissions_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the site permission objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOSitePermissionsGraph.ps1 -AllSites -IncludeLibraryPermissions
    Lists every application with Sites.Selected access in the tenant and the library-level permissions of every site.
.EXAMPLE
    PS> .\Get-SPOSitePermissionsGraph.ps1 -SiteUrl https://contoso.sharepoint.com/sites/HR -GrantAppAccess -AppId <guid> -AppDisplayName 'HR Sync' -Role write -WhatIf
    Shows the grant that would be made for the HR Sync app on the HR site without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Sites.FullControl.All (reading, granting and revoking site permissions all require it; the library permissions
                  alone would work with Sites.Read.All). SharePoint Administrator or Global Administrator role for delegated use.
    Category    : SharePoint & OneDrive (Graph)
    Changes     : Optional (-GrantAppAccess / -RevokePermissionId)
    Notes       : /sites/getAllSites is application-only, so with a delegated session -AllSites falls back to /sites?$search=*.
                  POST /permissions accepts only read and write; manage and fullcontrol are applied with a follow-up PATCH.
                  An app still needs the Sites.Selected application permission with admin consent to use the grant.
.LINK
    https://learn.microsoft.com/graph/api/site-list-permissions
.LINK
    https://learn.microsoft.com/graph/api/site-post-permissions
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()] [string[]]$SiteUrl,
    [Parameter()] [string[]]$SiteId,
    [Parameter()] [switch]$AllSites,
    [Parameter()] [switch]$IncludeLibraryPermissions,
    [Parameter()] [switch]$GrantAppAccess,
    [Parameter()] [string]$AppId,
    [Parameter()] [string]$AppDisplayName,
    [Parameter()] [ValidateSet('read', 'write', 'manage', 'fullcontrol')] [string]$Role = 'read',
    [Parameter()] [string]$RevokePermissionId,
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

function Get-GranteeLabel {
    <# Flattens grantedToV2 / grantedToIdentitiesV2 / grantedToIdentities (user, siteUser, group, siteGroup, application) into "Name <email> [kind]" labels. #>
    param([Parameter(Mandatory = $true)] [object]$Permission)
    $labels = foreach ($identity in (@($Permission.grantedToV2) + @($Permission.grantedToIdentitiesV2) + @($Permission.grantedToIdentities) | Where-Object { $null -ne $_ })) {
        foreach ($kind in 'user', 'siteUser', 'group', 'siteGroup', 'application') {
            $actor = $identity.$kind
            if ($null -eq $actor) { continue }
            $detail = $actor.email
            if ($kind -eq 'application') { $detail = $actor.id }
            if ([string]::IsNullOrEmpty($detail)) { "$($actor.displayName) [$kind]" } else { "$($actor.displayName) <$detail> [$kind]" }
        }
    }
    return (@($labels | Select-Object -Unique) -join '; ')
}
#endregion Helpers

#region Main
if (-not $AllSites -and -not $SiteUrl -and -not $SiteId) { throw 'Specify -SiteUrl, -SiteId or -AllSites.' }
if ($GrantAppAccess -and ([string]::IsNullOrWhiteSpace($AppId) -or [string]::IsNullOrWhiteSpace($AppDisplayName))) { throw '-GrantAppAccess requires -AppId and -AppDisplayName.' }
if (($GrantAppAccess -or $RevokePermissionId) -and ($AllSites -or ($SiteUrl.Count + $SiteId.Count) -ne 1)) { throw 'Changes require exactly one site (-SiteUrl or -SiteId), not -AllSites.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath ('SPOSitePermissions_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
$libraryPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_LibraryPermissions.csv')
try { Connect-GraphIfNeeded -Scopes @('Sites.FullControl.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
if ($AllSites) { Write-Warning 'Auditing every site in the tenant can take a long time; use -SiteUrl to narrow the scope.' }
try { $sites = @(Get-TargetSite -SiteUrl $SiteUrl -SiteId $SiteId -All:$AllSites) }
catch { throw "Failed to resolve the target sites: $($_.Exception.Message)" }

# Changes run first so that the report below reflects the new state of the site. Graph expects lowercase role names.
$changes = 0; $Role = $Role.ToLowerInvariant()
if ($GrantAppAccess -and $PSCmdlet.ShouldProcess($sites[0].webUrl, "Grant '$Role' to application '$AppDisplayName' ($AppId)")) {
    $permissionsUri = "https://graph.microsoft.com/v1.0/sites/$($sites[0].id)/permissions"
    $initialRole = $Role
    if ($Role -in @('manage', 'fullcontrol')) { $initialRole = 'write' }   # POST only accepts read/write; PATCH raises it afterwards
    $body = @{ roles = @($initialRole); grantedToIdentities = @(@{ application = @{ id = $AppId; displayName = $AppDisplayName } }) }
    try {
        $created = Invoke-MgGraphRequest -Method POST -Uri $permissionsUri -Body $body -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
        if ($initialRole -ne $Role) {
            Invoke-MgGraphRequest -Method PATCH -Uri "$permissionsUri/$($created.id)" -Body @{ roles = @($Role) } -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop | Out-Null
        }
        $changes++
        Write-Host "Granted '$Role' on $($sites[0].webUrl) to '$AppDisplayName' (permission id $($created.id))." -ForegroundColor Green
    }
    catch { throw "Failed to grant the application access: $($_.Exception.Message)" }
}
if ($RevokePermissionId -and $PSCmdlet.ShouldProcess($sites[0].webUrl, "Delete site permission $RevokePermissionId")) {
    try { Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/v1.0/sites/$($sites[0].id)/permissions/$RevokePermissionId" -ErrorAction Stop }
    catch { throw "Failed to delete permission '$RevokePermissionId': $($_.Exception.Message)" }
    $changes++
    Write-Host "Deleted permission $RevokePermissionId from $($sites[0].webUrl)." -ForegroundColor Green
}

$records = New-Object -TypeName System.Collections.Generic.List[object]
$libraryRecords = New-Object -TypeName System.Collections.Generic.List[object]
$siteCounter = 0
foreach ($site in $sites) {
    $siteCounter++
    Write-Progress -Activity 'Reading site permissions' -Status "$siteCounter of $($sites.Count): $($site.displayName)" -PercentComplete ([int](($siteCounter / $sites.Count) * 100))
    try { $permissions = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/permissions") }
    catch { Write-Warning "Could not read the permissions of '$($site.webUrl)': $($_.Exception.Message)"; continue }
    foreach ($permission in $permissions) {
        # grantedToIdentitiesV2 is the current shape; older grants may only carry grantedToIdentities
        $identities = @($permission.grantedToIdentitiesV2 | Where-Object { $null -ne $_ })
        if ($identities.Count -eq 0) { $identities = @($permission.grantedToIdentities | Where-Object { $null -ne $_ }) }
        $apps = @($identities | Where-Object { $null -ne $_.application } | ForEach-Object { $_.application })
        $records.Add([PSCustomObject]@{
                Site         = $site.displayName
                WebUrl       = $site.webUrl
                SiteId       = $site.id
                PermissionId = $permission.id
                AppName      = (@($apps | ForEach-Object { $_.displayName }) -join '; ')
                AppId        = (@($apps | ForEach-Object { $_.id }) -join '; ')
                Roles        = (@($permission.roles) -join ',')
            })
    }
    if (-not $IncludeLibraryPermissions) { continue }
    try { $drives = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/drives?`$select=id,name") }
    catch { Write-Warning "Could not list the libraries of '$($site.webUrl)': $($_.Exception.Message)"; continue }
    foreach ($drive in $drives) {
        try { $drivePermissions = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/drives/$($drive.id)/root/permissions") }
        catch { Write-Warning "Could not read the permissions of library '$($drive.name)' in '$($site.webUrl)': $($_.Exception.Message)"; continue }
        foreach ($permission in $drivePermissions) {
            $libraryRecords.Add([PSCustomObject]@{
                    Site         = $site.displayName
                    Library      = $drive.name
                    PermissionId = $permission.id
                    GrantedTo    = Get-GranteeLabel -Permission $permission
                    Roles        = (@($permission.roles) -join ',')
                    LinkType     = $permission.link.type
                    LinkScope    = $permission.link.scope
                    Inherited    = ($null -ne $permission.inheritedFrom)
                })
        }
        Start-Sleep -Milliseconds 100
    }
}
Write-Progress -Activity 'Reading site permissions' -Completed

$output = @($records | Sort-Object -Property WebUrl, AppName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No application permissions were found on the selected sites; no site permissions CSV was written.' }
if ($libraryRecords.Count -gt 0) { $libraryRecords | Export-Csv -Path $libraryPath -NoTypeInformation -Encoding UTF8 }

$distinctApps = @($output | Where-Object { $_.AppId } | Group-Object -Property AppId).Count
$privilegedGrants = @($output | Where-Object { $_.Roles -match 'manage|fullcontrol|owner' }).Count
Write-Host 'SharePoint site permissions summary' -ForegroundColor Cyan
Write-Host ('  Sites scanned / app grants : {0} / {1}; distinct apps: {2}; changes made: {3}' -f $sites.Count, $output.Count, $distinctApps, $changes)
Write-Host ('  Grants with manage, fullcontrol or owner : {0}' -f $privilegedGrants) -ForegroundColor Yellow
Write-Host '  Apps by number of sites (top 10):'
foreach ($group in ($output | Where-Object { $_.AppName } | Group-Object -Property AppName | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,5} sites  {1}' -f $group.Count, $group.Name)
}
if ($IncludeLibraryPermissions) { Write-Host ('  Library permission rows    : {0} -> {1}' -f $libraryRecords.Count, $libraryPath) }
Write-Host ('  Rows exported              : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
