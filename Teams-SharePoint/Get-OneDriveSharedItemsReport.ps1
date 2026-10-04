<#
.SYNOPSIS
    Reports every sharing link and direct permission on shared OneDrive files and folders per user, flagging anonymous and external access.
.DESCRIPTION
    For each user (-UserPrincipalName, -InputCsv or -All) enumerates the OneDrive with the delta API
    (/users/{upn}/drive/root/delta), keeps the items that carry the 'shared' facet and reads their permissions with
    /users/{upn}/drive/items/{id}/permissions. Each permission becomes one row with Owner, item, link type and scope,
    roles, grantees, expiration, password / download protection, inheritance and IsExternal (guest #EXT# accounts,
    e-mail domains outside the verified or -InternalDomains list, anonymous links). Users without a provisioned OneDrive
    are skipped with a warning. Prints the anonymous and external share counts per owner.
.PARAMETER UserPrincipalName
    One or more user principal names whose OneDrive should be scanned.
.PARAMETER InputCsv
    Path of a CSV with a UserPrincipalName column (for example an export from Entra ID or another report).
.PARAMETER All
    Scan the OneDrive of every enabled member user in the tenant. Slow in large tenants; the script warns before it starts.
.PARAMETER InternalDomains
    Domains treated as internal. Defaults to the tenant's verified domains (/organization) or, when that call is not permitted,
    the signed-in account's domain; pass the list explicitly in multi-domain tenants or app-only sessions.
.PARAMETER OnlyAnonymous
    Export only "anyone with the link" (anonymous) sharing links.
.PARAMETER OnlyExternal
    Export only permissions flagged IsExternal (guests, external domains and anonymous links).
.PARAMETER IncludeInherited
    Also export permissions inherited from a shared parent folder. By default only permissions set on the item itself are listed.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\OneDriveSharedItems_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-OneDriveSharedItemsReport.ps1 -UserPrincipalName megan@contoso.com, alex@contoso.com
    Lists every sharing link and direct permission on the shared items in Megan's and Alex's OneDrive.
.EXAMPLE
    PS> .\Get-OneDriveSharedItemsReport.ps1 -All -OnlyExternal -OutputPath C:\Temp\OneDriveExternal.csv -Verbose
    Tenant-wide list of OneDrive items exposed to guests, external domains or anonymous links.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Files.Read.All, User.Read.All. Delegated Files.Read.All only reaches OneDrives the signed-in user can already
                  open (for example as a site collection administrator); an app-only session with the application permissions
                  Files.Read.All and User.Read.All is recommended for a tenant-wide scan (connect with Connect-MgGraph first).
    Category    : SharePoint & OneDrive (Graph)
    Changes     : No
    Notes       : One permissions call per shared item with a 150 ms pause; the SDK retries HTTP 429. Users who never opened
                  OneDrive have no drive (HTTP 404) and are skipped. Items inside a shared folder inherit its permissions.
.LINK
    https://learn.microsoft.com/graph/api/driveitem-list-permissions
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()] [string[]]$UserPrincipalName,
    [Parameter()] [string]$InputCsv,
    [Parameter()] [switch]$All,
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

function Get-DriveItemList {
    <# Enumerates every item of a drive in one flat delta pass (no folder recursion); the last page carries @odata.deltaLink instead of @odata.nextLink. #>
    param([Parameter(Mandatory = $true)] [string]$DriveUri)
    $items = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = "$DriveUri/root/delta?`$select=id,name,size,folder,root,parentReference,webUrl,shared,lastModifiedDateTime"
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
if (-not $All -and -not $UserPrincipalName -and [string]::IsNullOrWhiteSpace($InputCsv)) { throw 'Specify -UserPrincipalName, -InputCsv or -All.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath ('OneDriveSharedItems_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
try { Connect-GraphIfNeeded -Scopes @('Files.Read.All', 'User.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$domains = @($InternalDomains | ForEach-Object { $_.ToLowerInvariant() })
if ($domains.Count -eq 0) {
    # Reading /organization needs a directory read scope; without it fall back to the signed-in account's domain.
    try { $domains = @((Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains')[0].verifiedDomains | ForEach-Object { $_.name.ToLowerInvariant() }) }
    catch { $domains = @(([string](Get-MgContext).Account).Split('@')[-1].ToLowerInvariant()); Write-Warning "Verified domains not readable; only '$($domains[0])' is internal." }
}
Write-Verbose "Internal domains: $($domains -join ', ')"

$users = New-Object -TypeName System.Collections.Generic.List[string]
foreach ($upn in $UserPrincipalName) { $users.Add($upn) }
if (-not [string]::IsNullOrWhiteSpace($InputCsv)) {
    foreach ($row in (Import-Csv -Path $InputCsv)) { if (-not [string]::IsNullOrWhiteSpace($row.UserPrincipalName)) { $users.Add($row.UserPrincipalName.Trim()) } }
}
if ($All) {
    Write-Warning 'Scanning the OneDrive of every member user can take hours in large tenants; use -UserPrincipalName or -InputCsv instead.'
    $usersUri = "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Member' and accountEnabled eq true&`$select=userPrincipalName&`$count=true"
    try { $allUsers = Invoke-GraphPaged -Uri $usersUri -Headers @{ ConsistencyLevel = 'eventual' } }
    catch { throw "Failed to list the users: $($_.Exception.Message)" }
    foreach ($user in $allUsers) { $users.Add($user.userPrincipalName) }
}
$users = @($users | Sort-Object -Unique)

$linkAudience = @{ anonymous = '(anyone with the link)'; organization = '(anyone in the organization)'; existingAccess = '(people with existing access)' }
$records = New-Object -TypeName System.Collections.Generic.List[object]
$sharedItemCount = 0; $skippedUsers = 0; $userCounter = 0
foreach ($upn in $users) {
    $userCounter++
    Write-Progress -Activity 'Reading OneDrive sharing permissions' -Status "$userCounter of $($users.Count): $upn" -PercentComplete ([int](($userCounter / $users.Count) * 100))
    $driveUri = "https://graph.microsoft.com/v1.0/users/$upn/drive"
    try { $sharedItems = @(Get-DriveItemList -DriveUri $driveUri | Where-Object { $null -ne $_.shared }) }
    catch {
        $skippedUsers++
        if ($_.Exception.Message -match 'NotFound|404|mysite') { Write-Warning "'$upn' has no provisioned OneDrive; skipped." }
        else { Write-Warning "Could not enumerate the OneDrive of '$upn': $($_.Exception.Message)" }
        continue
    }
    foreach ($item in $sharedItems) {
        $sharedItemCount++
        try { $permissions = @(Invoke-GraphPaged -Uri "$driveUri/items/$($item.id)/permissions") }
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
                    Owner              = $upn
                    Item               = $item.name
                    ItemType           = $(if ($null -ne $item.folder) { 'Folder' } else { 'File' })
                    # parentReference.path is /drives/{id}/root:/Folder/Sub; keep the part after root: and append the name
                    Path               = [uri]::UnescapeDataString(("$($item.parentReference.path)/$($item.name)" -replace '^.*?root:', ''))
                    SizeMB             = [math]::Round($item.size / 1MB, 2)
                    LastModified       = [datetime]$item.lastModifiedDateTime
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
Write-Progress -Activity 'Reading OneDrive sharing permissions' -Completed

$output = @($records)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No sharing permissions matched the selected filters; no CSV was written.' }

$externalRows = @($output | Where-Object { $_.IsExternal })
Write-Host 'OneDrive sharing summary' -ForegroundColor Cyan
Write-Host ('  Users scanned / skipped          : {0} / {1}; shared items: {2}' -f $users.Count, $skippedUsers, $sharedItemCount)
$anonymousCount = @($output | Where-Object { $_.LinkScope -eq 'anonymous' }).Count
Write-Host ('  Permissions exported             : {0} (external: {1}, anonymous links: {2})' -f $output.Count, $externalRows.Count, $anonymousCount) -ForegroundColor Yellow
Write-Host '  Owners with the most external / anonymous shares (top 10):'
foreach ($group in ($externalRows | Group-Object -Property Owner | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,6} external ({1,4} anonymous)  {2}' -f $group.Count, @($group.Group | Where-Object { $_.LinkScope -eq 'anonymous' }).Count, $group.Name)
}
Write-Host ('  Rows exported                    : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
