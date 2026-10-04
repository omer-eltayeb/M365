<#
.SYNOPSIS
    Reports every delegated and application permission granted to enterprise applications and flags high-privilege ones.
.DESCRIPTION
    Builds a tenant-wide API permission inventory through Microsoft Graph. Delegated permissions come from GET /oauth2PermissionGrants
    (one row per scope, with the consent type and the user it was granted to); application permissions come from
    GET /servicePrincipals/{id}/appRoleAssignments of every client service principal, with the appRoleId resolved to its value through
    the appRoles of the resource service principals (indexed once, no extra calls). Each row is flagged HighPrivilege when the
    permission allows tenant-wide access to the directory, mail, files, devices or security policies.
.PARAMETER AppName
    Restricts the report to client applications whose display name matches this value (wildcards allowed, e.g. 'Contoso*').
.PARAMETER HighPrivilegeOnly
    Exports only rows whose permission is on the high-privilege list.
.PARAMETER ExcludeMicrosoft
    Excludes Microsoft first-party client applications. Default $true; pass -ExcludeMicrosoft $false to include them.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraAppPermissions_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraAppPermissionsReport.ps1
    Exports all delegated and application permissions of non-Microsoft applications to the default CSV.
.EXAMPLE
    PS> .\Get-EntraAppPermissionsReport.ps1 -HighPrivilegeOnly -OutputPath C:\Temp\HighPrivilegeAppPermissions.csv -Verbose
    Exports only high-privilege permissions, which is the shortlist to review first in a consent audit.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Application.Read.All, Directory.Read.All, DelegatedPermissionGrant.Read.All (delegated)
    Category    : Applications & consent
    Changes     : No
    Notes       : Application permissions need one Graph call per service principal, so large tenants take a few minutes.
                  The high-privilege list is a starting point; extend the $highPrivilegePermissions array to match your policy.
.LINK
    https://learn.microsoft.com/graph/api/oauth2permissiongrant-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$AppName,

    [Parameter()]
    [switch]$HighPrivilegeOnly,

    [Parameter()]
    [bool]$ExcludeMicrosoft = $true,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
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

function New-PermissionRow {
    <# Shapes one report row; HighPrivilege is set when the permission is on the built-in list. #>
    param([object]$Client, [string]$PermissionType, [string]$Permission, [string]$Resource, [string]$ConsentType, [string]$GrantedToUser)
    return [PSCustomObject]@{
        AppName        = $Client.displayName
        AppId          = $Client.appId
        Origin         = $Client.Origin
        PermissionType = $PermissionType
        Permission     = $Permission
        Resource       = $Resource
        ConsentType    = $ConsentType
        GrantedToUser  = $GrantedToUser
        HighPrivilege  = ($script:highPrivilegePermissions -contains $Permission)
    }
}
#endregion Helpers

#region Main
$graphV1 = 'https://graph.microsoft.com/v1.0'
# Service principals owned by these two tenants are Microsoft first-party applications.
$microsoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
# Permissions that allow tenant-wide read or write of the directory, mail, files, devices or security policy.
$script:highPrivilegePermissions = @(
    'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Mail.ReadWrite',
    'Mail.Read', 'Mail.Send', 'MailboxSettings.ReadWrite', 'Files.ReadWrite.All', 'Sites.FullControl.All', 'Sites.ReadWrite.All', 'User.ReadWrite.All',
    'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod',
    'UserAuthenticationMethod.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementManagedDevices.PrivilegedOperations.All',
    'Exchange.ManageAsApp', 'full_access_as_app', 'Domain.ReadWrite.All', 'Organization.ReadWrite.All', 'PrivilegedAccess.ReadWrite.AzureAD'
)

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraAppPermissions_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('Application.Read.All', 'Directory.Read.All', 'DelegatedPermissionGrant.Read.All')
    $tenantId = @(Invoke-GraphPaged -Uri ('{0}/organization?$select=id' -f $graphV1))[0].id
    Write-Verbose 'Retrieving service principals (with their app roles) and delegated permission grants.'
    $servicePrincipals = @(Invoke-GraphPaged -Uri ('{0}/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,appRoles&$top=999' -f $graphV1))
    $delegatedGrants = @(Invoke-GraphPaged -Uri ('{0}/oauth2PermissionGrants' -f $graphV1))
}
catch { throw "Failed to read service principals or permission grants from Microsoft Graph: $($_.Exception.Message)" }
# Every service principal is indexed to name resources and resolve app role ids; only the filtered ones are evaluated as clients.
$spById = @{}; $clientById = @{}; $appRoleValueById = @{}; $excludedMicrosoft = 0
foreach ($sp in $servicePrincipals) {
    $spById[$sp.id] = $sp
    foreach ($role in @($sp.appRoles)) { if ($null -ne $role) { $appRoleValueById[[string]$role.id] = $role.value } }
    $origin = 'OtherTenant'
    if ($microsoftTenantIds -contains $sp.appOwnerOrganizationId) { $origin = 'Microsoft' }
    elseif ([string]::IsNullOrEmpty($sp.appOwnerOrganizationId) -or $sp.appOwnerOrganizationId -eq $tenantId) { $origin = 'ThisTenant' }
    $sp | Add-Member -NotePropertyName Origin -NotePropertyValue $origin -Force
    if ($ExcludeMicrosoft -and $origin -eq 'Microsoft') { $excludedMicrosoft++; continue }
    if (-not [string]::IsNullOrEmpty($AppName) -and $sp.displayName -notlike $AppName) { continue }
    $clientById[$sp.id] = $sp
}
$rows = New-Object -TypeName System.Collections.Generic.List[object]; $userCache = @{}
foreach ($grant in $delegatedGrants) {
    $client = $clientById[$grant.clientId]
    if ($null -eq $client) { continue }
    $resourceName = if ($spById.ContainsKey($grant.resourceId)) { $spById[$grant.resourceId].displayName } else { $grant.resourceId }
    $grantedTo = $null
    if ($grant.consentType -eq 'Principal' -and -not [string]::IsNullOrEmpty($grant.principalId)) {
        if (-not $userCache.ContainsKey($grant.principalId)) {
            $userUri = '{0}/users/{1}?$select=userPrincipalName' -f $graphV1, $grant.principalId
            try { $userCache[$grant.principalId] = (Invoke-MgGraphRequest -Method GET -Uri $userUri -OutputType PSObject -ErrorAction Stop).userPrincipalName }
            catch { $userCache[$grant.principalId] = $grant.principalId }
        }
        $grantedTo = $userCache[$grant.principalId]
    }
    foreach ($scope in @(([string]$grant.scope) -split ' ' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $rows.Add((New-PermissionRow -Client $client -PermissionType 'Delegated' -Permission $scope.Trim() -Resource $resourceName -ConsentType $grant.consentType -GrantedToUser $grantedTo))
    }
}
$delegatedRowCount = $rows.Count
$clients = @($clientById.Values); $processed = 0
foreach ($client in $clients) {
    $processed++
    Write-Progress -Activity 'Reading application permissions' -Status "$processed of $($clients.Count): $($client.displayName)" -PercentComplete (($processed / $clients.Count) * 100)
    try {
        foreach ($assignment in @(Invoke-GraphPaged -Uri ('{0}/servicePrincipals/{1}/appRoleAssignments' -f $graphV1, $client.id))) {
            $roleValue = $appRoleValueById[[string]$assignment.appRoleId]
            if ([string]::IsNullOrEmpty($roleValue)) { $roleValue = [string]$assignment.appRoleId }
            # Application permissions are always admin-consented for the whole tenant, hence AllPrincipals.
            $rows.Add((New-PermissionRow -Client $client -PermissionType 'Application' -Permission $roleValue -Resource $assignment.resourceDisplayName -ConsentType 'AllPrincipals'))
        }
    }
    catch { Write-Warning ("App role assignments of '{0}' could not be read: {1}" -f $client.displayName, $_.Exception.Message) }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading application permissions' -Completed
$report = @($rows | Where-Object { -not $HighPrivilegeOnly -or $_.HighPrivilege } | Sort-Object -Property AppName, PermissionType, Resource, Permission)
if ($report.Count -gt 0) { $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No permissions matched the filters; no CSV was written.' }
$highPrivilegeRows = @($report | Where-Object { $_.HighPrivilege })
Write-Host 'Application permission summary' -ForegroundColor Cyan
Write-Host ('  Client apps evaluated : {0} ({1} Microsoft first-party excluded)' -f $clients.Count, $excludedMicrosoft)
Write-Host ('  Permission rows       : {0} delegated, {1} application' -f $delegatedRowCount, ($rows.Count - $delegatedRowCount))
Write-Host ('  High-privilege rows   : {0} across {1} app(s)' -f $highPrivilegeRows.Count, @($highPrivilegeRows | Select-Object -ExpandProperty AppId -Unique).Count) -ForegroundColor Yellow
Write-Host ('  Rows exported         : {0} -> {1}' -f $report.Count, $OutputPath)

if ($PassThru) { $report }
#endregion Main
