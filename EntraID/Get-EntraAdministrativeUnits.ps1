<#
.SYNOPSIS
    Reports the Microsoft Entra administrative units with their membership counts, dynamic rules and scoped administrators.
.DESCRIPTION
    Reads every administrative unit (GET /directory/administrativeUnits) with its membership type, dynamic rule, restricted
    management flag and visibility, counts the members per object type (GET /directory/administrativeUnits/{id}/members) and
    lists the administrators scoped to the unit (GET /directory/administrativeUnits/{id}/scopedRoleMembers, role ids resolved
    through /directoryRoles). One CSV row per unit is written to -OutputPath, the scoped administrators to
    <OutputPath>_ScopedAdmins.csv and, with -IncludeMembers, every member to <OutputPath>_Members.csv.
.PARAMETER IncludeMembers
    Also exports every member (type, display name, UPN or mail) of every administrative unit to a second CSV.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraAdministrativeUnits_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the administrative unit objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraAdministrativeUnits.ps1
    Exports the administrative units and their scoped administrators and prints a summary per unit.
.EXAMPLE
    PS> .\Get-EntraAdministrativeUnits.ps1 -IncludeMembers -OutputPath C:\Temp\AdminUnits.csv -Verbose
    Also writes C:\Temp\AdminUnits_Members.csv with every user, group and device that belongs to a unit.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AdministrativeUnit.Read.All, RoleManagement.Read.Directory, Directory.Read.All (delegated).
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : Administrative units require Microsoft Entra ID P1. Members of restricted management units are still listed
                  for readers with Global Reader; counting large units pages through all members, so -IncludeMembers can take a while.
.LINK
    https://learn.microsoft.com/graph/api/directory-list-administrativeunits
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeMembers,

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraAdministrativeUnits_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$basePath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath))

try { Connect-GraphIfNeeded -Scopes @('AdministrativeUnit.Read.All', 'RoleManagement.Read.Directory', 'Directory.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# scopedRoleMembers.roleId refers to the activated directoryRole object, not the role template, so /directoryRoles is the right lookup.
$roleNames = @{}
try {
    foreach ($role in (Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName')) { $roleNames[[string]$role.id] = $role.displayName }
}
catch { Write-Warning "Directory roles could not be read; scoped role ids will stay unresolved. $($_.Exception.Message)" }

$unitsUri = 'https://graph.microsoft.com/v1.0/directory/administrativeUnits?$select=id,displayName,description,membershipType,' +
    'membershipRule,membershipRuleProcessingState,isMemberManagementRestricted,visibility'
try { $units = @(Invoke-GraphPaged -Uri $unitsUri | Sort-Object -Property displayName) }
catch { throw "Failed to read administrative units: $($_.Exception.Message)" }
Write-Verbose "Loaded $($units.Count) administrative units."

$memberSelect = 'id'
if ($IncludeMembers) { $memberSelect = 'id,displayName,userPrincipalName,mail' }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$adminRows = New-Object -TypeName System.Collections.Generic.List[object]
$memberRows = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($unit in $units) {
    $processed++
    Write-Progress -Activity 'Reading administrative units' -Status $unit.displayName -PercentComplete (($processed / $units.Count) * 100)
    $members = @()
    $scopedAdmins = @()
    try {
        $members = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/directory/administrativeUnits/{0}/members?$select={1}&$top=999' -f $unit.id, $memberSelect))
        $scopedAdmins = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/directory/administrativeUnits/{0}/scopedRoleMembers' -f $unit.id))
        Start-Sleep -Milliseconds 200
    }
    catch {
        Write-Warning ('Members or scoped administrators of "{0}" could not be read: {1}' -f $unit.displayName, $_.Exception.Message)
    }

    $typeCounts = @{ user = 0; group = 0; device = 0 }
    foreach ($member in $members) {
        $memberType = ([string]$member.'@odata.type') -replace '^#microsoft\.graph\.', ''
        if ($typeCounts.ContainsKey($memberType)) { $typeCounts[$memberType]++ }
        if ($IncludeMembers) {
            $memberRows.Add([PSCustomObject]@{
                AdministrativeUnit = $unit.displayName
                MemberType         = $memberType
                DisplayName        = $member.displayName
                UserPrincipalName  = @($member.userPrincipalName, $member.mail) | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 1
                Id                 = $member.id
            })
        }
    }
    foreach ($scoped in $scopedAdmins) {
        $resolvedRole = $roleNames[[string]$scoped.roleId]
        if ([string]::IsNullOrEmpty($resolvedRole)) { $resolvedRole = [string]$scoped.roleId }
        $adminRows.Add([PSCustomObject]@{
            AdministrativeUnit = $unit.displayName
            RoleName           = $resolvedRole
            AdminDisplayName   = $scoped.roleMemberInfo.displayName
            AdminId            = $scoped.roleMemberInfo.id
        })
    }

    $membershipType = $unit.membershipType
    if ([string]::IsNullOrEmpty($membershipType)) { $membershipType = 'assigned' }
    $visibility = $unit.visibility
    if ([string]::IsNullOrEmpty($visibility)) { $visibility = 'Public' }
    $rows.Add([PSCustomObject]@{
        DisplayName                   = $unit.displayName
        Description                   = $unit.description
        MembershipType                = $membershipType
        MembershipRule                = $unit.membershipRule
        MembershipRuleProcessingState = $unit.membershipRuleProcessingState
        IsMemberManagementRestricted  = [bool]$unit.isMemberManagementRestricted
        Visibility                    = $visibility
        UserCount                     = $typeCounts['user']
        GroupCount                    = $typeCounts['group']
        DeviceCount                   = $typeCounts['device']
        TotalMembers                  = $members.Count
        ScopedAdminCount              = $scopedAdmins.Count
        Id                            = $unit.id
    })
}
Write-Progress -Activity 'Reading administrative units' -Completed

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'The tenant has no administrative units; no CSV was written.' }
if ($adminRows.Count -gt 0) { $adminRows | Sort-Object -Property AdministrativeUnit, RoleName | Export-Csv -Path "${basePath}_ScopedAdmins.csv" -NoTypeInformation -Encoding UTF8 }
if ($memberRows.Count -gt 0) { $memberRows | Export-Csv -Path "${basePath}_Members.csv" -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'Administrative unit summary (users / groups / devices / scoped admins)' -ForegroundColor Cyan
foreach ($row in $rows) {
    $flags = @()
    if ($row.MembershipType -eq 'dynamic') { $flags += 'dynamic' }
    if ($row.IsMemberManagementRestricted) { $flags += 'restricted' }
    if ($row.Visibility -ne 'Public') { $flags += 'hidden' }
    Write-Host ('  {0,-40} {1,6} / {2,6} / {3,6} / {4,3}  {5}' -f $row.DisplayName, $row.UserCount, $row.GroupCount, $row.DeviceCount, $row.ScopedAdminCount, ($flags -join ', '))
}
Write-Host ('  Units exported        : {0} -> {1}' -f $rows.Count, $OutputPath)
Write-Host ('  Scoped administrators : {0} -> {1}' -f $adminRows.Count, "${basePath}_ScopedAdmins.csv")
if ($IncludeMembers) { Write-Host ('  Members exported      : {0} -> {1}' -f $memberRows.Count, "${basePath}_Members.csv") }
$unscoped = @($rows | Where-Object { $_.ScopedAdminCount -eq 0 })
if ($unscoped.Count -gt 0) { Write-Host ('  Units without scoped administrators: {0}' -f $unscoped.Count) -ForegroundColor Yellow }

if ($PassThru) { $rows }
#endregion Main
