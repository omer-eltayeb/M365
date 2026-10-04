<#
.SYNOPSIS
    Reports which users, groups and service principals are assigned to each enterprise application and in which role.
.DESCRIPTION
    Lists non-Microsoft enterprise applications through Microsoft Graph (GET /servicePrincipals) and reads the assignments of each
    one (GET /servicePrincipals/{id}/appRoleAssignedTo), resolving the appRoleId to the role display name through the app's
    appRoles (the all-zero id is reported as "Default Access"). With -ExpandGroups every assigned group is expanded to its
    transitive members (GET /groups/{id}/transitiveMembers), one row per member with the group name in EffectiveVia. Apps
    with appRoleAssignmentRequired set to false are flagged because any user in the tenant can sign in to them.
.PARAMETER AppName
    Restricts the report to applications whose display name matches this value (wildcards allowed, e.g. 'Contoso*').
.PARAMETER OnlyAssignmentRequired
    Evaluates only applications that require user assignment (appRoleAssignmentRequired = true).
.PARAMETER ExpandGroups
    Adds one row per transitive member of every assigned group. One extra Graph call per distinct group.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraAppRoleAssignments_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraAppRoleAssignmentsReport.ps1
    Exports the direct assignments of every non-Microsoft enterprise application to the default CSV.
.EXAMPLE
    PS> .\Get-EntraAppRoleAssignmentsReport.ps1 -AppName 'Salesforce*' -ExpandGroups -OutputPath C:\Temp\SalesforceAccess.csv -Verbose
    Exports who can effectively access the Salesforce apps, including members of assigned groups.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Application.Read.All, Directory.Read.All (delegated); GroupMember.Read.All is added with -ExpandGroups.
    Category    : Applications & consent
    Changes     : No
    Notes       : One Graph call per application (plus one per distinct group with -ExpandGroups), so large tenants take a few minutes.
                  When assignment is not required every user can sign in, so the assignment list is not the effective access list;
                  such apps stay visible even without assignments through a row of PrincipalType None.
.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-list-approleassignedto
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$AppName,

    [Parameter()]
    [switch]$OnlyAssignmentRequired,

    [Parameter()]
    [switch]$ExpandGroups,

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

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([Parameter()][object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function New-AssignmentRow {
    <# Shapes one report row; the principal is the assignment's principal, a group member when -Member is passed, or None. #>
    param([object]$App, [object]$Assignment, [string]$Role, [string]$EffectiveVia, [object]$Member)
    $type = 'None'; $name = 'Any user in the tenant (assignment not required)'; $id = $null
    if ($null -ne $Member) {
        $type = [string]$Member.'@odata.type' -replace '^#microsoft\.graph\.', ''
        if ($type.Length -gt 1) { $type = $type.Substring(0, 1).ToUpper() + $type.Substring(1) }
        $name = $Member.userPrincipalName
        if ([string]::IsNullOrEmpty($name)) { $name = $Member.displayName }
        $id = $Member.id
    }
    elseif ($null -ne $Assignment) { $type = $Assignment.principalType; $name = $Assignment.principalDisplayName; $id = $Assignment.principalId }
    return [PSCustomObject]@{
        AppName            = $App.displayName
        AppId              = $App.appId
        AssignmentRequired = ($App.appRoleAssignmentRequired -eq $true)
        PrincipalType      = $type
        PrincipalName      = $name
        PrincipalId        = $id
        Role               = $Role
        EffectiveVia       = $EffectiveVia
        AssignedDateTime   = ConvertTo-UtcDateTime -Value $Assignment.createdDateTime
    }
}
#endregion Helpers

#region Main
$requiredScopes = @('Application.Read.All', 'Directory.Read.All'); if ($ExpandGroups) { $requiredScopes += 'GroupMember.Read.All' }
$graphV1 = 'https://graph.microsoft.com/v1.0'
# Service principals owned by these two tenants are Microsoft first-party applications and are not reported.
$microsoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraAppRoleAssignments_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
    $spUri = "{0}/servicePrincipals?`$filter=servicePrincipalType eq 'Application'&`$select=id,appId,displayName,appOwnerOrganizationId,appRoleAssignmentRequired,appRoles&`$top=999" -f $graphV1
    $servicePrincipals = @(Invoke-GraphPaged -Uri $spUri)
}
catch { throw "Failed to list service principals from Microsoft Graph: $($_.Exception.Message)" }
$apps = @($servicePrincipals | Where-Object {
        $microsoftTenantIds -notcontains $_.appOwnerOrganizationId -and
        ([string]::IsNullOrEmpty($AppName) -or $_.displayName -like $AppName) -and
        (-not $OnlyAssignmentRequired -or $_.appRoleAssignmentRequired -eq $true)
    } | Sort-Object -Property displayName)
$rows = New-Object -TypeName System.Collections.Generic.List[object]; $groupMemberCache = @{}
$directAssignments = 0; $appsWithoutAssignments = 0; $processed = 0
foreach ($app in $apps) {
    $processed++
    Write-Progress -Activity 'Reading app role assignments' -Status "$processed of $($apps.Count): $($app.displayName)" -PercentComplete (($processed / $apps.Count) * 100)
    $roleNames = @{ '00000000-0000-0000-0000-000000000000' = 'Default Access' }
    foreach ($role in @($app.appRoles)) { if ($null -ne $role) { $roleNames[[string]$role.id] = $role.displayName } }
    try { $assignments = @(Invoke-GraphPaged -Uri ('{0}/servicePrincipals/{1}/appRoleAssignedTo?$top=999' -f $graphV1, $app.id)) }
    catch { Write-Warning ("Assignments of '{0}' could not be read: {1}" -f $app.displayName, $_.Exception.Message); continue }
    Start-Sleep -Milliseconds 200
    if ($assignments.Count -eq 0) {
        $appsWithoutAssignments++
        # An app that needs no assignment is open to every user even without assignments, so it stays visible in the report.
        if ($app.appRoleAssignmentRequired -ne $true) { $rows.Add((New-AssignmentRow -App $app -EffectiveVia 'NoAssignmentRequired')) }
        continue
    }
    foreach ($assignment in $assignments) {
        $directAssignments++
        $roleName = $roleNames[[string]$assignment.appRoleId]
        if ([string]::IsNullOrEmpty($roleName)) { $roleName = [string]$assignment.appRoleId }
        $rows.Add((New-AssignmentRow -App $app -Assignment $assignment -Role $roleName -EffectiveVia 'Direct'))
        if (-not $ExpandGroups -or $assignment.principalType -ne 'Group') { continue }
        if (-not $groupMemberCache.ContainsKey($assignment.principalId)) {
            # transitiveMembers already flattens nested groups, so the group objects themselves are dropped.
            $memberUri = '{0}/groups/{1}/transitiveMembers?$select=id,displayName,userPrincipalName&$top=999' -f $graphV1, $assignment.principalId
            try { $groupMemberCache[$assignment.principalId] = @(Invoke-GraphPaged -Uri $memberUri | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.group' }) }
            catch { $groupMemberCache[$assignment.principalId] = @(); Write-Warning ("Members of group '{0}' could not be read: {1}" -f $assignment.principalDisplayName, $_.Exception.Message) }
            Start-Sleep -Milliseconds 200
        }
        foreach ($member in $groupMemberCache[$assignment.principalId]) {
            $rows.Add((New-AssignmentRow -App $app -Assignment $assignment -Role $roleName -EffectiveVia $assignment.principalDisplayName -Member $member))
        }
    }
}
Write-Progress -Activity 'Reading app role assignments' -Completed
if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No app role assignments matched the filters; no CSV was written.' }
$openApps = @($rows | Where-Object { -not $_.AssignmentRequired } | Select-Object -ExpandProperty AppName -Unique)
Write-Host 'App role assignment summary' -ForegroundColor Cyan
Write-Host ('  Applications evaluated        : {0} ({1} without any assignment)' -f $apps.Count, $appsWithoutAssignments)
Write-Host ('  Assignment rows               : {0} direct, {1} via group expansion' -f $directAssignments, @($rows | Where-Object { $_.EffectiveVia -notin @('Direct', 'NoAssignmentRequired') }).Count)
Write-Host ('  Apps open to every user       : {0}' -f $openApps.Count) -ForegroundColor Yellow
Write-Host ('  Rows exported                 : {0} -> {1}' -f $rows.Count, $OutputPath)

if ($PassThru) { $rows }
#endregion Main
