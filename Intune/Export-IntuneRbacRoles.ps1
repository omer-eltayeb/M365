<#
.SYNOPSIS
    Exports Intune RBAC role definitions (permissions) and role assignments (admin groups, scope groups, scope tags) to JSON and CSV.
.DESCRIPTION
    Reads the beta collections /deviceManagement/roleDefinitions (built-in and custom roles with their allowed resource
    actions) and /deviceManagement/roleAssignments, then expands every assignment (GET /roleAssignments/{id}?$expand=roleDefinition)
    to obtain the member groups, scope groups or scope type and the scope tags. Group ids are resolved to display names.
    Writes one JSON file per role definition (including its assignments) plus RoleDefinitions.csv and RoleAssignments.csv
    into the output folder - a complete, reviewable snapshot of who can do what in Intune.
.PARAMETER OutputFolder
    Root folder for the export. Defaults to .\IntuneRbacExport_yyyyMMdd-HHmm and is created when missing.
.EXAMPLE
    PS> .\Export-IntuneRbacRoles.ps1
    Exports all role definitions and assignments to .\IntuneRbacExport_<timestamp>\.
.EXAMPLE
    PS> .\Export-IntuneRbacRoles.ps1 -OutputFolder D:\Audit\IntuneRbac -Verbose
    Writes the snapshot into D:\Audit\IntuneRbac and shows each Graph call.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementRBAC.Read.All, Group.Read.All (delegated)
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : scopeType, scopeMembers and roleScopeTagIds on role assignments exist only on the beta endpoint, which Microsoft
                  may change without notice. Entra ID roles such as Intune Administrator or Global Administrator are not Intune
                  RBAC assignments and therefore do not appear here. One Graph call per assignment plus one per unique group.
.LINK
    https://learn.microsoft.com/graph/api/intune-rbac-roledefinition-list?view=graph-rest-beta
.LINK
    https://learn.microsoft.com/graph/api/intune-rbac-deviceandappmanagementroleassignment-get?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder
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

$script:groupNameCache = @{}
function Get-GroupDisplayName {
    <# Resolves a group id to its display name through a script-level cache; deleted groups return '<deleted group>'. #>
    param([string]$GroupId)
    if ($script:groupNameCache.ContainsKey($GroupId)) { return $script:groupNameCache[$GroupId] }
    $name = '<unresolved>'
    try {
        $group = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/groups/{0}?$select=displayName' -f $GroupId) -OutputType PSObject -ErrorAction Stop
        $name = [string]$group.displayName
    }
    catch {
        $errorText = '{0} {1}' -f $_.Exception.Message, $_.ErrorDetails.Message
        if ($errorText -match 'NotFound|\b404\b|does not exist') { $name = '<deleted group>' }
        else { Write-Warning ('Could not resolve group {0}: {1}' -f $GroupId, $_.Exception.Message) }
    }
    $script:groupNameCache[$GroupId] = $name
    return $name
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('IntuneRbacExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementRBAC.Read.All', 'Group.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphBeta = 'https://graph.microsoft.com/beta/deviceManagement'   # beta: scopeType, scopeMembers and roleScopeTagIds of role assignments are not exposed in v1.0
try {
    $definitions = @(Invoke-GraphPaged -Uri ('{0}/roleDefinitions?$select=id,displayName,description,isBuiltIn,rolePermissions' -f $graphBeta))
    $assignmentStubs = @(Invoke-GraphPaged -Uri ('{0}/roleAssignments?$select=id,displayName' -f $graphBeta))
}
catch {
    throw "Failed to list Intune role definitions or assignments: $($_.Exception.Message)"
}
$scopeTagNames = @{}
try {
    foreach ($tag in @(Invoke-GraphPaged -Uri ('{0}/roleScopeTags?$select=id,displayName' -f $graphBeta))) { $scopeTagNames[[string]$tag.id] = [string]$tag.displayName }
}
catch {
    Write-Warning ('Could not list scope tags; the ScopeTags column shows ids only: {0}' -f $_.Exception.Message)
}
Write-Verbose ('{0} role definitions and {1} role assignments found.' -f $definitions.Count, $assignmentStubs.Count)

$assignmentRows = New-Object -TypeName System.Collections.Generic.List[object]
$failed = 0; $index = 0
foreach ($stub in $assignmentStubs) {
    $index++
    $progress = @{ Activity = 'Expanding role assignments'; Status = ('{0} of {1}: {2}' -f $index, $assignmentStubs.Count, $stub.displayName) }
    Write-Progress @progress -PercentComplete ([int](($index / $assignmentStubs.Count) * 100))
    try {
        # The list call omits members and scope; only the single-item GET returns them.
        $assignment = Invoke-MgGraphRequest -Method GET -Uri ('{0}/roleAssignments/{1}?$expand=roleDefinition' -f $graphBeta, $stub.id) -OutputType PSObject -ErrorAction Stop
    }
    catch {
        $failed++
        Write-Warning ("Could not read role assignment '{0}': {1}" -f $stub.displayName, $_.Exception.Message)
        continue
    }
    $memberGroups = @(foreach ($groupId in @($assignment.members)) { Get-GroupDisplayName -GroupId ([string]$groupId) })
    $scopeGroups = @(foreach ($groupId in @($assignment.scopeMembers)) { Get-GroupDisplayName -GroupId ([string]$groupId) })
    $scopeTags = @(foreach ($tagId in @($assignment.roleScopeTagIds)) { if ($scopeTagNames.ContainsKey([string]$tagId)) { $scopeTagNames[[string]$tagId] } else { [string]$tagId } })
    $assignmentRows.Add([PSCustomObject]@{
            Role             = $assignment.roleDefinition.displayName
            RoleDefinitionId = $assignment.roleDefinition.id
            AssignmentName   = $assignment.displayName
            MemberGroups     = ($memberGroups -join '; ')
            ScopeGroups      = ($scopeGroups -join '; ')
            ScopeType        = $assignment.scopeType
            ScopeTags        = ($scopeTags -join '; ')
        })
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Expanding role assignments' -Completed

$definitionRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($definition in $definitions) {
    $actions = @(foreach ($permission in @($definition.rolePermissions)) { foreach ($resourceAction in @($permission.resourceActions)) { @($resourceAction.allowedResourceActions) } })
    $actions = @($actions | Sort-Object -Unique)
    $roleAssignments = @($assignmentRows | Where-Object { $_.RoleDefinitionId -eq $definition.id })
    $definitionRows.Add([PSCustomObject]@{
            Role            = $definition.displayName
            BuiltIn         = [bool]$definition.isBuiltIn
            PermissionCount = $actions.Count
            AssignmentCount = $roleAssignments.Count
            Description     = $definition.description
            Id              = $definition.id
        })
    try {
        $safeName = (([string]$definition.displayName) -replace '[\\/:*?"<>|\x00-\x1F]', '_').Trim()
        if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = 'Unnamed' }
        $jsonPath = Join-Path -Path $OutputFolder -ChildPath ('{0}_{1}.json' -f $safeName, ([string]$definition.id).Substring(0, 8))
        $definition | Add-Member -NotePropertyName 'allowedResourceActions' -NotePropertyValue $actions -Force
        $definition | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $roleAssignments -Force
        $definition | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
    }
    catch {
        $failed++
        Write-Warning ("Could not write JSON for role '{0}': {1}" -f $definition.displayName, $_.Exception.Message)
    }
}

$definitionRows | Sort-Object -Property BuiltIn, Role | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'RoleDefinitions.csv') -NoTypeInformation -Encoding UTF8
$assignmentRows | Sort-Object -Property Role, AssignmentName | Select-Object -Property Role, AssignmentName, MemberGroups, ScopeGroups, ScopeType, ScopeTags |
    Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'RoleAssignments.csv') -NoTypeInformation -Encoding UTF8

Write-Host ("`nExport folder     : {0}" -f $OutputFolder) -ForegroundColor Cyan
Write-Host ('Role definitions  : {0} ({1} custom)' -f $definitionRows.Count, @($definitionRows | Where-Object { -not $_.BuiltIn }).Count) -ForegroundColor Green
Write-Host ('Role assignments  : {0}' -f $assignmentRows.Count) -ForegroundColor Green
Write-Host ('Unique groups     : {0}' -f $script:groupNameCache.Count) -ForegroundColor Green
if ($failed -gt 0) { Write-Host ('Failed items      : {0}' -f $failed) -ForegroundColor Red }
#endregion Main
