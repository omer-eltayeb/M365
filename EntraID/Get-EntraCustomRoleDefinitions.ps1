<#
.SYNOPSIS
    Documents the custom Microsoft Entra directory roles: permissions, state and how many assignments each role has.
.DESCRIPTION
    Reads the custom role definitions (GET /roleManagement/directory/roleDefinitions?$filter=isBuiltIn eq false) with their
    rolePermissions, resource scopes and version, counts the active assignments of every role
    (GET /roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{id}') and saves each definition as a JSON file
    that can be used to re-create the role. A CSV summary lists name, state, action count, the joined actions (truncated to
    500 characters), the number of broad actions (allTasks / allProperties) and the assignment count.
.PARAMETER IncludeBuiltIn
    Also exports the built-in roles (100+ definitions, one assignment lookup each, so the run takes noticeably longer).
.PARAMETER OutputFolder
    Folder that receives one JSON file per role. Defaults to .\EntraCustomRoles_yyyyMMdd-HHmm\.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraCustomRoleDefinitions_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraCustomRoleDefinitions.ps1
    Exports every custom role to JSON and CSV and prints the roles that have no assignments.
.EXAMPLE
    PS> .\Get-EntraCustomRoleDefinitions.ps1 -IncludeBuiltIn -OutputFolder C:\Backup\EntraRoles -Verbose
    Documents built-in and custom roles and saves the JSON files to C:\Backup\EntraRoles.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : RoleManagement.Read.Directory (delegated); Global Reader or Privileged Role Administrator is sufficient.
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : Custom roles require Microsoft Entra ID P1. AssignmentCount covers active assignments only; PIM-eligible
                  assignments are not counted. Roles assigned to groups count the group as one assignment.
.LINK
    https://learn.microsoft.com/graph/api/rbacapplication-list-roledefinitions
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeBuiltIn,

    [Parameter()]
    [string]$OutputFolder,

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
$timestamp = Get-Date -Format 'yyyyMMdd-HHmm'
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraCustomRoleDefinitions_{0}.csv' -f $timestamp)
}
if ([string]::IsNullOrWhiteSpace($OutputFolder)) { $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('EntraCustomRoles_{0}' -f $timestamp) }
foreach ($folder in @((Split-Path -Path $OutputPath -Parent), $OutputFolder)) {
    if (-not [string]::IsNullOrWhiteSpace($folder) -and -not (Test-Path -Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
}

try { Connect-GraphIfNeeded -Scopes @('RoleManagement.Read.Directory') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,description,isBuiltIn,isEnabled,rolePermissions,resourceScopes,version,templateId'
if (-not $IncludeBuiltIn) { $uri += '&$filter=isBuiltIn eq false' }
try { $definitions = @(Invoke-GraphPaged -Uri $uri | Sort-Object -Property displayName) }
catch { throw "Failed to read role definitions: $($_.Exception.Message)" }
Write-Verbose "Loaded $($definitions.Count) role definitions."

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($definition in $definitions) {
    $processed++
    Write-Progress -Activity 'Documenting role definitions' -Status $definition.displayName -PercentComplete (($processed / $definitions.Count) * 100)
    $actions = @($definition.rolePermissions | ForEach-Object { $_.allowedResourceActions } | Where-Object { -not [string]::IsNullOrEmpty($_) })

    $assignmentCount = $null
    try {
        $assignmentsUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq ''{0}''&$select=id' -f $definition.id
        $assignmentCount = @(Invoke-GraphPaged -Uri $assignmentsUri).Count
        Start-Sleep -Milliseconds 200
    }
    catch {
        Write-Warning ('Assignments of role "{0}" could not be counted: {1}' -f $definition.displayName, $_.Exception.Message)
    }

    # Role names are unique per tenant, so the display name is a safe file name once invalid characters are replaced.
    $fileName = (($definition.displayName -replace '[\\/:*?"<>|]', '_').Trim()) + '.json'
    try { $definition | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path -Path $OutputFolder -ChildPath $fileName) -Encoding UTF8 }
    catch { Write-Warning ('Role "{0}" could not be saved as JSON: {1}' -f $definition.displayName, $_.Exception.Message); $fileName = $null }

    $joinedActions = ($actions -join '; ')
    if ($joinedActions.Length -gt 500) { $joinedActions = $joinedActions.Substring(0, 497) + '...' }
    $rows.Add([PSCustomObject]@{
        Name             = $definition.displayName
        Description      = $definition.description
        IsBuiltIn        = [bool]$definition.isBuiltIn
        Enabled          = [bool]$definition.isEnabled
        ActionCount      = $actions.Count
        BroadActionCount = @($actions | Where-Object { $_ -like '*/allTasks' -or $_ -like '*/allProperties/*' }).Count
        Actions          = $joinedActions
        ResourceScopes   = (@($definition.resourceScopes) -join '; ')
        AssignmentCount  = $assignmentCount
        Version          = $definition.version
        TemplateId       = $definition.templateId
        Id               = $definition.id
        JsonFile         = $fileName
    })
}
Write-Progress -Activity 'Documenting role definitions' -Completed

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No role definitions were returned; no CSV was written.' }

$customRows = @($rows | Where-Object { -not $_.IsBuiltIn })
$unassigned = @($customRows | Where-Object { $_.AssignmentCount -eq 0 })
Write-Host ''
Write-Host 'Role definition summary' -ForegroundColor Cyan
Write-Host ('  Custom roles        : {0} ({1} disabled)' -f $customRows.Count, @($customRows | Where-Object { -not $_.Enabled }).Count)
if ($IncludeBuiltIn) { Write-Host ('  Built-in roles      : {0}' -f ($rows.Count - $customRows.Count)) }
Write-Host ('  Definitions exported: {0} -> {1}' -f $rows.Count, $OutputPath)
Write-Host ('  JSON files          : {0}' -f $OutputFolder)
if ($unassigned.Count -gt 0) {
    Write-Host ('  Custom roles without active assignments ({0}): {1}' -f $unassigned.Count, (($unassigned | Select-Object -ExpandProperty Name) -join ', ')) -ForegroundColor Yellow
}
$broad = @($customRows | Where-Object { $_.BroadActionCount -gt 0 })
if ($broad.Count -gt 0) {
    Write-Host ('  Custom roles with broad actions ({0}): {1}' -f $broad.Count, (($broad | Select-Object -ExpandProperty Name) -join ', ')) -ForegroundColor Yellow
}

if ($PassThru) { $rows }
#endregion Main
