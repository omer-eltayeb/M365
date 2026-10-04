<#
.SYNOPSIS
    Reports who holds Microsoft Entra directory roles, including active assignments and PIM-eligible assignments.
.DESCRIPTION
    Reads the unified role definitions (beta, for the isPrivileged flag), the active role assignments
    (GET /roleManagement/directory/roleAssignments with $expand=principal) and, when available, the PIM eligibility
    schedules (GET /roleManagement/directory/roleEligibilitySchedules) through Microsoft Graph. Every assignment is returned
    as one row with the role name, whether Microsoft classifies the role as privileged, the assignment type,
    the directory scope and the principal details (type, display name, UPN or app id, enabled state and whether
    the account is synchronised from on-premises AD). The result is exported to CSV with a per-role summary.
.PARAMETER RoleName
    Only roles whose display name matches this wildcard pattern, for example 'Global*' or '*Administrator'.
.PARAMETER PrivilegedOnly
    Only roles flagged as privileged by Microsoft (isPrivileged = true).
.PARAMETER IncludeEligible
    Includes PIM-eligible assignments (default). Use -IncludeEligible:$false to report active assignments only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraPrivilegedRoleMembers_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraPrivilegedRoleMembers.ps1
    Exports every active and eligible directory role assignment and prints the count per role.
.EXAMPLE
    PS> .\Get-EntraPrivilegedRoleMembers.ps1 -PrivilegedOnly -OutputPath C:\Temp\PrivilegedRoles.csv -Verbose
    Reports only the roles Microsoft classifies as privileged and saves them to the given CSV.
.EXAMPLE
    PS> .\Get-EntraPrivilegedRoleMembers.ps1 -RoleName 'Global Administrator' -IncludeEligible:$false -PassThru
    Lists the active Global Administrators in the console without the PIM eligibility lookup.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : RoleManagement.Read.Directory, Directory.Read.All; RoleEligibilitySchedule.Read.Directory is added
                  when -IncludeEligible is on (default). A reader role such as Global Reader or Security Reader is sufficient.
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : Role definitions are read from the beta endpoint because the isPrivileged flag is not exposed in
                  v1.0 yet; if the beta call fails the script falls back to v1.0 and IsPrivilegedRole stays empty.
                  PIM eligibility requires Microsoft Entra ID P2 (or Microsoft Entra ID Governance); without it the
                  eligible lookup is skipped with a warning. Group assignments are listed as the group, not as its
                  members. Active rows include PIM activations that are current at the time of the run.
.LINK
    https://learn.microsoft.com/graph/api/rbacapplication-list-roleassignments
.LINK
    https://learn.microsoft.com/graph/api/rbacapplication-list-roleeligibilityschedules
.LINK
    https://learn.microsoft.com/graph/api/rbacapplication-list-roledefinitions
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$RoleName,

    [Parameter()]
    [switch]$PrivilegedOnly,

    [Parameter()]
    [switch]$IncludeEligible = $true,

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

function Get-PrincipalDetail {
    <# Returns type, UPN/app id, enabled state and on-premises sync state for a principal; cached per object id. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Principal
    )
    $id = [string]$Principal.id
    if ($script:PrincipalCache.ContainsKey($id)) { return $script:PrincipalCache[$id] }

    $type = ([string]$Principal.'@odata.type') -replace '^#microsoft\.graph\.', ''
    $detail = [PSCustomObject]@{ Type = $type; UpnOrAppId = $null; AccountEnabled = $null; OnPremisesSyncEnabled = $null }

    # The expanded principal only carries the default property set, so the sign-in related
    # properties are read with one typed request per unique principal.
    $uri = $null
    switch ($type) {
        'user' { $uri = 'https://graph.microsoft.com/v1.0/users/{0}?$select=userPrincipalName,accountEnabled,onPremisesSyncEnabled' -f $id }
        'group' { $uri = 'https://graph.microsoft.com/v1.0/groups/{0}?$select=mail,onPremisesSyncEnabled' -f $id }
        'servicePrincipal' { $uri = 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}?$select=appId,accountEnabled' -f $id }
    }
    if ($null -ne $uri) {
        try {
            $object = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
            Start-Sleep -Milliseconds 200
            switch ($type) {
                'user' {
                    $detail.UpnOrAppId = $object.userPrincipalName
                    $detail.AccountEnabled = [bool]$object.accountEnabled
                    $detail.OnPremisesSyncEnabled = [bool]$object.onPremisesSyncEnabled
                }
                'group' {
                    $detail.UpnOrAppId = $object.mail
                    $detail.OnPremisesSyncEnabled = [bool]$object.onPremisesSyncEnabled
                }
                'servicePrincipal' {
                    $detail.UpnOrAppId = $object.appId
                    $detail.AccountEnabled = [bool]$object.accountEnabled
                }
            }
        }
        catch {
            Write-Warning ('Could not read details for {0} {1}: {2}' -f $type, $id, $_.Exception.Message)
        }
    }
    $script:PrincipalCache[$id] = $detail
    return $detail
}
#endregion Helpers

#region Main
$requiredScopes = @('RoleManagement.Read.Directory', 'Directory.Read.All')
if ($IncludeEligible) { $requiredScopes += 'RoleEligibilitySchedule.Read.Directory' }
$script:PrincipalCache = @{}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraPrivilegedRoleMembers_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
}
catch {
    throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)"
}

$roleLookup = @{}
$privilegedFlagAvailable = $true
try {
    # beta: isPrivileged (Microsoft's "privileged role" classification) is only exposed on the beta roleDefinitions
    # resource. Role ids are identical in v1.0, so the join with the v1.0 assignments below is unaffected.
    $roleDefinitions = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,isPrivileged'
}
catch {
    Write-Warning "Role definitions could not be read from the beta endpoint; falling back to v1.0 without the isPrivileged flag (-PrivilegedOnly will match nothing). $($_.Exception.Message)"
    $privilegedFlagAvailable = $false
    $roleDefinitions = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn'
}
foreach ($definition in $roleDefinitions) { $roleLookup[[string]$definition.id] = $definition }
Write-Verbose "Loaded $($roleLookup.Count) role definitions."

try {
    $assignments = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($item in (Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal')) {
        $assignments.Add([PSCustomObject]@{ Source = $item; AssignmentType = 'Active' })
    }
    Write-Verbose "Loaded $($assignments.Count) active role assignments."
}
catch {
    throw "Failed to read role assignments: $($_.Exception.Message)"
}

if ($IncludeEligible) {
    try {
        $eligibleCount = 0
        foreach ($item in (Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal')) {
            $assignments.Add([PSCustomObject]@{ Source = $item; AssignmentType = 'Eligible' })
            $eligibleCount++
        }
        Write-Verbose "Loaded $eligibleCount PIM-eligible assignments."
    }
    catch {
        Write-Warning "PIM-eligible assignments could not be read (requires Microsoft Entra ID P2 and RoleEligibilitySchedule.Read.Directory); continuing with active assignments only. $($_.Exception.Message)"
    }
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($assignment in $assignments) {
    $processed++
    Write-Progress -Activity 'Resolving role assignments' -Status "$processed of $($assignments.Count)" -PercentComplete (($processed / $assignments.Count) * 100)
    $source = $assignment.Source
    $definition = $roleLookup[[string]$source.roleDefinitionId]
    $currentRoleName = [string]$source.roleDefinitionId
    $isPrivileged = $false
    if ($null -ne $definition) {
        $currentRoleName = $definition.displayName
        $isPrivileged = [bool]$definition.isPrivileged
    }
    if (-not $privilegedFlagAvailable) { $isPrivileged = $null }
    # Filter before the per-principal lookup so unwanted roles cost no extra Graph calls.
    if (-not [string]::IsNullOrWhiteSpace($RoleName) -and $currentRoleName -notlike $RoleName) { continue }
    if ($PrivilegedOnly -and -not $isPrivileged) { continue }

    $principal = $source.principal
    $principalName = '(principal not found)'
    $detail = [PSCustomObject]@{ Type = 'unknown'; UpnOrAppId = $null; AccountEnabled = $null; OnPremisesSyncEnabled = $null }
    if ($null -ne $principal) {
        $principalName = $principal.displayName
        $detail = Get-PrincipalDetail -Principal $principal
    }

    $rows.Add([PSCustomObject]@{
        RoleName              = $currentRoleName
        IsPrivilegedRole      = $isPrivileged
        AssignmentType        = $assignment.AssignmentType
        DirectoryScope        = $source.directoryScopeId
        PrincipalType         = $detail.Type
        PrincipalDisplayName  = $principalName
        PrincipalUpnOrAppId   = $detail.UpnOrAppId
        AccountEnabled        = $detail.AccountEnabled
        OnPremisesSyncEnabled = $detail.OnPremisesSyncEnabled
        PrincipalId           = $source.principalId
    })
}
Write-Progress -Activity 'Resolving role assignments' -Completed

$sortedRows = @($rows | Sort-Object -Property RoleName, AssignmentType, PrincipalDisplayName)
if ($sortedRows.Count -gt 0) {
    $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No role assignments matched the selected filters; no CSV was written.'
}

Write-Host ''
Write-Host 'Directory role membership summary (active / eligible)' -ForegroundColor Cyan
foreach ($group in ($sortedRows | Group-Object -Property RoleName | Sort-Object -Property Count -Descending)) {
    $activeCount = @($group.Group | Where-Object { $_.AssignmentType -eq 'Active' }).Count
    Write-Host ('  {0,-50} {1,4} / {2,-4}' -f $group.Name, $activeCount, ($group.Count - $activeCount))
}
Write-Host ('  Assignments exported : {0} -> {1}' -f $sortedRows.Count, $OutputPath)

$globalAdmins = @($sortedRows | Where-Object { $_.RoleName -eq 'Global Administrator' -and $_.AssignmentType -eq 'Active' } | Select-Object -ExpandProperty PrincipalId -Unique)
if ($globalAdmins.Count -gt 5) {
    Write-Warning ('{0} principals hold Global Administrator as an active assignment. Microsoft recommends fewer than 5 Global Administrators; move the rest to PIM eligibility or a lesser role.' -f $globalAdmins.Count)
}
$syncedPrivileged = @($sortedRows | Where-Object { $_.IsPrivilegedRole -and $_.OnPremisesSyncEnabled })
if ($syncedPrivileged.Count -gt 0) {
    $syncedNames = ($syncedPrivileged | Select-Object -ExpandProperty PrincipalDisplayName -Unique) -join ', '
    Write-Warning ('{0} privileged role assignment(s) belong to on-premises synced accounts, which should be cloud-only: {1}' -f $syncedPrivileged.Count, $syncedNames)
}

if ($PassThru) {
    $sortedRows
}
#endregion Main
