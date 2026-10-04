<#
.SYNOPSIS
    Exports the Privileged Identity Management (PIM) role settings (activation, assignment and approval rules) of every Entra directory role.
.DESCRIPTION
    Reads the PIM policy assignments of the directory (GET /policies/roleManagementPolicyAssignments filtered on scope '/' and
    scopeType DirectoryRole, expanded with policy and rules) and flattens the rules per role: maximum activation duration, MFA /
    justification / ticket requirements, approval and approvers, authentication context, permanent eligible and active assignment
    settings, MFA on active assignment and notification rule count. Privileged roles that activate without MFA or allow permanent
    active assignments are flagged in the Warning column. Each policy is saved as JSON and the flattened settings as CSV.
.PARAMETER RoleName
    Only roles whose display name matches this wildcard pattern, for example 'Global*' or '*Administrator'.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraPimRoleSettings_yyyyMMdd-HHmm.csv.
.PARAMETER JsonFolder
    Folder that receives one JSON file per role policy. Defaults to .\Reports\EntraPimRoleSettings_yyyyMMdd-HHmm\.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Export-EntraPimRoleSettings.ps1
    Exports the PIM settings of every directory role to CSV and JSON and prints the roles with warnings.
.EXAMPLE
    PS> .\Export-EntraPimRoleSettings.ps1 -RoleName 'Global Administrator' -JsonFolder C:\Backup\PIM -PassThru
    Shows the Global Administrator activation settings in the console and saves the policy JSON to C:\Backup\PIM.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : RoleManagementPolicy.Read.Directory, RoleManagement.Read.Directory (delegated).
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : Requires Microsoft Entra ID P2 or Entra ID Governance. Role definitions are read from beta for the isPrivileged
                  flag; if that fails the script falls back to v1.0 plus a built-in list of well-known privileged roles. Approver
                  names come from the description stored in the policy, so renamed users or groups may show the old name.
.LINK
    https://learn.microsoft.com/graph/api/policyroot-list-rolemanagementpolicyassignments
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$RoleName,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$JsonFolder,

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

function ConvertFrom-IsoDuration {
    <# Converts an ISO 8601 duration such as PT8H or P365D to a [timespan]; returns $null when empty. #>
    param([string]$Duration)
    if ([string]::IsNullOrWhiteSpace($Duration)) { return $null }
    return [System.Xml.XmlConvert]::ToTimeSpan($Duration)
}
#endregion Helpers

#region Main
$timestamp = Get-Date -Format 'yyyyMMdd-HHmm'
$reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraPimRoleSettings_{0}.csv' -f $timestamp) }
if ([string]::IsNullOrWhiteSpace($JsonFolder)) { $JsonFolder = Join-Path -Path $reportFolder -ChildPath ('EntraPimRoleSettings_{0}' -f $timestamp) }
foreach ($folder in @((Split-Path -Path $OutputPath -Parent), $JsonFolder)) {
    if (-not [string]::IsNullOrWhiteSpace($folder) -and -not (Test-Path -Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
}

try { Connect-GraphIfNeeded -Scopes @('RoleManagementPolicy.Read.Directory', 'RoleManagement.Read.Directory') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# Safety net for tenants where the beta isPrivileged flag cannot be read: roles that always deserve MFA and no permanent assignments.
$privilegedRoleNames = @('Global Administrator', 'Privileged Role Administrator', 'Security Administrator', 'Exchange Administrator',
    'SharePoint Administrator', 'Intune Administrator', 'Conditional Access Administrator', 'Application Administrator',
    'Cloud Application Administrator', 'User Administrator', 'Authentication Administrator', 'Privileged Authentication Administrator',
    'Hybrid Identity Administrator', 'Global Reader')
try {
    # beta: the isPrivileged classification is only exposed on the beta roleDefinitions resource; the ids are identical to v1.0.
    $definitions = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$select=id,displayName,isPrivileged'
}
catch {
    Write-Warning "Role definitions could not be read from beta; using v1.0 and the built-in list of privileged roles. $($_.Exception.Message)"
    $definitions = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName'
}
$roleLookup = @{}
foreach ($definition in $definitions) { $roleLookup[[string]$definition.id] = $definition }

$assignmentsUri = 'https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq ''/'' and scopeType eq ''DirectoryRole''&$expand=policy($expand=rules)'
try { $policyAssignments = Invoke-GraphPaged -Uri $assignmentsUri }
catch { throw "Failed to read the PIM role policies (requires Microsoft Entra ID P2): $($_.Exception.Message)" }
Write-Verbose "Loaded $($policyAssignments.Count) role policy assignments."

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($assignment in $policyAssignments) {
    $processed++
    $definition = $roleLookup[[string]$assignment.roleDefinitionId]
    $roleDisplayName = [string]$assignment.roleDefinitionId
    if ($null -ne $definition) { $roleDisplayName = $definition.displayName }
    if (-not [string]::IsNullOrWhiteSpace($RoleName) -and $roleDisplayName -notlike $RoleName) { continue }
    Write-Progress -Activity 'Exporting PIM role settings' -Status $roleDisplayName -PercentComplete (($processed / $policyAssignments.Count) * 100)

    # Rule ids are fixed by the service (Expiration_EndUser_Assignment, Enablement_Admin_Assignment, ...), so a lookup by id is reliable.
    $rules = @{}
    foreach ($rule in $assignment.policy.rules) { $rules[[string]$rule.id] = $rule }
    $activation = @($rules['Enablement_EndUser_Assignment'].enabledRules)
    $approval = $rules['Approval_EndUser_Assignment'].setting
    $authContext = $rules['AuthenticationContext_EndUser_Assignment']
    $approvers = foreach ($approver in @(@($approval.approvalStages) | ForEach-Object { $_.primaryApprovers })) {
        @($approver.description, $approver.userId, $approver.groupId) | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 1
    }
    $isPrivileged = [bool]$definition.isPrivileged -or $privilegedRoleNames -contains $roleDisplayName
    $mfaOnActivation = $activation -contains 'MultiFactorAuthentication'
    $permanentActiveAllowed = -not [bool]$rules['Expiration_Admin_Assignment'].isExpirationRequired
    $warnings = @()
    if ($isPrivileged -and -not $mfaOnActivation -and -not [bool]$authContext.isEnabled) { $warnings += 'Privileged role activates without MFA or authentication context' }
    if ($isPrivileged -and $permanentActiveAllowed) { $warnings += 'Privileged role allows permanent active assignments' }

    $fileName = (($roleDisplayName -replace '[\\/:*?"<>|]', '_').Trim()) + '.json'
    try { $assignment.policy | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path -Path $JsonFolder -ChildPath $fileName) -Encoding UTF8 }
    catch { Write-Warning ('Policy for "{0}" could not be saved as JSON: {1}' -f $roleDisplayName, $_.Exception.Message); $fileName = $null }
    $rows.Add([PSCustomObject]@{
        RoleName                 = $roleDisplayName
        IsPrivilegedRole         = $isPrivileged
        ActivationMaxHours       = (ConvertFrom-IsoDuration -Duration $rules['Expiration_EndUser_Assignment'].maximumDuration).TotalHours
        MfaOnActivation          = $mfaOnActivation
        JustificationRequired    = $activation -contains 'Justification'
        TicketRequired           = $activation -contains 'Ticketing'
        ApprovalRequired         = [bool]$approval.isApprovalRequired
        Approvers                = (@($approvers) -join '; ')
        AuthenticationContext    = $(if ([bool]$authContext.isEnabled) { $authContext.claimValue } else { $null })
        PermanentEligibleAllowed = -not [bool]$rules['Expiration_Admin_Eligibility'].isExpirationRequired
        EligibleMaxDays          = (ConvertFrom-IsoDuration -Duration $rules['Expiration_Admin_Eligibility'].maximumDuration).TotalDays
        PermanentActiveAllowed   = $permanentActiveAllowed
        ActiveMaxDays            = (ConvertFrom-IsoDuration -Duration $rules['Expiration_Admin_Assignment'].maximumDuration).TotalDays
        MfaOnActiveAssignment    = @($rules['Enablement_Admin_Assignment'].enabledRules) -contains 'MultiFactorAuthentication'
        NotificationRuleCount    = @($assignment.policy.rules | Where-Object { $_.id -like 'Notification_*' }).Count
        Warning                  = ($warnings -join '; ')
        PolicyId                 = $assignment.policyId
        LastModifiedDateTime     = $assignment.policy.lastModifiedDateTime
        JsonFile                 = $fileName
    })
}
Write-Progress -Activity 'Exporting PIM role settings' -Completed

$sortedRows = @($rows | Sort-Object -Property @{ Expression = 'IsPrivilegedRole'; Descending = $true }, RoleName)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No roles matched the selected filter; no CSV was written.' }

Write-Host 'PIM role settings summary' -ForegroundColor Cyan
Write-Host ('  Roles exported        : {0} -> {1}' -f $sortedRows.Count, $OutputPath)
Write-Host ('  Policy JSON files     : {0}' -f $JsonFolder)
Write-Host ('  Privileged roles      : {0}' -f @($sortedRows | Where-Object { $_.IsPrivilegedRole }).Count)
$flagged = @($sortedRows | Where-Object { -not [string]::IsNullOrEmpty($_.Warning) })
if ($flagged.Count -gt 0) {
    Write-Host ('  Roles with warnings   : {0}' -f $flagged.Count) -ForegroundColor Yellow
    foreach ($row in $flagged) { Write-Host ('    {0,-45} {1}' -f $row.RoleName, $row.Warning) -ForegroundColor Yellow }
}

if ($PassThru) { $sortedRows }
#endregion Main
