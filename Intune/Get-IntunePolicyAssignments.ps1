<#
.SYNOPSIS
    Builds a "who gets what" assignment matrix for Intune policies and (optionally) apps.
.DESCRIPTION
    Enumerates device configuration profiles (v1.0), settings catalog policies (beta), compliance
    policies (v1.0), administrative templates (beta) and, with -IncludeApps, assigned apps (v1.0),
    reads the /assignments collection of each one and emits one row per assignment with the
    resolved target (All users, All devices, included or excluded group) and assignment filter.
    Group display names are resolved once and cached; deleted groups are shown as <deleted group>.
    Policies without any assignment are listed as warnings at the end.
.PARAMETER GroupName
    Wildcard pattern (for example 'SG-Intune-*'). Only assignments that target a matching group are returned.
.PARAMETER IncludeApps
    Also include app assignments (mobileApps with isAssigned eq true). Requests DeviceManagementApps.Read.All.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntunePolicyAssignments_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the assignment rows to the pipeline.
.EXAMPLE
    PS> .\Get-IntunePolicyAssignments.ps1
    Exports every policy assignment and warns about policies that are not assigned to anything.
.EXAMPLE
    PS> .\Get-IntunePolicyAssignments.ps1 -GroupName 'SG-Pilot*' -IncludeApps -PassThru | Format-Table PolicyType, PolicyName, Intent, GroupName, FilterType
    Shows which policies and apps are targeted at the pilot groups, including assignment filters.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All, Group.Read.All and, with -IncludeApps,
                  DeviceManagementApps.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : Settings catalog policies and administrative templates are only exposed on the beta endpoint.
                  One Graph call is made per policy (plus one per distinct group); a 200 ms pause between policies
                  keeps the run inside the Intune throttling limits. FilterId refers to an assignment filter under
                  Devices > Assignment filters.
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-deviceconfigurationassignment-list
.LINK
    https://learn.microsoft.com/graph/api/intune-apps-mobileappassignment-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$GroupName,

    [Parameter()]
    [switch]$IncludeApps,

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

function Get-GroupDisplayName {
    <# Resolves a group id to its display name through a script-level cache; deleted groups return '<deleted group>'. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )
    if ($script:groupNameCache.ContainsKey($GroupId)) {
        return $script:groupNameCache[$GroupId]
    }
    $name = '<unresolved>'
    try {
        $group = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/groups/{0}?$select=displayName' -f $GroupId) -OutputType PSObject -ErrorAction Stop
        $name = [string]$group.displayName
    }
    catch {
        $errorText = '{0} {1}' -f $_.Exception.Message, $_.ErrorDetails.Message
        if ($errorText -match 'NotFound|\b404\b|does not exist') {
            $name = '<deleted group>'
        }
        else {
            Write-Warning ('Could not resolve group {0}: {1}' -f $GroupId, $_.Exception.Message)
        }
    }
    $script:groupNameCache[$GroupId] = $name
    return $name
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntunePolicyAssignments_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$scopes = @('DeviceManagementConfiguration.Read.All', 'Group.Read.All')
if ($IncludeApps) { $scopes += 'DeviceManagementApps.Read.All' }
try {
    Connect-GraphIfNeeded -Scopes $scopes
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0'
$graphBeta = 'https://graph.microsoft.com/beta'   # beta: settings catalog policies and administrative templates are not exposed in v1.0
$sources = @(
    [PSCustomObject]@{ PolicyType = 'DeviceConfiguration'; BaseUri = "$graphV1/deviceManagement/deviceConfigurations"; ListQuery = '?$select=id,displayName'; NameProperty = 'displayName' }
    [PSCustomObject]@{ PolicyType = 'SettingsCatalog'; BaseUri = "$graphBeta/deviceManagement/configurationPolicies"; ListQuery = '?$select=id,name'; NameProperty = 'name' }
    [PSCustomObject]@{ PolicyType = 'Compliance'; BaseUri = "$graphV1/deviceManagement/deviceCompliancePolicies"; ListQuery = '?$select=id,displayName'; NameProperty = 'displayName' }
    [PSCustomObject]@{ PolicyType = 'AdministrativeTemplate'; BaseUri = "$graphBeta/deviceManagement/groupPolicyConfigurations"; ListQuery = '?$select=id,displayName'; NameProperty = 'displayName' }
)
if ($IncludeApps) {
    $sources += [PSCustomObject]@{ PolicyType = 'App'; BaseUri = "$graphV1/deviceAppManagement/mobileApps"; ListQuery = '?$filter=isAssigned eq true&$select=id,displayName'; NameProperty = 'displayName' }
}

$targetTypeMap = @{
    '#microsoft.graph.allLicensedUsersAssignmentTarget' = 'AllUsers'
    '#microsoft.graph.allDevicesAssignmentTarget'       = 'AllDevices'
    '#microsoft.graph.groupAssignmentTarget'            = 'Group'
    '#microsoft.graph.exclusionGroupAssignmentTarget'   = 'ExclusionGroup'
}
$script:groupNameCache = @{}
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$unassigned = New-Object -TypeName System.Collections.Generic.List[object]
$policyCount = 0

foreach ($source in $sources) {
    Write-Verbose ('Listing {0} from {1}' -f $source.PolicyType, $source.BaseUri)
    try {
        $policies = @(Invoke-GraphPaged -Uri ($source.BaseUri + $source.ListQuery))
    }
    catch {
        Write-Warning ('Could not list {0} policies: {1}' -f $source.PolicyType, $_.Exception.Message)
        continue
    }
    $nameProperty = $source.NameProperty
    $index = 0
    foreach ($policy in $policies) {
        $index++
        $policyCount++
        $policyName = [string]$policy.$nameProperty
        Write-Progress -Activity ('Reading {0} assignments' -f $source.PolicyType) -Status ('{0} of {1}: {2}' -f $index, $policies.Count, $policyName) -PercentComplete ([int](($index / $policies.Count) * 100))
        try {
            $assignments = @(Invoke-GraphPaged -Uri ('{0}/{1}/assignments' -f $source.BaseUri, $policy.id))
        }
        catch {
            Write-Warning ("Could not read assignments of {0} '{1}': {2}" -f $source.PolicyType, $policyName, $_.Exception.Message)
            continue
        }
        if ($assignments.Count -eq 0) {
            $unassigned.Add(('{0}: {1}' -f $source.PolicyType, $policyName))
        }

        foreach ($assignment in $assignments) {
            $target = $assignment.target
            $odataType = [string]$target.'@odata.type'
            $targetType = $targetTypeMap[$odataType]
            if ([string]::IsNullOrEmpty($targetType)) { $targetType = $odataType }

            $groupId = $null
            $resolvedGroupName = $null
            if ($targetType -eq 'Group' -or $targetType -eq 'ExclusionGroup') {
                $groupId = [string]$target.groupId
                $resolvedGroupName = Get-GroupDisplayName -GroupId $groupId
            }

            # Apps carry a real intent (required/available/uninstall); configuration policies only include or exclude.
            if ($source.PolicyType -eq 'App') { $intent = [string]$assignment.intent }
            elseif ($targetType -eq 'ExclusionGroup') { $intent = 'Exclude' }
            else { $intent = 'Include' }

            $filterType = [string]$target.deviceAndAppManagementAssignmentFilterType
            if ([string]::IsNullOrEmpty($filterType)) { $filterType = 'none' }

            $rows.Add([PSCustomObject]@{
                    PolicyType = $source.PolicyType
                    PolicyName = $policyName
                    PolicyId   = $policy.id
                    Intent     = $intent
                    TargetType = $targetType
                    GroupId    = $groupId
                    GroupName  = $resolvedGroupName
                    FilterId   = $target.deviceAndAppManagementAssignmentFilterId
                    FilterType = $filterType
                })
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Progress -Activity ('Reading {0} assignments' -f $source.PolicyType) -Completed
}

$output = $rows
if (-not [string]::IsNullOrWhiteSpace($GroupName)) {
    $output = @($rows | Where-Object { $_.GroupName -like $GroupName })
    Write-Verbose ('{0} of {1} assignments target groups matching "{2}".' -f $output.Count, $rows.Count, $GroupName)
}

if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No assignments matched the specified criteria; no CSV file was written.'
}

Write-Host ''
Write-Host ('Policies scanned      : {0}' -f $policyCount) -ForegroundColor Cyan
Write-Host ('Assignments reported  : {0}' -f $output.Count) -ForegroundColor Cyan
foreach ($group in ($output | Group-Object -Property PolicyType | Sort-Object -Property Name)) {
    Write-Host ('  {0,-24} {1,6}' -f $group.Name, $group.Count)
}
if ($unassigned.Count -gt 0) {
    Write-Warning ('{0} policies have no assignments at all:' -f $unassigned.Count)
    foreach ($item in $unassigned) {
        Write-Warning ('  {0}' -f $item)
    }
}

if ($PassThru) {
    $output
}
#endregion Main
