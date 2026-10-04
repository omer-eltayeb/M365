<#
.SYNOPSIS
    Finds Intune policies, scripts and (optionally) apps that are not assigned, or are assigned only to empty or deleted groups.
.DESCRIPTION
    Lists device configuration profiles and compliance policies (v1.0), settings catalog policies, administrative templates,
    platform scripts and remediation scripts (beta) and optionally apps, reads the /assignments of every object and classifies
    it as NoAssignments, AssignedToEmptyGroup or AssignedToDeletedGroup. Group membership is checked once per group through
    /groups/{id}/members/$count and cached. Objects targeted to All Devices, All Users or at least one populated group are in
    use and are not reported. Writes a CSV and optionally emits the rows.
.PARAMETER IncludeApps
    Also evaluate mobile apps (/deviceAppManagement/mobileApps); requires DeviceManagementApps.Read.All.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\IntuneUnusedPolicies_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneUnusedPolicies.ps1
    Reports every policy and script without an effective assignment to .\Reports\IntuneUnusedPolicies_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-IntuneUnusedPolicies.ps1 -IncludeApps -PassThru | Where-Object { $_.Reason -eq 'AssignedToDeletedGroup' }
    Includes apps and shows only objects whose assignment groups no longer exist in Entra ID.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All, Group.Read.All, GroupMember.Read.All (delegated); DeviceManagementApps.Read.All with -IncludeApps
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : Settings catalog, administrative template, platform script and remediation script objects exist only on the beta
                  endpoint, which Microsoft may change without notice. Exclusion-only assignments count as NoAssignments. Apps used
                  as dependencies or supersedence targets can appear unused. One Graph call per object plus two per unique group.
.LINK
    https://learn.microsoft.com/graph/api/intune-shared-deviceconfiguration-list
.LINK
    https://learn.microsoft.com/graph/api/group-list-members
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
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

$script:groupCache = @{}
function Get-GroupInfo {
    <# Resolves a group's display name and member count once and caches it; a 404 marks the group as deleted. #>
    param([string]$GroupId)
    if ($script:groupCache.ContainsKey($GroupId)) { return $script:groupCache[$GroupId] }
    $info = [PSCustomObject]@{ Name = '<unresolved>'; MemberCount = $null; Exists = $true }
    try {
        $group = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/groups/{0}?$select=displayName' -f $GroupId) -OutputType PSObject -ErrorAction Stop
        $info.Name = [string]$group.displayName
        # $count returns a bare number (text/plain) and only works with the advanced-query consistency header.
        $count = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/groups/{0}/members/$count' -f $GroupId) -Headers @{ ConsistencyLevel = 'eventual' } -ErrorAction Stop
        $info.MemberCount = [int]"$count"
    }
    catch {
        $errorText = '{0} {1}' -f $_.Exception.Message, $_.ErrorDetails.Message
        if ($errorText -match 'NotFound|\b404\b|does not exist') { $info.Name = '<deleted group>'; $info.Exists = $false }
        else { Write-Warning ('Could not resolve group {0}: {1}' -f $GroupId, $_.Exception.Message) }
    }
    $script:groupCache[$GroupId] = $info
    return $info
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneUnusedPolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$scopes = @('DeviceManagementConfiguration.Read.All', 'Group.Read.All', 'GroupMember.Read.All')
if ($IncludeApps) { $scopes += 'DeviceManagementApps.Read.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$graphBeta = 'https://graph.microsoft.com/beta'   # beta: settings catalog, administrative templates, platform and remediation scripts are not exposed in v1.0
$sources = @(
    [PSCustomObject]@{ PolicyType = 'DeviceConfiguration'; BaseUri = "$graphV1/deviceManagement/deviceConfigurations"; NameProperty = 'displayName' }
    [PSCustomObject]@{ PolicyType = 'SettingsCatalog'; BaseUri = "$graphBeta/deviceManagement/configurationPolicies"; NameProperty = 'name' }
    [PSCustomObject]@{ PolicyType = 'Compliance'; BaseUri = "$graphV1/deviceManagement/deviceCompliancePolicies"; NameProperty = 'displayName' }
    [PSCustomObject]@{ PolicyType = 'AdministrativeTemplate'; BaseUri = "$graphBeta/deviceManagement/groupPolicyConfigurations"; NameProperty = 'displayName' }
    [PSCustomObject]@{ PolicyType = 'PlatformScript'; BaseUri = "$graphBeta/deviceManagement/deviceManagementScripts"; NameProperty = 'displayName' }
    [PSCustomObject]@{ PolicyType = 'RemediationScript'; BaseUri = "$graphBeta/deviceManagement/deviceHealthScripts"; NameProperty = 'displayName' }
)
if ($IncludeApps) {
    $sources += [PSCustomObject]@{ PolicyType = 'App'; BaseUri = "$graphV1/deviceAppManagement/mobileApps"; NameProperty = 'displayName' }
}
$includeTargetTypes = @('#microsoft.graph.groupAssignmentTarget', '#microsoft.graph.allDevicesAssignmentTarget', '#microsoft.graph.allLicensedUsersAssignmentTarget')

$results = New-Object -TypeName System.Collections.Generic.List[object]
$scanned = 0
foreach ($source in $sources) {
    try {
        $policies = @(Invoke-GraphPaged -Uri ('{0}?$select=id,{1},lastModifiedDateTime' -f $source.BaseUri, $source.NameProperty))
    }
    catch {
        Write-Warning ('Could not list {0} objects: {1}' -f $source.PolicyType, $_.Exception.Message)
        continue
    }
    $index = 0
    foreach ($policy in $policies) {
        $index++; $scanned++
        $policyName = [string]$policy.($source.NameProperty)
        $progress = @{ Activity = ('Checking {0} assignments' -f $source.PolicyType); Status = ('{0} of {1}: {2}' -f $index, $policies.Count, $policyName) }
        Write-Progress @progress -PercentComplete ([int](($index / $policies.Count) * 100))
        try {
            $assignments = @(Invoke-GraphPaged -Uri ('{0}/{1}/assignments' -f $source.BaseUri, $policy.id))
        }
        catch {
            Write-Warning ("Could not read assignments of {0} '{1}': {2}" -f $source.PolicyType, $policyName, $_.Exception.Message)
            continue
        }
        $includes = @($assignments | Where-Object { $includeTargetTypes -contains $_.target.'@odata.type' })
        $reason = $null; $groupNames = @()
        if ($includes.Count -eq 0) {
            $reason = 'NoAssignments'
            if ($assignments.Count -gt 0) { $groupNames += '(exclusion-only assignment)' }
        }
        else {
            $inUse = $false; $emptyGroups = 0
            foreach ($assignment in $includes) {
                if ($assignment.target.'@odata.type' -ne '#microsoft.graph.groupAssignmentTarget') { $inUse = $true; break }
                $info = Get-GroupInfo -GroupId ([string]$assignment.target.groupId)
                if (-not $info.Exists) { $groupNames += ('<deleted group {0}>' -f $assignment.target.groupId) }
                elseif ($info.MemberCount -eq 0) { $emptyGroups++; $groupNames += ('{0} (empty)' -f $info.Name) }
                else { $inUse = $true; break }   # populated, or membership unknown: never flag on incomplete data
            }
            if (-not $inUse) {
                $reason = 'AssignedToDeletedGroup'
                if ($emptyGroups -gt 0) { $reason = 'AssignedToEmptyGroup' }
            }
        }
        if ($null -ne $reason) {
            $lastModified = $null; if (-not [string]::IsNullOrEmpty($policy.lastModifiedDateTime)) { $lastModified = [datetime]$policy.lastModifiedDateTime }
            $results.Add([PSCustomObject]@{ PolicyType = $source.PolicyType; Name = $policyName; Id = $policy.id; LastModified = $lastModified
                    Reason = $reason; GroupNames = ($groupNames -join '; ') })
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Progress -Activity ('Checking {0} assignments' -f $source.PolicyType) -Completed
}

$results | Sort-Object -Property PolicyType, Name | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ("`nObjects scanned : {0}" -f $scanned) -ForegroundColor Cyan
Write-Host ('Unused objects  : {0}' -f $results.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Reason | Sort-Object -Property Name)) {
    Write-Host ('  {0,-24} {1,6}' -f $group.Name, $group.Count) -ForegroundColor Yellow
}
Write-Host ('Report saved to {0}' -f $OutputPath) -ForegroundColor Cyan
if ($PassThru) { $results }
#endregion Main
