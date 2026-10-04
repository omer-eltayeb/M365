<#
.SYNOPSIS
    Reports Intune scope tags with their auto-assignment groups and how many policies and apps carry each tag.
.DESCRIPTION
    Reads the beta collection /deviceManagement/roleScopeTags and each tag's /assignments (device groups that receive the
    tag automatically; group names are resolved through /groups/{id}). It then lists device configuration profiles and
    compliance policies (v1.0), settings catalog policies (beta) and apps with their roleScopeTagIds and counts, per tag,
    how many objects of each type reference it. Tags with no groups and no tagged objects are candidates for clean-up.
    Writes a CSV and optionally emits the rows.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\IntuneScopeTags_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneScopeTagsReport.ps1
    Writes one row per scope tag with assigned groups and usage counts to .\Reports\IntuneScopeTags_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-IntuneScopeTagsReport.ps1 -PassThru | Where-Object { $_.TotalTaggedObjects -eq 0 -and -not $_.IsBuiltIn }
    Shows custom scope tags that no policy or app currently uses.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementRBAC.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementApps.Read.All, Group.Read.All (delegated)
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : Scope tags and settings catalog policies are only exposed on the beta endpoint, which Microsoft may change
                  without notice. Tag id 0 is the built-in Default tag that every untagged object carries. Administrative
                  templates, scripts, enrollment profiles, devices and RBAC role assignments are not counted, so a tag can be
                  in use although every counter shows 0.
.LINK
    https://learn.microsoft.com/graph/api/intune-rbac-rolescopetag-list?view=graph-rest-beta
.LINK
    https://learn.microsoft.com/mem/intune/fundamentals/scope-tags
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
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
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneScopeTags_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$scopes = @('DeviceManagementRBAC.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementApps.Read.All', 'Group.Read.All')
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$graphBeta = 'https://graph.microsoft.com/beta'   # beta: scope tags and settings catalog policies are not exposed in v1.0
try {
    $tags = @(Invoke-GraphPaged -Uri ('{0}/deviceManagement/roleScopeTags?$select=id,displayName,description,isBuiltIn' -f $graphBeta))
}
catch {
    throw "Failed to list scope tags: $($_.Exception.Message)"
}
Write-Verbose ('{0} scope tags found.' -f $tags.Count)

# Count tagged objects per type once, instead of filtering server-side per tag (roleScopeTagIds does not support $filter).
$counters = @(
    [PSCustomObject]@{ Column = 'DeviceConfigurations'; Uri = ('{0}/deviceManagement/deviceConfigurations?$select=id,roleScopeTagIds' -f $graphV1) }
    [PSCustomObject]@{ Column = 'CompliancePolicies'; Uri = ('{0}/deviceManagement/deviceCompliancePolicies?$select=id,roleScopeTagIds' -f $graphV1) }
    [PSCustomObject]@{ Column = 'SettingsCatalogPolicies'; Uri = ('{0}/deviceManagement/configurationPolicies?$select=id,roleScopeTagIds' -f $graphBeta) }
    [PSCustomObject]@{ Column = 'Apps'; Uri = ('{0}/deviceAppManagement/mobileApps?$select=id,roleScopeTagIds' -f $graphV1) }
)
$tagCounts = @{}
$index = 0
foreach ($counter in $counters) {
    $index++
    Write-Progress -Activity 'Counting tagged objects' -Status $counter.Column -PercentComplete ([int](($index / $counters.Count) * 100))
    try {
        $objects = @(Invoke-GraphPaged -Uri $counter.Uri)
    }
    catch {
        Write-Warning ('Could not list {0}; this column stays empty: {1}' -f $counter.Column, $_.Exception.Message)
        continue
    }
    foreach ($object in $objects) {
        foreach ($tagId in @($object.roleScopeTagIds)) {
            $key = '{0}|{1}' -f $counter.Column, $tagId
            if (-not $tagCounts.ContainsKey($key)) { $tagCounts[$key] = 0 }
            $tagCounts[$key]++
        }
    }
}
Write-Progress -Activity 'Counting tagged objects' -Completed

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($tag in $tags) {
    $index++
    Write-Progress -Activity 'Reading scope tag assignments' -Status ('{0} of {1}: {2}' -f $index, $tags.Count, $tag.displayName) -PercentComplete ([int](($index / $tags.Count) * 100))
    $groupNames = @()
    try {
        $assignments = @(Invoke-GraphPaged -Uri ('{0}/deviceManagement/roleScopeTags/{1}/assignments' -f $graphBeta, $tag.id))
        foreach ($assignment in $assignments) {
            if (-not [string]::IsNullOrEmpty($assignment.target.groupId)) { $groupNames += Get-GroupDisplayName -GroupId ([string]$assignment.target.groupId) }
        }
    }
    catch {
        Write-Warning ("Could not read assignments of scope tag '{0}': {1}" -f $tag.displayName, $_.Exception.Message)
        $groupNames += '<assignments unavailable>'
    }
    $row = [ordered]@{ ScopeTagId = $tag.id; DisplayName = $tag.displayName; Description = $tag.description; IsBuiltIn = [bool]$tag.isBuiltIn
        AssignedGroups = ($groupNames -join '; '); AssignedGroupCount = $groupNames.Count }
    $total = 0
    foreach ($counter in $counters) {
        $count = 0
        if ($tagCounts.ContainsKey(('{0}|{1}' -f $counter.Column, $tag.id))) { $count = $tagCounts[('{0}|{1}' -f $counter.Column, $tag.id)] }
        $row[$counter.Column] = $count
        $total += $count
    }
    $row['TotalTaggedObjects'] = $total
    $results.Add([PSCustomObject]$row)
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading scope tag assignments' -Completed

$results | Sort-Object -Property DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$unused = @($results | Where-Object { $_.TotalTaggedObjects -eq 0 -and $_.AssignedGroupCount -eq 0 -and -not $_.IsBuiltIn }).Count
Write-Host ("`nScope tags        : {0}" -f $results.Count) -ForegroundColor Cyan
Write-Host ('  Built-in        : {0}' -f @($results | Where-Object { $_.IsBuiltIn }).Count) -ForegroundColor Gray
Write-Host ('  With auto-assignment groups : {0}' -f @($results | Where-Object { $_.AssignedGroupCount -gt 0 }).Count) -ForegroundColor Green
$unusedColour = 'Green'; if ($unused -gt 0) { $unusedColour = 'Yellow' }
Write-Host ('  Custom tags with no groups and no tagged objects : {0}' -f $unused) -ForegroundColor $unusedColour
Write-Host ('Report saved to {0}' -f $OutputPath) -ForegroundColor Cyan
if ($PassThru) { $results }
#endregion Main
