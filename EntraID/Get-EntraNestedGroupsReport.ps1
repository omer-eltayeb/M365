<#
.SYNOPSIS
    Reports nested group membership in Microsoft Entra ID (groups that contain other groups), including circular references.
.DESCRIPTION
    Reads the group members of each group with /groups/{id}/members/microsoft.graph.group through Microsoft Graph and
    walks the nesting tree recursively (default depth 5) with cycle protection. Each parent/child relationship becomes one
    row with RootGroup, ParentGroup, ChildGroup, Depth, ChildType and Flags: M365GroupNested, RoleAssignableContainsGroup,
    CircularReference (the child is one of its own ancestors) and MaxDepthReached. Without -GroupName / -GroupId every
    group is read once and the walk starts at the top-level groups, so each nesting chain is reported once.
.PARAMETER GroupName
    One or more display names (exact, or a wildcard matched client-side) of the groups to start from.
.PARAMETER GroupId
    One or more object IDs of the groups to start from.
.PARAMETER MaxDepth
    Maximum nesting depth to follow below each starting group (1-20, default 5).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraNestedGroups_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report rows to the pipeline.
.EXAMPLE
    PS> .\Get-EntraNestedGroupsReport.ps1
    Reads every group in the tenant and reports all nesting chains starting from the top-level groups.
.EXAMPLE
    PS> .\Get-EntraNestedGroupsReport.ps1 -GroupName 'SG-Intune-*' -MaxDepth 3 -PassThru | Where-Object { $_.Flags }
    Shows only the flagged relationships up to three levels below the SG-Intune- groups.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, GroupMember.Read.All (delegated)
    Category    : Groups
    Changes     : No
    Notes       : Without a group filter one request is made per group (about five per second), so 5,000 groups take roughly
                  20 minutes. Nesting that involves Microsoft 365 groups is ignored by most workloads (Teams, SharePoint,
                  licensing) and role-assignable groups must not contain groups, hence the flags on those rows.
.LINK
    https://learn.microsoft.com/graph/api/group-list-members
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$GroupName,

    [Parameter()]
    [string[]]$GroupId,

    [Parameter()]
    [ValidateRange(1, 20)]
    [int]$MaxDepth = 5,

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

function Get-ChildGroups {
    <# Returns the direct group members of a group; each group is read from Graph once and then served from the cache. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )
    if (-not $script:ChildCache.ContainsKey($GroupId)) {
        Write-Progress -Activity 'Reading group members' -Status ('{0} groups read' -f $script:ChildCache.Count)
        try { $script:ChildCache[$GroupId] = @(Invoke-GraphPaged -Uri ('{0}/groups/{1}/members/microsoft.graph.group?$select={2}&$top=999' -f $script:GraphV1, $GroupId, $script:GroupSelect)) }
        catch { Write-Warning "Group members of $GroupId could not be read: $($_.Exception.Message)"; $script:ChildCache[$GroupId] = @() }
        Start-Sleep -Milliseconds 200
    }
    return $script:ChildCache[$GroupId]
}

function Add-NestingRows {
    <# Adds one row per child group of the last group in $Path (root ... parent) and recurses until MaxDepth or a cycle is hit. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Parent,

        [Parameter(Mandatory = $true)]
        [string[]]$Path
    )
    $script:Walked[$Parent.id] = $true
    $depth = $Path.Count
    if ($depth -eq 1) { $script:RootName = $Parent.displayName }
    foreach ($child in (Get-ChildGroups -GroupId $Parent.id)) {
        $flags = New-Object -TypeName System.Collections.Generic.List[string]
        if (@($Parent.groupTypes) -contains 'Unified' -or @($child.groupTypes) -contains 'Unified') { $flags.Add('M365GroupNested') }
        if ($Parent.isAssignableToRole -eq $true) { $flags.Add('RoleAssignableContainsGroup') }
        $circular = $Path -contains $child.id
        if ($circular) { $flags.Add('CircularReference') }
        elseif ($depth -ge $MaxDepth -and @(Get-ChildGroups -GroupId $child.id).Count -gt 0) { $flags.Add('MaxDepthReached') }
        if (@($child.groupTypes) -contains 'Unified') { $childType = 'Microsoft 365' }
        elseif ($child.mailEnabled -and $child.securityEnabled) { $childType = 'Mail-enabled security' }
        elseif ($child.securityEnabled) { $childType = 'Security' }
        else { $childType = 'Distribution' }
        if (@($child.groupTypes) -contains 'DynamicMembership') { $childType = 'Dynamic ' + $childType }
        $script:Rows.Add([PSCustomObject]@{ RootGroup = $script:RootName; ParentGroup = $Parent.displayName; ParentGroupId = $Parent.id; ChildGroup = $child.displayName
            ChildGroupId = $child.id; Depth = $depth; ChildType = $childType; ChildIsRoleAssignable = ($child.isAssignableToRole -eq $true); Flags = ($flags -join ';') })
        if (-not $circular -and $depth -lt $MaxDepth) { Add-NestingRows -Parent $child -Path ($Path + $child.id) }
    }
}
#endregion Helpers
#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraNestedGroups_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('Group.Read.All', 'GroupMember.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$script:GraphV1 = 'https://graph.microsoft.com/v1.0'
$script:GroupSelect = 'id,displayName,groupTypes,isAssignableToRole,mailEnabled,securityEnabled'
$script:ChildCache = @{}
$script:Walked = @{}
$script:Rows = New-Object -TypeName System.Collections.Generic.List[object]
$scoped = (@($GroupName).Count + @($GroupId).Count) -gt 0
$roots = New-Object -TypeName System.Collections.Generic.List[object]
try {
    foreach ($id in @($GroupId | Where-Object { $_ })) {
        $roots.Add((Invoke-MgGraphRequest -Method GET -Uri ('{0}/groups/{1}?$select={2}' -f $script:GraphV1, $id, $script:GroupSelect) -OutputType PSObject -ErrorAction Stop))
    }
    foreach ($name in @($GroupName | Where-Object { $_ })) {
        # Graph has no wildcard filter for displayName, so patterns are matched client-side against all groups.
        $uri = "{0}/groups?`$filter=displayName eq '{1}'&`$select={2}" -f $script:GraphV1, $name.Replace("'", "''"), $script:GroupSelect
        $pattern = '*'
        if ($name -match '[\*\?]') { $uri = '{0}/groups?$select={1}&$top=999' -f $script:GraphV1, $script:GroupSelect; $pattern = $name }
        $hits = @(Invoke-GraphPaged -Uri $uri | Where-Object { $_.displayName -like $pattern })
        if ($hits.Count -eq 0) { Write-Warning "No group matches '$name'." }
        foreach ($hit in $hits) { $roots.Add($hit) }
    }
    if (-not $scoped) {
        $allGroups = @(Invoke-GraphPaged -Uri ('{0}/groups?$select={1}&$top=999' -f $script:GraphV1, $script:GroupSelect))
        foreach ($group in $allGroups) { $null = Get-ChildGroups -GroupId $group.id }
        # Top-level groups (never nested themselves) are the starting points, so every chain is reported once.
        $nestedIds = @{}
        foreach ($children in $script:ChildCache.Values) { foreach ($child in $children) { $nestedIds[$child.id] = $true } }
        foreach ($group in @($allGroups | Where-Object { @($script:ChildCache[$_.id]).Count -gt 0 -and -not $nestedIds.ContainsKey($_.id) })) { $roots.Add($group) }
    }
}
catch { throw "Failed to resolve the groups to report: $($_.Exception.Message)" }
$roots = @($roots | Sort-Object -Property id -Unique)
if ($scoped -and $roots.Count -eq 0) { throw 'No matching groups were found.' }
foreach ($root in $roots) { Add-NestingRows -Parent $root -Path @($root.id) }
if (-not $scoped) {
    # Groups that only exist inside a cycle have no top-level entry point; walk them too so the loop is reported.
    foreach ($group in @($allGroups | Where-Object { @($script:ChildCache[$_.id]).Count -gt 0 -and -not $script:Walked.ContainsKey($_.id) })) {
        Add-NestingRows -Parent $group -Path @($group.id)
    }
}
Write-Progress -Activity 'Reading group members' -Completed
$script:Rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ('Nested groups report: {0} starting group(s), {1} nesting relationship(s)' -f $roots.Count, $script:Rows.Count) -ForegroundColor Cyan
foreach ($flag in 'M365GroupNested', 'RoleAssignableContainsGroup', 'CircularReference', 'MaxDepthReached') {
    Write-Host ('  {0,-29}: {1}' -f $flag, @($script:Rows | Where-Object { $_.Flags -match $flag }).Count) -ForegroundColor Yellow
}
Write-Host ('  Report               : {0}' -f $OutputPath)
if ($PassThru) { $script:Rows }
#endregion Main
