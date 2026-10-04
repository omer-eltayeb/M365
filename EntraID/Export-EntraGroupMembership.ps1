<#
.SYNOPSIS
    Exports the members (direct or transitive) or the owners of one, several or all Microsoft Entra ID groups to CSV.
.DESCRIPTION
    Resolves the target groups by display name (exact or wildcard), by object ID or selects every group in the tenant,
    then reads /groups/{id}/members (or /transitiveMembers with -Transitive, or /owners with -OwnersOnly) through
    Microsoft Graph. Each member becomes one row with the member type taken from @odata.type (user, group, device,
    servicePrincipal, orgContact), display name, UPN, mail, user type and account state. Output columns: GroupName,
    GroupId, GroupType, Relationship (Direct / Transitive / Owner), MemberType, DisplayName, UserPrincipalName, Mail,
    UserType, AccountEnabled, MemberId.
.PARAMETER GroupName
    One or more group display names. Exact names are resolved server-side; names containing * or ? are matched
    client-side against every group in the tenant.
.PARAMETER GroupId
    One or more group object IDs.
.PARAMETER All
    Exports the membership of every group in the tenant (a warning is shown because this can take a long time).
.PARAMETER Transitive
    Reads /transitiveMembers so members of nested groups are flattened into the result. Cannot be combined with -OwnersOnly.
.PARAMETER OwnersOnly
    Exports the owners instead of the members.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraGroupMembership_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Export-EntraGroupMembership.ps1 -GroupName 'SG-Intune-Pilot'
    Exports the direct members of the pilot group.
.EXAMPLE
    PS> .\Export-EntraGroupMembership.ps1 -GroupName 'SG-Intune-*' -Transitive
    Exports the flattened membership of every group whose name starts with SG-Intune-.
.EXAMPLE
    PS> .\Export-EntraGroupMembership.ps1 -All -OwnersOnly -PassThru | Group-Object -Property UserPrincipalName | Sort-Object -Property Count -Descending
    Shows who owns the most groups in the tenant.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, GroupMember.Read.All, User.Read.All (delegated)
    Category    : Groups
    Changes     : No
    Notes       : UserPrincipalName, Mail, UserType and AccountEnabled are only populated for member types that carry
                  those properties (devices have AccountEnabled but no UPN; nested groups have neither). Members of
                  dynamic groups reflect the last rule evaluation, which can lag a few minutes behind directory changes.
.LINK
    https://learn.microsoft.com/graph/api/group-list-members
.LINK
    https://learn.microsoft.com/graph/api/group-list-transitivemembers
.LINK
    https://learn.microsoft.com/graph/api/group-list-owners
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
    [string[]]$GroupName,

    [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
    [string[]]$GroupId,

    [Parameter(Mandatory = $true, ParameterSetName = 'All')]
    [switch]$All,

    [Parameter()]
    [switch]$Transitive,

    [Parameter()]
    [switch]$OwnersOnly,

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

function Get-TargetGroup {
    <# Resolves group object IDs and display names (exact or wildcard) to group objects carrying the requested $select properties. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string[]]$GroupName,

        [Parameter()]
        [string[]]$GroupId,

        [Parameter(Mandatory = $true)]
        [string]$Select
    )
    $graphV1 = 'https://graph.microsoft.com/v1.0'
    $found = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($id in @($GroupId)) {
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        try {
            $found.Add((Invoke-MgGraphRequest -Method GET -Uri ('{0}/groups/{1}?$select={2}' -f $graphV1, $id, $Select) -OutputType PSObject -ErrorAction Stop))
        }
        catch {
            Write-Warning "Group with ID '$id' could not be read: $($_.Exception.Message)"
        }
    }
    $allGroups = $null
    foreach ($name in @($GroupName)) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        if ($name -match '[\*\?]') {
            # Graph has no wildcard filter for displayName, so patterns are matched client-side against all groups (read once).
            if ($null -eq $allGroups) { $allGroups = Invoke-GraphPaged -Uri ('{0}/groups?$select={1}&$top=999' -f $graphV1, $Select) }
            $hits = @($allGroups | Where-Object { $_.displayName -like $name })
        }
        else {
            $hits = @(Invoke-GraphPaged -Uri ("{0}/groups?`$filter=displayName eq '{1}'&`$select={2}" -f $graphV1, $name.Replace("'", "''"), $Select))
        }
        if ($hits.Count -eq 0) { Write-Warning "No group matches '$name'."; continue }
        foreach ($hit in $hits) { $found.Add($hit) }
    }
    return @($found | Sort-Object -Property id -Unique)
}
#endregion Helpers

#region Main
if ($Transitive -and $OwnersOnly) { throw '-Transitive and -OwnersOnly cannot be combined.' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraGroupMembership_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('Group.Read.All', 'GroupMember.Read.All', 'User.Read.All')
}
catch {
    throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0'
$groupSelect = 'id,displayName,groupTypes,mailEnabled,securityEnabled'
try {
    if ($All) {
        Write-Warning 'Exporting the membership of every group in the tenant; this can take a long time in large tenants.'
        $groups = @(Invoke-GraphPaged -Uri ('{0}/groups?$select={1}&$top=999' -f $graphV1, $groupSelect))
    }
    else {
        $groups = @(Get-TargetGroup -GroupName $GroupName -GroupId $GroupId -Select $groupSelect)
    }
}
catch {
    throw "Failed to resolve the target groups: $($_.Exception.Message)"
}
if ($groups.Count -eq 0) { throw 'No matching groups were found.' }
Write-Verbose "Exporting $($groups.Count) group(s)."

$relationship = 'Direct'
$segment = 'members'
if ($Transitive) { $relationship = 'Transitive'; $segment = 'transitiveMembers' }
if ($OwnersOnly) { $relationship = 'Owner'; $segment = 'owners' }
$memberSelect = 'id,displayName,userPrincipalName,mail,userType,accountEnabled'

$results = New-Object -TypeName System.Collections.Generic.List[object]
$emptyGroups = 0
$processed = 0
foreach ($group in $groups) {
    $processed++
    Write-Progress -Activity "Reading $segment" -Status "$processed of $($groups.Count): $($group.displayName)" -PercentComplete (($processed / $groups.Count) * 100)
    try {
        $members = Invoke-GraphPaged -Uri ('{0}/groups/{1}/{2}?$select={3}&$top=999' -f $graphV1, $group.id, $segment, $memberSelect)
    }
    catch {
        Write-Warning "Failed to read $segment of '$($group.displayName)': $($_.Exception.Message)"
        continue
    }
    if ($members.Count -eq 0) { $emptyGroups++ }
    $groupTypes = @($group.groupTypes)
    if ($groupTypes -contains 'Unified') { $groupType = 'Microsoft 365' }
    elseif ($group.mailEnabled -and $group.securityEnabled) { $groupType = 'Mail-enabled security' }
    elseif ($group.securityEnabled) { $groupType = 'Security' }
    else { $groupType = 'Distribution' }
    if ($groupTypes -contains 'DynamicMembership') { $groupType = 'Dynamic ' + $groupType }

    foreach ($member in $members) {
        $results.Add([PSCustomObject]@{
            GroupName         = $group.displayName
            GroupId           = $group.id
            GroupType         = $groupType
            Relationship      = $relationship
            MemberType        = (([string]$member.'@odata.type') -replace '^#microsoft\.graph\.', '')
            DisplayName       = $member.displayName
            UserPrincipalName = $member.userPrincipalName
            Mail              = $member.mail
            UserType          = $member.userType
            AccountEnabled    = $member.accountEnabled
            MemberId          = $member.id
        })
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity "Reading $segment" -Completed

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'The selected groups have no members/owners; no CSV was written.'
}

Write-Host ''
Write-Host 'Group membership export' -ForegroundColor Cyan
Write-Host ('  Groups processed : {0}' -f $groups.Count)
Write-Host ('  Groups without {0,-7}: {1}' -f $segment.Substring(0, [math]::Min(7, $segment.Length)), $emptyGroups)
Write-Host ('  Rows exported    : {0}' -f $results.Count) -ForegroundColor Yellow
foreach ($bucket in ($results | Group-Object -Property MemberType | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-16}: {1}' -f $bucket.Name, $bucket.Count)
}
Write-Host ('  Report           : {0}' -f $OutputPath)

if ($PassThru) {
    $results
}
#endregion Main
