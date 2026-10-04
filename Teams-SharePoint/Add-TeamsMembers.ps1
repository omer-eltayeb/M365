<#
.SYNOPSIS
    Adds users to teams as owners or members (or removes them) from a CSV file or from parameters, skipping existing memberships.
.DESCRIPTION
    Takes TeamName or TeamId, UserPrincipalName and Role (Owner | Member) from a CSV file, or -TeamName/-TeamId with -Members
    and -Role, resolves the team (GET /groups) and the user (GET /users/{upn}) and reads each team's members once
    (GET /teams/{id}/members). Missing users are added (POST /teams/{id}/members), members requested as Owner are promoted
    (PATCH .../members/{id}) and with -Remove memberships are deleted. Honours -WhatIf / -Confirm; a results CSV records every row.
.PARAMETER CsvPath
    CSV file with the columns TeamName (or TeamId), UserPrincipalName and optionally Role (Owner or Member; default Member).
.PARAMETER TeamName
    Exact display name of the target team (no wildcards). Use -TeamId when several teams share the same name.
.PARAMETER TeamId
    Id of the target team (Microsoft 365 group id).
.PARAMETER Members
    One or more user principal names to add to (or remove from) the team.
.PARAMETER Role
    Role for -Members: Owner or Member. Default Member. Existing members requested as Owner are promoted; owners are never demoted.
.PARAMETER Remove
    Remove the listed users from the listed teams instead of adding them.
.PARAMETER OutputPath
    Path of the CSV results file. Defaults to .\Reports\TeamsMembersChanges_yyyyMMdd-HHmm.csv.
.EXAMPLE
    PS> .\Add-TeamsMembers.ps1 -CsvPath .\NewHires.csv -WhatIf
    Shows which users would be added to (or promoted in) which teams, without changing anything.
.EXAMPLE
    PS> .\Add-TeamsMembers.ps1 -TeamName 'Project Falcon' -Members alex@contoso.com, sam@contoso.com -Role Owner -Confirm:$false
    Adds (or promotes) the two users as owners of Project Falcon without prompting; add -Remove to remove them instead.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, User.Read.All, TeamMember.ReadWrite.All (delegated). Teams Administrator role to change teams the
                  signed-in user does not own.
    Category    : Teams inventory & lifecycle
    Changes     : Yes
    Notes       : Graph returns 404 when a disabled user is added and rejects guests as owners; such rows end as Failed with the error
                  text. Use -Confirm:$false for unattended bulk runs; the script pauses 150 ms between changes (SDK retries HTTP 429).
.LINK
    https://learn.microsoft.com/graph/api/team-post-members
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Direct')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [string]$CsvPath,

    [Parameter(ParameterSetName = 'Direct')]
    [string]$TeamName,

    [Parameter(ParameterSetName = 'Direct')]
    [string]$TeamId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
    [string[]]$Members,

    [Parameter(ParameterSetName = 'Direct')]
    [ValidateSet('Owner', 'Member')]
    [string]$Role = 'Member',

    [Parameter()]
    [switch]$Remove,

    [Parameter()]
    [string]$OutputPath
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
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsMembersChanges_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if ($PSCmdlet.ParameterSetName -eq 'Csv') { $requests = @(Import-Csv -Path $CsvPath) }
else {
    if ([string]::IsNullOrWhiteSpace($TeamName) -and [string]::IsNullOrWhiteSpace($TeamId)) { throw 'Specify -TeamName or -TeamId together with -Members.' }
    $requests = @($Members | ForEach-Object { [PSCustomObject]@{ TeamName = $TeamName; TeamId = $TeamId; UserPrincipalName = $_; Role = $Role } })
}
if ($requests.Count -eq 0) { throw 'No membership requests were found.' }
try { Connect-GraphIfNeeded -Scopes @('Group.Read.All', 'User.Read.All', 'TeamMember.ReadWrite.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
$graphV1 = 'https://graph.microsoft.com/v1.0'
try { $teams = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select=id,displayName&$top=999' -f $graphV1)) }
catch { throw "Failed to list teams: $($_.Exception.Message)" }
$teamsById = @{}
$teamsByName = @{}
foreach ($team in $teams) {
    $teamsById[$team.id] = $team
    $nameKey = $team.displayName.Trim().ToLowerInvariant()
    # Two teams with the same name cannot be told apart by name; such rows must use TeamId.
    if ($teamsByName.ContainsKey($nameKey)) { $teamsByName[$nameKey] = 'ambiguous' } else { $teamsByName[$nameKey] = $team }
}
$ownerBody = @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; roles = @('owner') } | ConvertTo-Json
$userCache = @{}
$memberCache = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($request in $requests) {
    $counter++
    Write-Progress -Activity 'Processing requests' -Status "$counter of $($requests.Count): $($request.UserPrincipalName)" -PercentComplete ([int](($counter / $requests.Count) * 100))
    $wantedRole = $(if ([string]::IsNullOrWhiteSpace($request.Role)) { 'Member' } else { ([string]$request.Role).Trim() })
    $row = [PSCustomObject]@{ TeamName = $request.TeamName; TeamId = $request.TeamId; UserPrincipalName = $request.UserPrincipalName; RequestedRole = $wantedRole; Action = 'Skipped'; Detail = $null }
    $results.Add($row)
    if ($wantedRole -notin @('Owner', 'Member')) { $row.Detail = 'Role must be Owner or Member'; continue }
    $team = $null
    if (-not [string]::IsNullOrWhiteSpace($request.TeamId)) { $team = $teamsById[([string]$request.TeamId).Trim()] }
    elseif (-not [string]::IsNullOrWhiteSpace($request.TeamName)) { $team = $teamsByName[([string]$request.TeamName).Trim().ToLowerInvariant()] }
    if ($null -eq $team) { $row.Detail = 'Team not found'; continue }
    if ($team -is [string]) { $row.Detail = 'Team name is ambiguous; use TeamId'; continue }
    $row.TeamName = $team.displayName
    $row.TeamId = $team.id
    $upnKey = ([string]$request.UserPrincipalName).Trim().ToLowerInvariant()
    if ($upnKey -eq '') { $row.Detail = 'UserPrincipalName is empty'; continue }
    if (-not $userCache.ContainsKey($upnKey)) {
        $userUri = '{0}/users/{1}?$select=id,userPrincipalName' -f $graphV1, [uri]::EscapeDataString($upnKey)
        try { $userCache[$upnKey] = Invoke-MgGraphRequest -Method GET -Uri $userUri -OutputType PSObject -ErrorAction Stop }
        catch { $userCache[$upnKey] = $null }
    }
    $user = $userCache[$upnKey]
    if ($null -eq $user) { $row.Detail = 'User not found'; continue }
    $membersUri = '{0}/teams/{1}/members' -f $graphV1, $team.id
    if (-not $memberCache.ContainsKey($team.id)) {
        try { $teamMembers = @(Invoke-GraphPaged -Uri "$membersUri`?`$top=999") }
        catch { $row.Action = 'Failed'; $row.Detail = "Cannot read team members: $($_.Exception.Message)"; continue }
        $memberCache[$team.id] = @{}
        foreach ($member in $teamMembers) { if (-not [string]::IsNullOrWhiteSpace($member.userId)) { $memberCache[$team.id][$member.userId] = $member } }
    }
    $existing = $memberCache[$team.id][$user.id]
    try {
        if ($Remove) {
            if ($null -eq $existing) { $row.Action = 'NotMember'; continue }
            if (-not $PSCmdlet.ShouldProcess($team.displayName, "Remove $($user.userPrincipalName)")) { continue }
            Invoke-MgGraphRequest -Method DELETE -Uri "$membersUri/$($existing.id)" -ErrorAction Stop | Out-Null
            $memberCache[$team.id].Remove($user.id)
            $row.Action = 'Removed'
        }
        elseif ($null -ne $existing) {
            if ($wantedRole -ne 'Owner' -or (@($existing.roles) -contains 'owner')) { $row.Action = 'AlreadyMember'; $row.Detail = "Current roles: $(@($existing.roles) -join ',')"; continue }
            if (-not $PSCmdlet.ShouldProcess($team.displayName, "Promote $($user.userPrincipalName) to owner")) { continue }
            Invoke-MgGraphRequest -Method PATCH -Uri "$membersUri/$($existing.id)" -Body $ownerBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
            $existing.roles = @('owner')
            $row.Action = 'PromotedToOwner'
        }
        else {
            if (-not $PSCmdlet.ShouldProcess($team.displayName, "Add $($user.userPrincipalName) as $wantedRole")) { continue }
            $roles = @(if ($wantedRole -eq 'Owner') { 'owner' })
            $body = @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; roles = $roles; 'user@odata.bind' = ('{0}/users(''{1}'')' -f $graphV1, $user.id) } | ConvertTo-Json
            $memberCache[$team.id][$user.id] = Invoke-MgGraphRequest -Method POST -Uri $membersUri -Body $body -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
            $row.Action = 'Added'
        }
        Start-Sleep -Milliseconds 150
    }
    catch { $row.Action = 'Failed'; $row.Detail = $_.Exception.Message; Write-Warning "Change for '$($user.userPrincipalName)' in '$($team.displayName)' failed: $($_.Exception.Message)" }
}
Write-Progress -Activity 'Processing requests' -Completed
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host 'Teams membership changes summary' -ForegroundColor Cyan
foreach ($actionGroup in @($results | Group-Object -Property Action | Sort-Object -Property Name)) { Write-Host ('  {0,-20}: {1}' -f $actionGroup.Name, $actionGroup.Count) -ForegroundColor Yellow }
Write-Host ('  Results             : {0}' -f $OutputPath)
#endregion Main
