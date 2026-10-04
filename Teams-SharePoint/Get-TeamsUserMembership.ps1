<#
.SYNOPSIS
    Lists the teams one or more users belong to, with their role (Owner, Member, Guest) and the team's visibility and archive state.
.DESCRIPTION
    Resolves each user (GET /users/{upn}), lists the teams they are a direct member of (GET /users/{id}/joinedTeams, which also
    returns isArchived) and, per team, reads visibility and member count from GET /teams/{id} and the user's role from
    GET /teams/{id}/members?$filter=userId. With -IncludeAssociatedTeams it adds teams the user reaches only through a shared
    channel (GET /users/{id}/teamwork/associatedTeams), including teams hosted in other tenants. Exports one row per user and
    team and prints the number of teams and ownerships per user.
.PARAMETER UserPrincipalName
    One or more user principal names to look up.
.PARAMETER IncludeAssociatedTeams
    Also list teams the user is associated with through shared channel membership (Role SharedChannelMember). With delegated
    permissions Graph only allows this for the signed-in user; for other users a warning is shown and the rows are skipped.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\TeamsUserMembership_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsUserMembership.ps1 -UserPrincipalName megan@contoso.com, alex@contoso.com
    Lists every team the two users belong to with role, visibility and archive state, and exports the rows to CSV.
.EXAMPLE
    PS> .\Get-TeamsUserMembership.ps1 -UserPrincipalName (Get-MgContext).Account -IncludeAssociatedTeams -PassThru | Where-Object { $_.Role -eq 'Owner' }
    Shows the teams the signed-in user owns, including shared channel associations, in the console.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, Team.ReadBasic.All, TeamMember.Read.All (delegated). Teams Administrator or Global Reader role to
                  read teams the signed-in user is not a member of.
    Category    : Teams inventory & lifecycle
    Changes     : No
    Notes       : joinedTeams returns direct memberships only; a user who owns the Microsoft 365 group without being a team member is
                  not listed. Two Graph calls per team with a 200 ms pause, so a user in 100 teams takes about a minute. Visibility
                  and member count are not available for teams in other tenants.
.LINK
    https://learn.microsoft.com/graph/api/user-list-joinedteams
.LINK
    https://learn.microsoft.com/graph/api/associatedteaminfo-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$UserPrincipalName,

    [Parameter()]
    [switch]$IncludeAssociatedTeams,

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
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsUserMembership_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try {
    Connect-GraphIfNeeded -Scopes @('User.Read.All', 'Team.ReadBasic.All', 'TeamMember.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0'
$memberFilterUri = $graphV1 + '/teams/{0}/members?$filter=(microsoft.graph.aadUserConversationMember/userId eq ''{1}'')'
$homeTenantId = (Get-MgContext).TenantId
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($upn in $UserPrincipalName) {
    try { $user = Invoke-MgGraphRequest -Method GET -Uri ('{0}/users/{1}?$select=id,displayName,userPrincipalName' -f $graphV1, [uri]::EscapeDataString($upn)) -OutputType PSObject -ErrorAction Stop }
    catch { Write-Warning "User '$upn' was not found: $($_.Exception.Message)"; continue }
    try { $joinedTeams = @(Invoke-GraphPaged -Uri ('{0}/users/{1}/joinedTeams' -f $graphV1, $user.id)) }
    catch { Write-Warning "Could not list the teams of '$upn': $($_.Exception.Message)"; continue }
    Write-Verbose "$upn is a direct member of $($joinedTeams.Count) teams."
    $counter = 0
    foreach ($team in $joinedTeams) {
        $counter++
        Write-Progress -Activity "Reading teams of $upn" -Status "$counter of $($joinedTeams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $joinedTeams.Count) * 100))
        $role = $null
        $detail = $null
        try {
            $detail = Invoke-MgGraphRequest -Method GET -Uri ('{0}/teams/{1}?$select=id,visibility,summary' -f $graphV1, $team.id) -OutputType PSObject -ErrorAction Stop
            $membership = @(Invoke-GraphPaged -Uri ($memberFilterUri -f $team.id, $user.id))
            if ($membership.Count -gt 0) {
                $role = 'Member'
                if (@($membership[0].roles) -contains 'owner') { $role = 'Owner' }
                elseif (@($membership[0].roles) -contains 'guest') { $role = 'Guest' }
            }
            Start-Sleep -Milliseconds 200
        }
        catch {
            Write-Warning "Could not read team '$($team.displayName)' for '$upn': $($_.Exception.Message)"
        }
        $results.Add([PSCustomObject]@{
                UserPrincipalName = $user.userPrincipalName
                UserDisplayName   = $user.displayName
                TeamName          = $team.displayName
                TeamId            = $team.id
                Role              = $role
                MembershipType    = 'Team'
                Visibility        = $detail.visibility
                IsArchived        = ($team.isArchived -eq $true)
                MembersCount      = $detail.summary.membersCount
                TeamTenantId      = $team.tenantId
                IsExternalTenant  = (-not [string]::IsNullOrWhiteSpace($team.tenantId) -and $team.tenantId -ne $homeTenantId)
                Description       = $team.description
            })
    }
    Write-Progress -Activity "Reading teams of $upn" -Completed
    if ($IncludeAssociatedTeams) {
        try {
            $joinedIds = @($joinedTeams | ForEach-Object { $_.id })
            # associatedTeams also returns the teams from joinedTeams; keep only the ones reached through a shared channel.
            foreach ($associated in @(Invoke-GraphPaged -Uri ('{0}/users/{1}/teamwork/associatedTeams' -f $graphV1, $user.id) | Where-Object { $joinedIds -notcontains $_.id })) {
                $results.Add([PSCustomObject]@{
                        UserPrincipalName = $user.userPrincipalName
                        UserDisplayName   = $user.displayName
                        TeamName          = $associated.displayName
                        TeamId            = $associated.id
                        Role              = 'SharedChannelMember'
                        MembershipType    = 'SharedChannel'
                        Visibility        = $null
                        IsArchived        = $null
                        MembersCount      = $null
                        TeamTenantId      = $associated.tenantId
                        IsExternalTenant  = (-not [string]::IsNullOrWhiteSpace($associated.tenantId) -and $associated.tenantId -ne $homeTenantId)
                        Description       = $null
                    })
            }
        }
        catch {
            Write-Warning "Associated teams of '$upn' could not be read (with delegated permissions Graph only allows this for the signed-in user): $($_.Exception.Message)"
        }
    }
}

$output = @($results | Sort-Object -Property UserPrincipalName, MembershipType, TeamName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No team memberships were found for the given users; no CSV was written.' }
Write-Host ''
Write-Host 'Teams user membership summary' -ForegroundColor Cyan
foreach ($userGroup in @($output | Group-Object -Property UserPrincipalName | Sort-Object -Property Name)) {
    $ownerCount = @($userGroup.Group | Where-Object { $_.Role -eq 'Owner' }).Count
    $sharedCount = @($userGroup.Group | Where-Object { $_.MembershipType -eq 'SharedChannel' }).Count
    Write-Host ('  {0,-40}: {1} teams ({2} as owner, {3} via shared channels)' -f $userGroup.Name, $userGroup.Count, $ownerCount, $sharedCount)
}
Write-Host ('  Archived teams in the list               : {0}' -f @($output | Where-Object { $_.IsArchived -eq $true }).Count)
Write-Host ('  Report                                   : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
