<#
.SYNOPSIS
    Exports the membership of all or selected teams, one row per member with the role Owner, Member or Guest.
.DESCRIPTION
    Lists teams through GET /groups and reads every team's conversation members from GET /teams/{id}/members, which
    returns the Teams role (owner / guest / plain member) together with display name, email and user id. With
    -ResolveUsers each user is looked up once (GET /users/{id}) to add UPN, user type and account state. Writes one
    combined CSV or, with -OneFilePerTeam, one CSV per team into -OutputFolder, and prints membership totals.
.PARAMETER TeamName
    One or more team display names to export; wildcards are supported. Default: all teams.
.PARAMETER TeamId
    One or more team (Microsoft 365 group) ids to export. Takes precedence over -TeamName.
.PARAMETER ResolveUsers
    Look up every distinct user in Entra ID to fill UserPrincipalName, UserType and AccountEnabled (requires User.Read.All).
.PARAMETER OneFilePerTeam
    Write a separate CSV per team (named after the team) into -OutputFolder instead of one combined file.
.PARAMETER OutputFolder
    Folder for the per-team CSV files (-OneFilePerTeam). Defaults to .\Reports\TeamsMembership_yyyyMMdd-HHmm.
.PARAMETER OutputPath
    Path of the combined CSV report. Defaults to .\Reports\TeamsMembership_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the membership objects to the pipeline.
.EXAMPLE
    PS> .\Export-TeamsMembership.ps1
    Exports every membership of every team to one CSV file.
.EXAMPLE
    PS> .\Export-TeamsMembership.ps1 -TeamName 'HR*' -ResolveUsers -OneFilePerTeam -OutputFolder C:\Temp\HRTeams
    Writes one CSV per HR team, including each member's UPN, user type and whether the account is enabled.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, Team.ReadBasic.All, TeamMember.Read.All (delegated); User.Read.All only with -ResolveUsers.
                  Teams Administrator or Global Reader role to read teams the signed-in user is not a member of.
    Category    : Teams inventory & lifecycle
    Changes     : No
    Notes       : Rows are memberships, so a user in five teams produces five rows (the summary counts distinct users as well).
                  External participants of shared channels are channel members, not team members, and are therefore not listed.
.LINK
    https://learn.microsoft.com/graph/api/team-list-members
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$TeamName,

    [Parameter()]
    [string[]]$TeamId,

    [Parameter()]
    [switch]$ResolveUsers,

    [Parameter()]
    [switch]$OneFilePerTeam,

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
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
if ($OneFilePerTeam) {
    if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
        $OutputFolder = Join-Path -Path (Join-Path -Path (Get-Location).Path -ChildPath 'Reports') -ChildPath "TeamsMembership_$stamp"
    }
    if (-not (Test-Path -Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
}
else {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
        $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsMembership_{0}.csv' -f $stamp)
    }
    $reportParent = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($reportParent) -and -not (Test-Path -Path $reportParent)) {
        New-Item -Path $reportParent -ItemType Directory -Force | Out-Null
    }
}
$scopes = @('Group.Read.All', 'Team.ReadBasic.All', 'TeamMember.Read.All')
if ($ResolveUsers) { $scopes += 'User.Read.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
$graphV1 = 'https://graph.microsoft.com/v1.0'
try { $teams = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select=id,displayName,visibility&$top=999' -f $graphV1)) }
catch { throw "Failed to list teams: $($_.Exception.Message)" }
if ($PSBoundParameters.ContainsKey('TeamId')) { $teams = @($teams | Where-Object { $TeamId -contains $_.id }) }
elseif ($PSBoundParameters.ContainsKey('TeamName')) {
    $teams = @($teams | Where-Object { $candidate = $_.displayName; @($TeamName | Where-Object { $candidate -like $_ }).Count -gt 0 })
}
$userCache = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$filesWritten = 0
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Reading team membership' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    try {
        $members = @(Invoke-GraphPaged -Uri ('{0}/teams/{1}/members?$top=999' -f $graphV1, $team.id))
        Start-Sleep -Milliseconds 200
    }
    catch {
        Write-Warning "Could not read the members of team '$($team.displayName)': $($_.Exception.Message)"
        continue
    }
    $teamRows = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($member in $members) {
        $role = 'Member'
        if (@($member.roles) -contains 'owner') { $role = 'Owner' }
        elseif (@($member.roles) -contains 'guest') { $role = 'Guest' }
        $user = $null
        if ($ResolveUsers -and -not [string]::IsNullOrWhiteSpace($member.userId)) {
            if (-not $userCache.ContainsKey($member.userId)) {
                $userUri = '{0}/users/{1}?$select=userPrincipalName,userType,accountEnabled' -f $graphV1, $member.userId
                try { $userCache[$member.userId] = Invoke-MgGraphRequest -Method GET -Uri $userUri -OutputType PSObject -ErrorAction Stop }
                catch { $userCache[$member.userId] = $null; Write-Verbose "User $($member.userId) ($($member.displayName)) could not be resolved: $($_.Exception.Message)" }
                Start-Sleep -Milliseconds 100
            }
            $user = $userCache[$member.userId]
        }
        $teamRows.Add([PSCustomObject]@{
                TeamName          = $team.displayName
                TeamId            = $team.id
                TeamVisibility    = $team.visibility
                MemberDisplayName = $member.displayName
                Email             = $member.email
                Role              = $role
                UserPrincipalName = $user.userPrincipalName
                UserType          = $user.userType
                AccountEnabled    = $user.accountEnabled
                UserId            = $member.userId
                MembershipId      = $member.id
            })
    }
    foreach ($row in $teamRows) { $results.Add($row) }
    if ($OneFilePerTeam -and $teamRows.Count -gt 0) {
        # File names are built from the team name; characters Windows does not allow are replaced.
        $fileName = '{0}_{1}.csv' -f ([regex]::Replace($team.displayName, '[\\/:*?"<>|]', '_')), $team.id.Substring(0, 8)
        $teamRows | Sort-Object -Property Role, MemberDisplayName | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath $fileName) -NoTypeInformation -Encoding UTF8
        $filesWritten++
    }
}
Write-Progress -Activity 'Reading team membership' -Completed
$output = @($results | Sort-Object -Property TeamName, Role, MemberDisplayName)
if (-not $OneFilePerTeam) {
    if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
    else { Write-Warning 'No memberships were found for the selected teams; no CSV was written.' }
}
Write-Host 'Teams membership summary' -ForegroundColor Cyan
Write-Host ('  Teams exported / memberships   : {0} / {1}' -f $teams.Count, $output.Count)
foreach ($roleGroup in @($output | Group-Object -Property Role | Sort-Object -Property Name)) { Write-Host ('  {0,-31}: {1}' -f "Memberships with role $($roleGroup.Name)", $roleGroup.Count) }
Write-Host ('  Distinct users                 : {0}' -f @($output | Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserId) } | Sort-Object -Property UserId -Unique).Count)
if ($ResolveUsers) { Write-Host ('  Memberships of disabled users  : {0}' -f @($output | Where-Object { $_.AccountEnabled -eq $false }).Count) -ForegroundColor Yellow }
if ($OneFilePerTeam) { Write-Host ('  Files written                  : {0} -> {1}' -f $filesWritten, $OutputFolder) }
else { Write-Host ('  Report                         : {0}' -f $OutputPath) }
if ($PassThru) { $output }
#endregion Main
