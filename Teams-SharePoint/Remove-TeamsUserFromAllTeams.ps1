<#
.SYNOPSIS
    Offboarding helper: lists every team a user belongs to and, with -Remove, removes the user from all of them.
.DESCRIPTION
    Resolves each user (GET /users/{upn}), lists the teams they are a direct member of (GET /users/{id}/joinedTeams) and
    finds their membership record and role in each team (GET /teams/{id}/members?$filter=userId). For owners the team's
    owner count is read from GET /teams/{id} (summary): a team whose only owner is the user is skipped with a warning unless
    -ReplacementOwner is given, in which case that account is made owner first. Without -Remove the script only reports;
    with -Remove each membership is deleted (DELETE /teams/{id}/members/{membershipId}) after -WhatIf / -Confirm handling.
.PARAMETER UserPrincipalName
    One or more user principal names of the users to offboard from Teams.
.PARAMETER ExcludeTeamName
    Team display names to leave untouched; wildcards are supported (for example 'All Staff', 'Alumni*').
.PARAMETER ReplacementOwner
    UPN of the account that becomes owner of teams where the user is the only owner, so those teams do not end up ownerless.
.PARAMETER Remove
    Perform the removals. Without this switch the script only reports what would happen.
.PARAMETER OutputPath
    Path of the CSV results file. Defaults to .\Reports\TeamsUserRemoval_yyyyMMdd-HHmm.csv.
.EXAMPLE
    PS> .\Remove-TeamsUserFromAllTeams.ps1 -UserPrincipalName leaver@contoso.com
    Lists every team the user belongs to, the role held and which teams would be left without an owner.
.EXAMPLE
    PS> .\Remove-TeamsUserFromAllTeams.ps1 -UserPrincipalName leaver@contoso.com -ReplacementOwner manager@contoso.com -ExcludeTeamName 'All Staff' -Remove
    Removes the user from all teams except All Staff, making the manager owner of teams the leaver owned alone.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, Team.ReadBasic.All, TeamMember.Read.All (delegated); TeamMember.ReadWrite.All only with -Remove.
                  Teams Administrator role to read and change teams the signed-in user is not a member of.
    Category    : Teams inventory & lifecycle
    Changes     : Optional (-Remove)
    Notes       : joinedTeams lists direct team memberships only: group ownerships without membership and shared channel memberships
                  in other teams are not covered (use Export-EntraGroupMembership.ps1 and Get-TeamsPrivateAndSharedChannelsReport.ps1).
                  Removing a member from an archived team is allowed. Removals take a moment to appear in the Teams client.
.LINK
    https://learn.microsoft.com/graph/api/team-delete-members
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$UserPrincipalName,

    [Parameter()]
    [string[]]$ExcludeTeamName,

    [Parameter()]
    [string]$ReplacementOwner,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsUserRemoval_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('User.Read.All', 'Team.ReadBasic.All', 'TeamMember.Read.All')
if ($Remove) { $scopes += 'TeamMember.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$memberFilterUri = $graphV1 + '/teams/{0}/members?$filter=(microsoft.graph.aadUserConversationMember/userId eq ''{1}'')'
$memberType = '#microsoft.graph.aadUserConversationMember'
$promoteBody = @{ '@odata.type' = $memberType; roles = @('owner') } | ConvertTo-Json
$replacement = $null
if (-not [string]::IsNullOrWhiteSpace($ReplacementOwner)) {
    $replacementUri = '{0}/users/{1}?$select=id,userPrincipalName,accountEnabled' -f $graphV1, [uri]::EscapeDataString($ReplacementOwner)
    try { $replacement = Invoke-MgGraphRequest -Method GET -Uri $replacementUri -OutputType PSObject -ErrorAction Stop }
    catch { throw "The replacement owner '$ReplacementOwner' could not be found: $($_.Exception.Message)" }
    if ($replacement.accountEnabled -ne $true) { throw "The replacement owner '$ReplacementOwner' is disabled; choose an enabled account." }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($upn in $UserPrincipalName) {
    try { $user = Invoke-MgGraphRequest -Method GET -Uri ('{0}/users/{1}?$select=id,displayName,userPrincipalName' -f $graphV1, [uri]::EscapeDataString($upn)) -OutputType PSObject -ErrorAction Stop }
    catch { Write-Warning "User '$upn' was not found: $($_.Exception.Message)"; continue }
    try { $joinedTeams = @(Invoke-GraphPaged -Uri ('{0}/users/{1}/joinedTeams' -f $graphV1, $user.id)) }
    catch { Write-Warning "Could not list the teams of '$upn': $($_.Exception.Message)"; continue }
    Write-Verbose "$upn is a member of $($joinedTeams.Count) teams."
    $counter = 0
    foreach ($team in $joinedTeams) {
        $counter++
        Write-Progress -Activity "Processing teams of $upn" -Status "$counter of $($joinedTeams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $joinedTeams.Count) * 100))
        if ($PSBoundParameters.ContainsKey('ExcludeTeamName') -and @($ExcludeTeamName | Where-Object { $team.displayName -like $_ }).Count -gt 0) { continue }
        $row = [PSCustomObject]@{
            UserPrincipalName = $user.userPrincipalName
            UserDisplayName   = $user.displayName
            TeamName          = $team.displayName
            TeamId            = $team.id
            Role              = $null
            OwnersCount       = $null
            Action            = 'WouldRemove'
            Detail            = $null
        }
        $results.Add($row)
        try {
            $membership = @(Invoke-GraphPaged -Uri ($memberFilterUri -f $team.id, $user.id))
            if ($membership.Count -eq 0) { $row.Action = 'NotMember'; $row.Detail = 'No membership record found (group owner only, or already removed)'; continue }
            $isOwner = (@($membership[0].roles) -contains 'owner')
            $row.Role = $(if ($isOwner) { 'Owner' } elseif (@($membership[0].roles) -contains 'guest') { 'Guest' } else { 'Member' })
            if ($isOwner) {
                $detail = Invoke-MgGraphRequest -Method GET -Uri ('{0}/teams/{1}?$select=id,summary' -f $graphV1, $team.id) -OutputType PSObject -ErrorAction Stop
                $row.OwnersCount = $detail.summary.ownersCount
            }
            Start-Sleep -Milliseconds 200
            if ($isOwner -and $row.OwnersCount -le 1) {
                if ($null -eq $replacement -or $replacement.id -eq $user.id) {
                    $row.Action = 'SkippedSoleOwner'
                    $row.Detail = 'The user is the only owner; pass -ReplacementOwner to hand the team over'
                    Write-Warning "'$($team.displayName)': $upn is the only owner; skipped. Use -ReplacementOwner."
                    continue
                }
                $row.Action = 'WouldRemoveAfterReplacingOwner'
                # Never remove the last owner unless the replacement really was added (declining the prompt skips the team).
                if (-not $Remove -or -not $PSCmdlet.ShouldProcess($team.displayName, "Add replacement owner $($replacement.userPrincipalName)")) { continue }
                $current = @(Invoke-GraphPaged -Uri ($memberFilterUri -f $team.id, $replacement.id))
                if ($current.Count -gt 0) {
                    # The replacement is already a plain member; promote the existing membership instead of adding it again.
                    $patchUri = '{0}/teams/{1}/members/{2}' -f $graphV1, $team.id, $current[0].id
                    Invoke-MgGraphRequest -Method PATCH -Uri $patchUri -Body $promoteBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
                }
                else {
                    $addBody = @{ '@odata.type' = $memberType; roles = @('owner'); 'user@odata.bind' = ('{0}/users(''{1}'')' -f $graphV1, $replacement.id) } | ConvertTo-Json
                    Invoke-MgGraphRequest -Method POST -Uri ('{0}/teams/{1}/members' -f $graphV1, $team.id) -Body $addBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
                }
                $row.Detail = "Owner added: $($replacement.userPrincipalName)"
            }
            if (-not $Remove -or -not $PSCmdlet.ShouldProcess($team.displayName, "Remove $upn ($($row.Role))")) { continue }
            Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/teams/{1}/members/{2}' -f $graphV1, $team.id, $membership[0].id) -ErrorAction Stop | Out-Null
            $row.Action = 'Removed'
        }
        catch { $row.Action = 'Failed'; $row.Detail = $_.Exception.Message; Write-Warning "'$($team.displayName)': $($_.Exception.Message)" }
    }
    Write-Progress -Activity "Processing teams of $upn" -Completed
}

$output = @($results | Sort-Object -Property UserPrincipalName, TeamName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No team memberships were found for the given users; no CSV was written.' }
Write-Host ''
Write-Host 'Teams user removal summary' -ForegroundColor Cyan
Write-Host ('  Users / memberships evaluated  : {0} / {1}' -f $UserPrincipalName.Count, $output.Count)
foreach ($actionGroup in @($output | Group-Object -Property Action | Sort-Object -Property Name)) { Write-Host ('  {0,-31}: {1}' -f $actionGroup.Name, $actionGroup.Count) -ForegroundColor Yellow }
Write-Host ('  Results                        : {0}' -f $OutputPath)
#endregion Main
