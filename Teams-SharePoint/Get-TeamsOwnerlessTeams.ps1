<#
.SYNOPSIS
    Finds teams with no owner, with only disabled owners or with a single owner, and can assign a new owner.
.DESCRIPTION
    Lists all teams through GET /groups and reads each team's owners from GET /groups/{id}/owners (UPN, accountEnabled).
    Finding is NoOwners when the team has no user owner, AllOwnersDisabled when every owner is blocked from signing in,
    and SingleOwner (only with -SingleOwner) when one enabled owner remains. With -AddOwner the given user becomes owner
    of the NoOwners / AllOwnersDisabled teams via POST /teams/{id}/members (roles owner), i.e. member and owner in one step.
.PARAMETER TeamName
    One or more team display names to evaluate; wildcards are supported. Default: all teams.
.PARAMETER TeamId
    One or more team (Microsoft 365 group) ids to evaluate. Takes precedence over -TeamName.
.PARAMETER SingleOwner
    Also report teams that have exactly one enabled owner (a single point of failure; not changed by -AddOwner).
.PARAMETER AddOwner
    User principal name of the account to add as owner of every NoOwners / AllOwnersDisabled team. Honours -WhatIf / -Confirm.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\TeamsOwnerlessTeams_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsOwnerlessTeams.ps1 -SingleOwner
    Reports teams without owners, teams whose owners are all disabled and teams with a single owner.
.EXAMPLE
    PS> .\Get-TeamsOwnerlessTeams.ps1 -AddOwner teams-admin@contoso.com -WhatIf
    Shows which ownerless teams would receive the Teams admin account as owner, without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, GroupMember.Read.All, User.Read.All (delegated); TeamMember.ReadWrite.All only with -AddOwner.
                  The Teams Administrator role is needed to add owners to teams the signed-in user does not own.
    Category    : Teams inventory & lifecycle
    Changes     : Optional (-AddOwner)
    Notes       : Deleted accounts disappear from the owner list, so a team whose last owner was deleted shows as NoOwners.
                  Service-principal owners are ignored (they cannot manage the team in Teams). One Graph call per team, 200 ms pause.
.LINK
    https://learn.microsoft.com/graph/api/team-post-members
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$TeamName,

    [Parameter()]
    [string[]]$TeamId,

    [Parameter()]
    [switch]$SingleOwner,

    [Parameter()]
    [string]$AddOwner,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsOwnerlessTeams_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('Group.Read.All', 'GroupMember.Read.All', 'User.Read.All')
if (-not [string]::IsNullOrWhiteSpace($AddOwner)) { $scopes += 'TeamMember.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$newOwner = $null
if (-not [string]::IsNullOrWhiteSpace($AddOwner)) {
    $ownerUri = '{0}/users/{1}?$select=id,userPrincipalName,accountEnabled' -f $graphV1, [uri]::EscapeDataString($AddOwner)
    try { $newOwner = Invoke-MgGraphRequest -Method GET -Uri $ownerUri -OutputType PSObject -ErrorAction Stop }
    catch { throw "The owner account '$AddOwner' could not be found: $($_.Exception.Message)" }
    if ($newOwner.accountEnabled -ne $true) { throw "The owner account '$AddOwner' is disabled; choose an enabled account." }
}
try { $teams = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select=id,displayName,visibility,createdDateTime&$top=999' -f $graphV1)) }
catch { throw "Failed to list teams: $($_.Exception.Message)" }
if ($PSBoundParameters.ContainsKey('TeamId')) { $teams = @($teams | Where-Object { $TeamId -contains $_.id }) }
elseif ($PSBoundParameters.ContainsKey('TeamName')) {
    $teams = @($teams | Where-Object { $candidate = $_.displayName; @($TeamName | Where-Object { $candidate -like $_ }).Count -gt 0 })
}
Write-Verbose "Checking the owners of $($teams.Count) teams."

$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Reading team owners' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    try {
        $owners = @(Invoke-GraphPaged -Uri ('{0}/groups/{1}/owners?$select=id,userPrincipalName,accountEnabled&$top=999' -f $graphV1, $team.id))
        Start-Sleep -Milliseconds 200
    }
    catch {
        Write-Warning "Could not read the owners of team '$($team.displayName)': $($_.Exception.Message)"
        continue
    }
    # Service principals have no UPN; only user owners can manage a team from the Teams client.
    $userOwners = @($owners | Where-Object { -not [string]::IsNullOrWhiteSpace($_.userPrincipalName) })
    $enabledOwners = @($userOwners | Where-Object { $_.accountEnabled -eq $true })
    $finding = $null
    if ($userOwners.Count -eq 0) { $finding = 'NoOwners' }
    elseif ($enabledOwners.Count -eq 0) { $finding = 'AllOwnersDisabled' }
    elseif ($SingleOwner -and $enabledOwners.Count -eq 1) { $finding = 'SingleOwner' }
    if ($null -eq $finding) { continue }
    $results.Add([PSCustomObject]@{
            TeamName        = $team.displayName
            TeamId          = $team.id
            Finding         = $finding
            OwnersCount     = $userOwners.Count
            Owners          = (@($userOwners | ForEach-Object { if ($_.accountEnabled -eq $true) { $_.userPrincipalName } else { "$($_.userPrincipalName) (disabled)" } }) -join ';')
            Visibility      = $team.visibility
            CreatedDateTime = $(if ([string]::IsNullOrWhiteSpace([string]$team.createdDateTime)) { $null } else { [datetime]$team.createdDateTime })
            ActionTaken     = 'None'
        })
}
Write-Progress -Activity 'Reading team owners' -Completed
if ($null -ne $newOwner) {
    $promoteBody = @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; roles = @('owner') } | ConvertTo-Json
    $addBody = @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; roles = @('owner'); 'user@odata.bind' = ('{0}/users(''{1}'')' -f $graphV1, $newOwner.id) } | ConvertTo-Json
    foreach ($row in @($results | Where-Object { $_.Finding -ne 'SingleOwner' })) {
        if (-not $PSCmdlet.ShouldProcess($row.TeamName, "Add owner $($newOwner.userPrincipalName)")) { continue }
        try {
            # An existing member cannot be added again; promote the existing membership instead.
            $memberUri = '{0}/teams/{1}/members?$filter=(microsoft.graph.aadUserConversationMember/userId eq ''{2}'')' -f $graphV1, $row.TeamId, $newOwner.id
            $existing = @(Invoke-GraphPaged -Uri $memberUri)
            if ($existing.Count -gt 0) {
                $patchUri = '{0}/teams/{1}/members/{2}' -f $graphV1, $row.TeamId, $existing[0].id
                Invoke-MgGraphRequest -Method PATCH -Uri $patchUri -Body $promoteBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
                $row.ActionTaken = 'PromotedToOwner'
            }
            else {
                Invoke-MgGraphRequest -Method POST -Uri ('{0}/teams/{1}/members' -f $graphV1, $row.TeamId) -Body $addBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
                $row.ActionTaken = 'OwnerAdded'
            }
            Start-Sleep -Milliseconds 200
        }
        catch {
            $row.ActionTaken = 'Failed'
            Write-Warning "Adding owner to '$($row.TeamName)' failed: $($_.Exception.Message)"
        }
    }
}

$output = @($results | Sort-Object -Property Finding, TeamName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No ownerless or at-risk teams were found; no CSV was written.' }
Write-Host ''
Write-Host 'Teams ownership summary' -ForegroundColor Cyan
Write-Host ('  Teams evaluated / flagged  : {0} / {1}' -f $teams.Count, $output.Count)
Write-Host ('  No owners                  : {0}' -f @($output | Where-Object { $_.Finding -eq 'NoOwners' }).Count) -ForegroundColor Yellow
Write-Host ('  All owners disabled        : {0}' -f @($output | Where-Object { $_.Finding -eq 'AllOwnersDisabled' }).Count) -ForegroundColor Yellow
if ($SingleOwner) { Write-Host ('  Single owner               : {0}' -f @($output | Where-Object { $_.Finding -eq 'SingleOwner' }).Count) }
if ($null -ne $newOwner) { Write-Host ('  Owners added / promoted    : {0}' -f @($output | Where-Object { $_.ActionTaken -in @('OwnerAdded', 'PromotedToOwner') }).Count) -ForegroundColor Green }
Write-Host ('  Report                     : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
