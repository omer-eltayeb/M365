<#
.SYNOPSIS
    Lists archived Microsoft Teams teams and can unarchive them or delete them (with their Microsoft 365 group).
.DESCRIPTION
    Lists all teams through GET /groups, reads the archive state and the owner/member/guest summary of each team from
    GET /teams/{id} and exports the archived ones with visibility, classification, age and counts. With -Unarchive each
    archived team is restored through POST /teams/{id}/unarchive; with -DeleteArchived the team and its group are
    deleted through DELETE /groups/{id} (soft delete, recoverable for 30 days). Both honour -WhatIf / -Confirm.
.PARAMETER TeamName
    One or more team display names to evaluate; wildcards are supported. Default: all teams.
.PARAMETER TeamId
    One or more team (Microsoft 365 group) ids to evaluate. Takes precedence over -TeamName.
.PARAMETER Unarchive
    Unarchive every archived team in the selection. Use with -TeamName or -TeamId to target specific teams.
.PARAMETER DeleteArchived
    Delete every archived team in the selection together with its Microsoft 365 group, mailbox and SharePoint site.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\TeamsArchivedTeams_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsArchivedTeams.ps1
    Exports every archived team with its owner, member and guest counts.
.EXAMPLE
    PS> .\Get-TeamsArchivedTeams.ps1 -TeamName 'FY22 *' -Unarchive -Confirm:$false
    Restores all archived teams whose name starts with "FY22 " without prompting.
.EXAMPLE
    PS> .\Get-TeamsArchivedTeams.ps1 -DeleteArchived -WhatIf
    Shows which archived teams would be deleted, without deleting anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, Team.ReadBasic.All (delegated); TeamSettings.ReadWrite.All only with -Unarchive and
                  Group.ReadWrite.All only with -DeleteArchived. Teams Administrator (or Groups Administrator for deletion) role.
    Category    : Teams inventory & lifecycle
    Changes     : Optional (-Unarchive / -DeleteArchived)
    Notes       : Graph does not expose the date a team was archived. Unarchiving is asynchronous (HTTP 202). Deleted groups can be
                  restored for 30 days (Entra admin center > Groups > Deleted groups); afterwards team, mailbox and site are gone.
.LINK
    https://learn.microsoft.com/graph/api/team-unarchive
.LINK
    https://learn.microsoft.com/graph/api/group-delete
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
    [switch]$Unarchive,

    [Parameter()]
    [switch]$DeleteArchived,

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
if ($Unarchive -and $DeleteArchived) { throw 'Use either -Unarchive or -DeleteArchived, not both.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsArchivedTeams_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('Group.Read.All', 'Team.ReadBasic.All')
if ($Unarchive) { $scopes += 'TeamSettings.ReadWrite.All' }
if ($DeleteArchived) { $scopes += 'Group.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$groupSelect = 'id,displayName,description,visibility,classification,createdDateTime,mail'
try { $teams = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select={1}&$top=999' -f $graphV1, $groupSelect)) }
catch { throw "Failed to list teams: $($_.Exception.Message)" }
if ($PSBoundParameters.ContainsKey('TeamId')) { $teams = @($teams | Where-Object { $TeamId -contains $_.id }) }
elseif ($PSBoundParameters.ContainsKey('TeamName')) {
    $teams = @($teams | Where-Object { $candidate = $_.displayName; @($TeamName | Where-Object { $candidate -like $_ }).Count -gt 0 })
}
Write-Verbose "Checking the archive state of $($teams.Count) teams."

$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Reading archive state' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    try {
        $detail = Invoke-MgGraphRequest -Method GET -Uri ('{0}/teams/{1}?$select=id,isArchived,summary,webUrl' -f $graphV1, $team.id) -OutputType PSObject -ErrorAction Stop
        Start-Sleep -Milliseconds 200
    }
    catch {
        Write-Warning "Could not read team '$($team.displayName)': $($_.Exception.Message)"
        continue
    }
    if ($detail.isArchived -ne $true) { continue }
    $created = $null
    $ageDays = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$team.createdDateTime)) {
        $created = [datetime]$team.createdDateTime
        $ageDays = [int](((Get-Date) - $created).TotalDays)
    }
    $results.Add([PSCustomObject]@{
            TeamName        = $team.displayName
            TeamId          = $team.id
            Visibility      = $team.visibility
            Classification  = $team.classification
            CreatedDateTime = $created
            AgeDays         = $ageDays
            OwnersCount     = $detail.summary.ownersCount
            MembersCount    = $detail.summary.membersCount
            GuestsCount     = $detail.summary.guestsCount
            Mail            = $team.mail
            WebUrl          = $detail.webUrl
            Description     = $team.description
            ActionTaken     = 'None'
        })
}
Write-Progress -Activity 'Reading archive state' -Completed

if ($Unarchive -or $DeleteArchived) {
    foreach ($row in $results) {
        try {
            if ($Unarchive -and $PSCmdlet.ShouldProcess($row.TeamName, 'Unarchive team')) {
                Invoke-MgGraphRequest -Method POST -Uri ('{0}/teams/{1}/unarchive' -f $graphV1, $row.TeamId) -ErrorAction Stop | Out-Null
                $row.ActionTaken = 'UnarchiveRequested'
            }
            elseif ($DeleteArchived -and $PSCmdlet.ShouldProcess($row.TeamName, 'Delete team and Microsoft 365 group (recoverable for 30 days)')) {
                Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/groups/{1}' -f $graphV1, $row.TeamId) -ErrorAction Stop | Out-Null
                $row.ActionTaken = 'Deleted'
            }
            else { continue }
            Start-Sleep -Milliseconds 200
        }
        catch {
            $row.ActionTaken = 'Failed'
            Write-Warning "Changing team '$($row.TeamName)' failed: $($_.Exception.Message)"
        }
    }
}

$output = @($results | Sort-Object -Property TeamName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No archived teams were found in the selection; no CSV was written.' }
Write-Host ''
Write-Host 'Archived teams summary' -ForegroundColor Cyan
Write-Host ('  Teams evaluated            : {0}' -f $teams.Count)
Write-Host ('  Archived teams             : {0}' -f $output.Count) -ForegroundColor Yellow
Write-Host ('  Archived without owners    : {0}' -f @($output | Where-Object { $_.OwnersCount -eq 0 }).Count)
if ($Unarchive) { Write-Host ('  Unarchive requested        : {0}' -f @($output | Where-Object { $_.ActionTaken -eq 'UnarchiveRequested' }).Count) -ForegroundColor Green }
if ($DeleteArchived) { Write-Host ('  Deleted                    : {0}' -f @($output | Where-Object { $_.ActionTaken -eq 'Deleted' }).Count) -ForegroundColor Green }
Write-Host ('  Report                     : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
