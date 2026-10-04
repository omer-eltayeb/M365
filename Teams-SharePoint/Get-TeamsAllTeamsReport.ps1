<#
.SYNOPSIS
    Inventories every Microsoft Teams team with owner, member, guest and channel counts, archive state and age.
.DESCRIPTION
    Lists all teams through GET /groups (filtered on resourceProvisioningOptions Team), reads archive state,
    specialization, web URL and the owner/member/guest summary from GET /teams/{id}, and counts standard, private and
    shared channels from GET /teams/{id}/channels. Exports one row per team to CSV and prints a summary by visibility
    plus the number of archived, ownerless and single-owner teams.
.PARAMETER TeamName
    One or more team display names to report on; wildcards are supported (for example 'Project*'). Default: all teams.
.PARAMETER TeamId
    One or more team (Microsoft 365 group) ids to report on. Takes precedence over -TeamName.
.PARAMETER IncludeArchived
    Include archived teams. Default $true; pass -IncludeArchived:$false to export active teams only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\TeamsAllTeams_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsAllTeamsReport.ps1
    Exports every team, including archived ones, with counts and prints the summary.
.EXAMPLE
    PS> .\Get-TeamsAllTeamsReport.ps1 -TeamName 'Project*', 'Sales*' -IncludeArchived:$false -OutputPath C:\Temp\Teams.csv -Verbose
    Reports only active teams whose name starts with Project or Sales.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, Team.ReadBasic.All, TeamSettings.Read.All, Channel.ReadBasic.All (delegated). The Teams
                  Administrator or Global Reader role lets the signed-in user read teams they are not a member of.
    Category    : Teams inventory & lifecycle
    Changes     : No
    Notes       : Two Graph calls per team plus a 200 ms pause, so 1,000 teams take roughly 10 minutes; use -TeamName to narrow
                  the scope. Channel counts cover channels hosted by the team only. Teams still being provisioned can return
                  404 from /teams/{id}; they stay in the report with empty detail columns.
.LINK
    https://learn.microsoft.com/graph/api/team-get
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
    [bool]$IncludeArchived = $true,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsAllTeams_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('Group.Read.All', 'Team.ReadBasic.All', 'TeamSettings.Read.All', 'Channel.ReadBasic.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0'
$groupSelect = 'id,displayName,description,visibility,createdDateTime,mail,classification'
try {
    if ($PSBoundParameters.ContainsKey('TeamId')) {
        $teams = @(foreach ($id in $TeamId) { Invoke-MgGraphRequest -Method GET -Uri ('{0}/groups/{1}?$select={2}' -f $graphV1, $id, $groupSelect) -OutputType PSObject -ErrorAction Stop })
    }
    else {
        $teams = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select={1}&$top=999' -f $graphV1, $groupSelect))
    }
}
catch {
    throw "Failed to list teams: $($_.Exception.Message)"
}
if ($PSBoundParameters.ContainsKey('TeamName') -and -not $PSBoundParameters.ContainsKey('TeamId')) {
    $teams = @($teams | Where-Object { $candidate = $_.displayName; @($TeamName | Where-Object { $candidate -like $_ }).Count -gt 0 })
}
Write-Verbose "Evaluating $($teams.Count) teams."

# Without this header Graph reports shared channels as 'unknownFutureValue'.
$channelHeaders = @{ 'Prefer' = 'include-unknown-enum-members' }
$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Reading team details' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    $detail = $null
    $channels = $null
    try {
        $detail = Invoke-MgGraphRequest -Method GET -Uri ('{0}/teams/{1}?$select=id,isArchived,summary,specialization,webUrl' -f $graphV1, $team.id) -OutputType PSObject -ErrorAction Stop
        $channels = @(Invoke-GraphPaged -Uri ('{0}/teams/{1}/channels?$select=id,membershipType' -f $graphV1, $team.id) -Headers $channelHeaders)
    }
    catch {
        Write-Warning "Could not read details of team '$($team.displayName)': $($_.Exception.Message)"
    }
    Start-Sleep -Milliseconds 200
    $created = $null
    $ageDays = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$team.createdDateTime)) {
        $created = [datetime]$team.createdDateTime
        $ageDays = [int](((Get-Date) - $created).TotalDays)
    }
    $counts = @{ total = $null; standard = $null; private = $null; shared = $null }
    if ($null -ne $channels) {
        $counts['total'] = $channels.Count
        foreach ($type in @('standard', 'private', 'shared')) { $counts[$type] = @($channels | Where-Object { $_.membershipType -eq $type }).Count }
    }
    $results.Add([PSCustomObject]@{
            TeamName         = $team.displayName
            TeamId           = $team.id
            Visibility       = $team.visibility
            Classification   = $team.classification
            IsArchived       = $(if ($null -ne $detail) { $detail.isArchived -eq $true } else { $null })
            Specialization   = $detail.specialization
            CreatedDateTime  = $created
            AgeDays          = $ageDays
            OwnersCount      = $detail.summary.ownersCount
            MembersCount     = $detail.summary.membersCount
            GuestsCount      = $detail.summary.guestsCount
            ChannelsCount    = $counts['total']
            StandardChannels = $counts['standard']
            PrivateChannels  = $counts['private']
            SharedChannels   = $counts['shared']
            Mail             = $team.mail
            WebUrl           = $detail.webUrl
            Description      = $team.description
        })
}
Write-Progress -Activity 'Reading team details' -Completed
$output = @($results | Sort-Object -Property TeamName)
if (-not $IncludeArchived) { $output = @($output | Where-Object { $_.IsArchived -ne $true }) }
if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No teams matched the selection; no CSV was written.'
}
Write-Host ''
Write-Host 'Teams inventory summary' -ForegroundColor Cyan
Write-Host ('  Teams evaluated / exported : {0} / {1}' -f $results.Count, $output.Count)
foreach ($visibilityGroup in @($output | Group-Object -Property Visibility | Sort-Object -Property Name)) {
    Write-Host ('  {0,-27}: {1}' -f "Visibility $($visibilityGroup.Name)", $visibilityGroup.Count)
}
Write-Host ('  Archived teams             : {0}' -f @($results | Where-Object { $_.IsArchived -eq $true }).Count)
Write-Host ('  Ownerless teams            : {0}' -f @($output | Where-Object { $_.OwnersCount -eq 0 }).Count) -ForegroundColor Yellow
Write-Host ('  Single-owner teams         : {0}' -f @($output | Where-Object { $_.OwnersCount -eq 1 }).Count) -ForegroundColor Yellow
Write-Host ('  Report                     : {0}' -f $OutputPath)

if ($PassThru) { $output }
#endregion Main
