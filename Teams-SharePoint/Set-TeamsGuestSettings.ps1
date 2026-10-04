<#
.SYNOPSIS
    Standardises guest permissions (and optionally member and fun settings) across Microsoft Teams teams.
.DESCRIPTION
    Reads the current guestSettings, memberSettings and funSettings of each selected team (/teams/{id}), compares them with the
    values requested through the setting parameters and patches only the properties that differ (PATCH /teams/{id}). Only the
    parameters that are actually passed are enforced; teams that already comply and archived teams are skipped. Without -Apply
    the script only reports what would change; every change honours -WhatIf / -Confirm. One result object per team is emitted.
.PARAMETER TeamName
    Only process teams whose display name matches this wildcard pattern (a value without wildcards is matched as *value*). Ignored with -TeamId.
.PARAMETER TeamId
    Process a single team by its group id.
.PARAMETER All
    Process every team in the tenant. Required when neither -TeamName nor -TeamId is given, to avoid accidental tenant-wide changes.
.PARAMETER AllowGuestCreateUpdateChannels
    Whether guests may create and update channels (guestSettings.allowCreateUpdateChannels).
.PARAMETER AllowGuestDeleteChannels
    Whether guests may delete channels (guestSettings.allowDeleteChannels).
.PARAMETER AllowMemberCreatePrivateChannels
    Whether members may create private channels (memberSettings.allowCreatePrivateChannels).
.PARAMETER AllowMemberAddRemoveApps
    Whether members may add and remove apps (memberSettings.allowAddRemoveApps).
.PARAMETER AllowGiphy
    Whether Giphy is enabled in conversations (funSettings.allowGiphy).
.PARAMETER GiphyContentRating
    Giphy content rating, strict or moderate (funSettings.giphyContentRating).
.PARAMETER Apply
    Apply the changes. Without this switch non-compliant teams are reported as WouldChange and nothing is modified.
.EXAMPLE
    PS> .\Set-TeamsGuestSettings.ps1 -All -AllowGuestCreateUpdateChannels:$false -AllowGuestDeleteChannels:$false
    Reports every team where guests are still allowed to create, update or delete channels, without changing anything.
.EXAMPLE
    PS> .\Set-TeamsGuestSettings.ps1 -TeamName 'Project*' -AllowGuestCreateUpdateChannels:$false -AllowGiphy:$false -Apply -Confirm:$false
    Disables guest channel creation and Giphy on all project teams without prompting; compliant teams are skipped.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : TeamSettings.ReadWrite.All, Group.Read.All (delegated). Teams Administrator or Global Administrator role.
    Category    : Teams apps, settings & usage
    Changes     : Yes
    Notes       : Results: AlreadyCompliant, WouldChange, Changed, SkippedByUser, Skipped (archived) or Failed; the Changes column lists
                  every property as "name: before -> after". Archived teams cannot be patched; unarchive them first. Other settings
                  (messaging, tabs, connectors) can be reviewed with Get-TeamsTeamSettingsReport.ps1. Pipe the output to Export-Csv.
.LINK
    https://learn.microsoft.com/graph/api/team-update
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string]$TeamName,

    [Parameter()]
    [string]$TeamId,

    [Parameter()]
    [switch]$All,

    [Parameter()]
    [bool]$AllowGuestCreateUpdateChannels,

    [Parameter()]
    [bool]$AllowGuestDeleteChannels,

    [Parameter()]
    [bool]$AllowMemberCreatePrivateChannels,

    [Parameter()]
    [bool]$AllowMemberAddRemoveApps,

    [Parameter()]
    [bool]$AllowGiphy,

    [Parameter()]
    [ValidateSet('strict', 'moderate')]
    [string]$GiphyContentRating,

    [Parameter()]
    [switch]$Apply
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
# Parameter name -> Graph settings group and property. Only parameters that were bound are enforced.
$settingMap = [ordered]@{
    AllowGuestCreateUpdateChannels   = @('guestSettings', 'allowCreateUpdateChannels')
    AllowGuestDeleteChannels         = @('guestSettings', 'allowDeleteChannels')
    AllowMemberCreatePrivateChannels = @('memberSettings', 'allowCreatePrivateChannels')
    AllowMemberAddRemoveApps         = @('memberSettings', 'allowAddRemoveApps')
    AllowGiphy                       = @('funSettings', 'allowGiphy')
    GiphyContentRating               = @('funSettings', 'giphyContentRating')
}
$requested = @($settingMap.Keys | Where-Object { $PSBoundParameters.ContainsKey($_) })
if ($requested.Count -eq 0) { throw 'Specify at least one setting parameter, for example -AllowGuestCreateUpdateChannels:$false.' }
if ([string]::IsNullOrWhiteSpace($TeamName) -and [string]::IsNullOrWhiteSpace($TeamId) -and -not $All) { throw 'Select teams with -TeamName or -TeamId, or pass -All to process every team.' }

try { Connect-GraphIfNeeded -Scopes @('TeamSettings.ReadWrite.All', 'Group.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
$graphV1 = 'https://graph.microsoft.com/v1.0'
try {
    $teamsUri = $graphV1 + '/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select=id,displayName&$top=999'
    if (-not [string]::IsNullOrWhiteSpace($TeamId)) { $teamsUri = '{0}/groups/{1}?$select=id,displayName' -f $graphV1, $TeamId }
    $teams = @(Invoke-GraphPaged -Uri $teamsUri)
}
catch { throw "Failed to list teams: $($_.Exception.Message)" }
if ([string]::IsNullOrWhiteSpace($TeamId) -and -not [string]::IsNullOrWhiteSpace($TeamName)) {
    $pattern = $TeamName
    if ($pattern -notmatch '[\*\?]') { $pattern = "*$pattern*" }
    $teams = @($teams | Where-Object { $_.displayName -like $pattern })
}
if ($teams.Count -eq 0) { Write-Warning 'No teams matched the selection; nothing to do.'; return }
if ($All -and $Apply) { Write-Warning ('-All with -Apply: settings will be enforced on ALL {0} teams. Each team prompts for confirmation unless -Confirm:$false is supplied.' -f $teams.Count) }
$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Applying team settings' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    $result = [PSCustomObject]@{ TeamName = $team.displayName; TeamId = $team.id; Changes = $null; Result = $null; Detail = $null }
    $results.Add($result)
    try {
        $current = Invoke-MgGraphRequest -Method GET -Uri ('{0}/teams/{1}?$select=isArchived,guestSettings,memberSettings,funSettings' -f $graphV1, $team.id) -OutputType PSObject -ErrorAction Stop
        if ($current.isArchived -eq $true) { $result.Result = 'Skipped'; $result.Detail = 'Team is archived'; continue }
        $body = @{}
        $changes = @()
        foreach ($name in $requested) {
            $group, $property = $settingMap[$name]
            $desired = $PSBoundParameters[$name]
            $actual = $current.$group.$property
            # String comparison covers booleans and the Giphy rating alike.
            if ("$actual" -eq "$desired") { continue }
            if (-not $body.ContainsKey($group)) { $body[$group] = @{} }
            $body[$group][$property] = $desired
            $changes += ('{0}: {1} -> {2}' -f $property, $actual, $desired)
        }
        $result.Changes = $changes -join '; '
        if ($changes.Count -eq 0) { $result.Result = 'AlreadyCompliant'; continue }
        if (-not $Apply) { $result.Result = 'WouldChange'; continue }
        $result.Result = 'SkippedByUser'
        if ($PSCmdlet.ShouldProcess($team.displayName, "Update team settings ($($result.Changes))")) {
            Invoke-MgGraphRequest -Method PATCH -Uri ('{0}/teams/{1}' -f $graphV1, $team.id) -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
            $result.Result = 'Changed'
        }
    }
    catch {
        $result.Result = 'Failed'
        $result.Detail = $_.Exception.Message
        Write-Warning "Team '$($team.displayName)': $($_.Exception.Message)"
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Applying team settings' -Completed

Write-Host ('Team settings summary - {0}' -f $(if ($Apply) { 'APPLY' } else { 'report only (add -Apply to change)' })) -ForegroundColor Cyan
Write-Host ('  Settings enforced : {0}' -f ($requested -join ', '))
Write-Host ('  Teams processed   : {0}' -f $results.Count)
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = 'Yellow'
    if ($group.Name -eq 'Failed') { $colour = 'Red' } elseif ($group.Name -in @('Changed', 'AlreadyCompliant')) { $colour = 'Green' }
    Write-Host ('  {0,-18}: {1}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
