<#
.SYNOPSIS
    Reports the member, guest, messaging, fun and discovery settings of Microsoft Teams teams and flags deviations from the defaults.
.DESCRIPTION
    Lists every team (groups with the Team provisioning option) from /groups, or one team selected with -TeamName / -TeamId,
    and reads /teams/{id}?$select=memberSettings,guestSettings,messagingSettings,funSettings,discoverySettings,... for each.
    The nested settings are flattened into one column per setting (AllowCreateUpdateChannels, GuestAllowDeleteChannels,
    AllowGiphy, GiphyContentRating, ShowInTeamsSearchAndSuggestions, ...). Every value is compared with what Microsoft applies
    to a newly created team; the deviations are listed in NonDefaultSettings and -NonDefaultOnly exports only those teams.
.PARAMETER TeamName
    Only evaluate teams whose display name matches this wildcard pattern (a value without wildcards is matched as *value*). Ignored with -TeamId.
.PARAMETER TeamId
    Evaluate a single team by its group id.
.PARAMETER NonDefaultOnly
    Export only teams with at least one setting that differs from the Microsoft default.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsTeamSettings_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsTeamSettingsReport.ps1
    Exports the settings of every team and shows which settings are changed most often across the tenant.
.EXAMPLE
    PS> .\Get-TeamsTeamSettingsReport.ps1 -NonDefaultOnly -OutputPath C:\Temp\TeamSettingsDeviations.csv -Verbose
    Exports only the teams whose owners changed at least one setting, for example teams that let guests create channels.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : TeamSettings.Read.All, Team.ReadBasic.All, Group.Read.All (delegated). Global Reader can run it end to end.
    Category    : Teams apps, settings & usage
    Changes     : No
    Notes       : Defaults used for the comparison: all member and messaging settings true, both guest channel settings false, Giphy
                  enabled with the moderate rating, stickers and custom memes allowed, team shown in search and suggestions. A missing
                  settings group (older or archived teams) leaves the column empty and is not counted as a deviation. One Graph call
                  per team with a 200 ms pause; use -TeamName to narrow large tenants.
.LINK
    https://learn.microsoft.com/graph/api/team-get
.LINK
    https://learn.microsoft.com/graph/api/resources/team
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TeamName,

    [Parameter()]
    [string]$TeamId,

    [Parameter()]
    [switch]$NonDefaultOnly,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsTeamSettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

# Output column, Graph settings group, Graph property and the value Microsoft applies to a newly created team.
$settingDefinitions = @(
    @{ Column = 'AllowCreateUpdateChannels'; Group = 'memberSettings'; Property = 'allowCreateUpdateChannels'; Default = $true }
    @{ Column = 'AllowCreatePrivateChannels'; Group = 'memberSettings'; Property = 'allowCreatePrivateChannels'; Default = $true }
    @{ Column = 'AllowDeleteChannels'; Group = 'memberSettings'; Property = 'allowDeleteChannels'; Default = $true }
    @{ Column = 'AllowAddRemoveApps'; Group = 'memberSettings'; Property = 'allowAddRemoveApps'; Default = $true }
    @{ Column = 'AllowCreateUpdateRemoveTabs'; Group = 'memberSettings'; Property = 'allowCreateUpdateRemoveTabs'; Default = $true }
    @{ Column = 'AllowCreateUpdateRemoveConnectors'; Group = 'memberSettings'; Property = 'allowCreateUpdateRemoveConnectors'; Default = $true }
    @{ Column = 'GuestAllowCreateUpdateChannels'; Group = 'guestSettings'; Property = 'allowCreateUpdateChannels'; Default = $false }
    @{ Column = 'GuestAllowDeleteChannels'; Group = 'guestSettings'; Property = 'allowDeleteChannels'; Default = $false }
    @{ Column = 'AllowUserEditMessages'; Group = 'messagingSettings'; Property = 'allowUserEditMessages'; Default = $true }
    @{ Column = 'AllowUserDeleteMessages'; Group = 'messagingSettings'; Property = 'allowUserDeleteMessages'; Default = $true }
    @{ Column = 'AllowOwnerDeleteMessages'; Group = 'messagingSettings'; Property = 'allowOwnerDeleteMessages'; Default = $true }
    @{ Column = 'AllowTeamMentions'; Group = 'messagingSettings'; Property = 'allowTeamMentions'; Default = $true }
    @{ Column = 'AllowChannelMentions'; Group = 'messagingSettings'; Property = 'allowChannelMentions'; Default = $true }
    @{ Column = 'AllowGiphy'; Group = 'funSettings'; Property = 'allowGiphy'; Default = $true }
    @{ Column = 'GiphyContentRating'; Group = 'funSettings'; Property = 'giphyContentRating'; Default = 'moderate' }
    @{ Column = 'AllowStickersAndMemes'; Group = 'funSettings'; Property = 'allowStickersAndMemes'; Default = $true }
    @{ Column = 'AllowCustomMemes'; Group = 'funSettings'; Property = 'allowCustomMemes'; Default = $true }
    @{ Column = 'ShowInTeamsSearchAndSuggestions'; Group = 'discoverySettings'; Property = 'showInTeamsSearchAndSuggestions'; Default = $true }
)

try { Connect-GraphIfNeeded -Scopes @('TeamSettings.Read.All', 'Team.ReadBasic.All', 'Group.Read.All') }
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

$select = '$select=id,displayName,isArchived,visibility,classification,specialization,memberSettings,guestSettings,messagingSettings,funSettings,discoverySettings'
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Reading team settings' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    try {
        $detail = Invoke-MgGraphRequest -Method GET -Uri ('{0}/teams/{1}?{2}' -f $graphV1, $team.id, $select) -OutputType PSObject -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not read the settings of team '$($team.displayName)': $($_.Exception.Message)"
        continue
    }
    $row = [ordered]@{ TeamName = $team.displayName; TeamId = $team.id; Visibility = $detail.visibility; IsArchived = $detail.isArchived }
    $row['Classification'] = $detail.classification
    $row['Specialization'] = $detail.specialization
    $deviations = @()
    foreach ($definition in $settingDefinitions) {
        $value = $null
        $group = $detail.($definition.Group)
        if ($null -ne $group) { $value = $group.($definition.Property) }
        $row[$definition.Column] = $value
        # String comparison covers booleans and the Giphy rating alike; a missing group is unknown, not a deviation.
        if ($null -ne $value -and "$value" -ne "$($definition.Default)") { $deviations += ('{0}={1}' -f $definition.Column, $value) }
    }
    $row['NonDefaultSettings'] = $deviations -join ';'
    $row['NonDefaultCount'] = $deviations.Count
    $rows.Add([PSCustomObject]$row)
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading team settings' -Completed

$output = @($rows | Sort-Object -Property @{ Expression = 'NonDefaultCount'; Descending = $true }, TeamName)
if ($NonDefaultOnly) { $output = @($output | Where-Object { $_.NonDefaultCount -gt 0 }) }
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No teams to export (no team could be read or none deviates from the defaults); no CSV was written.' }

$nonDefaultTeams = @($rows | Where-Object { $_.NonDefaultCount -gt 0 })
$topDeviations = @($nonDefaultTeams | ForEach-Object { $_.NonDefaultSettings.Split(';') } | Group-Object | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, Name | Select-Object -First 10)
Write-Host ''
Write-Host 'Teams settings summary' -ForegroundColor Cyan
Write-Host ('  Teams evaluated / readable   : {0} / {1}' -f $teams.Count, $rows.Count)
Write-Host ('  Archived teams               : {0}' -f @($rows | Where-Object { $_.IsArchived -eq $true }).Count)
Write-Host ('  Teams with non-default values: {0}' -f $nonDefaultTeams.Count) -ForegroundColor Yellow
Write-Host ('  Guests may create channels   : {0}' -f @($rows | Where-Object { $_.GuestAllowCreateUpdateChannels -eq $true }).Count) -ForegroundColor Yellow
Write-Host ('  Hidden from search/suggestion: {0}' -f @($rows | Where-Object { $_.ShowInTeamsSearchAndSuggestions -eq $false }).Count)
if ($topDeviations.Count -gt 0) {
    Write-Host '  Most common deviations (setting=value, number of teams):'
    foreach ($deviation in $topDeviations) { Write-Host ('    {0,-50} {1,5}' -f $deviation.Name, $deviation.Count) }
}
Write-Host ('  Rows exported                : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
