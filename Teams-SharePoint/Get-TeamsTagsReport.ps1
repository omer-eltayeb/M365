<#
.SYNOPSIS
    Reports the tags defined in Microsoft Teams teams (and their members) and can bulk-create tags from a CSV.
.DESCRIPTION
    Lists every team (groups with the Team provisioning option) from /groups, or the teams selected with -TeamName / -TeamId,
    reads /teams/{id}/tags for each and writes one row per tag with its description, member count and type; -IncludeMembers
    adds the member names from /teams/{id}/tags/{tagId}/members. -CreateFromCsv additionally creates the tags listed in a CSV
    (TeamName, TagName, Members as semicolon-separated UPNs) with POST /teams/{id}/tags, skipping tags that already exist;
    every creation honours -WhatIf / -Confirm. The console summary shows tags per team and the tag names used in most teams.
.PARAMETER TeamName
    Only evaluate teams whose display name matches this wildcard pattern (a value without wildcards is matched as *value*). Ignored with -TeamId.
.PARAMETER TeamId
    Evaluate a single team by its group id.
.PARAMETER TagName
    Only export tags whose name matches this wildcard pattern (for example 'Shift*').
.PARAMETER IncludeMembers
    Also read the members of every tag (one extra Graph call per tag) into the Members column.
.PARAMETER CreateFromCsv
    Path to a CSV with the columns TeamName, TagName and Members (semicolon-separated UPNs). Without -TeamName / -TeamId the report covers only the CSV teams.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsTags_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsTagsReport.ps1 -IncludeMembers
    Exports every tag in every team the signed-in account can read, including the tagged members.
.EXAMPLE
    PS> .\Get-TeamsTagsReport.ps1 -CreateFromCsv .\tags.csv -Confirm:$false -OutputPath C:\Temp\Tags.csv -Verbose
    Creates the tags listed in tags.csv (existing tags are skipped) and exports the resulting tags of those teams.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : TeamworkTag.Read, Team.ReadBasic.All, Group.Read.All (delegated); -CreateFromCsv adds TeamworkTag.ReadWrite and User.Read.All.
    Category    : Teams apps, settings & usage
    Changes     : Optional (-CreateFromCsv)
    Notes       : With delegated permissions the tags API only returns tags of teams the signed-in account is a member of (other teams
                  produce a warning); a tenant-wide inventory needs an app-only run with TeamworkTag.Read.All. Tag creation follows the
                  tagging policy in the Teams admin center and needs at least one resolvable member. TagType scheduled marks Shifts tags.
.LINK
    https://learn.microsoft.com/graph/api/teamworktag-list
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
    [string]$TagName,

    [Parameter()]
    [switch]$IncludeMembers,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$CreateFromCsv,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsTags_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('TeamworkTag.Read', 'Team.ReadBasic.All', 'Group.Read.All')
$csvRows = @()
if (-not [string]::IsNullOrWhiteSpace($CreateFromCsv)) {
    $csvRows = @(Import-Csv -Path $CreateFromCsv -ErrorAction Stop)
    if ($csvRows.Count -eq 0 -or @(@('TeamName', 'TagName', 'Members') | Where-Object { $csvRows[0].PSObject.Properties.Name -notcontains $_ }).Count -gt 0) { throw 'The CSV must contain rows with the TeamName, TagName and Members columns.' }
    $scopes += @('TeamworkTag.ReadWrite', 'User.Read.All')
}
try { Connect-GraphIfNeeded -Scopes $scopes }
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
elseif ([string]::IsNullOrWhiteSpace($TeamId) -and $csvRows.Count -gt 0) {
    $csvTeamNames = @($csvRows | ForEach-Object { ([string]$_.TeamName).Trim() })
    $teams = @($teams | Where-Object { $csvTeamNames -contains $_.displayName })
}
$tagPattern = $TagName; if (-not [string]::IsNullOrWhiteSpace($tagPattern) -and $tagPattern -notmatch '[\*\?]') { $tagPattern = "*$tagPattern*" }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$tagNamesByTeam = @{}; $counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Reading team tags' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    try { $tags = @(Invoke-GraphPaged -Uri ('{0}/teams/{1}/tags' -f $graphV1, $team.id)) }
    catch { Write-Warning "Could not read the tags of team '$($team.displayName)': $($_.Exception.Message)"; continue }
    $tagNamesByTeam[$team.id] = @($tags | ForEach-Object { $_.displayName })
    foreach ($tag in $tags) {
        if (-not [string]::IsNullOrWhiteSpace($tagPattern) -and $tag.displayName -notlike $tagPattern) { continue }
        $members = $null
        if ($IncludeMembers) {
            try { $members = (@(Invoke-GraphPaged -Uri ('{0}/teams/{1}/tags/{2}/members' -f $graphV1, $team.id, $tag.id)) | ForEach-Object { $_.displayName } | Sort-Object) -join ';' }
            catch { Write-Warning "Could not read the members of tag '$($tag.displayName)' in '$($team.displayName)': $($_.Exception.Message)" }
        }
        $rows.Add([PSCustomObject]@{ TeamName = $team.displayName; TeamId = $team.id; TagName = $tag.displayName; Description = $tag.description; MemberCount = $tag.memberCount; TagType = $tag.tagType; TagId = $tag.id; Members = $members })
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading team tags' -Completed
$created = 0; $userIds = @{}
foreach ($csvRow in $csvRows) {
    $newTagName = ([string]$csvRow.TagName).Trim()
    $target = @($teams | Where-Object { $_.displayName -eq ([string]$csvRow.TeamName).Trim() })
    if ($target.Count -ne 1 -or [string]::IsNullOrWhiteSpace($newTagName)) { Write-Warning "CSV row '$($csvRow.TeamName)' / '$newTagName': team not found or ambiguous, or empty tag name; skipped."; continue }
    $team = $target[0]
    if ($tagNamesByTeam[$team.id] -contains $newTagName) { Write-Verbose "Tag '$newTagName' already exists in team '$($team.displayName)'; skipped."; continue }
    $memberUpns = @(([string]$csvRow.Members).Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } | Sort-Object -Unique)
    foreach ($upn in $memberUpns) {
        if ($userIds.ContainsKey($upn)) { continue }
        try { $userIds[$upn] = (Invoke-MgGraphRequest -Method GET -Uri ('{0}/users/{1}?$select=id' -f $graphV1, [uri]::EscapeDataString($upn)) -OutputType PSObject -ErrorAction Stop).id }
        catch { Write-Warning "Account '$upn' could not be resolved: $($_.Exception.Message)"; $userIds[$upn] = $null }
    }
    $memberIds = @($memberUpns | ForEach-Object { $userIds[$_] } | Where-Object { $null -ne $_ })
    if ($memberIds.Count -eq 0) { Write-Warning "Tag '$newTagName' in team '$($team.displayName)' has no resolvable members; a tag needs at least one."; continue }
    if (-not $PSCmdlet.ShouldProcess($team.displayName, "Create tag '$newTagName' with $($memberIds.Count) member(s)")) { continue }
    try {
        $body = @{ displayName = $newTagName; members = @($memberIds | ForEach-Object { @{ userId = $_ } }) }
        $newTag = Invoke-MgGraphRequest -Method POST -Uri ('{0}/teams/{1}/tags' -f $graphV1, $team.id) -Body (ConvertTo-Json -InputObject $body -Depth 4) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
        $rows.Add([PSCustomObject]@{ TeamName = $team.displayName; TeamId = $team.id; TagName = $newTagName; Description = $null; MemberCount = $memberIds.Count; TagType = 'standard'; TagId = $newTag.id; Members = ($memberUpns -join ';') })
        $tagNamesByTeam[$team.id] += $newTagName
        $created++
    }
    catch { Write-Warning "Could not create tag '$newTagName' in team '$($team.displayName)': $($_.Exception.Message)" }
    Start-Sleep -Milliseconds 200
}
$output = @($rows | Sort-Object -Property TeamName, TagName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No tags to export (no tags found in the evaluated teams); no CSV was written.' }
$topTagNames = @($output | Group-Object -Property TagName | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, Name | Select-Object -First 10)
Write-Host 'Teams tags summary' -ForegroundColor Cyan
Write-Host ('  Teams evaluated / readable / with tags : {0} / {1} / {2}' -f $teams.Count, $tagNamesByTeam.Count, @($output | Select-Object -ExpandProperty TeamId -Unique).Count)
if ($csvRows.Count -gt 0) { Write-Host ('  Tags created from CSV                  : {0} of {1} rows' -f $created, $csvRows.Count) -ForegroundColor Green }
if ($topTagNames.Count -gt 0) {
    Write-Host '  Tag names used in most teams (number of teams):'
    foreach ($entry in $topTagNames) { Write-Host ('    {0,-40} {1,5}' -f $entry.Name, $entry.Count) }
}
Write-Host ('  Tags exported                          : {0} -> {1}' -f $output.Count, $OutputPath)
if ($PassThru) { $output }
#endregion Main
