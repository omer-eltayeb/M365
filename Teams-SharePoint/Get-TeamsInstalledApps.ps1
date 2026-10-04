<#
.SYNOPSIS
    Inventories the apps installed in Microsoft Teams teams, with version, distribution method and bot flag.
.DESCRIPTION
    Lists every team (groups with the Team provisioning option) from /groups, or one team selected with -TeamName / -TeamId,
    then reads /teams/{id}/installedApps?$expand=teamsApp,teamsAppDefinition($expand=bot) for each team. One row is written
    per installation with the app name, version, publishing state, distribution method (store, organization, sideloaded),
    whether the app contains a bot and the app identifiers. The console summary ranks apps by the number of teams they are
    installed in and highlights sideloaded (custom uploaded) apps, which usually deserve a governance review.
.PARAMETER TeamName
    Only evaluate teams whose display name matches this wildcard pattern (a value without wildcards is matched as *value*). Ignored with -TeamId.
.PARAMETER TeamId
    Evaluate a single team by its group id.
.PARAMETER AppName
    Only export installations whose app name matches this wildcard pattern (for example '*Planner*').
.PARAMETER DistributionMethod
    Only export apps with this distribution method: store, organization or sideloaded.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsInstalledApps_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsInstalledApps.ps1
    Exports every app installation in every team and shows the most installed apps plus the sideloaded ones.
.EXAMPLE
    PS> .\Get-TeamsInstalledApps.ps1 -DistributionMethod sideloaded -OutputPath C:\Temp\SideloadedApps.csv -Verbose
    Lists only custom apps that were uploaded directly into teams, bypassing the organisation's app catalog.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : TeamsAppInstallation.ReadForTeam, Team.ReadBasic.All, Group.Read.All (delegated). Unattended runs would use the
                  application permission TeamsAppInstallation.ReadForTeam.All instead.
    Category    : Teams apps, settings & usage
    Changes     : No
    Notes       : With delegated permissions a team the signed-in account cannot access produces a warning and is skipped; run as a
                  Teams Administrator for full coverage. One Graph call per team with a 200 ms pause. The v1.0 API does not expose
                  the app publisher, so Microsoft first-party and third-party store apps cannot be told apart here. HasBot is empty
                  when the service rejects the nested bot expansion (the script then falls back to the documented expansion).
.LINK
    https://learn.microsoft.com/graph/api/team-list-installedapps
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
    [string]$AppName,

    [Parameter()]
    [ValidateSet('store', 'organization', 'sideloaded')]
    [string]$DistributionMethod,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsInstalledApps_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('TeamsAppInstallation.ReadForTeam', 'Team.ReadBasic.All', 'Group.Read.All') }
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

$expand = '$expand=teamsApp,teamsAppDefinition($expand=bot)'
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$teamsRead = 0
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Reading installed apps' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    try {
        try { $installations = @(Invoke-GraphPaged -Uri ('{0}/teams/{1}/installedApps?{2}' -f $graphV1, $team.id, $expand)) }
        catch {
            # The nested bot expansion is not documented for this endpoint; fall back to the documented expansion if it is rejected.
            if ($expand -notlike '*bot*' -or $_.Exception.Message -notmatch 'expand|bot|BadRequest|400') { throw }
            Write-Verbose "Nested bot expansion rejected, continuing without HasBot: $($_.Exception.Message)"
            $expand = '$expand=teamsApp,teamsAppDefinition'
            $installations = @(Invoke-GraphPaged -Uri ('{0}/teams/{1}/installedApps?{2}' -f $graphV1, $team.id, $expand))
        }
    }
    catch {
        Write-Warning "Could not read the installed apps of team '$($team.displayName)': $($_.Exception.Message)"
        continue
    }
    $teamsRead++
    foreach ($installation in $installations) {
        $definition = $installation.teamsAppDefinition
        $hasBot = $null
        if ($expand -like '*bot*') { $hasBot = ($null -ne $definition.bot) }
        $rows.Add([PSCustomObject]@{
            TeamName           = $team.displayName
            TeamId             = $team.id
            AppName            = $definition.displayName
            Version            = $definition.version
            DistributionMethod = $installation.teamsApp.distributionMethod
            PublishingState    = $definition.publishingState
            HasBot             = $hasBot
            AppId              = $installation.teamsApp.id
            ExternalId         = $installation.teamsApp.externalId
            AzureAdAppId       = $definition.azureADAppId
            InstallationId     = $installation.id
        })
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading installed apps' -Completed

$output = @($rows)
if (-not [string]::IsNullOrWhiteSpace($AppName)) {
    $appPattern = $AppName
    if ($appPattern -notmatch '[\*\?]') { $appPattern = "*$appPattern*" }
    $output = @($output | Where-Object { $_.AppName -like $appPattern })
}
if (-not [string]::IsNullOrWhiteSpace($DistributionMethod)) { $output = @($output | Where-Object { $_.DistributionMethod -eq $DistributionMethod }) }
$output = @($output | Sort-Object -Property TeamName, AppName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No app installations matched the filters; no CSV was written.' }

$byApp = @($output | Group-Object -Property AppName | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, Name)
$methodSummary = @($output | Group-Object -Property DistributionMethod | Sort-Object -Property Name | ForEach-Object { '{0} {1}' -f $_.Name, @($_.Group | Select-Object -ExpandProperty AppName -Unique).Count })
$sideloaded = @($output | Where-Object { $_.DistributionMethod -eq 'sideloaded' })
Write-Host ''
Write-Host 'Teams installed apps summary' -ForegroundColor Cyan
Write-Host ('  Teams evaluated / readable    : {0} / {1}' -f $teams.Count, $teamsRead)
Write-Host ('  Installations / distinct apps : {0} / {1}' -f $output.Count, $byApp.Count)
Write-Host ('  Distinct apps by method       : {0}' -f ($methodSummary -join ', '))
Write-Host ('  Sideloaded installations      : {0} in {1} team(s)' -f $sideloaded.Count, @($sideloaded | Select-Object -ExpandProperty TeamId -Unique).Count) -ForegroundColor Yellow
if ($byApp.Count -gt 0) {
    Write-Host '  Most installed apps (number of teams):'
    foreach ($app in ($byApp | Select-Object -First 10)) { Write-Host ('    {0,-50} {1,5}' -f $app.Name, $app.Count) }
}
Write-Host ('  Rows exported                 : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
