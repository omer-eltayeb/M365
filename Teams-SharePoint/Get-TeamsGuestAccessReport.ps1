<#
.SYNOPSIS
    Reports which Microsoft Teams teams contain guest users and which external domains they come from.
.DESCRIPTION
    Lists every team (groups with the Team provisioning option) from /groups, reads the members of each
    team from /groups/{id}/members and keeps the members whose userType is Guest. The guest's home domain
    is taken from the mail attribute, or decoded from the #EXT# user principal name when mail is empty.
    By default one row per guest membership is exported; -SummaryOnly exports one row per team instead.
    -IncludeTeamSettings adds the team's guest channel permissions from /teams/{id}?$select=guestSettings.
    Prints a summary with the number of teams that have guests, total guests and the top 10 guest domains.
.PARAMETER TeamName
    Only evaluate teams whose display name matches this wildcard pattern (for example 'Project*'). A value
    without wildcards is matched as *value*.
.PARAMETER SummaryOnly
    Export one row per team (TeamName, TeamId, Visibility, MemberCount, GuestCount, GuestDomains) instead of one row per guest.
.PARAMETER IncludeTeamSettings
    Also read each team's guest settings (AllowGuestCreateUpdateChannels, AllowGuestDeleteChannels). Needs the
    Team.ReadBasic.All and TeamSettings.Read.All scopes and one extra Graph call per team.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsGuestAccess_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsGuestAccessReport.ps1
    Exports every guest membership in every team and shows the top guest domains in the console.
.EXAMPLE
    PS> .\Get-TeamsGuestAccessReport.ps1 -TeamName 'Project*' -SummaryOnly -IncludeTeamSettings -OutputPath C:\Temp\ProjectGuests.csv -Verbose
    Evaluates only teams starting with "Project", exports one row per team including the guest channel permissions.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, GroupMember.Read.All, User.Read.All (delegated); plus Team.ReadBasic.All and
                  TeamSettings.Read.All when -IncludeTeamSettings is used. Global Reader can run it end to end.
    Category    : Teams inventory & lifecycle
    Changes     : No
    Notes       : Only direct team members are evaluated. External participants of shared channels are not team
                  members and therefore do not appear here. Guest counts are memberships: a guest who belongs to
                  three teams produces three rows. One Graph call per team (two with -IncludeTeamSettings); large
                  tenants should expect a few minutes and may use -TeamName to narrow the scope.
.LINK
    https://learn.microsoft.com/graph/api/group-list-members
.LINK
    https://learn.microsoft.com/graph/api/team-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TeamName,

    [Parameter()]
    [switch]$SummaryOnly,

    [Parameter()]
    [switch]$IncludeTeamSettings,

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

function Get-GuestDomain {
    <# Returns the guest's home domain from the mail address, or decoded from a UPN like user_contoso.com#EXT#@tenant.onmicrosoft.com. #>
    param(
        [Parameter()]
        [string]$Mail,

        [Parameter()]
        [string]$UserPrincipalName
    )
    if (-not [string]::IsNullOrWhiteSpace($Mail) -and $Mail.Contains('@')) {
        return $Mail.Split('@')[-1].ToLowerInvariant()
    }
    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName) -and $UserPrincipalName -match '^(?<local>.+)#EXT#@') {
        $local = $Matches['local']
        $separator = $local.LastIndexOf('_')
        if ($separator -ge 0 -and $separator -lt ($local.Length - 1)) {
            return $local.Substring($separator + 1).ToLowerInvariant()
        }
    }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsGuestAccess_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$scopes = @('Group.Read.All', 'GroupMember.Read.All', 'User.Read.All')
if ($IncludeTeamSettings) { $scopes += @('Team.ReadBasic.All', 'TeamSettings.Read.All') }
try {
    Connect-GraphIfNeeded -Scopes $scopes
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

Write-Verbose 'Listing all teams from /groups.'
try {
    $groupsUri = 'https://graph.microsoft.com/v1.0/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select=id,displayName,visibility&$top=999'
    $teams = @(Invoke-GraphPaged -Uri $groupsUri)
}
catch {
    throw "Failed to list teams: $($_.Exception.Message)"
}
if (-not [string]::IsNullOrWhiteSpace($TeamName)) {
    $namePattern = $TeamName
    if ($namePattern -notmatch '[\*\?]') { $namePattern = "*$namePattern*" }
    $teams = @($teams | Where-Object { $_.displayName -like $namePattern })
}
Write-Verbose "Evaluating $($teams.Count) teams."

$guestRows = New-Object -TypeName System.Collections.Generic.List[object]
$teamRows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Reading team membership' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))

    try {
        $members = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/groups/{0}/members?$select=id,displayName,userPrincipalName,mail,userType&$top=999' -f $team.id))
    }
    catch {
        Write-Warning "Could not read the members of team '$($team.displayName)': $($_.Exception.Message)"
        continue
    }
    $guests = @($members | Where-Object { $_.userType -eq 'Guest' })

    $allowGuestCreateUpdateChannels = $null
    $allowGuestDeleteChannels = $null
    if ($IncludeTeamSettings) {
        try {
            $teamSettings = Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/teams/{0}?$select=guestSettings' -f $team.id) -OutputType PSObject -ErrorAction Stop
            $allowGuestCreateUpdateChannels = $teamSettings.guestSettings.allowCreateUpdateChannels
            $allowGuestDeleteChannels = $teamSettings.guestSettings.allowDeleteChannels
        }
        catch {
            Write-Warning "Could not read the guest settings of team '$($team.displayName)': $($_.Exception.Message)"
        }
    }

    $domains = @($guests | ForEach-Object { Get-GuestDomain -Mail $_.mail -UserPrincipalName $_.userPrincipalName } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
    $teamRows.Add([PSCustomObject]@{
            TeamName                       = $team.displayName
            TeamId                         = $team.id
            Visibility                     = $team.visibility
            MemberCount                    = $members.Count
            GuestCount                     = $guests.Count
            GuestDomains                   = ($domains -join ';')
            AllowGuestCreateUpdateChannels = $allowGuestCreateUpdateChannels
            AllowGuestDeleteChannels       = $allowGuestDeleteChannels
        })
    foreach ($guest in $guests) {
        $guestRows.Add([PSCustomObject]@{
                TeamName                       = $team.displayName
                TeamId                         = $team.id
                Visibility                     = $team.visibility
                GuestDisplayName               = $guest.displayName
                GuestUserPrincipalName         = $guest.userPrincipalName
                GuestEmail                     = $guest.mail
                GuestDomain                    = Get-GuestDomain -Mail $guest.mail -UserPrincipalName $guest.userPrincipalName
                MemberCount                    = $members.Count
                GuestCount                     = $guests.Count
                AllowGuestCreateUpdateChannels = $allowGuestCreateUpdateChannels
                AllowGuestDeleteChannels       = $allowGuestDeleteChannels
            })
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading team membership' -Completed

if ($SummaryOnly) {
    $output = @($teamRows | Sort-Object -Property @{ Expression = 'GuestCount'; Descending = $true }, TeamName)
}
else {
    $output = @($guestRows | Sort-Object -Property TeamName, GuestDisplayName)
}

if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No rows to export (no guests found in the evaluated teams); no CSV was written.'
}

$teamsWithGuests = @($teamRows | Where-Object { $_.GuestCount -gt 0 }).Count
$uniqueGuests = @($guestRows | Select-Object -ExpandProperty GuestUserPrincipalName -Unique).Count
$domainGroups = @($guestRows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.GuestDomain) } | Group-Object -Property GuestDomain)
$topDomains = @($domainGroups | Sort-Object -Property Count -Descending | Select-Object -First 10)
Write-Host ''
Write-Host 'Teams guest access summary' -ForegroundColor Cyan
Write-Host ('  Teams evaluated              : {0}' -f $teamRows.Count)
Write-Host ('  Teams with guests            : {0}' -f $teamsWithGuests) -ForegroundColor Yellow
Write-Host ('  Guest memberships / accounts : {0} / {1}' -f $guestRows.Count, $uniqueGuests)
if ($topDomains.Count -gt 0) {
    Write-Host '  Top guest domains:'
    foreach ($domain in $topDomains) {
        Write-Host ('    {0,-45} {1,5}' -f $domain.Name, $domain.Count)
    }
}
Write-Host ('  Rows exported                : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
