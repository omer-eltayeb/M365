<#
.SYNOPSIS
    Finds Microsoft Teams teams that nobody uses, based on the Teams team activity usage report.
.DESCRIPTION
    Downloads the Microsoft Graph usage report /reports/getTeamsTeamActivityDetail(period='D90') as CSV,
    then enriches every team with group details from /groups (visibility, creation date, mail) and,
    optionally, the owner list from /groups/{id}/owners. A team is flagged IsInactive when the report
    shows no activity at all in the period or when its last activity is -DaysInactive days old or older.
    Exports one row per team to CSV and prints a short summary (total, inactive and ownerless teams).
.PARAMETER Period
    Usage report period: D7, D30, D90 or D180. Default D90. Choose a period at least as long as -DaysInactive.
.PARAMETER DaysInactive
    Number of days without activity after which a team is flagged IsInactive. Default 90.
.PARAMETER OnlyInactive
    Export only teams flagged IsInactive.
.PARAMETER IncludeOwners
    Query the owners of every team (one extra Graph call per team) and flag teams without any owner.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsInactiveTeams_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsInactiveTeams.ps1
    Reports every team with its 90-day activity metrics and flags teams idle for 90 days or more.
.EXAMPLE
    PS> .\Get-TeamsInactiveTeams.ps1 -Period D180 -DaysInactive 120 -OnlyInactive -IncludeOwners -OutputPath C:\Temp\StaleTeams.csv -Verbose
    Uses the 180-day report, exports only teams idle for 120 days or more and lists their owners so you know whom to ask before archiving.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Reports.Read.All, Group.Read.All (delegated). The Reports Reader or Global Reader role is enough to read usage reports.
    Category    : Teams inventory & lifecycle
    Changes     : No
    Notes       : Usage report data lags about 48 hours behind real time, so a team that became active yesterday can still look idle.
                  If "Display concealed user, group, and site names in all reports" is enabled (Microsoft 365 admin center >
                  Settings > Org settings > Reports) the report shows hashed names; this script joins on Team Id and takes
                  TeamName from the group object, but turn the setting off if the ids also fail to match.
                  Teams without a row in the report are treated as never active in the period. Activity counters
                  (messages, meetings) are totals for the selected period.
.LINK
    https://learn.microsoft.com/graph/api/reportroot-getteamsteamactivitydetail
.LINK
    https://learn.microsoft.com/graph/teams-list-all-teams
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('D7', 'D30', 'D90', 'D180')]
    [string]$Period = 'D90',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [switch]$OnlyInactive,

    [Parameter()]
    [switch]$IncludeOwners,

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

function Get-GraphReportCsv {
    <# Downloads a usage report (Graph answers with a redirect to a CSV) into a temp file and imports it. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    $tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('GraphReport_{0}.csv' -f [guid]::NewGuid().ToString('N'))
    try {
        Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputFilePath $tempCsv -ErrorAction Stop
        return @(Import-Csv -Path $tempCsv -Encoding UTF8)
    }
    finally {
        if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue }
    }
}

function Get-ReportValue {
    <# Returns a report column value, or $null when the row or column is missing (report schemas change over time) or empty. #>
    param(
        [Parameter()]
        [object]$Row,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if ($null -eq $Row) { return $null }
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) { return $null }
    return $property.Value
}

function ConvertTo-ReportInt {
    <# Casts a report column to [int]; $null when the column is missing or empty. #>
    param(
        [Parameter()]
        [object]$Row,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    $value = Get-ReportValue -Row $Row -Name $Name
    if ($null -eq $value) { return $null }
    return [int]$value
}

function ConvertTo-UtcDateTime {
    <# Normalises a date value (ISO 8601 string, yyyy-MM-dd report date or [datetime]) to a UTC [datetime]; $null when empty. #>
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsInactiveTeams_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$periodDays = [int]$Period.TrimStart('D')
if ($DaysInactive -gt $periodDays) {
    Write-Warning "DaysInactive ($DaysInactive) is longer than the report period ($Period); consider -Period D180 so the last activity date covers the whole window."
}

try {
    Connect-GraphIfNeeded -Scopes @('Reports.Read.All', 'Group.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

Write-Verbose "Downloading the Teams team activity report for period $Period."
try {
    $reportRows = @(Get-GraphReportCsv -Uri "https://graph.microsoft.com/v1.0/reports/getTeamsTeamActivityDetail(period='$Period')")
}
catch {
    throw "Failed to download the Teams team activity report: $($_.Exception.Message)"
}
$refreshDate = Get-ReportValue -Row ($reportRows | Select-Object -First 1) -Name 'Report Refresh Date'
Write-Verbose "Report contains $($reportRows.Count) rows (refresh date: $refreshDate)."

$activityByTeamId = @{}
foreach ($row in $reportRows) {
    $teamId = Get-ReportValue -Row $row -Name 'Team Id'
    if ($null -ne $teamId) { $activityByTeamId[$teamId] = $row }
}

Write-Verbose 'Listing all teams from /groups.'
try {
    $groupsUri = 'https://graph.microsoft.com/v1.0/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select=id,displayName,visibility,createdDateTime,mail,description&$top=999'
    $teams = @(Invoke-GraphPaged -Uri $groupsUri)
}
catch {
    throw "Failed to list teams: $($_.Exception.Message)"
}
if ($reportRows.Count -gt 0 -and $teams.Count -gt 0) {
    $matchedTeams = @($teams | Where-Object { $activityByTeamId.ContainsKey($_.id) }).Count
    if ($matchedTeams -eq 0) { Write-Warning 'No report row matched any team id; every team will look inactive. See the concealed names note in .NOTES.' }
}

$today = [datetime]::UtcNow.Date
$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Evaluating teams' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))

    $row = $activityByTeamId[$team.id]
    $lastActivity = ConvertTo-UtcDateTime -Value (Get-ReportValue -Row $row -Name 'Last Activity Date')
    $daysSinceLastActivity = $null
    if ($null -ne $lastActivity) { $daysSinceLastActivity = [int](($today - $lastActivity.Date).TotalDays) }
    $created = ConvertTo-UtcDateTime -Value $team.createdDateTime
    $ageDays = $null
    if ($null -ne $created) { $ageDays = [int](($today - $created.Date).TotalDays) }

    $ownerCount = $null
    $owners = $null
    $isOwnerless = $null
    if ($IncludeOwners) {
        try {
            $ownerList = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/groups/{0}/owners?$select=displayName,userPrincipalName' -f $team.id))
            $ownerCount = $ownerList.Count
            $isOwnerless = ($ownerCount -eq 0)
            # Prefer the UPN; service principals and some directory objects only expose a display name.
            $owners = @($ownerList | ForEach-Object { if ([string]::IsNullOrWhiteSpace($_.userPrincipalName)) { $_.displayName } else { $_.userPrincipalName } }) -join ';'
        }
        catch {
            Write-Warning "Could not read the owners of team '$($team.displayName)': $($_.Exception.Message)"
        }
        Start-Sleep -Milliseconds 200
    }

    $results.Add([PSCustomObject]@{
            TeamName              = $team.displayName
            TeamId                = $team.id
            Visibility            = $team.visibility
            Mail                  = $team.mail
            CreatedDateTime       = $created
            AgeDays               = $ageDays
            LastActivityDate      = $lastActivity
            DaysSinceLastActivity = $daysSinceLastActivity
            ActiveUsers           = ConvertTo-ReportInt -Row $row -Name 'Active Users'
            ChannelMessages       = ConvertTo-ReportInt -Row $row -Name 'Channel Messages'
            PostMessages          = ConvertTo-ReportInt -Row $row -Name 'Post Messages'
            ReplyMessages         = ConvertTo-ReportInt -Row $row -Name 'Reply Messages'
            MeetingsOrganized     = ConvertTo-ReportInt -Row $row -Name 'Meetings Organized'
            Guests                = ConvertTo-ReportInt -Row $row -Name 'Guests'
            IsInactive            = (($null -eq $lastActivity) -or ($daysSinceLastActivity -ge $DaysInactive))
            OwnerCount            = $ownerCount
            Owners                = $owners
            IsOwnerless           = $isOwnerless
            Description           = $team.description
        })
}
Write-Progress -Activity 'Evaluating teams' -Completed

$output = @($results)
if ($OnlyInactive) { $output = @($output | Where-Object { $_.IsInactive }) }
# Never-active teams first, then the longest idle.
$output = @($output | Sort-Object -Property @{ Expression = { if ($null -eq $_.DaysSinceLastActivity) { [int]::MaxValue } else { $_.DaysSinceLastActivity } }; Descending = $true }, TeamName)

if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No teams matched the selected filters; no CSV was written.'
}

$inactiveCount = @($results | Where-Object { $_.IsInactive }).Count
$ownerlessCount = @($results | Where-Object { $_.IsOwnerless -eq $true }).Count
Write-Host ''
Write-Host 'Teams activity summary' -ForegroundColor Cyan
Write-Host ('  Report period / refresh date : {0} / {1}' -f $Period, $refreshDate)
Write-Host ('  Total teams                  : {0}' -f $results.Count)
Write-Host ('  Inactive teams (>= {0} days)  : {1}' -f $DaysInactive, $inactiveCount) -ForegroundColor Yellow
if ($IncludeOwners) {
    Write-Host ('  Ownerless teams              : {0}' -f $ownerlessCount) -ForegroundColor Yellow
}
else {
    Write-Host '  Ownerless teams              : n/a (use -IncludeOwners)'
}
Write-Host ('  Rows exported                : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
