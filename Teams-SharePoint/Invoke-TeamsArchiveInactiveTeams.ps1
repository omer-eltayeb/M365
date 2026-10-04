<#
.SYNOPSIS
    Reports teams with no activity for N days and, on request, notifies their owners and archives them.
.DESCRIPTION
    Downloads the usage report /reports/getTeamsTeamActivityDetail (D90, or D180 when -DaysInactive exceeds 90), joins it on
    Team Id with the team list from GET /groups and selects teams whose last activity is -DaysInactive days old or missing,
    skipping teams younger than -MinimumAgeDays and names matching -ExcludeTeamName. Candidates are checked with GET /teams/{id}
    (already archived, no owner). Read-only by default; -NotifyOwners emails the owners (POST /me/sendMail), -Archive archives.
.PARAMETER DaysInactive
    Days without activity after which a team is a candidate. Default 90.
.PARAMETER MinimumAgeDays
    Teams created less than this many days ago are never candidates (they simply have not been used yet). Default 30.
.PARAMETER ExcludeTeamName
    Team display names to leave alone; wildcards are supported (for example 'Board*', '*Archive').
.PARAMETER Archive
    Archive the candidate teams. Without this switch the script is read-only.
.PARAMETER SetSiteReadOnly
    When archiving, also make the team's SharePoint site read-only for members (shouldSetSpoSiteReadOnlyForMembers).
.PARAMETER NotifyOwners
    Email the owners of each candidate team from the signed-in mailbox (before archiving, or as an advance warning without -Archive).
.PARAMETER OutputPath
    Path of the CSV results file. Defaults to .\Reports\TeamsArchiveInactive_yyyyMMdd-HHmm.csv.
.EXAMPLE
    PS> .\Invoke-TeamsArchiveInactiveTeams.ps1 -DaysInactive 120
    Lists teams idle for 120 days or more, with owner counts, without changing anything.
.EXAMPLE
    PS> .\Invoke-TeamsArchiveInactiveTeams.ps1 -ExcludeTeamName 'Board*' -NotifyOwners -Archive -SetSiteReadOnly -Confirm:$false
    Emails the owners, then archives every team idle for 90+ days (except Board teams) and makes the sites read-only.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Reports.Read.All, Group.Read.All, Team.ReadBasic.All (delegated); TeamSettings.ReadWrite.All only with -Archive,
                  Mail.Send only with -NotifyOwners. Reports Reader or Global Reader role to read the report, Teams Administrator to archive.
    Category    : Teams inventory & lifecycle
    Changes     : Optional (-Archive)
    Notes       : Usage data lags about 48 hours. With "Display concealed user, group, and site names in all reports" enabled the report
                  shows hashed names, but the join uses Team Id and still works. Graph refuses to archive a team without an owner
                  (SkippedNoOwner); archiving is asynchronous (HTTP 202) and -Archive / -NotifyOwners honour -WhatIf and -Confirm.
.LINK
    https://learn.microsoft.com/graph/api/team-archive
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateRange(7, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [int]$MinimumAgeDays = 30,

    [Parameter()]
    [string[]]$ExcludeTeamName,

    [Parameter()]
    [switch]$Archive,

    [Parameter()]
    [switch]$SetSiteReadOnly,

    [Parameter()]
    [switch]$NotifyOwners,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsArchiveInactive_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('Reports.Read.All', 'Group.Read.All', 'Team.ReadBasic.All')
if ($Archive) { $scopes += 'TeamSettings.ReadWrite.All' }
if ($NotifyOwners) { $scopes += 'Mail.Send' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
$graphV1 = 'https://graph.microsoft.com/v1.0'
$period = 'D90'
if ($DaysInactive -gt 90) { $period = 'D180' }   # Last Activity Date is only filled for activity inside the report period.
$tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('TeamsActivity_{0}.csv' -f [guid]::NewGuid().ToString('N'))
try {
    Invoke-MgGraphRequest -Method GET -Uri "$graphV1/reports/getTeamsTeamActivityDetail(period='$period')" -OutputFilePath $tempCsv -ErrorAction Stop
    $reportRows = @(Import-Csv -Path $tempCsv -Encoding UTF8)
}
catch { throw "Failed to download the Teams team activity report: $($_.Exception.Message)" }
finally { if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue } }
$activityByTeamId = @{}
foreach ($reportRow in $reportRows) { if (-not [string]::IsNullOrWhiteSpace($reportRow.'Team Id')) { $activityByTeamId[$reportRow.'Team Id'] = $reportRow } }
try { $teams = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select=id,displayName,createdDateTime&$top=999' -f $graphV1)) }
catch { throw "Failed to list teams: $($_.Exception.Message)" }
$mailText = "Hello,`r`n`r`nYou own the Teams team '{0}', which has had {1}. Unused teams are archived (read-only) under the lifecycle policy. If it is still needed, use it or contact IT."
$archiveBody = @{ shouldSetSpoSiteReadOnlyForMembers = [bool]$SetSiteReadOnly } | ConvertTo-Json
$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Evaluating teams' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    if ($PSBoundParameters.ContainsKey('ExcludeTeamName') -and @($ExcludeTeamName | Where-Object { $team.displayName -like $_ }).Count -gt 0) { continue }
    $ageDays = [int](((Get-Date) - [datetime]$team.createdDateTime).TotalDays)
    if ($ageDays -lt $MinimumAgeDays) { continue }
    $activity = $activityByTeamId[$team.id]
    $lastActivity = $null
    if ($null -ne $activity -and -not [string]::IsNullOrWhiteSpace($activity.'Last Activity Date')) { $lastActivity = [datetime]$activity.'Last Activity Date' }
    $daysSince = $null
    if ($null -ne $lastActivity) { $daysSince = [int](((Get-Date).Date - $lastActivity.Date).TotalDays) }
    if ($null -ne $daysSince -and $daysSince -lt $DaysInactive) { continue }
    $idleText = "no activity in the last $($period.TrimStart('D')) days"
    if ($null -ne $daysSince) { $idleText = "no activity for $daysSince days" }
    $action = 'WouldArchive'
    $detail = $null
    try {
        $detail = Invoke-MgGraphRequest -Method GET -Uri ('{0}/teams/{1}?$select=id,isArchived,summary' -f $graphV1, $team.id) -OutputType PSObject -ErrorAction Stop
        if ($detail.isArchived -eq $true) { $action = 'AlreadyArchived' }
        elseif ($detail.summary.ownersCount -eq 0) { $action = 'SkippedNoOwner' }
    }
    catch { $action = 'Failed'; Write-Warning "Could not read team '$($team.displayName)': $($_.Exception.Message)" }
    $notified = 0
    if ($action -eq 'WouldArchive' -and $NotifyOwners) {
        try {
            $owners = @(Invoke-GraphPaged -Uri ('{0}/groups/{1}/owners?$select=mail' -f $graphV1, $team.id) | Where-Object { -not [string]::IsNullOrWhiteSpace($_.mail) })
            if ($owners.Count -gt 0 -and $PSCmdlet.ShouldProcess($team.displayName, "Email $($owners.Count) owner(s)")) {
                $recipients = @($owners | ForEach-Object { @{ emailAddress = @{ address = $_.mail } } })
                $body = @{ contentType = 'Text'; content = ($mailText -f $team.displayName, $idleText) }
                $mail = @{ message = @{ subject = "Inactive team: $($team.displayName)"; body = $body; toRecipients = $recipients }; saveToSentItems = $true }
                Invoke-MgGraphRequest -Method POST -Uri "$graphV1/me/sendMail" -Body ($mail | ConvertTo-Json -Depth 6) -ContentType 'application/json' -ErrorAction Stop | Out-Null
                $notified = $owners.Count
            }
        }
        catch { Write-Warning "Could not notify the owners of '$($team.displayName)': $($_.Exception.Message)" }
    }
    if ($action -eq 'WouldArchive' -and $Archive -and $PSCmdlet.ShouldProcess($team.displayName, "Archive team ($idleText)")) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri ('{0}/teams/{1}/archive' -f $graphV1, $team.id) -Body $archiveBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
            $action = 'ArchiveRequested'
        }
        catch { $action = 'Failed'; Write-Warning "Archiving '$($team.displayName)' failed: $($_.Exception.Message)" }
    }
    Start-Sleep -Milliseconds 200
    $results.Add([PSCustomObject]@{
            TeamName              = $team.displayName
            TeamId                = $team.id
            AgeDays               = $ageDays
            LastActivityDate      = $lastActivity
            DaysSinceLastActivity = $daysSince
            OwnersCount           = $detail.summary.ownersCount
            Action                = $action
            OwnersNotified        = $notified
        })
}
Write-Progress -Activity 'Evaluating teams' -Completed
$output = @($results | Sort-Object -Property @{ Expression = { if ($null -eq $_.DaysSinceLastActivity) { [int]::MaxValue } else { $_.DaysSinceLastActivity } }; Descending = $true }, TeamName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No inactive teams matched the criteria; no CSV was written.' }
Write-Host 'Inactive teams summary' -ForegroundColor Cyan
Write-Host ('  Teams evaluated / idle >= {0} days : {1} / {2}' -f $DaysInactive, $teams.Count, $output.Count)
foreach ($actionGroup in @($output | Group-Object -Property Action | Sort-Object -Property Name)) { Write-Host ('  {0,-35}: {1}' -f $actionGroup.Name, $actionGroup.Count) -ForegroundColor Yellow }
Write-Host ('  Results                            : {0}' -f $OutputPath)
#endregion Main
