<#
.SYNOPSIS
    Reports Microsoft Teams lifecycle, membership, channel, app and settings events from the unified audit log.
.DESCRIPTION
    Searches RecordType MicrosoftTeams one day at a time with Search-UnifiedAuditLog (ReturnLargeSet paging), parses
    AuditData and flattens team, channel, member (UPN and role), add-on and setting-change details into one row per event.
    Rows are flagged for guest/external members added, team deletions and app, bot or connector installs. Exports a CSV
    and prints counts by operation, team and actor.
.PARAMETER DaysBack
    Number of days to search back from now (default 7, maximum 180). Ignored when -StartDate is used.
.PARAMETER StartDate
    Start of the search window (UTC). Use with -EndDate instead of -DaysBack.
.PARAMETER EndDate
    End of the search window (UTC). Defaults to now.
.PARAMETER UserIds
    One or more actor user principal names to filter on.
.PARAMETER Operations
    Teams operations to include. Defaults to team, member, channel, setting, app, tab, connector and bot events.
.PARAMETER IncludeMessageEvents
    Also include MessageSent and MessagesListed, which require Audit (Premium) and are very high volume.
.PARAMETER TeamName
    Wildcard filter on the team name, for example Finance*.
.PARAMETER InternalDomains
    Your accepted domains. Added members whose UPN domain is not in the list are flagged as external (guests always are).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewAuditTeamsActivity_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the flattened records to the pipeline.
.EXAMPLE
    PS> .\Search-PurviewAuditTeamsActivity.ps1 -InternalDomains contoso.com
    Exports the last 7 days of Teams admin and membership events and flags guest additions, deletions and app installs.
.EXAMPLE
    PS> .\Search-PurviewAuditTeamsActivity.ps1 -DaysBack 30 -TeamName 'Project*' -Operations MemberAdded, MemberRemoved, MemberRoleChanged -PassThru | Format-Table
    Shows the membership history of the project teams for the last month.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); unified audit log ingestion must be enabled
    Category    : Audit log scenarios
    Changes     : No
    Notes       : Uses an Exchange Online session because Search-UnifiedAuditLog is an Exchange Online cmdlet. The window is sliced
                  into one-day searches because a ReturnLargeSet session returns at most 50,000 records. Member roles (1 Member, 2 Owner,
                  3 Guest) and add-on types (1 Bot, 2 Connector, 3 Tab) are numeric in AuditData and translated; unknown codes stay
                  numeric. Times are UTC. Beyond 90 days a warning is shown because Audit (Standard) keeps 180 days.
.LINK
    https://learn.microsoft.com/microsoftteams/audit-log-events
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'DaysBack')]
param(
    [Parameter(ParameterSetName = 'DaysBack')]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 7,

    [Parameter(Mandatory = $true, ParameterSetName = 'Dates')]
    [datetime]$StartDate,

    [Parameter(ParameterSetName = 'Dates')]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [string[]]$UserIds,

    [Parameter()]
    [string[]]$Operations = @('TeamCreated', 'TeamDeleted', 'MemberAdded', 'MemberRemoved', 'MemberRoleChanged', 'ChannelAdded', 'ChannelDeleted',
        'TeamSettingChanged', 'AppInstalled', 'AppUninstalled', 'TabAdded', 'TabRemoved', 'ConnectorAdded', 'ConnectorRemoved', 'BotAddedToTeam'),

    [Parameter()]
    [switch]$IncludeMessageEvents,

    [Parameter()]
    [string]$TeamName,

    [Parameter()]
    [string[]]$InternalDomains,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-ExchangeIfNeeded {
    <# Connects to Exchange Online (or Security & Compliance PowerShell) only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Compliance
    )
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($Compliance) {
        $active = @($connections | Where-Object { $_.ConnectionUri -like '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Security & Compliance PowerShell.'
            Connect-IPPSSession -ErrorAction Stop
        }
    }
    else {
        $active = @($connections | Where-Object { $_.ConnectionUri -notlike '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
    }
}

function Search-AuditRecords {
    <# Pages through Search-UnifiedAuditLog with ReturnLargeSet and returns de-duplicated records. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter()]
        [string[]]$RecordType,

        [Parameter()]
        [string[]]$Operations,

        [Parameter()]
        [string[]]$UserIds,

        [Parameter()]
        [string]$FreeText
    )
    $sessionId = [guid]::NewGuid().ToString()
    $records = New-Object -TypeName System.Collections.Generic.List[object]
    $seen = @{}
    do {
        $searchParams = @{ StartDate = $StartDate; EndDate = $EndDate; SessionId = $sessionId; SessionCommand = 'ReturnLargeSet'; ResultSize = 5000; ErrorAction = 'Stop' }
        if ($RecordType) { $searchParams['RecordType'] = $RecordType }
        if ($Operations) { $searchParams['Operations'] = $Operations }
        if ($UserIds) { $searchParams['UserIds'] = $UserIds }
        if ($FreeText) { $searchParams['FreeText'] = $FreeText }
        $page = @(Search-UnifiedAuditLog @searchParams)
        foreach ($record in $page) {
            if (-not $seen.ContainsKey($record.Identity)) {
                $seen[$record.Identity] = $true
                $records.Add($record)
            }
        }
    } while ($page.Count -gt 0)
    return $records
}
#endregion Helpers

#region Main
if ($PSCmdlet.ParameterSetName -eq 'DaysBack') { $StartDate = (Get-Date).AddDays(-$DaysBack) }
if ($EndDate -le $StartDate) { throw 'EndDate must be later than StartDate.' }
if (($EndDate - $StartDate).TotalDays -gt 90) { Write-Warning 'Window longer than 90 days: records beyond Audit (Standard) retention need Audit (Premium) retention policies.' }
if ($IncludeMessageEvents) { $Operations += 'MessageSent', 'MessagesListed' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewAuditTeamsActivity_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }
# One search session per day keeps every slice under the 50,000-record ReturnLargeSet ceiling.
$records = New-Object -TypeName System.Collections.Generic.List[object]
$totalDays = [int][math]::Ceiling(($EndDate - $StartDate).TotalDays)
for ($day = 0; $day -lt $totalDays; $day++) {
    $sliceStart = $StartDate.AddDays($day)
    $sliceEnd = $StartDate.AddDays($day + 1)
    if ($sliceEnd -gt $EndDate) { $sliceEnd = $EndDate }
    Write-Progress -Activity 'Audit log search' -Status ('Day {0}/{1} ({2:yyyy-MM-dd}): {3} records' -f ($day + 1), $totalDays, $sliceStart, $records.Count) -PercentComplete (100 * $day / $totalDays)
    try { $records.AddRange(@(Search-AuditRecords -StartDate $sliceStart -EndDate $sliceEnd -RecordType 'MicrosoftTeams' -Operations $Operations -UserIds $UserIds)) }
    catch { Write-Warning ('Search for {0:yyyy-MM-dd} failed: {1}' -f $sliceStart, $_.Exception.Message) }
}
Write-Progress -Activity 'Audit log search' -Completed
$memberRoles = @{ '1' = 'Member'; '2' = 'Owner'; '3' = 'Guest' }
$addOnTypes = @{ '1' = 'Bot'; '2' = 'Connector'; '3' = 'Tab' }
$flagByOperation = @{ TeamDeleted = 'TeamDeleted'; AppInstalled = 'AppInstalled'; BotAddedToTeam = 'AppInstalled'; ConnectorAdded = 'AppInstalled' }
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "Could not parse AuditData for record $($record.Identity); skipped."; continue }
    if ($TeamName -and [string]$audit.TeamName -notlike $TeamName) { continue }
    $operation = [string]$audit.Operation
    $members = @($audit.Members | Where-Object { $null -ne $_ })
    $externalMembers = @($members | Where-Object { [string]$_.Role -eq '3' -or $_.UPN -like '*#EXT#*' -or ($InternalDomains -and $InternalDomains -notcontains ([string]$_.UPN).Split('@')[-1]) })
    $externalAdded = ($operation -eq 'MemberAdded' -and $externalMembers.Count -gt 0)
    $row = [ordered]@{ CreationTime = [datetime]$record.CreationDate; Operation = $operation; UserId = [string]$audit.UserId }
    foreach ($field in 'TeamName', 'TeamGuid', 'ChannelName', 'ChannelType', 'ClientIP', 'ItemName', 'AddOnName') { $row[$field] = [string]$audit.$field }
    $row['Members'] = @($members | ForEach-Object { '{0} ({1})' -f $_.UPN, $(if ($memberRoles.ContainsKey([string]$_.Role)) { $memberRoles[[string]$_.Role] } else { $_.Role }) }) -join '; '
    $row['AddOnType'] = $(if ($addOnTypes.ContainsKey([string]$audit.AddOnType)) { $addOnTypes[[string]$audit.AddOnType] } else { [string]$audit.AddOnType })
    $row['Settings'] = $(if ($audit.Name) { '{0}={1} (was {2})' -f $audit.Name, $audit.NewValue, $audit.OldValue } else { '' })  # TeamSettingChanged only
    $row['Flag'] = $(if ($externalAdded) { 'GuestAdded' } else { [string]$flagByOperation[$operation] })
    $results.Add([PSCustomObject]$row)
}
$results = @($results | Sort-Object -Property CreationTime)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
Write-Host 'Teams activity summary' -ForegroundColor Cyan
Write-Host ('  Window : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} UTC, {2} event(s) in {3} day slice(s)' -f $StartDate, $EndDate, $results.Count, $totalDays)
$flagCounts = foreach ($name in 'GuestAdded', 'TeamDeleted', 'AppInstalled') { '{0} {1}' -f $name, @($results | Where-Object { $_.Flag -eq $name }).Count }
Write-Host ('  Flags  : {0}' -f ($flagCounts -join '   ')) -ForegroundColor Yellow
foreach ($section in @(@('By operation', 'Operation', 20), @('By team', 'TeamName', 10), @('By actor', 'UserId', 10))) {
    Write-Host ('  {0}:' -f $section[0])
    $groups = $results | Group-Object -Property $section[1] | Sort-Object -Property Count -Descending | Select-Object -First $section[2]
    foreach ($group in $groups) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
}
Write-Host ('  Report : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
