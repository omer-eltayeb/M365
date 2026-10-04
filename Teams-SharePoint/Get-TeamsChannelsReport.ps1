<#
.SYNOPSIS
    Lists every channel of every team (standard, private, shared) with type, age, email, archive state and optional file size.
.DESCRIPTION
    Lists teams through GET /groups and reads each team's channels from GET /teams/{id}/channels plus the General channel id
    from GET /teams/{id}/primaryChannel. Optionally adds the size and URL of the channel's SharePoint folder
    (GET /channels/{id}/filesFolder) and the date of the newest post (GET /channels/{id}/messages?$top=1). Exports one row
    per channel and prints totals per channel type plus teams that approach the private channel limit.
.PARAMETER TeamName
    One or more team display names to report on; wildcards are supported. Default: all teams.
.PARAMETER TeamId
    One or more team (Microsoft 365 group) ids to report on. Takes precedence over -TeamName.
.PARAMETER IncludeFilesFolder
    Add FilesFolderSizeMB and FilesFolderUrl (one extra Graph call per channel; requires Files.Read.All).
.PARAMETER IncludeLastMessage
    Add LastMessageDateTime and DaysSinceLastMessage (one extra Graph call per channel; requires ChannelMessage.Read.All).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\TeamsChannels_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsChannelsReport.ps1
    Exports every channel of every team with its type, creation date, email address and archive state.
.EXAMPLE
    PS> .\Get-TeamsChannelsReport.ps1 -TeamName 'Project*' -IncludeFilesFolder -IncludeLastMessage -OutputPath C:\Temp\Channels.csv
    Adds folder sizes and the newest post date for the channels of all Project teams.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, Team.ReadBasic.All, Channel.ReadBasic.All (delegated); Files.Read.All only with -IncludeFilesFolder,
                  ChannelMessage.Read.All only with -IncludeLastMessage. Teams Administrator or Global Reader role.
    Category    : Teams inventory & lifecycle
    Changes     : No
    Notes       : Only channels hosted by the team are listed (channels shared into the team from elsewhere are not). The files folder
                  is created the first time someone opens the Files tab, and private channel messages are only readable for members,
                  so those columns can stay empty; run with -Verbose to see why. Limits: 30 private and 200 shared channels per team.
.LINK
    https://learn.microsoft.com/graph/api/channel-list
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
    [switch]$IncludeFilesFolder,

    [Parameter()]
    [switch]$IncludeLastMessage,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsChannels_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('Group.Read.All', 'Team.ReadBasic.All', 'Channel.ReadBasic.All')
if ($IncludeFilesFolder) { $scopes += 'Files.Read.All' }
if ($IncludeLastMessage) { $scopes += 'ChannelMessage.Read.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
try { $teams = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select=id,displayName,visibility&$top=999' -f $graphV1)) }
catch { throw "Failed to list teams: $($_.Exception.Message)" }
if ($PSBoundParameters.ContainsKey('TeamId')) { $teams = @($teams | Where-Object { $TeamId -contains $_.id }) }
elseif ($PSBoundParameters.ContainsKey('TeamName')) {
    $teams = @($teams | Where-Object { $candidate = $_.displayName; @($TeamName | Where-Object { $candidate -like $_ }).Count -gt 0 })
}

# Without this header Graph reports shared channels as 'unknownFutureValue'.
$channelHeaders = @{ 'Prefer' = 'include-unknown-enum-members' }
$channelSelect = 'id,displayName,description,membershipType,createdDateTime,email,webUrl,isFavoriteByDefault,isArchived'
$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Reading channels' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    try {
        $channels = @(Invoke-GraphPaged -Uri ('{0}/teams/{1}/channels?$select={2}' -f $graphV1, $team.id, $channelSelect) -Headers $channelHeaders)
        $general = Invoke-MgGraphRequest -Method GET -Uri ('{0}/teams/{1}/primaryChannel?$select=id' -f $graphV1, $team.id) -OutputType PSObject -ErrorAction Stop
        Start-Sleep -Milliseconds 200
    }
    catch {
        Write-Warning "Could not read the channels of team '$($team.displayName)': $($_.Exception.Message)"
        continue
    }
    foreach ($channel in $channels) {
        $channelUri = '{0}/teams/{1}/channels/{2}' -f $graphV1, $team.id, [uri]::EscapeDataString($channel.id)
        $folderSizeMB = $null
        $folderUrl = $null
        if ($IncludeFilesFolder) {
            try {
                $folder = Invoke-MgGraphRequest -Method GET -Uri "$channelUri/filesFolder" -OutputType PSObject -ErrorAction Stop
                $folderSizeMB = [math]::Round(([double]$folder.size / 1MB), 2)
                $folderUrl = $folder.webUrl
            }
            catch { Write-Verbose "No files folder for channel '$($channel.displayName)' in '$($team.displayName)': $($_.Exception.Message)" }
        }
        $lastMessage = $null
        if ($IncludeLastMessage) {
            try {
                # Messages come back newest first (sorted by the last modified date of the reply chain); one page of one is enough.
                $messages = Invoke-MgGraphRequest -Method GET -Uri "$channelUri/messages?`$top=1" -OutputType PSObject -ErrorAction Stop
                if (@($messages.value).Count -gt 0) { $lastMessage = [datetime]$messages.value[0].lastModifiedDateTime }
            }
            catch { Write-Verbose "Cannot read messages of channel '$($channel.displayName)' in '$($team.displayName)': $($_.Exception.Message)" }
        }
        if ($IncludeFilesFolder -or $IncludeLastMessage) { Start-Sleep -Milliseconds 100 }
        $results.Add([PSCustomObject]@{
                TeamName             = $team.displayName
                TeamId               = $team.id
                TeamVisibility       = $team.visibility
                ChannelName          = $channel.displayName
                ChannelId            = $channel.id
                MembershipType       = $channel.membershipType
                IsGeneral            = ($channel.id -eq $general.id)
                IsArchived           = ($channel.isArchived -eq $true)
                IsFavoriteByDefault  = ($channel.isFavoriteByDefault -eq $true)
                CreatedDateTime      = $(if ([string]::IsNullOrWhiteSpace([string]$channel.createdDateTime)) { $null } else { [datetime]$channel.createdDateTime })
                Email                = $channel.email
                FilesFolderSizeMB    = $folderSizeMB
                FilesFolderUrl       = $folderUrl
                LastMessageDateTime  = $lastMessage
                DaysSinceLastMessage = $(if ($null -ne $lastMessage) { [int](((Get-Date) - $lastMessage).TotalDays) } else { $null })
                WebUrl               = $channel.webUrl
                Description          = $channel.description
            })
    }
}
Write-Progress -Activity 'Reading channels' -Completed

$output = @($results | Sort-Object -Property TeamName, MembershipType, ChannelName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No channels were found for the selected teams; no CSV was written.' }
$teamGroups = @($output | Group-Object -Property TeamId)
$nearPrivateLimit = @($teamGroups | Where-Object { @($_.Group | Where-Object { $_.MembershipType -eq 'private' }).Count -ge 25 }).Count
Write-Host ''
Write-Host 'Teams channels summary' -ForegroundColor Cyan
Write-Host ('  Teams / channels                    : {0} / {1}' -f $teamGroups.Count, $output.Count)
foreach ($typeGroup in @($output | Group-Object -Property MembershipType | Sort-Object -Property Name)) {
    Write-Host ('  {0,-36}: {1}' -f "Channels of type $($typeGroup.Name)", $typeGroup.Count)
}
Write-Host ('  Archived channels                   : {0}' -f @($output | Where-Object { $_.IsArchived }).Count)
Write-Host ('  Teams with 25+ private channels     : {0} (limit 30)' -f $nearPrivateLimit) -ForegroundColor Yellow
Write-Host ('  Teams with 200+ channels            : {0}' -f @($teamGroups | Where-Object { $_.Count -ge 200 }).Count) -ForegroundColor Yellow
Write-Host ('  Report                              : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
