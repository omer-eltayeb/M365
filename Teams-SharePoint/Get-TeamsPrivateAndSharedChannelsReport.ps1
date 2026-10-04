<#
.SYNOPSIS
    Reports private and shared channels with their owner, member, guest and external member counts and sharing targets.
.DESCRIPTION
    Lists teams through GET /groups, reads the channels of each team from GET /teams/{id}/channels and keeps the private
    and shared ones. For each of those it reads the direct members from GET /teams/{id}/channels/{cid}/members (roles and
    home tenant) and, optionally, the teams the channel is shared with (/sharedWithTeams) and the channel's SharePoint
    folder URL (/filesFolder). Flags ownerless channels and channels with members from other tenants.
.PARAMETER TeamName
    One or more team display names to report on; wildcards are supported. Default: all teams.
.PARAMETER TeamId
    One or more team (Microsoft 365 group) ids to report on. Takes precedence over -TeamName.
.PARAMETER IncludeMemberList
    Add a Members column listing every direct member as "email (owner|member|guest)".
.PARAMETER IncludeSharedWith
    For shared channels, add the teams the channel is shared with; teams from other tenants are marked [external].
.PARAMETER IncludeSiteUrl
    Add the URL of the channel's own SharePoint files folder (one extra Graph call per channel; requires Files.Read.All).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\TeamsPrivateSharedChannels_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsPrivateAndSharedChannelsReport.ps1
    Exports every private and shared channel with member counts and flags for ownerless channels and external members.
.EXAMPLE
    PS> .\Get-TeamsPrivateAndSharedChannelsReport.ps1 -TeamName 'Partner*' -IncludeMemberList -IncludeSharedWith -IncludeSiteUrl -Verbose
    Full detail for the Partner teams: member list, sharing targets and SharePoint folder URLs.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, Team.ReadBasic.All, Channel.ReadBasic.All, ChannelMember.Read.All (delegated); Files.Read.All only
                  with -IncludeSiteUrl. Teams Administrator or Global Reader role to read channels of teams you are not a member of.
    Category    : Teams inventory & lifecycle
    Changes     : No
    Notes       : Only channels hosted by the selected teams are listed. Members are direct channel members; people who reach a shared
                  channel through another team are not counted (see -IncludeSharedWith). External = member from another tenant.
.LINK
    https://learn.microsoft.com/graph/api/channel-list-members
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
    [switch]$IncludeMemberList,

    [Parameter()]
    [switch]$IncludeSharedWith,

    [Parameter()]
    [switch]$IncludeSiteUrl,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsPrivateSharedChannels_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('Group.Read.All', 'Team.ReadBasic.All', 'Channel.ReadBasic.All', 'ChannelMember.Read.All')
if ($IncludeSiteUrl) { $scopes += 'Files.Read.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
$graphV1 = 'https://graph.microsoft.com/v1.0'
$homeTenantId = (Get-MgContext).TenantId
try { $teams = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter=resourceProvisioningOptions/Any(x:x eq ''Team'')&$select=id,displayName&$top=999' -f $graphV1)) }
catch { throw "Failed to list teams: $($_.Exception.Message)" }
if ($PSBoundParameters.ContainsKey('TeamId')) { $teams = @($teams | Where-Object { $TeamId -contains $_.id }) }
elseif ($PSBoundParameters.ContainsKey('TeamName')) {
    $teams = @($teams | Where-Object { $candidate = $_.displayName; @($TeamName | Where-Object { $candidate -like $_ }).Count -gt 0 })
}
# Without this header Graph reports shared channels as 'unknownFutureValue'.
$channelHeaders = @{ 'Prefer' = 'include-unknown-enum-members' }
$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($team in $teams) {
    $counter++
    Write-Progress -Activity 'Reading private and shared channels' -Status "$counter of $($teams.Count): $($team.displayName)" -PercentComplete ([int](($counter / $teams.Count) * 100))
    try {
        $channels = @(Invoke-GraphPaged -Uri ('{0}/teams/{1}/channels?$select=id,displayName,membershipType,createdDateTime' -f $graphV1, $team.id) -Headers $channelHeaders)
        Start-Sleep -Milliseconds 200
    }
    catch {
        Write-Warning "Could not read the channels of team '$($team.displayName)': $($_.Exception.Message)"
        continue
    }
    foreach ($channel in @($channels | Where-Object { $_.membershipType -in @('private', 'shared') })) {
        $channelUri = '{0}/teams/{1}/channels/{2}' -f $graphV1, $team.id, [uri]::EscapeDataString($channel.id)
        try { $members = @(Invoke-GraphPaged -Uri "$channelUri/members") }
        catch { Write-Warning "Could not read the members of channel '$($channel.displayName)' in '$($team.displayName)': $($_.Exception.Message)"; continue }
        $owners = @($members | Where-Object { @($_.roles) -contains 'owner' })
        $guests = @($members | Where-Object { @($_.roles) -contains 'guest' })
        $external = @($members | Where-Object { -not [string]::IsNullOrWhiteSpace($_.tenantId) -and $_.tenantId -ne $homeTenantId })
        $sharedWith = $null
        if ($IncludeSharedWith -and $channel.membershipType -eq 'shared') {
            try {
                $sharedTeams = @(Invoke-GraphPaged -Uri "$channelUri/sharedWithTeams" | Where-Object { $_.isHostTeam -ne $true })
                $sharedWith = @($sharedTeams | ForEach-Object { if ($_.tenantId -ne $homeTenantId) { "$($_.displayName) [external]" } else { $_.displayName } }) -join ';'
            }
            catch { Write-Verbose "Could not read sharedWithTeams of '$($channel.displayName)': $($_.Exception.Message)" }
        }
        $siteUrl = $null
        if ($IncludeSiteUrl) {
            try { $siteUrl = (Invoke-MgGraphRequest -Method GET -Uri "$channelUri/filesFolder" -OutputType PSObject -ErrorAction Stop).webUrl }
            catch { Write-Verbose "No files folder for channel '$($channel.displayName)': $($_.Exception.Message)" }
        }
        $memberList = $null
        if ($IncludeMemberList) {
            # roles is empty for plain members and contains 'owner' and/or 'guest' otherwise.
            $memberList = @($members | ForEach-Object {
                    $label = $(if ([string]::IsNullOrWhiteSpace($_.email)) { $_.displayName } else { $_.email })
                    '{0} ({1})' -f $label, $(if (@($_.roles).Count -gt 0) { @($_.roles) -join '/' } else { 'member' })
                }) -join ';'
        }
        Start-Sleep -Milliseconds 100
        $results.Add([PSCustomObject]@{
                TeamName             = $team.displayName
                TeamId               = $team.id
                ChannelName          = $channel.displayName
                ChannelId            = $channel.id
                MembershipType       = $channel.membershipType
                CreatedDateTime      = $(if ([string]::IsNullOrWhiteSpace([string]$channel.createdDateTime)) { $null } else { [datetime]$channel.createdDateTime })
                OwnersCount          = $owners.Count
                MembersCount         = $members.Count
                GuestsCount          = $guests.Count
                ExternalMembersCount = $external.Count
                ExternalTenants      = (@($external | ForEach-Object { $_.tenantId } | Sort-Object -Unique) -join ';')
                IsOwnerless          = ($owners.Count -eq 0)
                HasExternalMembers   = ($external.Count -gt 0)
                SharedWithTeams      = $sharedWith
                Members              = $memberList
                FilesFolderUrl       = $siteUrl
            })
    }
}
Write-Progress -Activity 'Reading private and shared channels' -Completed
$output = @($results | Sort-Object -Property TeamName, MembershipType, ChannelName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No private or shared channels were found for the selected teams; no CSV was written.' }
Write-Host 'Private and shared channels summary' -ForegroundColor Cyan
Write-Host ('  Teams evaluated                : {0}' -f $teams.Count)
Write-Host ('  Private / shared channels      : {0} / {1}' -f @($output | Where-Object { $_.MembershipType -eq 'private' }).Count, @($output | Where-Object { $_.MembershipType -eq 'shared' }).Count)
Write-Host ('  Ownerless channels             : {0}' -f @($output | Where-Object { $_.IsOwnerless }).Count) -ForegroundColor Yellow
Write-Host ('  Channels with external members : {0}' -f @($output | Where-Object { $_.HasExternalMembers }).Count) -ForegroundColor Yellow
Write-Host ('  Report                         : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
