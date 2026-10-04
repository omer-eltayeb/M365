<#
.SYNOPSIS
    Reviews the tenant-wide Teams external access, guest access and anonymous meeting settings against recommended values.
.DESCRIPTION
    Reads Get-CsTenantFederationConfiguration (federation mode, allowed and blocked domains, Teams consumer access, trial
    tenants), Get-CsTeamsClientConfiguration (guest access, e-mail into channels, third-party cloud storage, resource account
    messaging, scoped people search), the three guest configurations (meeting, messaging, calling) and the Global meeting
    policy (anonymous join and start, lobby, PSTN lobby bypass, external control, presenter role). Every setting becomes a
    row with its value, the recommended value where one exists, a Status (OK, Review or Info) and short guidance. The console
    summary raises risk flags such as open federation, anonymous users who can start meetings or guests combined with
    third-party storage.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsExternalAccess_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the setting rows to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsExternalAccessConfiguration.ps1
    Exports all external access related settings and prints the risk flags found in the tenant.
.EXAMPLE
    PS> .\Get-TeamsExternalAccessConfiguration.ps1 -PassThru | Where-Object { $_.Status -eq 'Review' } | Format-Table Area, Setting, Value, Recommended
    Shows only the settings that differ from the recommended value.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, MicrosoftTeams
    Permissions : Teams Administrator or Global Reader (read-only).
    Category    : Teams administration (MicrosoftTeams module)
    Changes     : No
    Notes       : Recommendations follow the Microsoft security baseline for Teams and are a starting point, not a mandate;
                  an allow list is only enforced when AllowFederatedUsers is True. Per-user external access policies
                  (Get-CsExternalAccessPolicy) and custom meeting policies can override the Global values shown here.
                  AllowPublicUsers (Skype consumer interop) was retired in May 2025 and is reported only when still present.
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-cstenantfederationconfiguration
.LINK
    https://learn.microsoft.com/microsoftteams/trusted-organizations-external-meetings-chat
#>
#Requires -Version 5.1
#Requires -Modules MicrosoftTeams

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-TeamsIfNeeded {
    <# Connects to Microsoft Teams PowerShell only when there is no live session. #>
    [CmdletBinding()]
    param()
    $connected = $false
    try { $null = Get-CsTenant -ErrorAction Stop; $connected = $true } catch { $connected = $false }
    if (-not $connected) {
        Write-Verbose 'Connecting to Microsoft Teams PowerShell.'
        Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
    }
}

function Add-SettingRow {
    <# Adds one setting to the report; Status is Review when the value differs from the recommendation, OK when it matches, Info without one. #>
    param(
        [Parameter(Mandatory = $true)][string]$Area,
        [Parameter(Mandatory = $true)][string]$Setting,
        [Parameter()][object]$Value,
        [Parameter()][string]$Recommended,
        [Parameter()][string]$Guidance
    )
    $status = 'Info'
    if (-not [string]::IsNullOrEmpty($Recommended)) {
        $status = 'OK'
        if ([string]$Value -ne $Recommended) { $status = 'Review' }
    }
    $script:rows.Add([PSCustomObject]@{ Area = $Area; Setting = $Setting; Value = [string]$Value
            Recommended = $Recommended; Status = $status; Guidance = $Guidance })
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsExternalAccess_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-TeamsIfNeeded } catch { throw "Failed to connect to Microsoft Teams PowerShell: $($_.Exception.Message)" }

try {
    $federation = Get-CsTenantFederationConfiguration -ErrorAction Stop
    $client = Get-CsTeamsClientConfiguration -ErrorAction Stop
    $guestMeeting = Get-CsTeamsGuestMeetingConfiguration -ErrorAction Stop
    $guestMessaging = Get-CsTeamsGuestMessagingConfiguration -ErrorAction Stop
    $guestCalling = Get-CsTeamsGuestCallingConfiguration -ErrorAction Stop
    $meetingPolicy = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop
}
catch {
    throw "Failed to read the Teams tenant configuration: $($_.Exception.Message)"
}

# AllowedDomains is either an AllowAllKnownDomains marker object or an AllowList whose AllowedDomain entries carry the domain names.
$allowedDomains = @()
$allowedMode = 'AllowAllKnownDomains'
if ($null -ne $federation.AllowedDomains -and $null -ne $federation.AllowedDomains.PSObject.Properties['AllowedDomain']) {
    $allowedDomains = @($federation.AllowedDomains.AllowedDomain | ForEach-Object { [string]$_.Domain })
    $allowedMode = 'AllowList'
}
$blockedDomains = @($federation.BlockedDomains | ForEach-Object { [string]$_.Domain })
$storageApps = @('AllowDropBox', 'AllowBox', 'AllowGoogleDrive', 'AllowShareFile', 'AllowEgnyte')
$storageEnabled = @($storageApps | Where-Object { $client.$_ -eq $true })

# Recommended values follow the Microsoft Teams security baseline; settings without an entry are reported as Info.
$recommended = @{
    AllowedDomainsMode = 'AllowList'; AllowTeamsConsumer = 'False'; AllowTeamsConsumerInbound = 'False'; ExternalAccessWithTrialTenants = 'Blocked'
    AllowDropBox = 'False'; AllowBox = 'False'; AllowGoogleDrive = 'False'; AllowShareFile = 'False'; AllowEgnyte = 'False'
    AllowAnonymousUsersToStartMeeting = 'False'; AutoAdmittedUsers = 'EveryoneInCompanyExcludingGuests'; AllowPSTNUsersToBypassLobby = 'False'
    AllowExternalParticipantGiveRequestControl = 'False'; DesignatedPresenterRoleMode = 'EveryoneInCompanyUserOverride'
}
$guidance = @{
    AllowFederatedUsers                         = 'Master switch for chat, calls and meetings with other organisations.'
    AllowedDomainsMode                          = 'AllowAllKnownDomains lets any organisation reach your users; prefer an allow list or a maintained block list.'
    AllowedDomains                              = 'Domains on the allow list (only enforced when AllowFederatedUsers is True).'
    BlockedDomains                              = 'Blocked domains; only enforced in AllowAllKnownDomains mode.'
    BlockAllSubdomains                          = 'Also blocks subdomains of the blocked domains.'
    AllowTeamsConsumer                          = 'Chat and calls with personal (consumer) Teams accounts.'
    AllowTeamsConsumerInbound                   = 'Consumer accounts may discover and start chats with your users.'
    RestrictTeamsConsumerToExternalUserProfiles = 'Limits consumer collaboration to the extended directory.'
    ExternalAccessWithTrialTenants              = 'Trial-only tenants are a common phishing source; safelist partners with AllowedTrialTenantDomains.'
    AllowedTrialTenantDomains                   = 'Trial-only tenant domains that stay reachable while trial tenants are blocked.'
    TreatDiscoveredPartnersAsUnverified         = 'Legacy Skype for Business setting.'
    SharedSipAddressSpace                       = 'True only during a Skype for Business hybrid coexistence.'
    AllowPublicUsers                            = 'Skype consumer interop; retired in May 2025.'
    AllowGuestUser                              = 'Org-wide guest access switch (Entra B2B guests in teams and channels).'
    AllowPrivateCalling                         = 'Guests may make private one-to-one calls.'
    AllowEmailIntoChannel                       = 'Channel e-mail addresses accept mail from the RestrictedSenderList domains (all when empty).'
    RestrictedSenderList                        = 'Domains allowed to e-mail channels.'
    AllowDropBox                                = 'Third-party storage in the Files tab bypasses SharePoint governance and DLP.'
    AllowOrganizationTab                        = 'Organisation chart tab in chats.'
    AllowResourceAccountSendMessage             = 'Skype for Business Server resource accounts can send messages.'
    ResourceAccountContentAccess                = 'Content access level of resource accounts.'
    AllowScopedPeopleSearchandAccess            = 'Information barriers scoped people search.'
    ContentPin                                  = 'PIN requirement for content access on Teams devices.'
    AllowAnonymousUsersToJoinMeeting            = 'Unauthenticated participants can join; usually needed for external meetings.'
    AllowAnonymousUsersToStartMeeting           = 'Anonymous users could start a meeting before the organiser and bypass the lobby.'
    AutoAdmittedUsers                           = 'Who bypasses the lobby; Everyone admits anonymous and external users automatically.'
    AllowPSTNUsersToBypassLobby                 = 'Dial-in callers are unauthenticated and should wait in the lobby.'
    AllowExternalParticipantGiveRequestControl  = 'External participants could take control of shared screens.'
    DesignatedPresenterRoleMode                 = 'Default presenter role; EveryoneUserOverride makes every attendee a presenter.'
    ExternalMeetingJoin                         = 'Which external meetings your users may join.'
}
foreach ($storageApp in $storageApps) { $guidance[$storageApp] = $guidance['AllowDropBox'] }
$sections = @(
    @{ Area = 'Federation'; Source = $federation; Settings = @('AllowFederatedUsers', 'BlockAllSubdomains', 'AllowTeamsConsumer', 'AllowTeamsConsumerInbound',
            'RestrictTeamsConsumerToExternalUserProfiles', 'ExternalAccessWithTrialTenants', 'TreatDiscoveredPartnersAsUnverified', 'SharedSipAddressSpace', 'AllowPublicUsers') }
    @{ Area = 'Guest access'; Source = $client; Settings = @('AllowGuestUser') }
    @{ Area = 'Guest access'; Source = $guestCalling; Settings = @('AllowPrivateCalling') }
    @{ Area = 'Guest meetings'; Source = $guestMeeting; Settings = @('AllowIPVideo', 'ScreenSharingMode', 'AllowMeetNow', 'LiveCaptionsEnabledType', 'AllowTranscription') }
    @{ Area = 'Guest messaging'; Source = $guestMessaging; Settings = @('AllowUserChat', 'AllowUserEditMessage', 'AllowUserDeleteMessage', 'AllowUserDeleteChat', 'AllowGiphy',
            'GiphyRatingType', 'AllowMemes', 'AllowStickers', 'AllowImmersiveReader') }
    @{ Area = 'Client'; Source = $client; Settings = @('AllowEmailIntoChannel', 'RestrictedSenderList') + $storageApps + @('AllowOrganizationTab',
            'AllowResourceAccountSendMessage', 'ResourceAccountContentAccess', 'AllowScopedPeopleSearchandAccess', 'ContentPin') }
    @{ Area = 'Global meeting policy'; Source = $meetingPolicy; Settings = @('AllowAnonymousUsersToJoinMeeting', 'AllowAnonymousUsersToStartMeeting', 'AutoAdmittedUsers',
            'AllowPSTNUsersToBypassLobby', 'AllowExternalParticipantGiveRequestControl', 'DesignatedPresenterRoleMode', 'ExternalMeetingJoin') }
)

$script:rows = New-Object -TypeName System.Collections.Generic.List[object]
Add-SettingRow -Area 'Federation' -Setting 'AllowedDomainsMode' -Value $allowedMode -Recommended $recommended['AllowedDomainsMode'] -Guidance $guidance['AllowedDomainsMode']
Add-SettingRow -Area 'Federation' -Setting 'AllowedDomains' -Value ($allowedDomains -join ';') -Guidance $guidance['AllowedDomains']
Add-SettingRow -Area 'Federation' -Setting 'BlockedDomains' -Value ($blockedDomains -join ';') -Guidance $guidance['BlockedDomains']
Add-SettingRow -Area 'Federation' -Setting 'AllowedTrialTenantDomains' -Value (@($federation.AllowedTrialTenantDomains) -join ';') -Guidance $guidance['AllowedTrialTenantDomains']
foreach ($section in $sections) {
    foreach ($setting in $section.Settings) {
        # Settings that the installed module version (or the service) no longer returns are skipped, e.g. the retired AllowPublicUsers.
        if ($null -eq $section.Source.PSObject.Properties[$setting]) { continue }
        Add-SettingRow -Area $section.Area -Setting $setting -Value $section.Source.$setting -Recommended $recommended[$setting] -Guidance $guidance[$setting]
    }
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$riskFlags = New-Object -TypeName System.Collections.Generic.List[string]
if ($federation.AllowFederatedUsers -eq $true -and $allowedMode -eq 'AllowAllKnownDomains' -and $blockedDomains.Count -eq 0) {
    $riskFlags.Add('Open federation: every Microsoft 365 organisation can reach your users (no allow or block list).')
}
if ($federation.AllowTeamsConsumer -eq $true -and $federation.AllowTeamsConsumerInbound -eq $true) { $riskFlags.Add('Personal Teams accounts can discover and start chats with your users.') }
if ([string]$federation.ExternalAccessWithTrialTenants -eq 'Allowed') { $riskFlags.Add('Trial-only tenants are allowed to contact your users.') }
if ($meetingPolicy.AllowAnonymousUsersToJoinMeeting -eq $true -and $meetingPolicy.AllowAnonymousUsersToStartMeeting -eq $true) { $riskFlags.Add('Anonymous users can join and start meetings.') }
if ([string]$meetingPolicy.AutoAdmittedUsers -eq 'Everyone') { $riskFlags.Add('Everyone bypasses the meeting lobby, including anonymous participants.') }
if ($client.AllowGuestUser -eq $true -and $storageEnabled.Count -gt 0) {
    $riskFlags.Add(('Guest access is on and third-party storage is enabled: {0}.' -f ($storageEnabled -join ', ')))
}

$reviewCount = @($rows | Where-Object { $_.Status -eq 'Review' }).Count
Write-Host ''
Write-Host 'Teams external access configuration summary' -ForegroundColor Cyan
Write-Host ('  Settings reported / to review : {0} / {1}' -f $rows.Count, $reviewCount)
Write-Host ('  Federation                    : AllowFederatedUsers={0}, {1} ({2} allowed, {3} blocked)' -f $federation.AllowFederatedUsers, $allowedMode, $allowedDomains.Count, $blockedDomains.Count)
Write-Host ('  Guest access                  : {0}' -f $client.AllowGuestUser)
if ($riskFlags.Count -gt 0) {
    Write-Host '  Risk flags:' -ForegroundColor Yellow
    foreach ($flag in $riskFlags) { Write-Host ('    - {0}' -f $flag) -ForegroundColor Yellow }
}
else {
    Write-Host '  Risk flags                    : none' -ForegroundColor Green
}
Write-Host ('  Rows exported                 : {0} -> {1}' -f $rows.Count, $OutputPath)

if ($PassThru) { $rows }
#endregion Main
