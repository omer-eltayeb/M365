<#
.SYNOPSIS
    Reports the security and feature settings of every Teams meeting policy plus the tenant meeting configuration.
.DESCRIPTION
    Reads all meeting policies with Get-CsTeamsMeetingPolicy and exports one row per policy with 29 settings: anonymous join
    and start, lobby (AutoAdmittedUsers, PSTN bypass), recording and transcription (storage region, expiration), registration,
    engagement report, video and bit rate, screen sharing and external control, breakout rooms, reactions, watermarks, meeting
    chat, live captions, presenter role, Meet now, Outlook add-in, Copilot, external meeting join and avatars. Settings that
    the installed module version does not expose are omitted. -IncludeUserCounts adds the number of users directly assigned
    to each policy, -NonDefaultOnly exports one row per setting that differs from the Global policy instead. The tenant-wide
    Get-CsTeamsMeetingConfiguration (media ports, QoS, anonymous join, branding URLs, footer) goes to <name>_MeetingConfiguration.csv.
.PARAMETER IncludeUserCounts
    Count the users directly assigned to each meeting policy (one enumeration of all users; several minutes in large tenants).
.PARAMETER NonDefaultOnly
    Export only the settings of custom policies that differ from the Global policy (PolicyName, Setting, Value, GlobalValue).
.PARAMETER OutputPath
    Path of the policy CSV (default .\Reports\TeamsMeetingSettings_<timestamp>.csv); <name>_MeetingConfiguration.csv is written next to it.
.PARAMETER PassThru
    Also emit the policy rows to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsMeetingSettingsReport.ps1
    Exports every meeting policy with its settings and the tenant meeting configuration and prints the risky lobby settings.
.EXAMPLE
    PS> .\Get-TeamsMeetingSettingsReport.ps1 -NonDefaultOnly -IncludeUserCounts -OutputPath C:\Temp\MeetingDiff.csv
    Lists only the settings in which custom policies deviate from Global, together with the number of users on each policy.
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
    Notes       : Newer settings (Copilot, AllowAvatarsInGallery, ExternalMeetingJoin, watermarking) require a recent module
                  version and some need Teams Premium to take effect. User counts are direct assignments; users without one
                  use Global or a group-assigned policy. Meeting policy values are strings such as Enabled/Disabled or
                  EveryoneInCompany rather than booleans for several settings.
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-csteamsmeetingpolicy
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-csteamsmeetingconfiguration
#>
#Requires -Version 5.1
#Requires -Modules MicrosoftTeams

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeUserCounts,

    [Parameter()]
    [switch]$NonDefaultOnly,

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

function Get-PolicyName {
    <# Normalises a policy identity or Get-CsOnlineUser policy value ("Tag:Name", UserPolicyDefinition object or $null) to its name; empty = Global. #>
    param([Parameter()][object]$Value)
    $name = [string]$Value
    if ($null -ne $Value -and $null -ne $Value.PSObject.Properties['Name']) { $name = [string]$Value.Name }
    $name = $name -replace '^Tag:', ''
    if ([string]::IsNullOrWhiteSpace($name)) { return 'Global' }
    return $name
}

function Format-NameList {
    <# Joins names for the console summary; an empty list reads as "none". #>
    param([Parameter()][string[]]$Names)
    if (@($Names).Count -eq 0) { return 'none' }
    return (@($Names) -join ', ')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsMeetingSettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$configurationPath = [System.IO.Path]::ChangeExtension($OutputPath, $null) + '_MeetingConfiguration.csv'

try { Connect-TeamsIfNeeded } catch { throw "Failed to connect to Microsoft Teams PowerShell: $($_.Exception.Message)" }

try {
    $policies = @(Get-CsTeamsMeetingPolicy -ErrorAction Stop)
    $configuration = Get-CsTeamsMeetingConfiguration -ErrorAction Stop
}
catch {
    throw "Failed to read the Teams meeting policies: $($_.Exception.Message)"
}
$globalPolicy = @($policies | Where-Object { [string]$_.Identity -eq 'Global' })[0]
if ($null -eq $globalPolicy) { throw 'The Global meeting policy was not returned; cannot build the report.' }

$settingNames = @(
    'AllowAnonymousUsersToJoinMeeting', 'AllowAnonymousUsersToStartMeeting', 'AutoAdmittedUsers', 'AllowPSTNUsersToBypassLobby',
    'AllowCloudRecording', 'AllowRecordingStorageOutsideRegion', 'RecordingStorageMode', 'NewMeetingRecordingExpirationDays',
    'AllowTranscription', 'AllowMeetingRegistration', 'WhoCanRegister', 'AllowEngagementReport', 'AllowIPVideo', 'MediaBitRateKb',
    'ScreenSharingMode', 'AllowExternalParticipantGiveRequestControl', 'AllowBreakoutRooms', 'AllowMeetingReactions',
    'AllowWatermarkForScreenSharing', 'AllowWatermarkForCameraVideo', 'AllowedUsersForMeetingContext', 'MeetingChatEnabledType',
    'LiveCaptionsEnabledType', 'DesignatedPresenterRoleMode', 'AllowPrivateMeetNow', 'AllowOutlookAddIn', 'Copilot',
    'ExternalMeetingJoin', 'AllowAvatarsInGallery'
)
# Only settings the installed module returns are reported, so older versions do not produce always-empty columns.
$settings = @($settingNames | Where-Object { $null -ne $globalPolicy.PSObject.Properties[$_] })
$configurationNames = @(
    'ClientAudioPort', 'ClientAudioPortRange', 'ClientVideoPort', 'ClientVideoPortRange', 'ClientAppSharingPort', 'ClientAppSharingPortRange',
    'ClientMediaPortRangeEnabled', 'DisableAnonymousJoin', 'EnableQoS', 'LogoURL', 'LegalURL', 'HelpURL', 'CustomFooterText',
    'DisableAppInteractionForAnonymousUsers', 'FeedbackSurveyForAnonymousUsers'
)

$userCounts = @{}
if ($IncludeUserCounts) {
    Write-Progress -Activity 'Counting users per meeting policy' -Status 'Enumerating users with Get-CsOnlineUser'
    try { $users = @(Get-CsOnlineUser -ResultSize Unlimited -ErrorAction Stop) } catch { throw "Failed to enumerate users: $($_.Exception.Message)" }
    foreach ($user in $users) {
        $name = Get-PolicyName -Value $user.TeamsMeetingPolicy
        $userCounts[$name] = [int]$userCounts[$name] + 1
    }
    Write-Progress -Activity 'Counting users per meeting policy' -Completed
    Write-Verbose "Counted $($users.Count) users."
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in @($policies | Sort-Object -Property Identity)) {
    $name = Get-PolicyName -Value $policy.Identity
    $userCount = $null
    if ($IncludeUserCounts) { $userCount = [int]$userCounts[$name] }
    if ($NonDefaultOnly) {
        if ($name -eq 'Global') { continue }
        foreach ($setting in $settings) {
            if ([string]$policy.$setting -ne [string]$globalPolicy.$setting) {
                $rows.Add([PSCustomObject]@{ PolicyName = $name; UserCount = $userCount; Setting = $setting; Value = [string]$policy.$setting; GlobalValue = [string]$globalPolicy.$setting })
            }
        }
        continue
    }
    $row = [ordered]@{ PolicyName = $name; Description = $policy.Description; UserCount = $userCount }
    foreach ($setting in $settings) { $row[$setting] = [string]$policy.$setting }
    $differences = @($settings | Where-Object { [string]$policy.$_ -ne [string]$globalPolicy.$_ })
    $row['DiffersFromGlobalCount'] = $differences.Count
    $row['DiffersFromGlobal'] = ($differences -join ';')
    $rows.Add([PSCustomObject]$row)
}

$configurationRows = @($configurationNames | Where-Object { $null -ne $configuration.PSObject.Properties[$_] } | ForEach-Object {
        [PSCustomObject]@{ Setting = $_; Value = [string]$configuration.$_ }
    })

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No rows to export (no custom policy differs from Global); the policy CSV was not written.' }
$configurationRows | Export-Csv -Path $configurationPath -NoTypeInformation -Encoding UTF8

$anonymousStart = @($policies | Where-Object { $_.AllowAnonymousUsersToStartMeeting -eq $true } | ForEach-Object { Get-PolicyName -Value $_.Identity })
$everyoneAdmitted = @($policies | Where-Object { [string]$_.AutoAdmittedUsers -eq 'Everyone' } | ForEach-Object { Get-PolicyName -Value $_.Identity })
$pstnBypass = @($policies | Where-Object { $_.AllowPSTNUsersToBypassLobby -eq $true } | ForEach-Object { Get-PolicyName -Value $_.Identity })
Write-Host ''
Write-Host 'Teams meeting settings summary' -ForegroundColor Cyan
Write-Host ('  Meeting policies (incl. Global) / settings    : {0} / {1}' -f $policies.Count, $settings.Count)
Write-Host ('  Anonymous users may start meetings            : {0}' -f (Format-NameList -Names $anonymousStart)) -ForegroundColor Yellow
Write-Host ('  Everyone bypasses the lobby                   : {0}' -f (Format-NameList -Names $everyoneAdmitted)) -ForegroundColor Yellow
Write-Host ('  Dial-in users bypass the lobby                : {0}' -f (Format-NameList -Names $pstnBypass)) -ForegroundColor Yellow
Write-Host ('  Anonymous join disabled tenant-wide           : {0}' -f $configuration.DisableAnonymousJoin)
if ($IncludeUserCounts) {
    Write-Host '  Users per meeting policy (direct assignments):'
    foreach ($entry in @($userCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10)) {
        Write-Host ('    {0,-45} {1,6}' -f $entry.Key, $entry.Value)
    }
}
Write-Host ('  Files                                         : {0}, {1}' -f $OutputPath, $configurationPath)

if ($PassThru) { $rows }
#endregion Main
