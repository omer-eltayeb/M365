<#
.SYNOPSIS
    Reports the Teams policies directly assigned to each user, finds who has a given policy and optionally exports group assignments.
.DESCRIPTION
    Reads users with Get-CsOnlineUser (every user, -UserPrincipalName or -InputCsv) and exports one row per user with the
    account basics (display name, usage location, account state, upgrade mode, Enterprise Voice state, line URI) and the
    directly assigned policy for 24 policy types (meeting, messaging, calling, app, channels, update management, events,
    live events, audio conferencing, emergency, dial plan, voice routing, voicemail, call park/hold, IP phone, encryption,
    Shifts, feedback, mobility, VDI, files). An empty value means no direct assignment and is reported as "Global": the user
    gets the org-wide default unless a group assignment applies. -PolicyName finds the users who have a given policy for any
    type, -NonGlobalOnly keeps users with a direct assignment and -IncludeGroupAssignments exports the group assignments too.
.PARAMETER UserPrincipalName
    One or more UPNs to report. When omitted (and -InputCsv is not used) every user returned by Get-CsOnlineUser is read.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column; the listed users are read one by one.
.PARAMETER PolicyName
    Keep only users that have a policy matching this name for any policy type. Wildcards are supported ('Kiosk*').
.PARAMETER NonGlobalOnly
    Keep only users that have at least one directly assigned (non-Global) policy.
.PARAMETER IncludeGroupAssignments
    Also export every group policy assignment (GroupId, PolicyType, PolicyName, Rank) to <OutputPath>_GroupAssignments.csv.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsUserPolicyAssignments_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsUserPolicyAssignments.ps1
    Exports the directly assigned policies of every user and prints how many users each meeting and messaging policy has.
.EXAMPLE
    PS> .\Get-TeamsUserPolicyAssignments.ps1 -PolicyName 'Kiosk*' -IncludeGroupAssignments -OutputPath C:\Temp\KioskUsers.csv -Verbose
    Lists only users that have a policy starting with "Kiosk" for any type and exports the group policy assignments as well.
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
    Notes       : Get-CsOnlineUser shows direct assignments only; use Get-CsUserPolicyAssignment -Identity <upn> -PolicyType <type>
                  to see the effective policy including group inheritance. Enumerating all users of a large tenant takes several
                  minutes and is throttled; the output includes guests and resource accounts. Policy types missing from the
                  installed module version are left empty.
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-csonlineuser
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-csgrouppolicyassignment
#>
#Requires -Version 5.1
#Requires -Modules MicrosoftTeams

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$UserPrincipalName,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [string]$PolicyName,

    [Parameter()]
    [switch]$NonGlobalOnly,

    [Parameter()]
    [switch]$IncludeGroupAssignments,

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
    <# Normalises a Get-CsOnlineUser policy value (UserPolicyDefinition object or legacy "Tag:Name" string) to its name; empty = Global. #>
    param([Parameter()][object]$Value)
    $name = [string]$Value
    if ($null -ne $Value -and $null -ne $Value.PSObject.Properties['Name']) { $name = [string]$Value.Name }
    $name = $name -replace '^Tag:', ''
    if ([string]::IsNullOrWhiteSpace($name)) { return 'Global' }
    return $name
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsUserPolicyAssignments_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-TeamsIfNeeded } catch { throw "Failed to connect to Microsoft Teams PowerShell: $($_.Exception.Message)" }

$policyProperties = @(
    'TeamsMeetingPolicy', 'TeamsMessagingPolicy', 'TeamsCallingPolicy', 'TeamsAppPermissionPolicy', 'TeamsAppSetupPolicy',
    'TeamsChannelsPolicy', 'TeamsUpdateManagementPolicy', 'TeamsEventsPolicy', 'TeamsMeetingBroadcastPolicy',
    'TeamsAudioConferencingPolicy', 'TeamsEmergencyCallingPolicy', 'TeamsEmergencyCallRoutingPolicy', 'TenantDialPlan',
    'OnlineVoiceRoutingPolicy', 'OnlineVoicemailPolicy', 'TeamsCallParkPolicy', 'TeamsCallHoldPolicy', 'TeamsIPPhonePolicy',
    'TeamsEnhancedEncryptionPolicy', 'TeamsShiftsPolicy', 'TeamsFeedbackPolicy', 'TeamsMobilityPolicy', 'TeamsVdiPolicy', 'TeamsFilesPolicy'
)

$requestedUpns = @($UserPrincipalName)
if (-not [string]::IsNullOrWhiteSpace($InputCsv)) {
    $requestedUpns += @(Import-Csv -Path $InputCsv | Select-Object -ExpandProperty UserPrincipalName -ErrorAction Stop)
}
$requestedUpns = @($requestedUpns | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

$users = New-Object -TypeName System.Collections.Generic.List[object]
if ($requestedUpns.Count -gt 0) {
    $counter = 0
    foreach ($upn in $requestedUpns) {
        $counter++
        Write-Progress -Activity 'Reading users' -Status "$counter of $($requestedUpns.Count): $upn" -PercentComplete ([int](($counter / $requestedUpns.Count) * 100))
        try {
            $user = Get-CsOnlineUser -Identity $upn -ErrorAction Stop
            if ($null -ne $user) { $users.Add($user) } else { Write-Warning "User '$upn' was not found." }
        }
        catch {
            Write-Warning "Could not read user '$upn': $($_.Exception.Message)"
        }
    }
    Write-Progress -Activity 'Reading users' -Completed
}
else {
    Write-Verbose 'Enumerating all users with Get-CsOnlineUser; this can take several minutes in large tenants.'
    try { foreach ($user in @(Get-CsOnlineUser -ResultSize Unlimited -ErrorAction Stop)) { $users.Add($user) } }
    catch { throw "Failed to enumerate users: $($_.Exception.Message)" }
}
Write-Verbose "Evaluating $($users.Count) users."

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($user in $users) {
    $counter++
    Write-Progress -Activity 'Evaluating policy assignments' -Status "$counter of $($users.Count)" -PercentComplete ([int](($counter / $users.Count) * 100))
    $row = [ordered]@{
        UserPrincipalName         = $user.UserPrincipalName
        DisplayName               = $user.DisplayName
        UsageLocation             = $user.UsageLocation
        AccountEnabled            = $user.AccountEnabled
        InterpretedUserType       = $user.InterpretedUserType
        TeamsUpgradeEffectiveMode = [string]$user.TeamsUpgradeEffectiveMode
        EnterpriseVoiceEnabled    = $user.EnterpriseVoiceEnabled
        LineUri                   = $user.LineUri
    }
    $nonGlobal = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($policyProperty in $policyProperties) {
        $name = $null
        # Older module versions do not expose every policy type; leave those columns empty instead of claiming "Global".
        if ($null -ne $user.PSObject.Properties[$policyProperty]) {
            $name = Get-PolicyName -Value $user.$policyProperty
            if ($name -ne 'Global') { $nonGlobal.Add(('{0}={1}' -f $policyProperty, $name)) }
        }
        $row[$policyProperty] = $name
    }
    $row['NonGlobalPolicyCount'] = $nonGlobal.Count
    $row['NonGlobalPolicies'] = ($nonGlobal -join ';')
    if ($NonGlobalOnly -and $nonGlobal.Count -eq 0) { continue }
    if (-not [string]::IsNullOrWhiteSpace($PolicyName) -and @($policyProperties | Where-Object { $row[$_] -like $PolicyName }).Count -eq 0) { continue }
    $rows.Add([PSCustomObject]$row)
}
Write-Progress -Activity 'Evaluating policy assignments' -Completed

$output = @($rows | Sort-Object -Property UserPrincipalName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No users matched the selection; no CSV was written.' }

$groupRows = @()
$groupPath = [System.IO.Path]::ChangeExtension($OutputPath, $null) + '_GroupAssignments.csv'
if ($IncludeGroupAssignments) {
    try {
        $groupRows = @(Get-CsGroupPolicyAssignment -ErrorAction Stop | Select-Object -Property GroupId, PolicyType, PolicyName, Rank, CreatedTime, CreatedBy | Sort-Object -Property PolicyType, Rank)
        if ($groupRows.Count -gt 0) { $groupRows | Export-Csv -Path $groupPath -NoTypeInformation -Encoding UTF8 }
    }
    catch {
        Write-Warning "Could not read group policy assignments: $($_.Exception.Message)"
    }
}

Write-Host ''
Write-Host 'Teams user policy assignment summary' -ForegroundColor Cyan
Write-Host ('  Users read / exported         : {0} / {1}' -f $users.Count, $output.Count)
Write-Host ('  Users with direct assignments : {0}' -f @($output | Where-Object { $_.NonGlobalPolicyCount -gt 0 }).Count) -ForegroundColor Yellow
foreach ($summaryType in @('TeamsMeetingPolicy', 'TeamsMessagingPolicy')) {
    Write-Host ('  Users per {0}:' -f $summaryType)
    foreach ($group in @($output | Group-Object -Property $summaryType | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
        Write-Host ('    {0,-45} {1,6}' -f $group.Name, $group.Count)
    }
}
if ($IncludeGroupAssignments) { Write-Host ('  Group policy assignments      : {0} -> {1}' -f $groupRows.Count, $groupPath) }
Write-Host ('  Rows exported                 : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
