<#
.SYNOPSIS
    Reports Enterprise Voice enabled Teams users with their phone number, voice policies, licensing and configuration gaps.
.DESCRIPTION
    Reads voice-enabled users with Get-CsOnlineUser -Filter 'EnterpriseVoiceEnabled -eq $true' (falling back to a client-side
    filter when the service rejects the filter), looks up the type of each assigned number (Calling Plan, Operator Connect,
    Direct Routing, Teams Phone Mobile) from Get-CsPhoneNumberAssignment and exports one row per user with the line URI,
    voice routing policy, dial plan, calling, voicemail and emergency policies, FeatureTypes licensing (PhoneSystem, CallingPlan)
    and upgrade mode. Flags highlight users enabled without a number, Direct Routing numbers without a voice routing policy
    and numbers without a Phone System licence. -IncludeLicensedNotEnabled adds users licensed for Phone System but not enabled.
.PARAMETER IncludeLicensedNotEnabled
    Also report users whose FeatureTypes contain PhoneSystem but who are not Enterprise Voice enabled (paid for, not configured).
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsVoiceEnabledUsers_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsVoiceEnabledUsers.ps1
    Exports every Enterprise Voice enabled user with the number type and voice policies and prints the configuration flags.
.EXAMPLE
    PS> .\Get-TeamsVoiceEnabledUsers.ps1 -IncludeLicensedNotEnabled -OutputPath C:\Temp\Voice.csv -Verbose
    Adds the users that hold a Phone System licence without being voice enabled, so unused licences can be reclaimed or configured.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, MicrosoftTeams 4.0 or later
    Permissions : Teams Communications Administrator, Teams Administrator or Global Reader (read-only).
    Category    : Teams administration (MicrosoftTeams module)
    Changes     : No
    Notes       : Policy columns show direct assignments only ("Global" = org-wide default or a group assignment). FeatureTypes
                  reflects licences assigned in Microsoft 365; a user can hold a Phone System licence and still have no number.
                  Operator Connect and Calling Plan users do not need a voice routing policy, so that flag is raised for Direct
                  Routing numbers only. Large tenants: the two bulk queries take a few minutes and are throttled by the service.
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-csonlineuser
.LINK
    https://learn.microsoft.com/microsoftteams/direct-routing-enable-users
#>
#Requires -Version 5.1
#Requires -Modules MicrosoftTeams

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeLicensedNotEnabled,

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

function Get-TeamsUserSet {
    <# Runs a server-side Get-CsOnlineUser filter; falls back to filtering all users client-side when the service rejects it. #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Filter,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ClientFilter
    )
    try {
        return @(Get-CsOnlineUser -Filter $Filter -ResultSize Unlimited -ErrorAction Stop)
    }
    catch {
        Write-Warning "Server-side filter '$Filter' failed ($($_.Exception.Message)); filtering all users client-side."
        if ($null -eq $script:allUsers) { $script:allUsers = @(Get-CsOnlineUser -ResultSize Unlimited -ErrorAction Stop) }
        return @($script:allUsers | Where-Object -FilterScript $ClientFilter)
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsVoiceEnabledUsers_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-TeamsIfNeeded } catch { throw "Failed to connect to Microsoft Teams PowerShell: $($_.Exception.Message)" }

$script:allUsers = $null
Write-Verbose 'Reading Enterprise Voice enabled users.'
$users = @(Get-TeamsUserSet -Filter 'EnterpriseVoiceEnabled -eq $true' -ClientFilter { $_.EnterpriseVoiceEnabled -eq $true })
if ($IncludeLicensedNotEnabled) {
    Write-Verbose 'Reading users licensed for Phone System that are not voice enabled.'
    $licensed = @(Get-TeamsUserSet -Filter "FeatureTypes -Contains 'PhoneSystem'" -ClientFilter { @($_.FeatureTypes) -contains 'PhoneSystem' })
    $users = @($users) + @($licensed | Where-Object { $_.EnterpriseVoiceEnabled -ne $true })
}
Write-Verbose "Evaluating $($users.Count) users."

# One paged query gives the number type per assigned user object ID; it is far cheaper than one lookup per user.
$numberTypes = @{}
$skip = 0
do {
    try { $page = @(Get-CsPhoneNumberAssignment -PstnAssignmentStatus UserAssigned -Top 1000 -Skip $skip -ErrorAction Stop) }
    catch { Write-Warning "Could not read phone number assignments; NumberType will be empty: $($_.Exception.Message)"; $page = @() }
    foreach ($number in $page) {
        if (-not [string]::IsNullOrWhiteSpace($number.AssignedPstnTargetId)) { $numberTypes[[string]$number.AssignedPstnTargetId] = [string]$number.NumberType }
    }
    $skip += 1000
} while ($page.Count -eq 1000)

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($user in $users) {
    $counter++
    Write-Progress -Activity 'Evaluating voice users' -Status "$counter of $($users.Count): $($user.UserPrincipalName)" -PercentComplete ([int](($counter / $users.Count) * 100))
    $featureTypes = @($user.FeatureTypes)
    $lineUri = [string]$user.LineUri
    $voiceRoutingPolicy = Get-PolicyName -Value $user.OnlineVoiceRoutingPolicy
    $numberType = $numberTypes[[string]$user.Identity]
    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ($user.EnterpriseVoiceEnabled -eq $true -and [string]::IsNullOrWhiteSpace($lineUri)) { $flags.Add('EnterpriseVoiceWithoutLineUri') }
    if ($numberType -eq 'DirectRouting' -and $voiceRoutingPolicy -eq 'Global') { $flags.Add('DirectRoutingWithoutVoiceRoutingPolicy') }
    if (-not [string]::IsNullOrWhiteSpace($lineUri) -and $featureTypes -notcontains 'PhoneSystem') { $flags.Add('LineUriWithoutPhoneSystemLicence') }
    if ($user.EnterpriseVoiceEnabled -ne $true -and $featureTypes -contains 'PhoneSystem') { $flags.Add('PhoneSystemLicenceNotVoiceEnabled') }
    $rows.Add([PSCustomObject]@{
            UserPrincipalName               = $user.UserPrincipalName
            DisplayName                     = $user.DisplayName
            AccountEnabled                  = $user.AccountEnabled
            UsageLocation                   = $user.UsageLocation
            EnterpriseVoiceEnabled          = $user.EnterpriseVoiceEnabled
            LineUri                         = $lineUri
            OnPremLineUri                   = $user.OnPremLineURI
            NumberType                      = $numberType
            OnlineVoiceRoutingPolicy        = $voiceRoutingPolicy
            TenantDialPlan                  = Get-PolicyName -Value $user.TenantDialPlan
            TeamsCallingPolicy              = Get-PolicyName -Value $user.TeamsCallingPolicy
            OnlineVoicemailPolicy           = Get-PolicyName -Value $user.OnlineVoicemailPolicy
            TeamsEmergencyCallingPolicy     = Get-PolicyName -Value $user.TeamsEmergencyCallingPolicy
            TeamsEmergencyCallRoutingPolicy = Get-PolicyName -Value $user.TeamsEmergencyCallRoutingPolicy
            HasPhoneSystem                  = ($featureTypes -contains 'PhoneSystem')
            HasCallingPlan                  = ($featureTypes -contains 'CallingPlan')
            FeatureTypes                    = ($featureTypes -join ';')
            TeamsUpgradeEffectiveMode       = [string]$user.TeamsUpgradeEffectiveMode
            Flags                           = ($flags -join ';')
        })
}
Write-Progress -Activity 'Evaluating voice users' -Completed

$output = @($rows | Sort-Object -Property UserPrincipalName)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No voice-enabled users were found; no CSV was written.' }

$voiceEnabled = @($output | Where-Object { $_.EnterpriseVoiceEnabled -eq $true })
Write-Host ''
Write-Host 'Teams voice users summary' -ForegroundColor Cyan
Write-Host ('  Enterprise Voice enabled users   : {0}' -f $voiceEnabled.Count)
Write-Host ('  With a line URI                  : {0}' -f @($voiceEnabled | Where-Object { -not [string]::IsNullOrWhiteSpace($_.LineUri) }).Count)
Write-Host '  By number type:'
foreach ($group in @($voiceEnabled | Group-Object -Property NumberType | Sort-Object -Property Count -Descending)) {
    $label = $group.Name
    if ([string]::IsNullOrWhiteSpace($label)) { $label = '(no assigned number)' }
    Write-Host ('    {0,-38} {1,6}' -f $label, $group.Count)
}
Write-Host '  Flags:'
foreach ($group in @($output | ForEach-Object { $_.Flags -split ';' } | Where-Object { $_ } | Group-Object | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-38} {1,6}' -f $group.Name, $group.Count) -ForegroundColor Yellow
}
Write-Host ('  Rows exported                    : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
