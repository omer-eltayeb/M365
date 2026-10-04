<#
.SYNOPSIS
    Documents every Teams call queue, auto attendant and voice application resource account, with configuration gaps flagged.
.DESCRIPTION
    Pages through Get-CsCallQueue and Get-CsAutoAttendant (100 per page) and reads all resource accounts with
    Get-CsOnlineApplicationInstance. Call queues are exported with routing method, agent alert time, agent count, team channel
    or distribution lists, overflow and timeout handling, presence-based routing, conference mode, language and welcome music;
    auto attendants with language, time zone, voice, default greeting type, menu option count, call flow count, business hours
    (from the after-hours schedule), holiday count, operator and scopes. Resource accounts are resolved to UPN and phone number
    on every row and listed in their own CSV with the application type. Flags: queues without agents, attendants without
    operator, objects without a resource account and resource accounts without a phone number.
.PARAMETER OutputPath
    Path of the call queue CSV (default .\Reports\TeamsVoiceApps_<timestamp>.csv); <name>_AutoAttendants.csv and <name>_ResourceAccounts.csv are written next to it.
.PARAMETER PassThru
    Also emit the call queue and auto attendant objects to the pipeline (property ObjectType tells them apart).
.EXAMPLE
    PS> .\Get-TeamsCallQueuesAndAutoAttendants.ps1
    Exports the three CSV files and prints the number of queues, attendants and resource accounts together with the flags.
.EXAMPLE
    PS> .\Get-TeamsCallQueuesAndAutoAttendants.ps1 -OutputPath C:\Temp\VoiceApps.csv -PassThru | Where-Object { $_.Flags } | Format-Table Name, ObjectType, Flags
    Shows only the queues and attendants that have at least one configuration flag.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, MicrosoftTeams
    Permissions : Teams Communications Administrator, Teams Administrator or Global Reader (read-only).
    Category    : Teams administration (MicrosoftTeams module)
    Changes     : No
    Notes       : Agent counts include channel or distribution list members only after the service has expanded the membership.
                  Business hours come from the after-hours schedule (its ranges are the open hours when the schedule is complemented);
                  resource accounts also need a Teams Phone Resource Account licence, which this report cannot see.
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-cscallqueue
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-csautoattendant
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

function Get-VoiceAppPaged {
    <# Returns every object of Get-CsCallQueue / Get-CsAutoAttendant, which hand out at most 100 items per call. #>
    param([Parameter(Mandatory = $true)][string]$Cmdlet)
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $skip = 0
    do {
        $page = @(& $Cmdlet -First 100 -Skip $skip -ErrorAction Stop)
        foreach ($item in $page) { $results.Add($item) }
        $skip += 100
    } while ($page.Count -eq 100)
    return , $results
}

function Get-ScheduleSummary {
    <# Summarises the weekly ranges of a schedule as "Mon 09:00-17:00; Tue ..."; fixed-date schedules return $null. #>
    param([Parameter()][object]$Schedule)
    $weekly = $Schedule.WeeklyRecurrentSchedule
    if ($null -eq $weekly) { return $null }
    $parts = foreach ($day in @('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')) {
        $ranges = @($weekly.("${day}Hours"))
        if ($ranges.Count -eq 0) { continue }
        $text = @($ranges | ForEach-Object { '{0}-{1}' -f $_.Start.ToString('hh\:mm'), ($_.End.ToString('hh\:mm') -replace '^00:00$', '24:00') }) -join ','
        '{0} {1}' -f $day.Substring(0, 3), $text
    }
    return ($parts -join '; ')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsVoiceApps_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$basePath = [System.IO.Path]::ChangeExtension($OutputPath, $null)
try { Connect-TeamsIfNeeded } catch { throw "Failed to connect to Microsoft Teams PowerShell: $($_.Exception.Message)" }

$applicationTypes = @{ '11cd3e2e-fccb-42ad-ad00-878b93575e07' = 'CallQueue'; 'ce933385-9390-45d1-9512-c8d228074e07' = 'AutoAttendant' }
Write-Progress -Activity 'Reading voice applications' -Status 'Resource accounts, call queues and auto attendants'
try { $instances = @(Get-CsOnlineApplicationInstance -ErrorAction Stop) } catch { throw "Failed to read resource accounts: $($_.Exception.Message)" }
$instanceMap = @{}
$associations = @{}
foreach ($instance in $instances) { $instanceMap[[string]$instance.ObjectId] = $instance }
try { $callQueues = Get-VoiceAppPaged -Cmdlet 'Get-CsCallQueue' } catch { throw "Failed to read call queues: $($_.Exception.Message)" }
try { $autoAttendants = Get-VoiceAppPaged -Cmdlet 'Get-CsAutoAttendant' } catch { throw "Failed to read auto attendants: $($_.Exception.Message)" }
Write-Progress -Activity 'Reading voice applications' -Completed
Write-Verbose "Read $($callQueues.Count) call queues, $($autoAttendants.Count) auto attendants and $($instances.Count) resource accounts."
$queueRows = New-Object -TypeName System.Collections.Generic.List[object]
$attendantRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($queue in $callQueues) {
    $accounts = @(@($queue.ApplicationInstances) | ForEach-Object { $instanceMap[[string]$_] } | Where-Object { $null -ne $_ })
    foreach ($account in $accounts) { $associations[[string]$account.ObjectId] = $queue.Name }
    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if (@($queue.Agents).Count -eq 0) { $flags.Add('NoAgents') }
    if ($accounts.Count -eq 0) { $flags.Add('NoResourceAccount') }
    if (@($accounts | Where-Object { [string]::IsNullOrWhiteSpace($_.PhoneNumber) }).Count -gt 0) { $flags.Add('ResourceAccountWithoutPhoneNumber') }
    $queueRows.Add([PSCustomObject]@{
            ObjectType                  = 'CallQueue'
            Name                        = $queue.Name
            Identity                    = [string]$queue.Identity
            RoutingMethod               = [string]$queue.RoutingMethod
            AgentAlertTime              = $queue.AgentAlertTime
            AgentCount                  = @($queue.Agents).Count
            DistributionLists           = (@($queue.DistributionLists) -join ';')
            ChannelId                   = $queue.ChannelId
            OverflowThreshold           = $queue.OverflowThreshold
            OverflowAction              = [string]$queue.OverflowAction
            OverflowActionTarget        = [string]$queue.OverflowActionTarget.Id
            TimeoutThreshold            = $queue.TimeoutThreshold
            TimeoutAction               = [string]$queue.TimeoutAction
            TimeoutActionTarget         = [string]$queue.TimeoutActionTarget.Id
            AllowOptOut                 = $queue.AllowOptOut
            ConferenceMode              = $queue.ConferenceMode
            PresenceBasedRouting        = $queue.PresenceBasedRouting
            LanguageId                  = $queue.LanguageId
            WelcomeMusicFileName        = $queue.WelcomeMusicFileName
            ResourceAccounts            = (@($accounts | ForEach-Object { $_.UserPrincipalName }) -join ';')
            ResourceAccountPhoneNumbers = (@($accounts | ForEach-Object { $_.PhoneNumber } | Where-Object { $_ }) -join ';')
            Flags                       = ($flags -join ';')
        })
}
foreach ($attendant in $autoAttendants) {
    $accounts = @(@($attendant.ApplicationInstances) | ForEach-Object { $instanceMap[[string]$_] } | Where-Object { $null -ne $_ })
    foreach ($account in $accounts) { $associations[[string]$account.ObjectId] = $attendant.Name }
    $handling = @($attendant.CallHandlingAssociations)
    $afterHoursIds = @($handling | Where-Object { [string]$_.Type -eq 'AfterHours' } | ForEach-Object { [string]$_.ScheduleId })
    $businessHours = $null
    foreach ($schedule in @($attendant.Schedules | Where-Object { $afterHoursIds -contains [string]$_.Id })) { $businessHours = Get-ScheduleSummary -Schedule $schedule }
    $greetingType = 'None'
    foreach ($greeting in @($attendant.DefaultCallFlow.Greetings | Select-Object -First 1)) { $greetingType = [string]$greeting.ActiveType }
    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ($null -eq $attendant.Operator) { $flags.Add('NoOperator') }
    if ($accounts.Count -eq 0) { $flags.Add('NoResourceAccount') }
    if (@($accounts | Where-Object { [string]::IsNullOrWhiteSpace($_.PhoneNumber) }).Count -gt 0) { $flags.Add('ResourceAccountWithoutPhoneNumber') }
    $attendantRows.Add([PSCustomObject]@{
            ObjectType                  = 'AutoAttendant'
            Name                        = $attendant.Name
            Identity                    = [string]$attendant.Identity
            LanguageId                  = $attendant.LanguageId
            TimeZoneId                  = $attendant.TimeZoneId
            VoiceId                     = $attendant.VoiceId
            DefaultGreetingType         = $greetingType
            DefaultMenuOptionCount      = @($attendant.DefaultCallFlow.Menu.MenuOptions).Count
            DialByNameEnabled           = $attendant.DefaultCallFlow.Menu.DialByNameEnabled
            CallFlowCount               = @($attendant.CallFlows).Count
            BusinessHours               = $businessHours
            HolidayCount                = @($handling | Where-Object { [string]$_.Type -eq 'Holiday' }).Count
            OperatorType                = [string]$attendant.Operator.Type
            OperatorTarget              = [string]$attendant.Operator.Id
            DialScopes                  = (@(@('Inclusion', 'Exclusion') | Where-Object { $null -ne $attendant."${_}Scope" }) -join ';')
            ResourceAccounts            = (@($accounts | ForEach-Object { $_.UserPrincipalName }) -join ';')
            ResourceAccountPhoneNumbers = (@($accounts | ForEach-Object { $_.PhoneNumber } | Where-Object { $_ }) -join ';')
            Flags                       = ($flags -join ';')
        })
}

$accountRows = @($instances | ForEach-Object {
        $flags = @()
        if ([string]::IsNullOrWhiteSpace($_.PhoneNumber)) { $flags += 'NoPhoneNumber' }
        if (-not $associations.ContainsKey([string]$_.ObjectId)) { $flags += 'NotAssociated' }
        [PSCustomObject]@{
            DisplayName       = $_.DisplayName
            UserPrincipalName = $_.UserPrincipalName
            ObjectId          = [string]$_.ObjectId
            PhoneNumber       = $_.PhoneNumber
            ApplicationId     = [string]$_.ApplicationId
            ApplicationType   = $applicationTypes[[string]$_.ApplicationId]
            AssociatedTo      = $associations[[string]$_.ObjectId]
            Flags             = ($flags -join ';')
        }
    } | Sort-Object -Property ApplicationType, DisplayName)

$queueOutput = @($queueRows | Sort-Object -Property Name)
$attendantOutput = @($attendantRows | Sort-Object -Property Name)
if ($queueOutput.Count -gt 0) { $queueOutput | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 } else { Write-Warning 'No call queues found; the call queue CSV was not written.' }
if ($attendantOutput.Count -gt 0) { $attendantOutput | Export-Csv -Path "${basePath}_AutoAttendants.csv" -NoTypeInformation -Encoding UTF8 }
if ($accountRows.Count -gt 0) { $accountRows | Export-Csv -Path "${basePath}_ResourceAccounts.csv" -NoTypeInformation -Encoding UTF8 }

$noAgents = @($queueOutput | Where-Object { $_.Flags -like '*NoAgents*' }).Count
$noOperator = @($attendantOutput | Where-Object { $_.Flags -like '*NoOperator*' }).Count
$noNumber = @($accountRows | Where-Object { $_.Flags -like '*NoPhoneNumber*' }).Count
$unassociated = @($accountRows | Where-Object { $_.Flags -like '*NotAssociated*' }).Count
Write-Host ''
Write-Host 'Teams call queues and auto attendants summary' -ForegroundColor Cyan
Write-Host ('  Call queues / auto attendants / resource accounts   : {0} / {1} / {2}' -f $queueOutput.Count, $attendantOutput.Count, $accountRows.Count)
Write-Host ('  Queues without agents / attendants without operator : {0} / {1}' -f $noAgents, $noOperator) -ForegroundColor Yellow
Write-Host ('  Resource accounts without number / unassociated     : {0} / {1}' -f $noNumber, $unassociated) -ForegroundColor Yellow
Write-Host ('  Files                                               : {0}, {1}_AutoAttendants.csv, {1}_ResourceAccounts.csv' -f $OutputPath, $basePath)

if ($PassThru) { $queueOutput; $attendantOutput }
#endregion Main
