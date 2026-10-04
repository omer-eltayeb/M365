<#
.SYNOPSIS
    Applies a consistent booking policy (calendar processing) and optional Places metadata to room and equipment mailboxes.
.DESCRIPTION
    Compares the current Get-CalendarProcessing settings of every resource in scope with the desired policy and writes
    only the differing settings with Set-CalendarProcessing. -StandardPolicy applies a recommended baseline; individual
    parameters override or complement it. With -InputCsv, optional Capacity/City/Building/Floor columns are written to
    Set-Place for room mailboxes. Nothing is changed unless -Apply is specified; every change is wrapped in ShouldProcess.
    One result object per resource (Status, Changes) is emitted to the pipeline - pipe to Export-Csv to keep a record.
.PARAMETER Identity
    One or more resource mailbox identities (UPN, primary SMTP address, alias or GUID). When omitted, every room and equipment mailbox is processed.
.PARAMETER InputCsv
    Path to a CSV with an Identity, UserPrincipalName or PrimarySmtpAddress column, plus optional Capacity, City, Building and Floor columns.
.PARAMETER StandardPolicy
    Apply the recommended baseline described in the notes. Explicit settings passed alongside override the baseline values.
.PARAMETER AutomateProcessing
    Booking mode: AutoAccept (recommended for rooms), AutoUpdate (tentative until a delegate decides) or None.
.PARAMETER BookingWindowInDays
    How far ahead the resource can be booked (0-1080 days).
.PARAMETER MaximumDurationInMinutes
    Longest allowed meeting in minutes; 0 means unlimited.
.PARAMETER AllowRecurringMeetings
    $true to accept recurring meetings, $false to reject them.
.PARAMETER AllowConflicts
    $true to accept double bookings, $false to decline conflicting requests.
.PARAMETER ScheduleOnlyDuringWorkHours
    $true to decline requests outside the resource's working hours.
.PARAMETER DeleteComments
    $true to strip the message body from accepted requests.
.PARAMETER DeleteSubject
    $true to remove the original subject from the booking shown in the resource calendar.
.PARAMETER AddOrganizerToSubject
    $true to show the organiser's name as the subject in the resource calendar.
.PARAMETER ResourceDelegates
    Delegates (UPN or SMTP) who receive requests that fall outside policy. Always written when specified.
.PARAMETER Apply
    Perform the changes. Without this switch the script is read-only and reports the differences.
.EXAMPLE
    PS> .\Set-EXORoomBookingPolicy.ps1 -StandardPolicy | Export-Csv -Path .\RoomPolicyDrift.csv -NoTypeInformation
    Reports which rooms and equipment deviate from the baseline and saves the differences. Nothing is changed.
.EXAMPLE
    PS> .\Set-EXORoomBookingPolicy.ps1 -StandardPolicy -BookingWindowInDays 365 -Apply -WhatIf
    Shows the Set-CalendarProcessing calls that would run with the baseline and a one-year booking window.
.EXAMPLE
    PS> .\Set-EXORoomBookingPolicy.ps1 -InputCsv .\Rooms.csv -AutomateProcessing AutoAccept -ResourceDelegates facilities@contoso.com -Apply
    Enforces auto-accept and a delegate on the listed rooms and writes the Capacity/City/Building/Floor columns to Places.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients for the report; Mail Recipients role (Recipient Management / Exchange Administrator) for -Apply
    Category    : Calendar & resource mailboxes
    Changes     : Yes
    Notes       : Baseline = AutoAccept, AllowConflicts $false, AllowRecurringMeetings $true, BookingWindowInDays 180, MaximumDurationInMinutes
                  1440, EnforceSchedulingHorizon $true, ScheduleOnlyDuringWorkHours $false, DeleteComments/DeleteSubject/AddOrganizerToSubject
                  $true, RemovePrivateProperty $true - the Exchange defaults with auto-accept enforced.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/set-calendarprocessing
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'Identity', Mandatory = $true)]
    [string[]]$Identity,

    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$StandardPolicy,

    # Individual booking settings; omitted settings are left untouched unless -StandardPolicy supplies them.
    [Parameter()] [ValidateSet('AutoAccept', 'AutoUpdate', 'None')] [string]$AutomateProcessing,
    [Parameter()] [ValidateRange(0, 1080)] [int]$BookingWindowInDays,
    [Parameter()] [ValidateRange(0, 525600)] [int]$MaximumDurationInMinutes,
    [Parameter()] [bool]$AllowRecurringMeetings,
    [Parameter()] [bool]$AllowConflicts,
    [Parameter()] [bool]$ScheduleOnlyDuringWorkHours,
    [Parameter()] [bool]$DeleteComments,
    [Parameter()] [bool]$DeleteSubject,
    [Parameter()] [bool]$AddOrganizerToSubject,
    [Parameter()] [string[]]$ResourceDelegates,

    [Parameter()]
    [switch]$Apply
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
#endregion Helpers

#region Main
# CSV rows are kept per identity because they may carry Places columns.
$placeColumns = @('Capacity', 'City', 'Building', 'Floor')
$rowsById = @{}
$hasPlaceColumns = $false
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
    $column = @('Identity', 'UserPrincipalName', 'PrimarySmtpAddress') | Where-Object { $rows.Count -gt 0 -and $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
    if ($null -eq $column) { throw "InputCsv must contain an 'Identity', 'UserPrincipalName' or 'PrimarySmtpAddress' column." }
    foreach ($row in $rows) { if (-not [string]::IsNullOrWhiteSpace($row.$column)) { $rowsById[[string]$row.$column] = $row } }
    $Identity = @($rowsById.Keys)
    $hasPlaceColumns = @($placeColumns | Where-Object { $rows[0].PSObject.Properties.Name -contains $_ }).Count -gt 0
}

# Desired policy = baseline (when requested) overlaid with every explicitly passed setting.
$desired = @{}
if ($StandardPolicy) {
    $desired = @{ AutomateProcessing = 'AutoAccept'; AllowConflicts = $false; AllowRecurringMeetings = $true; BookingWindowInDays = 180; MaximumDurationInMinutes = 1440
        EnforceSchedulingHorizon = $true; ScheduleOnlyDuringWorkHours = $false; DeleteComments = $true; DeleteSubject = $true; AddOrganizerToSubject = $true; RemovePrivateProperty = $true }
}
$overrides = @{ AutomateProcessing = $AutomateProcessing; BookingWindowInDays = $BookingWindowInDays; MaximumDurationInMinutes = $MaximumDurationInMinutes
    AllowRecurringMeetings = $AllowRecurringMeetings; AllowConflicts = $AllowConflicts; ScheduleOnlyDuringWorkHours = $ScheduleOnlyDuringWorkHours
    DeleteComments = $DeleteComments; DeleteSubject = $DeleteSubject; AddOrganizerToSubject = $AddOrganizerToSubject; ResourceDelegates = $ResourceDelegates }
foreach ($name in $overrides.Keys) { if ($PSBoundParameters.ContainsKey($name)) { $desired[$name] = $overrides[$name] } }
if ($desired.Count -eq 0 -and -not $hasPlaceColumns) { throw 'Nothing to apply: specify -StandardPolicy, at least one booking setting, or a CSV with Capacity/City/Building/Floor columns.' }

try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$resourceTypes = @('RoomMailbox', 'EquipmentMailbox')
$properties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails')
$targets = New-Object -TypeName System.Collections.Generic.List[object]
if ($null -ne $Identity -and $Identity.Count -gt 0) {
    foreach ($id in $Identity) {
        try {
            $mailbox = Get-EXOMailbox -Identity $id -Properties $properties -ErrorAction Stop
            if ([string]$mailbox.RecipientTypeDetails -notin $resourceTypes) { throw 'not a room or equipment mailbox' }
            $targets.Add(@{ Mailbox = $mailbox; Row = $rowsById[$id] })
        }
        catch { Write-Warning "'$id' skipped: $($_.Exception.Message)" }
    }
}
else {
    try { $allResources = @(Get-EXOMailbox -RecipientTypeDetails $resourceTypes -ResultSize Unlimited -Properties $properties -ErrorAction Stop) }
    catch { throw "Failed to retrieve resource mailboxes: $($_.Exception.Message)" }
    foreach ($mailbox in $allResources) { $targets.Add(@{ Mailbox = $mailbox; Row = $null }) }
}
if (-not $Apply) { Write-Host 'Read-only mode: add -Apply to change settings.' -ForegroundColor Yellow }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($target in $targets) {
    $index++
    $upn = [string]$target.Mailbox.UserPrincipalName
    Write-Progress -Activity 'Applying booking policy' -Status "$index of $($targets.Count) - $upn" -PercentComplete (($index / $targets.Count) * 100)
    try { $current = Get-CalendarProcessing -Identity $upn -ErrorAction Stop }
    catch { Write-Warning "Get-CalendarProcessing failed for '$upn': $($_.Exception.Message)"; continue }

    # Only differing settings are written. Delegates are always written because Exchange returns them as canonical names.
    $changes = @{}
    foreach ($name in $desired.Keys) { if ($name -eq 'ResourceDelegates' -or [string]$current.$name -ne [string]$desired[$name]) { $changes[$name] = $desired[$name] } }
    $placeParams = @{}
    if ($null -ne $target.Row -and [string]$target.Mailbox.RecipientTypeDetails -eq 'RoomMailbox') {
        foreach ($column in @($placeColumns | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$target.Row.$_) })) {
            $placeParams[$column] = $(if ($column -in @('Capacity', 'Floor')) { [int]$target.Row.$column } else { [string]$target.Row.$column })
        }
    }
    $description = @(@($changes.Keys | Sort-Object | ForEach-Object { '{0}: {1} -> {2}' -f $_, (@($current.$_) -join ','), (@($changes[$_]) -join ',') }) +
        @($placeParams.Keys | Sort-Object | ForEach-Object { 'Place.{0}={1}' -f $_, $placeParams[$_] })) -join '; '
    $status = 'Compliant'
    if ($changes.Count -gt 0 -or $placeParams.Count -gt 0) {
        $status = 'WouldChange'
        if ($Apply -and $PSCmdlet.ShouldProcess($upn, "Apply booking policy ($description)")) {
            try {
                if ($changes.Count -gt 0) { Set-CalendarProcessing -Identity $upn @changes -Confirm:$false -ErrorAction Stop }
                if ($placeParams.Count -gt 0) { Set-Place -Identity $upn @placeParams -ErrorAction Stop }
                $status = 'Changed'
            }
            catch { $status = 'Failed'; Write-Warning "Update failed for '$upn': $($_.Exception.Message)" }
        }
        elseif ($Apply) { $status = 'Skipped' }
    }
    $results.Add([PSCustomObject]@{ Room = $target.Mailbox.DisplayName; UserPrincipalName = $upn; Type = [string]$target.Mailbox.RecipientTypeDetails; Status = $status; Changes = $description })
}
Write-Progress -Activity 'Applying booking policy' -Completed

Write-Host ''
Write-Host 'Room booking policy summary' -ForegroundColor Cyan
Write-Host ('  Resources evaluated : {0}' -f $targets.Count)
foreach ($group in ($results | Group-Object -Property Status | Sort-Object -Property Name)) {
    $colour = switch ($group.Name) { 'Compliant' { 'Green' } 'Changed' { 'Green' } 'Failed' { 'Red' } default { 'Yellow' } }
    Write-Host ('    {0,-16}: {1}' -f $group.Name, $group.Count) -ForegroundColor $colour
}

$results
#endregion Main
