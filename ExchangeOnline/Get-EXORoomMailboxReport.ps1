<#
.SYNOPSIS
    Inventories room and equipment mailboxes with their booking (calendar processing) settings, Places metadata and room list membership.
.DESCRIPTION
    Collects every RoomMailbox/EquipmentMailbox with Get-EXOMailbox, reads the resource booking configuration with
    Get-CalendarProcessing (AutomateProcessing, booking window, duration limits, delegates, in-policy settings) and
    maps each resource to the room lists that contain it (Get-DistributionGroup -RecipientTypeDetails RoomList).
    With -IncludePlaces the Places metadata (city, building, floor, capacity, AV devices, tags) from Get-Place is added.
    Resources that do not auto-accept, are not in any room list or have no capacity are flagged. The script is read-only.
.PARAMETER Identity
    One or more resource mailbox identities (UPN, primary SMTP address, alias or GUID). When omitted, every room and equipment mailbox is reported.
.PARAMETER InputCsv
    Path to a CSV with an Identity, UserPrincipalName or PrimarySmtpAddress column listing the resources to report.
.PARAMETER IncludePlaces
    Also query Get-Place for each room mailbox (one extra call per room; equipment mailboxes have no Places record).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXORoomMailboxes_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXORoomMailboxReport.ps1
    Reports every room and equipment mailbox and writes .\Reports\EXORoomMailboxes_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXORoomMailboxReport.ps1 -IncludePlaces -PassThru | Where-Object { $_.Finding } | Format-Table Room, AutomateProcessing, RoomLists, Finding
    Adds Places metadata and lists only the resources that need attention.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients (Exchange Online) for the report
    Category    : Calendar & resource mailboxes
    Changes     : No
    Notes       : Get-CalendarProcessing is not REST-based (about one second per resource). Capacity comes from the
                  mailbox (ResourceCapacity); PlaceCapacity is the Places value, which Room Finder uses. Rooms must be in
                  a room list to be discoverable in Room Finder, hence the 'Not in a room list' finding.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-calendarprocessing
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'Identity', Mandatory = $true)]
    [string[]]$Identity,

    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$IncludePlaces,

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXORoomMailboxes_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
    $column = @('Identity', 'UserPrincipalName', 'PrimarySmtpAddress') | Where-Object { $rows.Count -gt 0 -and $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
    if ($null -eq $column) { throw "InputCsv must contain an 'Identity', 'UserPrincipalName' or 'PrimarySmtpAddress' column." }
    $Identity = @($rows | ForEach-Object { $_.$column } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$resourceTypes = @('RoomMailbox', 'EquipmentMailbox')
$properties = @('DisplayName', 'UserPrincipalName', 'PrimarySmtpAddress', 'RecipientTypeDetails', 'ResourceCapacity', 'Office', 'HiddenFromAddressListsEnabled')
$resources = New-Object -TypeName System.Collections.Generic.List[object]
if ($null -ne $Identity -and $Identity.Count -gt 0) {
    foreach ($id in $Identity) {
        try {
            $mailbox = Get-EXOMailbox -Identity $id -Properties $properties -ErrorAction Stop
            if ([string]$mailbox.RecipientTypeDetails -in $resourceTypes) { $resources.Add($mailbox) } else { Write-Warning "'$id' is not a room or equipment mailbox - skipped." }
        }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    try { foreach ($mailbox in (Get-EXOMailbox -RecipientTypeDetails $resourceTypes -ResultSize Unlimited -Properties $properties -ErrorAction Stop)) { $resources.Add($mailbox) } }
    catch { throw "Failed to retrieve resource mailboxes: $($_.Exception.Message)" }
}

# Room lists are distribution groups of type RoomList; index their members by SMTP address once.
$roomListIndex = @{}
try {
    foreach ($roomList in @(Get-DistributionGroup -RecipientTypeDetails RoomList -ResultSize Unlimited -ErrorAction Stop)) {
        foreach ($member in @(Get-DistributionGroupMember -Identity ([string]$roomList.PrimarySmtpAddress) -ResultSize Unlimited -ErrorAction Stop)) {
            $key = ([string]$member.PrimarySmtpAddress).ToLowerInvariant()
            if (-not $roomListIndex.ContainsKey($key)) { $roomListIndex[$key] = New-Object -TypeName System.Collections.Generic.List[string] }
            $roomListIndex[$key].Add([string]$roomList.DisplayName)
        }
    }
}
catch { Write-Warning "Room list membership could not be read: $($_.Exception.Message)" }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($resource in $resources) {
    $index++
    $upn = [string]$resource.UserPrincipalName
    Write-Progress -Activity 'Reading resource mailboxes' -Status "$index of $($resources.Count) - $upn" -PercentComplete (($index / $resources.Count) * 100)
    try { $processing = Get-CalendarProcessing -Identity $upn -ErrorAction Stop }
    catch { Write-Warning "Get-CalendarProcessing failed for '$upn': $($_.Exception.Message)"; continue }
    $place = $null
    if ($IncludePlaces -and [string]$resource.RecipientTypeDetails -eq 'RoomMailbox') {
        try { $place = Get-Place -Identity $upn -ErrorAction Stop } catch { Write-Verbose "Get-Place failed for '$upn': $($_.Exception.Message)" }
    }
    $roomLists = @()
    $smtpKey = ([string]$resource.PrimarySmtpAddress).ToLowerInvariant()
    if ($roomListIndex.ContainsKey($smtpKey)) { $roomLists = $roomListIndex[$smtpKey].ToArray() }
    # Room list membership and capacity only matter for rooms (Room Finder); equipment is judged on auto-accept alone.
    $isRoom = [string]$resource.RecipientTypeDetails -eq 'RoomMailbox'
    $findings = New-Object -TypeName System.Collections.Generic.List[string]
    if ([string]$processing.AutomateProcessing -ne 'AutoAccept') { $findings.Add(('AutomateProcessing is {0}' -f $processing.AutomateProcessing)) }
    if ($isRoom -and $roomLists.Count -eq 0) { $findings.Add('Not in a room list') }
    if ($isRoom -and ($null -eq $resource.ResourceCapacity -or [int]$resource.ResourceCapacity -eq 0)) { $findings.Add('No capacity') }

    # $place stays $null for equipment or without -IncludePlaces; member access on $null yields empty columns.
    $results.Add([PSCustomObject]@{
            Room                           = $resource.DisplayName
            UserPrincipalName              = $upn
            PrimarySmtpAddress             = [string]$resource.PrimarySmtpAddress
            Type                           = [string]$resource.RecipientTypeDetails
            Office                         = [string]$resource.Office
            Capacity                       = $resource.ResourceCapacity
            HiddenFromAddressLists         = [bool]$resource.HiddenFromAddressListsEnabled
            AutomateProcessing             = [string]$processing.AutomateProcessing
            AllowConflicts                 = [bool]$processing.AllowConflicts
            BookingWindowInDays            = $processing.BookingWindowInDays
            MaximumDurationInMinutes       = $processing.MaximumDurationInMinutes
            AllowRecurringMeetings         = [bool]$processing.AllowRecurringMeetings
            EnforceSchedulingHorizon       = [bool]$processing.EnforceSchedulingHorizon
            ScheduleOnlyDuringWorkHours    = [bool]$processing.ScheduleOnlyDuringWorkHours
            DeleteComments                 = [bool]$processing.DeleteComments
            DeleteSubject                  = [bool]$processing.DeleteSubject
            AddOrganizerToSubject          = [bool]$processing.AddOrganizerToSubject
            RemovePrivateProperty          = [bool]$processing.RemovePrivateProperty
            ResourceDelegates              = (@($processing.ResourceDelegates | ForEach-Object { [string]$_ }) -join '; ')
            AllBookInPolicy                = [bool]$processing.AllBookInPolicy
            AllRequestInPolicy             = [bool]$processing.AllRequestInPolicy
            BookInPolicyCount              = @($processing.BookInPolicy | Where-Object { $null -ne $_ }).Count
            ProcessExternalMeetingMessages = [bool]$processing.ProcessExternalMeetingMessages
            RoomLists                      = ($roomLists -join '; ')
            City                           = [string]$place.City
            Building                       = [string]$place.Building
            Floor                          = $place.Floor
            PlaceCapacity                  = $place.Capacity
            AudioDeviceName                = [string]$place.AudioDeviceName
            VideoDeviceName                = [string]$place.VideoDeviceName
            Tags                           = (@($place.Tags | ForEach-Object { [string]$_ }) -join '; ')
            IsWheelChairAccessible         = $place.IsWheelChairAccessible
            Finding                        = ($findings -join '; ')
        })
}
Write-Progress -Activity 'Reading resource mailboxes' -Completed

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

$flagged = @($results | Where-Object { -not [string]::IsNullOrEmpty($_.Finding) })
Write-Host ''
Write-Host 'Resource mailbox summary' -ForegroundColor Cyan
Write-Host ('  Rooms / equipment    : {0} / {1}' -f @($results | Where-Object { $_.Type -eq 'RoomMailbox' }).Count, @($results | Where-Object { $_.Type -eq 'EquipmentMailbox' }).Count)
Write-Host ('  Auto-accepting       : {0}' -f @($results | Where-Object { $_.AutomateProcessing -eq 'AutoAccept' }).Count)
Write-Host ('  Not in a room list   : {0}' -f @($results | Where-Object { $_.Finding -like '*Not in a room list*' }).Count)
Write-Host ('  Without capacity     : {0}' -f @($results | Where-Object { $_.Finding -like '*No capacity*' }).Count)
Write-Host ('  Resources flagged    : {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
if ($results.Count -gt 0) { Write-Host ('  Report               : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
