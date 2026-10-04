<#
.SYNOPSIS
    Inventories meeting rooms (places) with capacity, location, AV devices and room list membership, and flags incomplete room metadata.
.DESCRIPTION
    Reads every room from /places/microsoft.graph.room (display name, email, capacity, building, floor, label, booking type,
    accessibility, audio/video/display device names, tags, city) and, with -IncludeRoomLists, every room list from
    /places/microsoft.graph.roomList together with its rooms (/places/{roomListEmail}/microsoft.graph.roomlist/rooms) so each
    room shows the room lists it belongs to. Rooms are flagged when the capacity is missing, when neither building nor floor is
    set, when no AV device name is recorded (not a Teams Rooms system) or when they are not in any room list, which hides them
    from Room Finder. The console summary counts rooms per building and per flag.
.PARAMETER IncludeRoomLists
    Also read all room lists and their members (one extra Graph call per room list) and flag rooms that are in no list.
.PARAMETER FlaggedOnly
    Export only rooms with at least one flag.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsRoomsAndPlaces_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsRoomsAndPlaces.ps1
    Exports every room with its metadata and shows which rooms lack capacity, location or AV device information.
.EXAMPLE
    PS> .\Get-TeamsRoomsAndPlaces.ps1 -IncludeRoomLists -FlaggedOnly -OutputPath C:\Temp\RoomsToFix.csv -Verbose
    Exports only rooms with incomplete metadata or without a room list, the work list for a Room Finder clean-up.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Place.Read.All (delegated). Any Exchange recipient-management or Global Reader role can read places.
    Category    : Teams apps, settings & usage
    Changes     : No
    Notes       : Room metadata is maintained with Set-Place (Exchange Online PowerShell); Graph changes made there take up to 24 hours
                  to appear. Capacity, building, floor, AV device names and tags are what Room Finder and Teams Rooms Pro use to help
                  users find a room, so empty values are flagged rather than treated as errors. Room lists are the distribution groups
                  that group rooms per building or site; rooms outside every list are invisible in the Room Finder list view.
.LINK
    https://learn.microsoft.com/graph/api/place-list
.LINK
    https://learn.microsoft.com/graph/api/resources/room
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeRoomLists,

    [Parameter()]
    [switch]$FlaggedOnly,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsRoomsAndPlaces_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('Place.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
Write-Progress -Activity 'Reading places' -Status 'Listing rooms'
try { $rooms = @(Invoke-GraphPaged -Uri "$graphV1/places/microsoft.graph.room") }
catch { throw "Failed to list rooms: $($_.Exception.Message)" }
Write-Verbose "$($rooms.Count) rooms returned."

# Room email (lower case) -> names of the room lists that contain it.
$roomListsByRoom = @{}
$roomLists = @()
if ($IncludeRoomLists) {
    try { $roomLists = @(Invoke-GraphPaged -Uri "$graphV1/places/microsoft.graph.roomList") }
    catch { throw "Failed to list room lists: $($_.Exception.Message)" }
    $counter = 0
    foreach ($roomList in $roomLists) {
        $counter++
        Write-Progress -Activity 'Reading places' -Status "Room list $counter of $($roomLists.Count): $($roomList.displayName)" -PercentComplete ([int](($counter / $roomLists.Count) * 100))
        try {
            $members = @(Invoke-GraphPaged -Uri ('{0}/places/{1}/microsoft.graph.roomlist/rooms' -f $graphV1, [uri]::EscapeDataString($roomList.emailAddress)))
        }
        catch {
            Write-Warning "Could not read the rooms of room list '$($roomList.displayName)': $($_.Exception.Message)"
            continue
        }
        foreach ($member in $members) {
            if ([string]::IsNullOrWhiteSpace($member.emailAddress)) { continue }
            $key = $member.emailAddress.ToLowerInvariant()
            if (-not $roomListsByRoom.ContainsKey($key)) { $roomListsByRoom[$key] = @() }
            $roomListsByRoom[$key] += $roomList.displayName
        }
        Start-Sleep -Milliseconds 200
    }
}
Write-Progress -Activity 'Reading places' -Completed

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($room in $rooms) {
    $flags = @()
    if ($null -eq $room.capacity -or [int]$room.capacity -le 0) { $flags += 'NoCapacity' }
    if ([string]::IsNullOrWhiteSpace($room.building) -and [string]::IsNullOrWhiteSpace([string]$room.floorNumber)) { $flags += 'NoLocation' }
    if ([string]::IsNullOrWhiteSpace($room.audioDeviceName) -and [string]::IsNullOrWhiteSpace($room.videoDeviceName) -and [string]::IsNullOrWhiteSpace($room.displayDeviceName)) { $flags += 'NoAvDevices' }
    $memberOf = @()
    if ($IncludeRoomLists) {
        $roomKey = ([string]$room.emailAddress).ToLowerInvariant()
        if ($roomListsByRoom.ContainsKey($roomKey)) { $memberOf = @($roomListsByRoom[$roomKey] | Sort-Object -Unique) }
        if ($memberOf.Count -eq 0) { $flags += 'NotInRoomList' }
    }
    $rows.Add([PSCustomObject]@{
        DisplayName            = $room.displayName
        EmailAddress           = $room.emailAddress
        Capacity               = $room.capacity
        Building               = $room.building
        FloorNumber            = $room.floorNumber
        FloorLabel             = $room.floorLabel
        Label                  = $room.label
        City                   = $room.address.city
        CountryOrRegion        = $room.address.countryOrRegion
        Phone                  = $room.phone
        BookingType            = $room.bookingType
        IsWheelChairAccessible = $room.isWheelChairAccessible
        AudioDeviceName        = $room.audioDeviceName
        VideoDeviceName        = $room.videoDeviceName
        DisplayDeviceName      = $room.displayDeviceName
        Tags                   = (@($room.tags) -join ';')
        RoomLists              = ($memberOf -join ';')
        Flags                  = ($flags -join ';')
        FlagCount              = $flags.Count
    })
}

$output = @($rows | Sort-Object -Property Building, FloorNumber, DisplayName)
if ($FlaggedOnly) { $output = @($output | Where-Object { $_.FlagCount -gt 0 }) }
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No rooms to export (none found or none flagged); no CSV was written.' }

$byBuilding = @($rows | Group-Object -Property { if ([string]::IsNullOrWhiteSpace($_.Building)) { '(no building)' } else { $_.Building } } | Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, Name)
$flagCounts = @($rows | ForEach-Object { $_.Flags.Split(';') } | Where-Object { $_ -ne '' } | Group-Object | Sort-Object -Property Name)
Write-Host ''
Write-Host 'Rooms and places summary' -ForegroundColor Cyan
Write-Host ('  Rooms                 : {0}' -f $rows.Count)
Write-Host ('  Reserved / accessible : {0} / {1}' -f @($rows | Where-Object { $_.BookingType -eq 'reserved' }).Count, @($rows | Where-Object { $_.IsWheelChairAccessible -eq $true }).Count)
if ($IncludeRoomLists) { Write-Host ('  Room lists            : {0}' -f $roomLists.Count) }
Write-Host ('  Rooms with flags      : {0}' -f @($rows | Where-Object { $_.FlagCount -gt 0 }).Count) -ForegroundColor Yellow
foreach ($flag in $flagCounts) { Write-Host ('    {0,-20} {1,5}' -f $flag.Name, $flag.Count) -ForegroundColor Yellow }
if ($byBuilding.Count -gt 0) {
    Write-Host '  Rooms per building (top 10):'
    foreach ($building in ($byBuilding | Select-Object -First 10)) { Write-Host ('    {0,-40} {1,5}' -f $building.Name, $building.Count) }
}
Write-Host ('  Rows exported         : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
