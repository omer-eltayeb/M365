<#
.SYNOPSIS
    Inventories every Teams phone number with its type, assignment, capabilities, location and PSTN partner.
.DESCRIPTION
    Pages through Get-CsPhoneNumberAssignment (1000 numbers per page) with optional server-side filters on number type,
    activation state, assignment status and country. The assigned user or resource account is resolved to a UPN with
    Get-CsOnlineUser and, with -ResolveAddresses, the emergency civic address is read with Get-CsOnlineLisCivicAddress
    (both cached, one call per distinct ID). Exports one row per number (TelephoneNumber, NumberType, ActivationState,
    PstnAssignmentStatus, AssignedTo..., Capability, IsoCountryCode, City, CivicAddressId, LocationId, PortInOrderStatus,
    PstnPartnerName, NumberSource) and prints a summary by number type, assigned vs unassigned and country.
.PARAMETER NumberType
    Only numbers of this type: CallingPlan, OperatorConnect, DirectRouting or OCMobile (Teams Phone Mobile).
.PARAMETER ActivationState
    Only numbers in this activation state: Activated, AssignmentPending, AssignmentFailed, UpdatePending or UpdateFailed.
.PARAMETER PstnAssignmentStatus
    Only numbers with this assignment status, for example Unassigned (unused numbers) or VoiceApplicationAssigned.
.PARAMETER IsoCountryCode
    Only numbers assigned to this ISO 3166-1 alpha-2 country code, for example US or GB.
.PARAMETER ResolveAddresses
    Read the civic address (description, street, city, country) of every distinct CivicAddressId. One extra call per address.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\TeamsPhoneNumberInventory_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-TeamsPhoneNumberInventory.ps1
    Exports every phone number of the tenant with the UPN of the user or resource account it is assigned to.
.EXAMPLE
    PS> .\Get-TeamsPhoneNumberInventory.ps1 -PstnAssignmentStatus Unassigned -NumberType CallingPlan -ResolveAddresses -Verbose
    Lists the unused Calling Plan numbers (still billed) together with the emergency address they are attached to.
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
    Notes       : Get-CsPhoneNumberAssignment returns at most 1000 numbers per call, so the script pages with -Skip; very large
                  inventories can alternatively be downloaded with Export-CsAcquiredPhoneNumber. Direct Routing numbers have no
                  civic address or partner unless the location was set with Set-CsPhoneNumberAssignment. The cmdlet is available
                  in commercial, GCC, GCC High and DoD clouds only.
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-csphonenumberassignment
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-csonlineliscivicaddress
#>
#Requires -Version 5.1
#Requires -Modules MicrosoftTeams

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('CallingPlan', 'OperatorConnect', 'DirectRouting', 'OCMobile')]
    [string]$NumberType,

    [Parameter()]
    [ValidateSet('Activated', 'AssignmentPending', 'AssignmentFailed', 'UpdatePending', 'UpdateFailed')]
    [string]$ActivationState,

    [Parameter()]
    [ValidateSet('Unassigned', 'UserAssigned', 'ConferenceAssigned', 'VoiceApplicationAssigned', 'ThirdPartyAppAssigned', 'PolicyAssigned')]
    [string]$PstnAssignmentStatus,

    [Parameter()]
    [ValidatePattern('^[A-Za-z]{2}$')]
    [string]$IsoCountryCode,

    [Parameter()]
    [switch]$ResolveAddresses,

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsPhoneNumberInventory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-TeamsIfNeeded } catch { throw "Failed to connect to Microsoft Teams PowerShell: $($_.Exception.Message)" }

# The four filters share their names with the cmdlet parameters, so bound values are passed straight through.
$queryParams = @{ Top = 1000; ErrorAction = 'Stop' }
foreach ($filterName in @('NumberType', 'ActivationState', 'PstnAssignmentStatus', 'IsoCountryCode')) {
    if ($PSBoundParameters.ContainsKey($filterName)) { $queryParams[$filterName] = $PSBoundParameters[$filterName] }
}

$numbers = New-Object -TypeName System.Collections.Generic.List[object]
$skip = 0
do {
    Write-Progress -Activity 'Reading phone numbers' -Status "$($numbers.Count) numbers read so far"
    try { $page = @(Get-CsPhoneNumberAssignment @queryParams -Skip $skip) }
    catch { throw "Failed to read phone numbers: $($_.Exception.Message)" }
    foreach ($number in $page) { $numbers.Add($number) }
    $skip += 1000
} while ($page.Count -eq 1000)
Write-Progress -Activity 'Reading phone numbers' -Completed
Write-Verbose "Read $($numbers.Count) phone numbers."

$targetCache = @{}
$addressCache = @{}
$emptyGuid = [guid]::Empty.ToString()
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($number in $numbers) {
    $counter++
    Write-Progress -Activity 'Resolving assignments' -Status "$counter of $($numbers.Count): $($number.TelephoneNumber)" -PercentComplete ([int](($counter / $numbers.Count) * 100))
    $targetId = [string]$number.AssignedPstnTargetId
    $assignedTo = $null
    # Users and resource accounts are referenced by object ID; a shared calling policy target is a policy name and is kept as is.
    if ($targetId -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
        if (-not $targetCache.ContainsKey($targetId)) {
            try { $targetCache[$targetId] = Get-CsOnlineUser -Identity $targetId -ErrorAction Stop }
            catch { Write-Verbose "Could not resolve target $targetId of $($number.TelephoneNumber): $($_.Exception.Message)"; $targetCache[$targetId] = $null }
        }
        $assignedTo = $targetCache[$targetId]
    }
    $civicAddressId = [string]$number.CivicAddressId
    $address = $null
    if ($ResolveAddresses -and -not [string]::IsNullOrWhiteSpace($civicAddressId) -and $civicAddressId -ne $emptyGuid) {
        if (-not $addressCache.ContainsKey($civicAddressId)) {
            try { $addressCache[$civicAddressId] = Get-CsOnlineLisCivicAddress -CivicAddressId $civicAddressId -ErrorAction Stop }
            catch { Write-Warning "Could not read civic address ${civicAddressId}: $($_.Exception.Message)"; $addressCache[$civicAddressId] = $null }
        }
        $address = $addressCache[$civicAddressId]
    }
    $rows.Add([PSCustomObject]@{
            TelephoneNumber       = $number.TelephoneNumber
            NumberType            = $number.NumberType
            ActivationState       = $number.ActivationState
            PstnAssignmentStatus  = $number.PstnAssignmentStatus
            AssignmentCategory    = $number.AssignmentCategory
            AssignedPstnTargetId  = $targetId
            AssignedToUpn         = $assignedTo.UserPrincipalName
            AssignedToDisplayName = $assignedTo.DisplayName
            AssignedToAccountType = $assignedTo.AccountType
            Capability            = (@($number.Capability) -join ';')
            IsoCountryCode        = $number.IsoCountryCode
            IsoSubdivision        = $number.IsoSubdivision
            City                  = $number.City
            CivicAddressId        = $civicAddressId
            AddressDescription    = $address.Description
            AddressStreet         = ('{0} {1}' -f $address.HouseNumber, $address.StreetName).Trim()
            AddressCity           = $address.City
            AddressCountry        = $address.CountryOrRegion
            LocationId            = $number.LocationId
            PortInOrderStatus     = $number.PortInOrderStatus
            PstnPartnerName       = $number.PstnPartnerName
            OperatorId            = $number.OperatorId
            NumberSource          = $number.NumberSource
        })
}
Write-Progress -Activity 'Resolving assignments' -Completed

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No phone numbers matched the filters; no CSV was written.' }

$unassigned = @($rows | Where-Object { $_.PstnAssignmentStatus -eq 'Unassigned' }).Count
Write-Host ''
Write-Host 'Teams phone number inventory summary' -ForegroundColor Cyan
Write-Host ('  Numbers read                 : {0}' -f $rows.Count)
Write-Host ('  Assigned / unassigned        : {0} / {1}' -f ($rows.Count - $unassigned), $unassigned) -ForegroundColor Yellow
if ($unassigned -gt 0) { Write-Host '  Unassigned Calling Plan and Operator Connect numbers are still billed; release the ones you no longer need.' -ForegroundColor Yellow }
Write-Host '  By number type:'
foreach ($group in @($rows | Group-Object -Property NumberType | Sort-Object -Property Count -Descending)) {
    $groupUnassigned = @($group.Group | Where-Object { $_.PstnAssignmentStatus -eq 'Unassigned' }).Count
    Write-Host ('    {0,-20} {1,6}  (unassigned {2})' -f $group.Name, $group.Count, $groupUnassigned)
}
Write-Host '  By country (top 10):'
foreach ($group in @($rows | Group-Object -Property IsoCountryCode | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,-20} {1,6}' -f $group.Name, $group.Count)
}
Write-Host ('  Rows exported                : {0} -> {1}' -f $rows.Count, $OutputPath)

if ($PassThru) { $rows }
#endregion Main
