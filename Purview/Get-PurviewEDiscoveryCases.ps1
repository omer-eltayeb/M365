<#
.SYNOPSIS
    Reports eDiscovery (Standard) and eDiscovery (Premium) cases with members, hold and search counts, and flags stale open cases.
.DESCRIPTION
    Lists every case returned by Get-ComplianceCase for the eDiscovery and AdvancedEdiscovery case types. For each case it
    adds the members (Get-ComplianceCaseMember), the number of case hold policies (Get-CaseHoldPolicy) and the number of
    searches (Get-ComplianceSearch), and derives LastActivity from the creation date and the newest hold or search change
    so that abandoned open cases can be found with -OnlyStaleOpen. Writes one row per case to CSV and prints a summary
    by case type and status. The script is read-only.
.PARAMETER Status
    Only return cases with this status: Active or Closed. Default: all cases.
.PARAMETER OnlyStaleOpen
    Only return Active cases whose LastActivity is older than -StaleDays.
.PARAMETER StaleDays
    Days without hold or search activity after which an open case is considered stale (default 180).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewEDiscoveryCases_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the case objects to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewEDiscoveryCases.ps1
    Exports every Standard and Premium case you can see, with members and hold/search counts, to .\Reports.
.EXAMPLE
    PS> .\Get-PurviewEDiscoveryCases.ps1 -OnlyStaleOpen -StaleDays 365 -PassThru | Format-Table Name, CaseType, LastActivity, HoldCount
    Shows open cases that have had no hold or search activity for a year, for example as candidates to close.
.EXAMPLE
    PS> .\Get-PurviewEDiscoveryCases.ps1 -Status Closed -OutputPath C:\Temp\ClosedCases.csv -Verbose
    Exports the closed cases, including who closed them and when.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : eDiscovery Manager role group (Security & Compliance PowerShell). An eDiscovery Manager only sees the cases
                  they are a member of; an eDiscovery Administrator sees every case.
    Category    : eDiscovery & content search
    Changes     : No
    Notes       : eDiscovery (Premium) cases need Microsoft 365 E5 / E5 Compliance licensing. Search counts only include
                  searches exposed by Get-ComplianceSearch; Premium collections created in the Purview portal may not be
                  listed. LastActivity is an approximation based on hold and search timestamps, not on review activity.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-compliancecase
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-compliancecasemember
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Active', 'Closed')]
    [string]$Status,

    [Parameter()]
    [switch]$OnlyStaleOpen,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 180,

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

function ConvertTo-NullableDate {
    <# Returns the value as [datetime], or $null when it is empty, so CSV columns stay blank instead of showing 01/01/0001. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { return [datetime]$Value } catch { return $null }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewEDiscoveryCases_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-ExchangeIfNeeded -Compliance
}
catch {
    throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)"
}

# Get-ComplianceCase returns one case type per call; Standard and Premium cases live in different types.
$cases = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($caseType in 'eDiscovery', 'AdvancedEdiscovery') {
    try {
        foreach ($case in @(Get-ComplianceCase -CaseType $caseType -ErrorAction Stop)) { $cases.Add($case) }
    }
    catch {
        Write-Warning ('Could not list {0} cases: {1}' -f $caseType, $_.Exception.Message)
    }
}
if ($PSBoundParameters.ContainsKey('Status')) { $cases = @($cases | Where-Object { $_.Status -eq $Status }) }
if ($OnlyStaleOpen) { $cases = @($cases | Where-Object { $_.Status -eq 'Active' }) }
$cases = @($cases)
if ($cases.Count -eq 0) { Write-Warning 'No eDiscovery cases were returned for the given filters.' }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($case in $cases) {
    $index++
    Write-Progress -Activity 'Collecting eDiscovery case details' -Status ('{0} of {1}: {2}' -f $index, $cases.Count, $case.Name) -PercentComplete ([int](($index / $cases.Count) * 100))
    $members = @(); $holds = @(); $searches = @()
    try { $members = @(Get-ComplianceCaseMember -Case $case.Identity -ResultSize Unlimited -ErrorAction Stop) }
    catch { Write-Warning ("Could not read the members of case '{0}': {1}" -f $case.Name, $_.Exception.Message) }
    try { $holds = @(Get-CaseHoldPolicy -Case $case.Identity -ErrorAction Stop) }
    catch { Write-Warning ("Could not read the holds of case '{0}': {1}" -f $case.Name, $_.Exception.Message) }
    try { $searches = @(Get-ComplianceSearch -Case $case.Name -ResultSize Unlimited -ErrorAction Stop) }
    catch { Write-Warning ("Could not read the searches of case '{0}': {1}" -f $case.Name, $_.Exception.Message) }

    # Case members are recipient objects; prefer the UPN, then the SMTP address, then the name.
    $memberNames = @(foreach ($member in $members) {
            $label = [string]$member.WindowsLiveID
            if ([string]::IsNullOrWhiteSpace($label)) { $label = [string]$member.PrimarySmtpAddress }
            if ([string]::IsNullOrWhiteSpace($label)) { $label = [string]$member.Name }
            $label
        })
    # LastActivity = newest of the creation date and every hold/search timestamp; invalid or empty values are ignored.
    $activityDates = @($case.CreatedDateTime) + @($holds | ForEach-Object { $_.WhenChanged }) + @($searches | ForEach-Object { $_.LastModifiedTime; $_.JobStartTime })
    $lastActivity = $null
    foreach ($value in $activityDates) {
        $date = ConvertTo-NullableDate -Value $value
        if ($null -ne $date -and ($null -eq $lastActivity -or $date -gt $lastActivity)) { $lastActivity = $date }
    }
    $daysSinceActivity = $null
    if ($null -ne $lastActivity) { $daysSinceActivity = [int]((Get-Date) - $lastActivity).TotalDays }

    $results.Add([PSCustomObject]@{
            Name              = [string]$case.Name
            Identity          = [string]$case.Identity
            CaseType          = [string]$case.CaseType
            Status            = [string]$case.Status
            CreatedDateTime   = ConvertTo-NullableDate -Value $case.CreatedDateTime
            ClosedDateTime    = ConvertTo-NullableDate -Value $case.ClosedDateTime
            ClosedBy          = [string]$case.ClosedBy
            Description       = [string]$case.Description
            ExternalId        = [string]$case.ExternalId
            MemberCount       = $members.Count
            Members           = ($memberNames -join '; ')
            HoldCount         = $holds.Count
            SearchCount       = $searches.Count
            LastActivity      = $lastActivity
            DaysSinceActivity = $daysSinceActivity
            IsStale           = ($case.Status -eq 'Active' -and $null -ne $daysSinceActivity -and $daysSinceActivity -ge $StaleDays)
        })
}
Write-Progress -Activity 'Collecting eDiscovery case details' -Completed

if ($OnlyStaleOpen) { $results = @($results | Where-Object { $_.IsStale }) }
$results = @($results | Sort-Object -Property CaseType, Name)
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}

Write-Host ''
Write-Host 'eDiscovery case summary' -ForegroundColor Cyan
Write-Host ('  Cases reported      : {0}' -f $results.Count)
foreach ($group in ($results | Group-Object -Property CaseType, Status | Sort-Object -Property Name)) {
    Write-Host ('    {0,5}  {1}' -f $group.Count, $group.Name)
}
$staleCount = @($results | Where-Object { $_.IsStale }).Count
Write-Host ('  Stale open cases    : {0} (no activity for {1}+ days)' -f $staleCount, $StaleDays) -ForegroundColor $(if ($staleCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Cases without holds : {0}' -f @($results | Where-Object { $_.HoldCount -eq 0 }).Count)
if ($results.Count -gt 0) { Write-Host ('  Report              : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
