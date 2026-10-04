<#
.SYNOPSIS
    Finds mobile device partnerships that have not synced for a long time and optionally removes them or wipes the account data.
.DESCRIPTION
    Enumerates device partnerships with Get-MobileDevice and reads the last successful sync with Get-EXOMobileDeviceStatistics.
    A device is stale when LastSuccessSync is older than -DaysInactive, or when it never synced and FirstSyncTime (or the
    partnership creation date) is that old. The default run only reports the stale devices. -Remove deletes the partnership
    with Remove-MobileDevice; -Remove -AccountWipe sends an account-only wipe with Clear-MobileDevice -AccountOnly instead.
    Devices with a pending wipe are skipped so the wipe is not cancelled. Every action uses ShouldProcess and is logged to CSV.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) whose devices are evaluated instead of all devices.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes whose devices are evaluated.
.PARAMETER DaysInactive
    Devices without a successful sync for this many days are considered stale. Default: 180.
.PARAMETER Remove
    Remove the stale partnerships (Remove-MobileDevice). Without it the script is read-only.
.PARAMETER AccountWipe
    Used with -Remove: send an account-only wipe (Clear-MobileDevice -AccountOnly) instead of removing the partnership.
.PARAMETER OutputPath
    Path of the CSV log. Defaults to .\Reports\EXOStaleMobileDevices_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\Remove-EXOStaleMobileDevices.ps1 -DaysInactive 365
    Reports every device partnership without a successful sync in the last year; nothing is changed.
.EXAMPLE
    PS> .\Remove-EXOStaleMobileDevices.ps1 -Remove -WhatIf
    Shows which partnerships would be removed with the default 180-day threshold.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator (Organization Client Access role) for -Remove; View-Only Recipients for the report
    Category    : Client access & mobile devices
    Changes     : Optional (-Remove)
    Notes       : Removing a partnership does not touch the device; it simply has to re-partner (and pass quarantine or device
                  access rules again) if it ever syncs. An account-only wipe is executed the next time the device connects, which
                  may never happen for a stale device, so prefer plain removal for clean-ups and the wipe for lost devices.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/remove-mobiledevice
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [ValidateRange(30, 3650)]
    [int]$DaysInactive = 180,

    [Parameter()]
    [switch]$Remove,

    [Parameter()]
    [switch]$AccountWipe,

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
if ($AccountWipe -and -not $Remove) { throw 'Use -AccountWipe together with -Remove; without -Remove the script only reports.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOStaleMobileDevices_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$selection = @($Identity)
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
$devices = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($id in $selection) {
    try { $devices.AddRange(@(Get-MobileDevice -Mailbox $id -ResultSize Unlimited -ErrorAction Stop)) }
    catch { Write-Warning "Devices of mailbox '$id' could not be read: $($_.Exception.Message)" }
}
if ($selection.Count -eq 0) {
    try { $devices.AddRange(@(Get-MobileDevice -ResultSize Unlimited -ErrorAction Stop)) }
    catch { throw "Failed to retrieve mobile devices: $($_.Exception.Message)" }
}

$cutoff = (Get-Date).AddDays(-$DaysInactive)
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Evaluating mobile devices' -Status "$index of $($devices.Count) - $($device.FriendlyName)" -PercentComplete (($index / $devices.Count) * 100)
    $segments = @([string]$device.Identity -split '[\\/]')
    $marker = [array]::IndexOf($segments, 'ExchangeActiveSyncDevices')
    $owner = [string]$device.UserDisplayName
    if ($marker -gt 0) { $owner = $segments[$marker - 1] }
    $target = '{0} - {1} ({2} {3})' -f $owner, $device.FriendlyName, $device.DeviceType, $device.DeviceModel

    $stats = $null
    try { $stats = Get-EXOMobileDeviceStatistics -Identity ([string]$device.Guid) -ErrorAction Stop }
    catch { Write-Warning "Statistics for '$target' could not be read; the device is skipped: $($_.Exception.Message)"; continue }

    # Never-synced partnerships have no LastSuccessSync, so the first sync (or the partnership creation) decides staleness.
    $lastSync = $null
    if (-not [string]::IsNullOrEmpty([string]$stats.LastSuccessSync)) { $lastSync = [datetime]$stats.LastSuccessSync }
    $reference = $lastSync
    $basis = 'LastSuccessSync'
    if ($null -eq $reference -and -not [string]::IsNullOrEmpty([string]$device.FirstSyncTime)) { $reference = [datetime]$device.FirstSyncTime; $basis = 'FirstSyncTime (never synced)' }
    if ($null -eq $reference) { $reference = [datetime]$device.WhenCreated; $basis = 'WhenCreated (never synced)' }
    if ($reference -ge $cutoff) { continue }
    $wipePending = (-not [string]::IsNullOrEmpty([string]$stats.DeviceWipeRequestTime)) -and [string]::IsNullOrEmpty([string]$stats.DeviceWipeAckTime)

    $result = 'Stale - report only'
    if ($wipePending) { $result = 'Skipped - wipe pending' }
    elseif ($Remove -and $AccountWipe) {
        if ($PSCmdlet.ShouldProcess($target, 'Account-only wipe (Clear-MobileDevice -AccountOnly)')) {
            try { Clear-MobileDevice -Identity ([string]$device.Guid) -AccountOnly -Confirm:$false -ErrorAction Stop; $result = 'Account wipe requested' }
            catch { $result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not request the wipe for '$target': $($_.Exception.Message)" }
        }
        else { $result = 'Not confirmed' }
    }
    elseif ($Remove) {
        if ($PSCmdlet.ShouldProcess($target, 'Remove device partnership (Remove-MobileDevice)')) {
            try { Remove-MobileDevice -Identity ([string]$device.Guid) -Confirm:$false -ErrorAction Stop; $result = 'Removed' }
            catch { $result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not remove '$target': $($_.Exception.Message)" }
        }
        else { $result = 'Not confirmed' }
    }

    $results.Add([PSCustomObject]@{
            Owner             = $owner
            FriendlyName      = [string]$device.FriendlyName
            DeviceType        = [string]$device.DeviceType
            DeviceModel       = [string]$device.DeviceModel
            DeviceOS          = [string]$device.DeviceOS
            DeviceAccessState = [string]$device.DeviceAccessState
            FirstSyncTime     = $device.FirstSyncTime
            LastSuccessSync   = $lastSync
            DaysInactive      = [int]((Get-Date) - $reference).TotalDays
            StaleBasis        = $basis
            WipePending       = $wipePending
            DeviceGuid        = [string]$device.Guid
            Result            = $result
        })
}
Write-Progress -Activity 'Evaluating mobile devices' -Completed

if ($results.Count -eq 0) { Write-Host "No stale device partnerships found among $($devices.Count) evaluated (threshold $DaysInactive days)." -ForegroundColor Green; return }
$results | Sort-Object -Property DaysInactive -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$failed = @($results | Where-Object { $_.Result -like 'Failed*' }).Count

Write-Host "Stale mobile device summary ($($devices.Count) partnerships evaluated, threshold $DaysInactive days)" -ForegroundColor Cyan
Write-Host ('  Stale partnerships     : {0}' -f $results.Count) -ForegroundColor Yellow
Write-Host ('  Removed                : {0}' -f @($results | Where-Object { $_.Result -eq 'Removed' }).Count) -ForegroundColor Green
Write-Host ('  Account wipes requested: {0}' -f @($results | Where-Object { $_.Result -eq 'Account wipe requested' }).Count) -ForegroundColor Green
Write-Host ('  Skipped (wipe pending) : {0}' -f @($results | Where-Object { $_.Result -like 'Skipped*' }).Count)
Write-Host ('  Not confirmed          : {0}' -f @($results | Where-Object { $_.Result -eq 'Not confirmed' }).Count)
Write-Host ('  Failed                 : {0}' -f $failed) -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })
if (-not $Remove) { Write-Host '  Report only - re-run with -Remove (optionally -AccountWipe) to act on these devices.' -ForegroundColor Yellow }
Write-Host ('  Log                    : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
