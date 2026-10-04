<#
.SYNOPSIS
    Reports every mobile device partnership (ActiveSync and Outlook mobile) with owner, platform, access state and last sync.
.DESCRIPTION
    Lists the device partnerships with Get-MobileDevice (owner derived from the Identity path, type, model, OS, user agent,
    access state and reason, client type, first sync, device ID, friendly name) and enriches each with
    Get-EXOMobileDeviceStatistics (last successful sync, last sync attempt, status, wipe request time, policy applied and
    policy status). Devices whose last successful sync is older than -StaleDays are flagged. The organization ActiveSync
    access settings (DefaultAccessLevel, AdminMailRecipients) are printed with a summary by access state, OS and client type.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) whose devices are reported instead of all devices.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes whose devices are reported.
.PARAMETER StaleDays
    Devices without a successful sync for this many days are flagged as stale. Default: 90.
.PARAMETER OnlyBlockedOrQuarantined
    Report only devices whose access state is Blocked or Quarantined.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOMobileDevices_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMobileDevicesReport.ps1
    Reports every device partnership in the tenant and summarises them by access state, OS family and client type.
.EXAMPLE
    PS> .\Get-EXOMobileDevicesReport.ps1 -OnlyBlockedOrQuarantined -StaleDays 30 -Verbose
    Lists only blocked or quarantined devices and flags those that have not synced in the last 30 days.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients + View-Only Configuration (or Global Reader)
    Category    : Client access & mobile devices
    Changes     : No
    Notes       : Get-EXOMobileDeviceStatistics is called once per device, so large tenants take a while (Write-Progress shows the
                  position). Outlook for iOS and Android appears with DeviceType Outlook. Partnerships that never synced have no
                  LastSuccessSync and are judged stale from FirstSyncTime. Use Remove-EXOStaleMobileDevices.ps1 to clean them up.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-mobiledevice
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 90,

    [Parameter()]
    [switch]$OnlyBlockedOrQuarantined,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMobileDevices_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$orgSettings = $null
try { $orgSettings = Get-ActiveSyncOrganizationSettings -ErrorAction Stop }
catch { Write-Warning "Could not read the ActiveSync organization settings: $($_.Exception.Message)" }

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
if ($OnlyBlockedOrQuarantined) {
    $devices = @($devices | Where-Object { [string]$_.DeviceAccessState -in @('Blocked', 'Quarantined') })
}
Write-Verbose "Evaluating $($devices.Count) device partnership(s)."

$cutoff = (Get-Date).AddDays(-$StaleDays)
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Reading mobile device statistics' -Status "$index of $($devices.Count) - $($device.FriendlyName)" -PercentComplete (($index / $devices.Count) * 100)

    # Identity is "<org path>/<owner>/ExchangeActiveSyncDevices/<type>-<id>": the segment before the container is the owner.
    $segments = @([string]$device.Identity -split '[\\/]')
    $marker = [array]::IndexOf($segments, 'ExchangeActiveSyncDevices')
    $owner = [string]$device.UserDisplayName
    if ($marker -gt 0) { $owner = $segments[$marker - 1] }

    $stats = $null
    try { $stats = Get-EXOMobileDeviceStatistics -Identity ([string]$device.Guid) -ErrorAction Stop }
    catch { Write-Warning "Statistics for device '$($device.FriendlyName)' of '$owner' could not be read: $($_.Exception.Message)" }

    $lastSync = $null
    if ($null -ne $stats -and -not [string]::IsNullOrEmpty([string]$stats.LastSuccessSync)) { $lastSync = [datetime]$stats.LastSuccessSync }
    $reference = $lastSync
    if ($null -eq $reference -and -not [string]::IsNullOrEmpty([string]$device.FirstSyncTime)) { $reference = [datetime]$device.FirstSyncTime }
    $daysSinceSync = $null
    if ($null -ne $lastSync) { $daysSinceSync = [int]((Get-Date) - $lastSync).TotalDays }

    $results.Add([PSCustomObject]@{
            Owner                         = $owner
            FriendlyName                  = [string]$device.FriendlyName
            DeviceType                    = [string]$device.DeviceType
            DeviceModel                   = [string]$device.DeviceModel
            DeviceOS                      = [string]$device.DeviceOS
            OsFamily                      = @([string]$device.DeviceOS -split '\s+')[0]
            ClientType                    = [string]$device.ClientType
            DeviceUserAgent               = [string]$device.DeviceUserAgent
            DeviceAccessState             = [string]$device.DeviceAccessState
            DeviceAccessStateReason       = [string]$device.DeviceAccessStateReason
            DeviceId                      = [string]$device.DeviceId
            FirstSyncTime                 = $device.FirstSyncTime
            LastSuccessSync               = $lastSync
            LastSyncAttemptTime           = $(if ($null -ne $stats) { $stats.LastSyncAttemptTime } else { $null })
            DaysSinceLastSync             = $daysSinceSync
            IsStale                       = ($null -ne $reference -and $reference -lt $cutoff)
            Status                        = $(if ($null -ne $stats) { [string]$stats.Status } else { 'Unknown' })
            DevicePolicyApplied           = $(if ($null -ne $stats) { [string]$stats.DevicePolicyApplied } else { '' })
            DevicePolicyApplicationStatus = $(if ($null -ne $stats) { [string]$stats.DevicePolicyApplicationStatus } else { '' })
            DeviceWipeRequestTime         = $(if ($null -ne $stats) { $stats.DeviceWipeRequestTime } else { $null })
            WhenChanged                   = $device.WhenChanged
            DeviceGuid                    = [string]$device.Guid
        })
}
Write-Progress -Activity 'Reading mobile device statistics' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mobile devices were found; nothing to export.'; return }
$results | Sort-Object -Property Owner, FriendlyName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$stale = @($results | Where-Object { $_.IsStale }).Count
$blocked = @($results | Where-Object { $_.DeviceAccessState -in @('Blocked', 'Quarantined') }).Count

Write-Host "Mobile device summary ($($results.Count) partnerships, $(@($results | Select-Object -Property Owner -Unique).Count) owners)" -ForegroundColor Cyan
if ($null -ne $orgSettings) {
    Write-Host ('  Org default access    : {0}' -f [string]$orgSettings.DefaultAccessLevel) -ForegroundColor $(if ([string]$orgSettings.DefaultAccessLevel -eq 'Allow') { 'Yellow' } else { 'Green' })
    Write-Host ('  Quarantine notices to : {0}' -f $(if (@($orgSettings.AdminMailRecipients).Count -gt 0) { @($orgSettings.AdminMailRecipients) -join ', ' } else { '(none)' }))
}
foreach ($property in 'DeviceAccessState', 'OsFamily', 'ClientType') {
    $groups = @($results | Group-Object -Property $property | Sort-Object -Property Count -Descending | Select-Object -First 6)
    $text = @($groups | ForEach-Object { '{0}={1}' -f $(if ([string]::IsNullOrEmpty($_.Name)) { '(blank)' } else { $_.Name }), $_.Count }) -join ', '
    Write-Host ('  {0,-22}: {1}' -f $property, $text)
}
Write-Host ('  Blocked or quarantined: {0}' -f $blocked) -ForegroundColor $(if ($blocked -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  {0,-22}: {1}' -f "Stale (> $StaleDays days)", $stale) -ForegroundColor $(if ($stale -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Report                : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
