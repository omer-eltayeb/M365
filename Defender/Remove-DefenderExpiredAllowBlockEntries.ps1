<#
.SYNOPSIS
    Reports (and with -Remove deletes) expired, aged or explicitly named entries in the Tenant Allow/Block List.
.DESCRIPTION
    Reads the Defender for Office 365 Tenant Allow/Block List with Get-TenantAllowBlockListItems and selects clean-up
    candidates: entries whose expiration date passed more than -GraceDays ago, allow entries last modified more than
    -RemoveAllowsOlderThanDays ago, or the exact values given with -Entries. The candidates are written to CSV and
    nothing is deleted unless -Remove is used; removal then runs Remove-TenantAllowBlockListItems in batches of 20 per
    list type under ShouldProcess, and a rejected batch is retried one value at a time.
.PARAMETER ListType
    List types to scan: Sender, Url, FileHash, IP. Default: all four. Exactly one type is required with -Entries.
.PARAMETER GraceDays
    Only treat an entry as expired when its expiration date is more than this many days in the past. Default 0.
.PARAMETER RemoveAllowsOlderThanDays
    Also select allow entries (any expiry) that were last modified more than this many days ago.
.PARAMETER Entries
    Explicit values to remove (exact Value as shown by Get-TenantAllowBlockListItems). Replaces the expiry-based selection.
.PARAMETER Remove
    Perform the removal. Without this switch the script only reports the candidates.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderAllowBlockCleanup_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the candidate objects (with their final Status) to the pipeline.
.EXAMPLE
    PS> .\Remove-DefenderExpiredAllowBlockEntries.ps1 -RemoveAllowsOlderThanDays 90
    Lists expired entries and allow entries older than 90 days without removing anything.
.EXAMPLE
    PS> .\Remove-DefenderExpiredAllowBlockEntries.ps1 -ListType Sender -Entries 'old-vendor.example', 'spam@mail.example' -Remove -WhatIf
    Shows that the two named sender entries would be removed; drop -WhatIf to remove them (add -Confirm:$false to skip the prompt).
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Reader or Global Reader for the report; Security Administrator for -Remove
    Category    : Email threat operations
    Changes     : Optional (-Remove)
    Notes       : The service normally purges expired entries on its own; this script catches entries that linger and, more
                  importantly, long-lived allow entries nobody reviews. Spoofed sender entries have no expiry and are not covered.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/remove-tenantallowblocklistitems
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('Sender', 'Url', 'FileHash', 'IP')]
    [string[]]$ListType = @('Sender', 'Url', 'FileHash', 'IP'),

    [Parameter()]
    [ValidateRange(0, 365)]
    [int]$GraceDays = 0,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$RemoveAllowsOlderThanDays,

    [Parameter()]
    [string[]]$Entries,

    [Parameter()]
    [switch]$Remove,

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

function ConvertTo-DateOrNull {
    <# The service returns some dates as [datetime] and others as culture-formatted text (for example "July 31, 2024"). #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) { return $parsed }
    if ([datetime]::TryParse([string]$Value, [ref]$parsed)) { return $parsed }
    return $null
}
#endregion Helpers

#region Main
$explicitMode = $PSBoundParameters.ContainsKey('Entries')
if ($explicitMode -and $ListType.Count -ne 1) { throw 'Specify exactly one -ListType when removing explicit -Entries.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderAllowBlockCleanup_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

$now = Get-Date
$allowCutoff = $(if ($PSBoundParameters.ContainsKey('RemoveAllowsOlderThanDays')) { $now.AddDays(-$RemoveAllowsOlderThanDays) } else { $null })
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($type in $ListType) {
    $index++
    Write-Progress -Activity 'Scanning Tenant Allow/Block List' -Status "$type entries" -PercentComplete (($index / $ListType.Count) * 100)
    try {
        $items = @(Get-TenantAllowBlockListItems -ListType $type -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not read $type entries: $($_.Exception.Message)"
        continue
    }
    foreach ($item in $items) {
        $expires = ConvertTo-DateOrNull -Value $item.ExpirationDate
        $modified = ConvertTo-DateOrNull -Value $item.LastModifiedDateTime
        $reason = $null
        if ($explicitMode) {
            if ($Entries -contains [string]$item.Value) { $reason = 'Explicit' }
        }
        elseif ($null -ne $expires -and $expires -lt $now.AddDays(-$GraceDays)) { $reason = 'Expired' }
        elseif ($null -ne $allowCutoff -and [string]$item.Action -eq 'Allow' -and $null -ne $modified -and $modified -lt $allowCutoff) { $reason = 'AllowOlderThanThreshold' }
        if ($null -eq $reason) { continue }
        $rows.Add([PSCustomObject]@{
                ListType       = $type
                Entry          = [string]$item.Value
                Action         = [string]$item.Action
                ListSubType    = [string]$item.ListSubType
                ExpirationDate = $expires
                LastModified   = $modified
                LastUsedDate   = ConvertTo-DateOrNull -Value $item.LastUsedDate
                Notes          = [string]$item.Notes
                Reason         = $reason
                Status         = $(if ($Remove) { 'Pending' } else { 'ReportOnly' })
                Message        = $null
            })
    }
}
Write-Progress -Activity 'Scanning Tenant Allow/Block List' -Completed
if ($explicitMode) {
    foreach ($missing in @($Entries | Where-Object { @($rows | Select-Object -ExpandProperty Entry) -notcontains $_ })) { Write-Warning "No $($ListType[0]) entry with the value '$missing' exists." }
}
if ($Remove) {
    # Entries are removed per list type (and sub type for phishing simulation URLs); the service rejects a whole batch on one bad value.
    foreach ($group in ($rows | Group-Object -Property ListType, ListSubType)) {
        $items = @($group.Group)
        $params = @{ ListType = $items[0].ListType; ErrorAction = 'Stop' }
        if ($items[0].ListSubType -eq 'AdvancedDelivery') { $params['ListSubType'] = 'AdvancedDelivery' }
        for ($offset = 0; $offset -lt $items.Count; $offset += 20) {
            $batch = @($items[$offset..([math]::Min($offset + 19, $items.Count - 1))])
            $preview = (@($batch | Select-Object -First 5 -ExpandProperty Entry) -join ', ') + $(if ($batch.Count -gt 5) { ', ...' } else { '' })
            if (-not $PSCmdlet.ShouldProcess("$($batch.Count) $($items[0].ListType) entr(y/ies): $preview", 'Remove from the Tenant Allow/Block List')) {
                foreach ($row in $batch) { $row.Status = 'Skipped'; $row.Message = 'Not confirmed (or -WhatIf)' }
                continue
            }
            try {
                Remove-TenantAllowBlockListItems @params -Entries @($batch | Select-Object -ExpandProperty Entry) | Out-Null
                foreach ($row in $batch) { $row.Status = 'Removed' }
            }
            catch {
                Write-Warning "A batch of $($batch.Count) entries was rejected ($($_.Exception.Message)); retrying one value at a time."
                foreach ($row in $batch) {
                    try { Remove-TenantAllowBlockListItems @params -Entries @($row.Entry) | Out-Null; $row.Status = 'Removed' }
                    catch { $row.Status = 'Failed'; $row.Message = $_.Exception.Message }
                }
            }
        }
    }
}

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host ('Tenant Allow/Block List clean-up ({0})' -f $(if ($Remove) { 'removal' } else { 'report only - use -Remove to delete' })) -ForegroundColor Cyan
foreach ($group in ($rows | Group-Object -Property Reason, Status | Sort-Object -Property Name)) {
    Write-Host ('  {0,-36} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $(if ($group.Name -like '*Failed') { 'Red' } else { 'Gray' })
}
Write-Host ('  Candidates                           {0,6}' -f $rows.Count) -ForegroundColor $(if ($rows.Count -gt 0) { 'Yellow' } else { 'Green' })
if ($rows.Count -gt 0) { Write-Host ('  Report: {0}' -f $OutputPath) }

if ($PassThru) { $rows }
#endregion Main
