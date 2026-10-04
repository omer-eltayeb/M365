<#
.SYNOPSIS
    Exports the Tenant Allow/Block List (senders, URLs, file hashes, IPv6 addresses and spoofed senders) with expiry and usage flags.
.DESCRIPTION
    Reads every entry of the Defender for Office 365 Tenant Allow/Block List with Get-TenantAllowBlockListItems (list
    types Sender, Url, FileHash and IP) plus the spoofed sender overrides from Get-TenantAllowBlockListSpoofItems and
    writes one row per entry to CSV. Rows are flagged when an allow entry expires within -WarnDays, never expires
    (NoExpiration) or has already expired, and when an entry older than -StaleDays was never matched by the filtering
    stack (empty LastUsedDate), so stale or risky overrides can be reviewed. Counts per list and action are printed.
.PARAMETER ListType
    One or more lists to read: Sender, Url, FileHash, IP and Spoof (spoofed sender overrides). Default: all five.
.PARAMETER ListSubType
    Restrict entries to one sub type: Tenant (regular entries) or AdvancedDelivery (non-Microsoft phishing simulation URLs).
.PARAMETER Action
    Return only Allow or only Block entries. Default: both.
.PARAMETER WarnDays
    Allow entries that expire within this many days are flagged ExpiringSoon. Default 7.
.PARAMETER StaleDays
    Entries last modified more than this many days ago that have never been used are flagged StaleNeverUsed. Default 30.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderTenantAllowBlockList_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderTenantAllowBlockList.ps1
    Exports all sender, URL, file hash, IPv6 and spoofed sender entries and prints counts per list type and action.
.EXAMPLE
    PS> .\Get-DefenderTenantAllowBlockList.ps1 -Action Allow -WarnDays 14 -PassThru | Where-Object { $_.Flags -ne '' }
    Lists only allow entries and returns those that expire within 14 days, never expire or were never used.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Reader, Global Reader or Security Administrator (Exchange Online PowerShell session)
    Category    : Email threat operations
    Changes     : No
    Notes       : Allow entries for senders, URLs and files are normally created through admin submissions and are kept 45
                  days after the last used date, so an allow entry that never expires or is never used deserves a review.
                  LastUsedDate exists only in recent module versions (and can arrive as text); without it the
                  StaleNeverUsed flag is not evaluated. Spoofed sender entries never expire by design.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-tenantallowblocklistitems
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Sender', 'Url', 'FileHash', 'IP', 'Spoof')]
    [string[]]$ListType = @('Sender', 'Url', 'FileHash', 'IP', 'Spoof'),

    [Parameter()]
    [ValidateSet('Tenant', 'AdvancedDelivery')]
    [string]$ListSubType,

    [Parameter()]
    [ValidateSet('Allow', 'Block')]
    [string]$Action,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$WarnDays = 7,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 30,

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
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderTenantAllowBlockList_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

# Collect raw entries first (list name + object) so a single loop below shapes regular and spoof entries the same way.
$collected = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($type in $ListType) {
    $index++
    Write-Progress -Activity 'Reading Tenant Allow/Block List' -Status "$type entries" -PercentComplete (($index / $ListType.Count) * 100)
    try {
        if ($type -eq 'Spoof') {
            $items = @(Get-TenantAllowBlockListSpoofItems -ErrorAction Stop)
        }
        else {
            $listParams = @{ ListType = $type; ErrorAction = 'Stop' }
            if ($PSBoundParameters.ContainsKey('ListSubType')) { $listParams['ListSubType'] = $ListSubType }
            $items = @(Get-TenantAllowBlockListItems @listParams)
        }
        foreach ($item in $items) { $collected.Add([PSCustomObject]@{ Type = $type; Item = $item }) }
    }
    catch {
        Write-Warning "Could not read $type entries: $($_.Exception.Message)"
    }
}
Write-Progress -Activity 'Reading Tenant Allow/Block List' -Completed

$now = Get-Date
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($entry in $collected) {
    $item = $entry.Item
    $isSpoof = ($entry.Type -eq 'Spoof')
    if ($PSBoundParameters.ContainsKey('Action') -and [string]$item.Action -ne $Action) { continue }

    $expires = ConvertTo-DateOrNull -Value $item.ExpirationDate
    $lastModified = ConvertTo-DateOrNull -Value $item.LastModifiedDateTime
    $usageProperty = $item.PSObject.Properties['LastUsedDate']
    $lastUsed = $(if ($null -ne $usageProperty) { ConvertTo-DateOrNull -Value $usageProperty.Value } else { $null })
    $daysUntilExpiry = $(if ($null -ne $expires) { [int][math]::Floor(($expires - $now).TotalDays) } else { $null })

    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ($null -ne $expires -and $expires -lt $now) { $flags.Add('Expired') }
    elseif ([string]$item.Action -eq 'Allow' -and $null -ne $daysUntilExpiry -and $daysUntilExpiry -le $WarnDays) { $flags.Add('ExpiringSoon') }
    if (-not $isSpoof -and [string]$item.Action -eq 'Allow' -and $null -eq $expires) { $flags.Add('NoExpiration') }
    if ($null -ne $usageProperty -and $null -eq $lastUsed -and $null -ne $lastModified -and $lastModified -lt $now.AddDays(-$StaleDays)) { $flags.Add('StaleNeverUsed') }

    $rows.Add([PSCustomObject]@{
            ListType              = $entry.Type
            Entry                 = $(if ($isSpoof) { '{0} via {1}' -f $item.SpoofedUser, $item.SendingInfrastructure } else { [string]$item.Value })
            Action                = [string]$item.Action
            ListSubType           = [string]$item.ListSubType
            SpoofedUser           = $(if ($isSpoof) { [string]$item.SpoofedUser } else { $null })
            SendingInfrastructure = $(if ($isSpoof) { [string]$item.SendingInfrastructure } else { $null })
            SpoofType             = $(if ($isSpoof) { [string]$item.SpoofType } else { $null })
            ExpirationDate        = $expires
            DaysUntilExpiry       = $daysUntilExpiry
            NoExpiration          = ($null -eq $expires)
            LastUsedDate          = $lastUsed
            LastModified          = $lastModified
            Notes                 = [string]$item.Notes
            SubmissionId          = [string]$item.SubmissionID
            Flags                 = ($flags -join ';')
        })
}

if ($rows.Count -gt 0) {
    $rows | Sort-Object -Property ListType, Action, Entry | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}

$expiringSoon = @($rows | Where-Object { $_.Flags -match 'ExpiringSoon' }).Count
$noExpiry = @($rows | Where-Object { $_.Flags -match 'NoExpiration' }).Count
Write-Host ''
Write-Host 'Tenant Allow/Block List summary' -ForegroundColor Cyan
foreach ($group in ($rows | Group-Object -Property ListType, Action | Sort-Object -Property Name)) {
    Write-Host ('  {0,-26} {1,6}' -f $group.Name, $group.Count)
}
Write-Host ('  Total entries                   : {0}' -f $rows.Count)
Write-Host ('  Allow expiring within {0,3} days   : {1}' -f $WarnDays, $expiringSoon) -ForegroundColor $(if ($expiringSoon -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Allow without expiry            : {0}' -f $noExpiry) -ForegroundColor $(if ($noExpiry -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Never used, older than {0,3} days : {1}' -f $StaleDays, @($rows | Where-Object { $_.Flags -match 'StaleNeverUsed' }).Count)
if ($rows.Count -gt 0) { Write-Host ('  Report                          : {0}' -f $OutputPath) }

if ($PassThru) { $rows }
#endregion Main
