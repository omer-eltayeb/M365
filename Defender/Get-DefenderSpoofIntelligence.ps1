<#
.SYNOPSIS
    Reports the senders that spoof intelligence allowed or blocked, joined with the spoofed sender overrides, and flags the risky ones.
.DESCRIPTION
    Reads the spoof intelligence insight (Get-SpoofIntelligenceInsight: spoofed user, sending infrastructure, spoof type,
    action, message count, last seen) and the admin overrides in the Tenant Allow/Block List
    (Get-TenantAllowBlockListSpoofItems), matches them on spoofed user + sending infrastructure and writes one row per
    pair to CSV. Flags: HighVolumeInternalSpoofBlocked (a service sending as your own domain without SPF/DKIM alignment,
    at least -MinimumMessages messages), ExternalSpoofAllowed (an external domain is allowed to be spoofed),
    HighVolumeExternalSpoofBlocked (likely campaign) and OverrideWithoutRecentTraffic (stale override worth removing).
.PARAMETER MinimumMessages
    Message count from which a blocked spoof pair is considered high volume. Default 10.
.PARAMETER SpoofType
    Only report Internal (your domains) or External (other domains) spoof pairs.
.PARAMETER Action
    Only report pairs that were allowed (Allow) or blocked (Block) by spoof intelligence.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderSpoofIntelligence_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderSpoofIntelligence.ps1
    Exports every spoof pair with its override state and prints the blocked internal senders that most likely need SPF/DKIM fixes.
.EXAMPLE
    PS> .\Get-DefenderSpoofIntelligence.ps1 -SpoofType Internal -Action Block -MinimumMessages 50 -PassThru | Where-Object { $_.Flags -ne '' }
    Returns only high-volume blocked internal spoof pairs - typically line-of-business applications or printers sending as the company domain.
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
    Notes       : The insight only contains recent detections (Microsoft documents a 30 day window); it is empty when spoof
                  intelligence is disabled in the anti-phishing policy. Blocked internal spoof from a legitimate service is best
                  fixed at the source (add the sender to SPF, sign with DKIM); an override is the fallback and is created with
                  New-TenantAllowBlockListSpoofItems -Action Allow -SpoofType Internal -SpoofedUser <user> -SendingInfrastructure <domain or IP>.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-spoofintelligenceinsight
.LINK
    https://learn.microsoft.com/defender-office-365/anti-spoofing-spoof-intelligence
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 100000)]
    [int]$MinimumMessages = 10,

    [Parameter()]
    [ValidateSet('Internal', 'External')]
    [string]$SpoofType,

    [Parameter()]
    [ValidateSet('Allow', 'Block')]
    [string]$Action,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderSpoofIntelligence_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-ExchangeIfNeeded
    $insights = @(Get-SpoofIntelligenceInsight -ErrorAction Stop)
}
catch {
    throw "Unable to read the spoof intelligence insight from Exchange Online: $($_.Exception.Message)"
}
$overrides = @{}
try {
    foreach ($item in @(Get-TenantAllowBlockListSpoofItems -ErrorAction Stop)) {
        $overrides[('{0}|{1}' -f $item.SpoofedUser, $item.SendingInfrastructure).ToLowerInvariant()] = $item
    }
}
catch {
    Write-Warning "Could not read the spoofed sender overrides; the OverrideAction column stays empty: $($_.Exception.Message)"
}
Write-Verbose "$($insights.Count) insight row(s) and $($overrides.Count) override(s) read."

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$matchedOverrides = @{}
$index = 0
foreach ($insight in $insights) {
    $index++
    if ($index % 100 -eq 0) { Write-Progress -Activity 'Evaluating spoof pairs' -PercentComplete (($index / $insights.Count) * 100) }
    $pairType = [string]$insight.SpoofType
    $pairAction = [string]$insight.Action
    if ($PSBoundParameters.ContainsKey('SpoofType') -and $pairType -ne $SpoofType) { continue }
    if ($PSBoundParameters.ContainsKey('Action') -and $pairAction -notlike "$Action*") { continue }

    $key = ('{0}|{1}' -f $insight.SpoofedUser, $insight.SendingInfrastructure).ToLowerInvariant()
    $override = $overrides[$key]
    if ($null -ne $override) { $matchedOverrides[$key] = $true }
    $messageCount = 0
    if ($null -ne $insight.MessageCount) { $messageCount = [int]$insight.MessageCount }
    # The service reports Block/Blocked and Allow/Allowed depending on the module version, so match on the prefix.
    $isBlocked = ($pairAction -like 'Block*')
    $isInternal = ($pairType -eq 'Internal')

    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ($isBlocked -and $isInternal -and $messageCount -ge $MinimumMessages) { $flags.Add('HighVolumeInternalSpoofBlocked') }
    if ($isBlocked -and -not $isInternal -and $messageCount -ge $MinimumMessages) { $flags.Add('HighVolumeExternalSpoofBlocked') }
    if (-not $isBlocked -and -not $isInternal) { $flags.Add('ExternalSpoofAllowed') }
    if ($null -ne $override -and ([string]$override.Action -like 'Allow*') -ne (-not $isBlocked)) { $flags.Add('OverrideDisagreesWithInsight') }

    $rows.Add([PSCustomObject]@{
            Source                = 'Insight'
            SpoofedUser           = [string]$insight.SpoofedUser
            SendingInfrastructure = [string]$insight.SendingInfrastructure
            SpoofType             = $pairType
            Action                = $pairAction
            MessageCount          = $messageCount
            LastSeen              = $(if ($null -ne $insight.LastSeen) { [datetime]$insight.LastSeen } else { $null })
            OverrideAction        = $(if ($null -ne $override) { [string]$override.Action } else { $null })
            Flags                 = ($flags -join ';')
        })
}
Write-Progress -Activity 'Evaluating spoof pairs' -Completed

# Overrides that no longer see traffic are candidates for removal - especially allow entries.
foreach ($key in @($overrides.Keys | Where-Object { -not $matchedOverrides.ContainsKey($_) })) {
    $override = $overrides[$key]
    if ($PSBoundParameters.ContainsKey('SpoofType') -and [string]$override.SpoofType -ne $SpoofType) { continue }
    if ($PSBoundParameters.ContainsKey('Action') -and [string]$override.Action -notlike "$Action*") { continue }
    $rows.Add([PSCustomObject]@{
            Source                = 'Override'
            SpoofedUser           = [string]$override.SpoofedUser
            SendingInfrastructure = [string]$override.SendingInfrastructure
            SpoofType             = [string]$override.SpoofType
            Action                = [string]$override.Action
            MessageCount          = $null
            LastSeen              = $null
            OverrideAction        = [string]$override.Action
            Flags                 = 'OverrideWithoutRecentTraffic'
        })
}

if ($rows.Count -gt 0) {
    $rows | Sort-Object -Property @{ Expression = 'MessageCount'; Descending = $true }, SpoofedUser | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}

Write-Host ''
Write-Host ('Spoof intelligence summary - {0} pair(s)' -f $rows.Count) -ForegroundColor Cyan
foreach ($group in ($rows | Where-Object { $_.Source -eq 'Insight' } | Group-Object -Property SpoofType, Action | Sort-Object -Property Name)) {
    Write-Host ('  {0,-22} {1,6}' -f $group.Name, $group.Count)
}
foreach ($flag in @('HighVolumeInternalSpoofBlocked', 'ExternalSpoofAllowed', 'HighVolumeExternalSpoofBlocked', 'OverrideDisagreesWithInsight', 'OverrideWithoutRecentTraffic')) {
    $count = @($rows | Where-Object { $_.Flags -match $flag }).Count
    Write-Host ('  {0,-32} {1,6}' -f $flag, $count) -ForegroundColor $(if ($count -gt 0) { 'Yellow' } else { 'Green' })
}
$topInternal = @($rows | Where-Object { $_.Flags -match 'HighVolumeInternalSpoofBlocked' } | Sort-Object -Property MessageCount -Descending | Select-Object -First 5)
if ($topInternal.Count -gt 0) {
    Write-Host '  Blocked internal spoof with the most messages (check SPF/DKIM for these sources):' -ForegroundColor Cyan
    foreach ($row in $topInternal) { Write-Host ('    {0,-40} via {1,-40} {2,7}' -f $row.SpoofedUser, $row.SendingInfrastructure, $row.MessageCount) }
}
if ($rows.Count -gt 0) { Write-Host ('  Report: {0}' -f $OutputPath) }

if ($PassThru) { $rows }
#endregion Main
