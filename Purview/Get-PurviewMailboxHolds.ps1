<#
.SYNOPSIS
    Decodes every hold on Exchange Online mailboxes (litigation, eDiscovery, retention policies, label and delay holds) into named rows.
.DESCRIPTION
    Reads mailboxes with Get-EXOMailbox (hold properties only) plus the organization-wide holds from Get-OrganizationConfig
    and decodes each InPlaceHolds entry: UniH = eDiscovery hold; mbx/skp/grp/cld = Purview retention policy for Exchange,
    Skype, Groups or an Exchange location, with suffix :1 delete (or label policy), :2 retain, :3 retain then delete;
    a leading '-' = excluded from an org-wide policy; a bare GUID = eDiscovery hold or legacy In-Place Hold. GUIDs are
    resolved to names with Get-RetentionCompliancePolicy and Get-CaseHoldPolicy (cached). One row per mailbox and hold
    (plus litigation, retention-label and delay holds) with all mailbox hold flags is written to CSV. Read-only.
.PARAMETER Identity
    One or more mailbox identities (UPN, alias, GUID). When omitted every mailbox in the tenant is processed.
.PARAMETER OnlyWithHolds
    Skip the 'None' rows for mailboxes without any hold.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewMailboxHolds_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the hold rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewMailboxHolds.ps1 -Identity alex@contoso.com
    Lists every hold on one mailbox - the first step before you can change or remove it.
.EXAMPLE
    PS> .\Get-PurviewMailboxHolds.ps1 -OnlyWithHolds -PassThru | Where-Object { $_.HoldType -eq 'eDiscoveryHold' } | Select-Object Mailbox, PolicyName -Unique
    Shows which mailboxes are on an eDiscovery case hold and the name of the hold.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients (Exchange Online) plus View-Only Retention Management and eDiscovery Manager or
                  View-Only Case in Security & Compliance PowerShell (to resolve policy and case hold names)
    Category    : Retention & records management
    Changes     : No
    Notes       : Opens an Exchange Online session and a Security & Compliance session. Org-wide mbx/skp/cld policies are
                  reported for user and shared mailboxes, grp policies only for group mailboxes (add -GroupMailbox to the
                  Get-EXOMailbox call to include those). Teams chat, Copilot and Viva Engage policies are not stamped on
                  mailboxes (see Get-AppRetentionCompliancePolicy). ComplianceTagHoldApplied stays True after the last
                  labelled item is gone; delay holds expire 30 days after a hold is removed and can be cleared earlier with
                  Set-Mailbox -RemoveDelayHoldApplied / -RemoveDelayReleaseHoldApplied (Legal Hold role).
.LINK
    https://learn.microsoft.com/purview/edisc-hold-types-mailboxes
.LINK
    https://learn.microsoft.com/powershell/module/exchangepowershell/get-exomailbox
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Identity,

    [Parameter()]
    [switch]$OnlyWithHolds,

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

function ConvertFrom-HoldId {
    <# Decodes one InPlaceHolds entry (type, 32-character GUID, action, exclusion) and resolves its policy or case hold name through $script:nameCache. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$HoldId)
    $info = [PSCustomObject]@{ HoldId = $HoldId; HoldType = 'Unknown'; Guid = $null; PolicyName = $null; Action = $null; Excluded = $HoldId.StartsWith('-') }
    $value = $HoldId.TrimStart('-')
    $typeByPrefix = @{ UniH = 'eDiscoveryHold'; mbx = 'RetentionPolicy-Exchange'; skp = 'RetentionPolicy-Skype'; grp = 'RetentionPolicy-Groups'; cld = 'RetentionPolicy-ExchangeLocation' }
    $actionBySuffix = @{ '1' = 'Delete (or label policy)'; '2' = 'Retain'; '3' = 'RetainThenDelete' }
    if ($value -match '^(?<prefix>UniH|mbx|skp|grp|cld)(?<guid>[0-9a-fA-F-]{32,36})(?::(?<action>\d))?$') {
        $info.HoldType = $typeByPrefix[$Matches['prefix']]
        $info.Guid = ($Matches['guid'] -replace '-', '').ToLowerInvariant()
        if ($Matches['action']) { $info.Action = $actionBySuffix[$Matches['action']] }
    }
    elseif ($value -match '^[0-9a-fA-F-]{32,36}$') {
        $info.HoldType = 'eDiscoveryHoldOrInPlaceHold'
        $info.Guid = ($value -replace '-', '').ToLowerInvariant()
    }
    if ($info.Excluded) { $info.Action = 'ExcludedFromPolicy' }
    if ($null -ne $info.Guid) {
        if (-not $script:nameCache.ContainsKey($info.Guid) -and $info.HoldType -like 'eDiscovery*') {
            try { $script:nameCache[$info.Guid] = [string](Get-CaseHoldPolicy -Identity ([guid]$info.Guid).ToString() -ErrorAction Stop).Name }
            catch { $script:nameCache[$info.Guid] = $null; Write-Verbose "No case hold policy found for $($info.Guid): $($_.Exception.Message)" }
        }
        $info.PolicyName = $script:nameCache[$info.Guid]
        if ($info.HoldType -eq 'eDiscoveryHoldOrInPlaceHold') { $info.HoldType = $(if ($info.PolicyName) { 'eDiscoveryHold' } else { 'InPlaceHold (legacy)' }) }
    }
    return $info
}

function New-HoldRow {
    <# Builds one report row for a mailbox hold; the mailbox-level hold flags are repeated on every row. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Mailbox, [Parameter()][string]$HoldId, [Parameter(Mandatory = $true)][string]$HoldType,
        [Parameter()][string]$PolicyName, [Parameter()][string]$Action, [Parameter(Mandatory = $true)][string]$Scope
    )
    return [PSCustomObject]@{
        Mailbox                  = [string]$Mailbox.UserPrincipalName
        DisplayName              = [string]$Mailbox.DisplayName
        RecipientTypeDetails     = [string]$Mailbox.RecipientTypeDetails
        HoldId                   = $HoldId
        HoldType                 = $HoldType
        PolicyName               = $PolicyName
        Action                   = $Action
        Scope                    = $Scope
        LitigationHoldEnabled    = [bool]$Mailbox.LitigationHoldEnabled
        LitigationHoldDate       = $Mailbox.LitigationHoldDate
        LitigationHoldDuration   = [string]$Mailbox.LitigationHoldDuration
        ComplianceTagHoldApplied = [bool]$Mailbox.ComplianceTagHoldApplied
        DelayHoldApplied         = [bool]$Mailbox.DelayHoldApplied
        DelayReleaseHoldApplied  = [bool]$Mailbox.DelayReleaseHoldApplied
        RetentionHoldEnabled     = [bool]$Mailbox.RetentionHoldEnabled
        ElcProcessingDisabled    = [bool]$Mailbox.ElcProcessingDisabled
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewMailboxHolds_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded; Connect-ExchangeIfNeeded -Compliance }
catch { throw "Unable to connect to Exchange Online / Security & Compliance PowerShell: $($_.Exception.Message)" }

$holdProperties = @('InPlaceHolds', 'LitigationHoldEnabled', 'LitigationHoldDate', 'LitigationHoldDuration', 'ComplianceTagHoldApplied',
    'DelayHoldApplied', 'DelayReleaseHoldApplied', 'RetentionHoldEnabled', 'ElcProcessingDisabled')
try {
    if ($Identity) { $mailboxes = @(foreach ($id in $Identity) { Get-EXOMailbox -Identity $id -Properties $holdProperties -ErrorAction Stop }) }
    else { $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -Properties $holdProperties -ErrorAction Stop) }
}
catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }

# Retention policy names are loaded once; case holds are resolved on demand (both keyed by the 32-character GUID).
$script:nameCache = @{}
try { foreach ($policy in @(Get-RetentionCompliancePolicy -ErrorAction Stop)) { $script:nameCache[([guid]$policy.Guid).ToString('N')] = [string]$policy.Name } }
catch { Write-Warning "Could not read retention policies; policy names will stay empty: $($_.Exception.Message)" }
try { $orgHolds = @((Get-OrganizationConfig -ErrorAction Stop).InPlaceHolds | Where-Object { $_ } | ForEach-Object { ConvertFrom-HoldId -HoldId ([string]$_) }) }
catch { $orgHolds = @(); Write-Warning "Could not read organization-wide holds: $($_.Exception.Message)" }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    Write-Progress -Activity 'Decoding mailbox holds' -Status $mailbox.UserPrincipalName -PercentComplete ([int](100 * $index / [math]::Max(1, $mailboxes.Count)))
    $mailboxRows = New-Object -TypeName System.Collections.Generic.List[object]
    $ownHolds = @($mailbox.InPlaceHolds | Where-Object { $_ } | ForEach-Object { ConvertFrom-HoldId -HoldId ([string]$_) })
    foreach ($hold in $ownHolds) {
        $mailboxRows.Add((New-HoldRow -Mailbox $mailbox -HoldId $hold.HoldId -HoldType $hold.HoldType -PolicyName $hold.PolicyName -Action $hold.Action -Scope 'Mailbox'))
    }
    # Org-wide policies apply unless the mailbox carries the '-<guid>' exclusion; grp policies only cover group mailboxes.
    $excludedGuids = @($ownHolds | Where-Object { $_.Excluded } | ForEach-Object { $_.Guid })
    $isGroupMailbox = ([string]$mailbox.RecipientTypeDetails -eq 'GroupMailbox')
    foreach ($hold in $orgHolds) {
        if ($hold.Excluded -or $excludedGuids -contains $hold.Guid -or (($hold.HoldType -eq 'RetentionPolicy-Groups') -ne $isGroupMailbox)) { continue }
        $mailboxRows.Add((New-HoldRow -Mailbox $mailbox -HoldId $hold.HoldId -HoldType $hold.HoldType -PolicyName $hold.PolicyName -Action $hold.Action -Scope 'OrgWide'))
    }
    if ($mailbox.LitigationHoldEnabled) { $mailboxRows.Add((New-HoldRow -Mailbox $mailbox -HoldType 'LitigationHold' -Action 'Retain' -Scope 'Mailbox')) }
    if ($mailbox.ComplianceTagHoldApplied) { $mailboxRows.Add((New-HoldRow -Mailbox $mailbox -HoldType 'RetentionLabelHold' -Action 'Retain (labelled items)' -Scope 'Mailbox')) }
    if ($mailbox.DelayHoldApplied) { $mailboxRows.Add((New-HoldRow -Mailbox $mailbox -HoldType 'DelayHold' -Action 'Retain Outlook items 30 days after hold removal' -Scope 'Mailbox')) }
    if ($mailbox.DelayReleaseHoldApplied) { $mailboxRows.Add((New-HoldRow -Mailbox $mailbox -HoldType 'DelayReleaseHold' -Action 'Retain cloud items 30 days after hold removal' -Scope 'Mailbox')) }
    if ($mailboxRows.Count -eq 0 -and -not $OnlyWithHolds) { $mailboxRows.Add((New-HoldRow -Mailbox $mailbox -HoldType 'None' -Scope 'Mailbox')) }
    $rows.AddRange($mailboxRows)
}
Write-Progress -Activity 'Decoding mailbox holds' -Completed

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

$heldMailboxes = @($rows | Where-Object { $_.HoldType -ne 'None' } | Select-Object -ExpandProperty Mailbox -Unique).Count
$delayMailboxes = @($mailboxes | Where-Object { $_.DelayHoldApplied -or $_.DelayReleaseHoldApplied }).Count
Write-Host "`nMailbox hold summary" -ForegroundColor Cyan
Write-Host ('  Mailboxes scanned          : {0} ({1} with at least one hold)' -f $mailboxes.Count, $heldMailboxes)
Write-Host ('  Organization-wide policies : {0}' -f @($orgHolds | Where-Object { -not $_.Excluded }).Count)
foreach ($group in ($rows | Where-Object { $_.HoldType -ne 'None' } | Group-Object -Property HoldType | Sort-Object -Property Name)) {
    Write-Host ('    {0,-32} : {1} rows on {2} mailboxes' -f $group.Name, $group.Count, @($group.Group | Select-Object -ExpandProperty Mailbox -Unique).Count)
}
Write-Host ('  Delay holds                : {0} mailboxes (30-day safety hold after another hold was removed, not a policy)' -f $delayMailboxes)
Write-Host ('  Report                     : {0}' -f $OutputPath)

if ($PassThru) {
    $rows
}
#endregion Main
