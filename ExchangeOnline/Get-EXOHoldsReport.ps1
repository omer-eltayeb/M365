<#
.SYNOPSIS
    Reports every hold applied to Exchange Online mailboxes and decodes the InPlaceHolds identifiers.
.DESCRIPTION
    Reads hold-related properties with Get-EXOMailbox: litigation hold (date, owner, duration), retention hold, the
    InPlaceHolds collection, compliance tag hold, delay holds and ElcProcessingDisabled. Each InPlaceHolds entry is
    decoded using the Microsoft prefix scheme: UniH = eDiscovery (Premium) case hold, cld = eDiscovery (Standard) case
    hold, mbx/skp/grp = Purview retention policy (suffix :1 retain, :2 delete, :3 retain then delete), -mbx = excluded
    from an org-wide retention policy, bare GUID = legacy In-Place Hold. Org-wide retention policies are counted from
    Get-OrganizationConfig because they do not appear on individual mailboxes. Writes a CSV report.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) to report instead of all mailboxes.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER RecipientTypeDetails
    Mailbox types to include. Default: UserMailbox and SharedMailbox.
.PARAMETER IncludeInactiveMailbox
    Also include inactive mailboxes (deleted users whose mailbox is kept by a hold) via Get-EXOMailbox -IncludeInactiveMailbox.
.PARAMETER OnlyWithHolds
    Export only mailboxes that have at least one hold (litigation, retention, Purview, eDiscovery, legacy or delay hold).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOMailboxHolds_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOHoldsReport.ps1 -OnlyWithHolds
    Lists every user and shared mailbox with at least one hold and writes .\Reports\EXOMailboxHolds_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOHoldsReport.ps1 -IncludeInactiveMailbox -PassThru | Where-Object { $_.IsInactiveMailbox } | Format-Table UserPrincipalName, InPlaceHoldsDecoded
    Shows which holds keep each inactive mailbox alive - release them (or wait for them to expire) before the mailbox can be purged.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients or Global Reader (the report is read-only)
    Category    : Mailbox lifecycle & compliance
    Changes     : No
    Notes       : No per-mailbox calls, so the run is fast even for large tenants. To resolve a GUID to a policy name connect to
                  Security & Compliance PowerShell: Get-RetentionCompliancePolicy <GUID> -DistributionDetail (mbx/skp/grp),
                  Get-CaseHoldPolicy <GUID> (UniH/cld) or Get-MailboxSearch -InPlaceHoldIdentity <GUID> (legacy In-Place Hold).
                  DelayHoldApplied means a hold was removed within the last 30 days and the content is still being preserved.
.LINK
    https://learn.microsoft.com/purview/ediscovery-identify-a-hold-on-an-exchange-online-mailbox
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
    [ValidateSet('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox')]
    [string[]]$RecipientTypeDetails = @('UserMailbox', 'SharedMailbox'),

    [Parameter()]
    [switch]$IncludeInactiveMailbox,

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

function ConvertFrom-InPlaceHold {
    <# Translates one InPlaceHolds entry into a readable hold type using the prefix scheme documented by Microsoft. #>
    param([Parameter(Mandatory = $true)][string]$Hold)
    if ($Hold -like 'UniH*') { return 'eDiscovery (Premium) case hold' }
    if ($Hold -like 'cld*') { return 'eDiscovery (Standard) case hold' }
    if ($Hold -like '-mbx*') { return 'Excluded from org-wide retention policy' }
    if ($Hold -match '^(mbx|skp|grp)[^:]+(:(\d))?$') {
        $scopes = @{ mbx = 'Exchange'; skp = 'Skype for Business'; grp = 'Microsoft 365 Group' }
        $actions = @{ '1' = 'retain'; '2' = 'delete'; '3' = 'retain then delete'; '' = 'action not specified' }
        return ('Purview retention policy ({0}, {1})' -f $scopes[$Matches[1]], $actions[[string]$Matches[3]])
    }
    return 'Legacy In-Place Hold'
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMailboxHolds_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$orgWideHolds = $null
try { $orgWideHolds = @((Get-OrganizationConfig -ErrorAction Stop).InPlaceHolds | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count }
catch { Write-Warning "Could not read organization-wide holds: $($_.Exception.Message)" }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails', 'IsInactiveMailbox', 'LitigationHoldEnabled', 'LitigationHoldDate',
    'LitigationHoldOwner', 'LitigationHoldDuration', 'RetentionHoldEnabled', 'StartDateForRetentionHold', 'EndDateForRetentionHold', 'InPlaceHolds',
    'ComplianceTagHoldApplied', 'DelayHoldApplied', 'DelayReleaseHoldApplied', 'ElcProcessingDisabled')
$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$getParams = @{ Properties = $mailboxProperties; ErrorAction = 'Stop' }
if ($IncludeInactiveMailbox) { $getParams['IncludeInactiveMailbox'] = $true }
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id @getParams)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    try {
        foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails $RecipientTypeDetails @getParams)) { $mailboxes.Add($mailbox) }
    }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    if ($index % 100 -eq 0) { Write-Progress -Activity 'Decoding holds' -Status "$index of $($mailboxes.Count)" -PercentComplete (($index / $mailboxes.Count) * 100) }
    $holds = @($mailbox.InPlaceHolds | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $purview = @($holds | Where-Object { $_ -match '^(mbx|skp|grp)' }).Count
    $excluded = @($holds | Where-Object { $_ -like '-mbx*' }).Count
    $ediscovery = @($holds | Where-Object { $_ -like 'UniH*' -or $_ -like 'cld*' }).Count
    $legacy = $holds.Count - $purview - $excluded - $ediscovery
    $anyHold = ([bool]$mailbox.LitigationHoldEnabled -or [bool]$mailbox.RetentionHoldEnabled -or ($purview + $ediscovery + $legacy) -gt 0 -or
        [bool]$mailbox.ComplianceTagHoldApplied -or [bool]$mailbox.DelayHoldApplied -or [bool]$mailbox.DelayReleaseHoldApplied)
    if ($OnlyWithHolds -and -not $anyHold) { continue }

    $results.Add([PSCustomObject]@{
            DisplayName              = $mailbox.DisplayName
            UserPrincipalName        = $mailbox.UserPrincipalName
            MailboxType              = [string]$mailbox.RecipientTypeDetails
            IsInactiveMailbox        = [bool]$mailbox.IsInactiveMailbox
            AnyHold                  = $anyHold
            LitigationHold           = [bool]$mailbox.LitigationHoldEnabled
            LitigationHoldDate       = $mailbox.LitigationHoldDate
            LitigationHoldOwner      = [string]$mailbox.LitigationHoldOwner
            LitigationHoldDuration   = [string]$mailbox.LitigationHoldDuration
            RetentionHold            = [bool]$mailbox.RetentionHoldEnabled
            RetentionHoldStart       = $mailbox.StartDateForRetentionHold
            RetentionHoldEnd         = $mailbox.EndDateForRetentionHold
            PurviewRetentionPolicies = $purview
            EDiscoveryHolds          = $ediscovery
            LegacyInPlaceHolds       = $legacy
            ExcludedFromOrgPolicies  = $excluded
            ComplianceTagHold        = [bool]$mailbox.ComplianceTagHoldApplied
            DelayHold                = [bool]$mailbox.DelayHoldApplied
            DelayReleaseHold         = [bool]$mailbox.DelayReleaseHoldApplied
            ElcProcessingDisabled    = [bool]$mailbox.ElcProcessingDisabled
            InPlaceHoldsDecoded      = (@($holds | ForEach-Object { '{0} = {1}' -f $_, (ConvertFrom-InPlaceHold -Hold $_) }) -join '; ')
        })
}
Write-Progress -Activity 'Decoding holds' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes matched; nothing to export.'; return }
$results | Sort-Object -Property @{ Expression = 'AnyHold'; Descending = $true }, DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host "Mailbox holds summary ($($mailboxes.Count) mailboxes read, $($results.Count) exported)" -ForegroundColor Cyan
Write-Host ('  With at least one hold          : {0}' -f @($results | Where-Object { $_.AnyHold }).Count) -ForegroundColor Yellow
Write-Host ('  Litigation hold                 : {0}' -f @($results | Where-Object { $_.LitigationHold }).Count)
Write-Host ('  Retention hold (MRM paused)     : {0}' -f @($results | Where-Object { $_.RetentionHold }).Count)
Write-Host ('  Purview retention (explicit)    : {0}' -f @($results | Where-Object { $_.PurviewRetentionPolicies -gt 0 }).Count)
Write-Host ('  eDiscovery case holds           : {0}' -f @($results | Where-Object { $_.EDiscoveryHolds -gt 0 }).Count)
Write-Host ('  Legacy In-Place Holds           : {0}' -f @($results | Where-Object { $_.LegacyInPlaceHolds -gt 0 }).Count)
Write-Host ('  Delay holds (recently released) : {0}' -f @($results | Where-Object { $_.DelayHold -or $_.DelayReleaseHold }).Count)
Write-Host ('  Inactive mailboxes              : {0}' -f @($results | Where-Object { $_.IsInactiveMailbox }).Count)
if ($null -ne $orgWideHolds) { Write-Host ('  Org-wide retention policies     : {0} (apply to every mailbox; not listed per row)' -f $orgWideHolds) }
Write-Host ('  Report                          : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
