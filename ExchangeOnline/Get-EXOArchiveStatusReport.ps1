<#
.SYNOPSIS
    Reports In-Place Archive status, size, quota usage and retention policy coverage for Exchange Online mailboxes.
.DESCRIPTION
    Enumerates user and shared mailboxes with Get-EXOMailbox and, for mailboxes whose archive is active, reads archive
    size and item count with Get-EXOMailboxStatistics -Archive. Retention policies and tags are read once so each row
    shows whether the assigned MRM policy actually contains a default "move to archive" tag - without one the archive
    stays empty. Archives at or above -ThresholdPercent of ArchiveQuota are flagged NearQuota. Writes a CSV report.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) to report instead of all mailboxes.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER RecipientTypeDetails
    Mailbox types to include: UserMailbox and/or SharedMailbox. Default is both.
.PARAMETER ThresholdPercent
    Percentage of ArchiveQuota at or above which an archive is flagged NearQuota. Default 80.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOArchiveStatus_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOArchiveStatusReport.ps1
    Reports every user and shared mailbox and writes .\Reports\EXOArchiveStatus_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOArchiveStatusReport.ps1 -RecipientTypeDetails UserMailbox -ThresholdPercent 90 -PassThru | Where-Object { $_.NoArchiveTag }
    Lists user mailboxes whose archive is enabled but whose retention policy never moves anything into it.
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
    Notes       : One archive statistics call per active archive. Only MRM retention tags move items to the archive; Purview
                  retention policies never do. Auto-expanding archives report the quota of the main archive shard (about
                  100-110 GB) while total capacity grows to 1.5 TB, so NearQuota is informational for them.
.LINK
    https://learn.microsoft.com/purview/enable-archive-mailboxes
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
    [ValidateSet('UserMailbox', 'SharedMailbox')]
    [string[]]$RecipientTypeDetails = @('UserMailbox', 'SharedMailbox'),

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$ThresholdPercent = 80,

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

function ConvertTo-GB {
    <# Converts Exchange size text such as "1.5 GB (1,610,612,736 bytes)" to GB with 2 decimals; "Unlimited" or empty returns $null. #>
    param([Parameter()][AllowNull()]$Size)
    if ($null -ne $Size -and $Size.ToString() -match '\(([\d,\.]+)\s+bytes\)') {
        return [math]::Round(([double]($Matches[1] -replace '[,\.]', '')) / 1GB, 2)
    }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOArchiveStatus_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

# Map each MRM policy to its default (Type = All) move-to-archive tag; personal tags only work when users apply them.
$archiveTagByPolicy = @{}
try {
    $archiveTags = @(Get-RetentionPolicyTag -ErrorAction Stop |
        Where-Object { [string]$_.RetentionAction -eq 'MoveToArchive' -and $_.RetentionEnabled -and [string]$_.Type -eq 'All' } | ForEach-Object { [string]$_.Name })
    foreach ($policy in @(Get-RetentionPolicy -ErrorAction Stop)) {
        $archiveTagByPolicy[[string]$policy.Name] = [string](@($policy.RetentionPolicyTagLinks | ForEach-Object { [string]$_ } | Where-Object { $archiveTags -contains $_ }) -join '; ')
    }
}
catch { Write-Warning "Could not read retention policies and tags; archive tag coverage will be empty: $($_.Exception.Message)" }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails', 'ExchangeGuid', 'SKUAssigned', 'ArchiveStatus', 'ArchiveState',
    'ArchiveGuid', 'AutoExpandingArchiveEnabled', 'ArchiveQuota', 'ArchiveWarningQuota', 'RetentionPolicy')
$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    try {
        foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails $RecipientTypeDetails -Properties $mailboxProperties -ErrorAction Stop)) {
            $mailboxes.Add($mailbox)
        }
    }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    Write-Progress -Activity 'Collecting archive status' -Status "$index of $($mailboxes.Count) - $($mailbox.DisplayName)" -PercentComplete (($index / $mailboxes.Count) * 100)
    $archiveEnabled = ([string]$mailbox.ArchiveStatus -eq 'Active')
    $archiveStats = $null
    if ($archiveEnabled) {
        try { $archiveStats = Get-EXOMailboxStatistics -ExchangeGuid $mailbox.ExchangeGuid -Archive -ErrorAction Stop }
        catch { Write-Warning "Could not read archive statistics for '$($mailbox.UserPrincipalName)': $($_.Exception.Message)" }
    }

    $archiveSizeGB = ConvertTo-GB -Size $archiveStats.TotalItemSize
    $quotaGB = ConvertTo-GB -Size $mailbox.ArchiveQuota
    $percentOfQuota = $null
    if ($null -ne $archiveSizeGB -and $null -ne $quotaGB -and $quotaGB -gt 0) { $percentOfQuota = [math]::Round(($archiveSizeGB / $quotaGB) * 100, 1) }
    $policyName = [string]$mailbox.RetentionPolicy
    $archiveTag = ''
    if ($archiveTagByPolicy.ContainsKey($policyName)) { $archiveTag = $archiveTagByPolicy[$policyName] }

    $results.Add([PSCustomObject]@{
            DisplayName           = $mailbox.DisplayName
            UserPrincipalName     = $mailbox.UserPrincipalName
            MailboxType           = [string]$mailbox.RecipientTypeDetails
            Licensed              = ($mailbox.SKUAssigned -eq $true)
            ArchiveEnabled        = $archiveEnabled
            ArchiveStatus         = [string]$mailbox.ArchiveStatus
            ArchiveState          = [string]$mailbox.ArchiveState
            ArchiveGuid           = [string]$mailbox.ArchiveGuid
            AutoExpandingArchive  = [bool]$mailbox.AutoExpandingArchiveEnabled
            ArchiveSizeGB         = $archiveSizeGB
            ArchiveItemCount      = $archiveStats.ItemCount
            ArchiveQuotaGB        = $quotaGB
            ArchiveWarningQuotaGB = ConvertTo-GB -Size $mailbox.ArchiveWarningQuota
            PercentOfArchiveQuota = $percentOfQuota
            NearQuota             = ($null -ne $percentOfQuota -and $percentOfQuota -ge $ThresholdPercent)
            RetentionPolicy       = $policyName
            ArchiveMoveTag        = $archiveTag
            NoArchiveTag          = ($archiveEnabled -and [string]::IsNullOrEmpty($archiveTag))
        })
}
Write-Progress -Activity 'Collecting archive status' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes were found; nothing to export.'; return }
$results | Sort-Object -Property PercentOfArchiveQuota, ArchiveSizeGB -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$nearQuota = @($results | Where-Object { $_.NearQuota } | Sort-Object -Property PercentOfArchiveQuota -Descending)
$archiveGB = ($results | Where-Object { $null -ne $_.ArchiveSizeGB } | Measure-Object -Property ArchiveSizeGB -Sum).Sum

$enabledCount = @($results | Where-Object { $_.ArchiveEnabled }).Count
$noTagCount = @($results | Where-Object { $_.NoArchiveTag }).Count
Write-Host 'Archive status summary' -ForegroundColor Cyan
Write-Host ('  Mailboxes reported         : {0} ({1} without archive)' -f $results.Count, ($results.Count - $enabledCount))
Write-Host ('  Archives enabled           : {0} ({1:N2} GB, {2} auto-expanding)' -f $enabledCount, [double]$archiveGB, @($results | Where-Object { $_.AutoExpandingArchive }).Count)
Write-Host ('  Without move-to-archive tag: {0}' -f $noTagCount) -ForegroundColor $(if ($noTagCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  At or above {0}% of quota    : {1}' -f $ThresholdPercent, $nearQuota.Count) -ForegroundColor $(if ($nearQuota.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $nearQuota) {
    Write-Host ('    {0,6:N1}%  {1} - {2:N2} of {3:N2} GB' -f $row.PercentOfArchiveQuota, $row.UserPrincipalName, $row.ArchiveSizeGB, $row.ArchiveQuotaGB) -ForegroundColor Yellow
}
Write-Host ('  Report                     : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
