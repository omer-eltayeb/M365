<#
.SYNOPSIS
    Reports the public folder hierarchy with sizes, item counts, mail-enabled addresses, stale folders and the public folder mailboxes.
.DESCRIPTION
    Reads the public folder deployment from Get-OrganizationConfig (PublicFoldersEnabled, RootPublicFolderMailbox) and the
    public folder mailboxes with Get-Mailbox -PublicFolder plus Get-MailboxStatistics. Then it walks the hierarchy below -Path
    with Get-PublicFolder -Recurse, joins Get-PublicFolderStatistics (item count, size, last modification) by EntryId and
    adds the SMTP address and address-list visibility of mail-enabled folders from Get-MailPublicFolder. Folders not
    modified for -StaleDays are flagged. Writes the folder CSV, a <report>_Mailboxes.csv and prints totals and the biggest folders.
.PARAMETER Path
    Root of the hierarchy to report, for example \Finance. Default: \ (everything).
.PARAMETER StaleDays
    Folders without any modification for this many days are flagged as stale. Default: 365.
.PARAMETER OutputPath
    Path of the folder CSV report. Defaults to .\Reports\EXOPublicFolders_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the folder objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOPublicFolderReport.ps1
    Reports the whole public folder hierarchy and the public folder mailboxes.
.EXAMPLE
    PS> .\Get-EXOPublicFolderReport.ps1 -Path '\Projects' -StaleDays 730 -PassThru | Where-Object { $_.IsStale } | Sort-Object TotalItemSizeMB -Descending
    Lists the folders under \Projects that nobody has touched for two years, biggest first.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Public Folders role (Organization Management or Public Folder Management role group) + View-Only Configuration
    Category    : Administration, audit & migration
    Changes     : No
    Notes       : Get-PublicFolderStatistics without -Identity returns statistics for the whole hierarchy in one call; folders missing
                  from that set are queried individually. Sizes are parsed from the "x GB (y bytes)" text. A public folder mailbox is
                  limited to 100 GB and the hierarchy to 1,000 mailboxes / 250,000 folders - keep an eye on the per-mailbox totals.
.LINK
    https://learn.microsoft.com/exchange/collaboration-exo/public-folders/public-folders
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^\\')]
    [string]$Path = '\',

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 365,

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

function Get-SizeBytes {
    <# Extracts the byte count from a "1.5 GB (1,610,612,736 bytes)" size value; returns $null when it is absent. #>
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Size
    )
    if ([string]$Size -match '\(([\d,\.]+) bytes\)') { return [long]($Matches[1] -replace '[,\.]', '') }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOPublicFolders_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$mailboxPath = [System.IO.Path]::Combine([string]$outputFolder, ([System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_Mailboxes.csv'))

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try { $orgConfig = Get-OrganizationConfig -ErrorAction Stop }
catch { throw "Failed to read the organization configuration: $($_.Exception.Message)" }
$pfMode = [string]$orgConfig.PublicFoldersEnabled
if ($pfMode -eq 'None') { Write-Warning 'PublicFoldersEnabled is None: this tenant has no public folders deployed.' }

$mailboxRows = New-Object -TypeName System.Collections.Generic.List[object]
try { $pfMailboxes = @(Get-Mailbox -PublicFolder -ResultSize Unlimited -ErrorAction Stop) }
catch { Write-Warning "Public folder mailboxes could not be read: $($_.Exception.Message)"; $pfMailboxes = @() }
foreach ($pfMailbox in $pfMailboxes) {
    $sizeBytes = $null
    $itemCount = $null
    try {
        $mailboxStats = Get-MailboxStatistics -Identity ([string]$pfMailbox.ExchangeGuid) -ErrorAction Stop
        $sizeBytes = Get-SizeBytes -Size $mailboxStats.TotalItemSize
        $itemCount = $mailboxStats.ItemCount
    }
    catch { Write-Warning "Statistics for public folder mailbox '$($pfMailbox.Name)' could not be read: $($_.Exception.Message)" }
    $mailboxRows.Add([PSCustomObject]@{
            Name                           = $pfMailbox.Name
            IsRootPublicFolderMailbox      = [bool]$pfMailbox.IsRootPublicFolderMailbox
            IsExcludedFromServingHierarchy = [bool]$pfMailbox.IsExcludedFromServingHierarchy
            IsHierarchyReady               = [bool]$pfMailbox.IsHierarchyReady
            ItemCount                      = $itemCount
            TotalItemSizeGB                = $(if ($null -ne $sizeBytes) { [math]::Round($sizeBytes / 1GB, 2) } else { $null })
        })
}

try { $folders = @(Get-PublicFolder -Identity $Path -Recurse -ResultSize Unlimited -ErrorAction Stop | Where-Object { [string]$_.Identity -ne '\' }) }
catch { throw "Failed to read the public folder hierarchy below '$Path': $($_.Exception.Message)" }
Write-Verbose "Retrieved $($folders.Count) public folder(s) below '$Path'."

# One statistics call for the whole hierarchy and one for the mail-enabled folders, both indexed by EntryId for the join.
$statsByEntryId = @{}
try { foreach ($stat in (Get-PublicFolderStatistics -ResultSize Unlimited -ErrorAction Stop)) { $statsByEntryId[[string]$stat.EntryId] = $stat } }
catch { Write-Warning "Public folder statistics could not be read in bulk; folders are queried individually: $($_.Exception.Message)" }
$mailByEntryId = @{}
try { foreach ($mailFolder in (Get-MailPublicFolder -ResultSize Unlimited -ErrorAction Stop)) { $mailByEntryId[[string]$mailFolder.EntryId] = $mailFolder } }
catch { Write-Warning "Mail-enabled public folders could not be read: $($_.Exception.Message)" }

$cutoff = (Get-Date).AddDays(-$StaleDays)
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($folder in $folders) {
    $index++
    if ($index % 50 -eq 0) { Write-Progress -Activity 'Evaluating public folders' -Status "$index of $($folders.Count) - $($folder.Identity)" -PercentComplete (($index / $folders.Count) * 100) }
    $entryId = [string]$folder.EntryId
    $stat = $statsByEntryId[$entryId]
    if ($null -eq $stat) {
        try { $stat = Get-PublicFolderStatistics -Identity ([string]$folder.Identity) -ErrorAction Stop }
        catch { Write-Warning "Statistics for '$($folder.Identity)' could not be read: $($_.Exception.Message)" }
    }
    $mailFolder = $mailByEntryId[$entryId]
    $sizeBytes = $null
    $lastModified = $null
    if ($null -ne $stat) {
        $sizeBytes = Get-SizeBytes -Size $stat.TotalItemSize
        if (-not [string]::IsNullOrEmpty([string]$stat.LastModificationTime)) { $lastModified = [datetime]$stat.LastModificationTime }
    }
    $results.Add([PSCustomObject]@{
            Identity               = [string]$folder.Identity
            Name                   = $folder.Name
            ParentPath             = [string]$folder.ParentPath
            FolderClass            = [string]$folder.FolderClass
            MailEnabled            = [bool]$folder.MailEnabled
            PrimarySmtpAddress     = $(if ($null -ne $mailFolder) { [string]$mailFolder.PrimarySmtpAddress } else { '' })
            HiddenFromAddressLists = $(if ($null -ne $mailFolder) { [bool]$mailFolder.HiddenFromAddressListsEnabled } else { $null })
            ContentMailboxName     = [string]$folder.ContentMailboxName
            HasSubfolders          = [bool]$folder.HasSubfolders
            ItemCount              = $(if ($null -ne $stat) { $stat.ItemCount } else { $null })
            TotalItemSizeMB        = $(if ($null -ne $sizeBytes) { [math]::Round($sizeBytes / 1MB, 2) } else { $null })
            TotalItemSizeGB        = $(if ($null -ne $sizeBytes) { [math]::Round($sizeBytes / 1GB, 2) } else { $null })
            LastModificationTime   = $lastModified
            DaysSinceModified      = $(if ($null -ne $lastModified) { [int]((Get-Date) - $lastModified).TotalDays } else { $null })
            IsStale                = ($null -ne $lastModified -and $lastModified -lt $cutoff)
            EntryId                = $entryId
        })
}
Write-Progress -Activity 'Evaluating public folders' -Completed

if ($mailboxRows.Count -gt 0) { $mailboxRows | Export-Csv -Path $mailboxPath -NoTypeInformation -Encoding UTF8 }
if ($results.Count -eq 0) { Write-Warning "No public folders were found below '$Path'; the folder report was not written."; return }
$results | Sort-Object -Property Identity | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$totalGB = [math]::Round(([double](($results | Where-Object { $null -ne $_.TotalItemSizeMB } | Measure-Object -Property TotalItemSizeMB -Sum).Sum)) / 1024, 2)
$totalItems = [long](($results | Where-Object { $null -ne $_.ItemCount } | Measure-Object -Property ItemCount -Sum).Sum)
$mailboxGB = [math]::Round([double](($mailboxRows | Where-Object { $null -ne $_.TotalItemSizeGB } | Measure-Object -Property TotalItemSizeGB -Sum).Sum), 2)
$stale = @($results | Where-Object { $_.IsStale }).Count

Write-Host "Public folder summary ($($results.Count) folders below '$Path')" -ForegroundColor Cyan
Write-Host ('  Deployment             : {0} (root mailbox: {1})' -f $pfMode, [string]$orgConfig.RootPublicFolderMailbox)
Write-Host ('  Public folder mailboxes: {0} ({1} GB in total)' -f $mailboxRows.Count, $mailboxGB)
Write-Host ('  Folder content         : {0} GB, {1} items' -f $totalGB, $totalItems)
Write-Host ('  Mail-enabled folders   : {0}' -f @($results | Where-Object { $_.MailEnabled }).Count)
Write-Host ('  {0,-23}: {1}' -f "Stale (> $StaleDays days)", $stale) -ForegroundColor $(if ($stale -gt 0) { 'Yellow' } else { 'Green' })
Write-Host '  Biggest folders:' -ForegroundColor Cyan
foreach ($big in ($results | Sort-Object -Property TotalItemSizeMB -Descending | Select-Object -First 5)) {
    Write-Host ('    {0,10:N2} MB  {1,8} items  {2}' -f $big.TotalItemSizeMB, $big.ItemCount, $big.Identity)
}
Write-Host ('  Report                 : {0}' -f $OutputPath)
if ($mailboxRows.Count -gt 0) { Write-Host ('  Mailboxes CSV          : {0}' -f $mailboxPath) }

if ($PassThru) { $results }
#endregion Main
