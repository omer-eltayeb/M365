<#
.SYNOPSIS
    Reports the largest folders of Exchange Online mailboxes with item counts, sizes and oldest/newest item dates.
.DESCRIPTION
    Runs Get-EXOMailboxFolderStatistics -IncludeOldestAndNewestItems once per selected mailbox, parses the
    "1.5 GB (1,610,612,736 bytes)" size text into MB and keeps the -TopFolders largest folders per mailbox that are at
    least -MinimumSizeMB. Mailboxes come from -Identity, a CSV with a UserPrincipalName column or - with a warning -
    every user mailbox in the tenant. Writes a CSV report and prints the biggest folders plus totals per folder type.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID).
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER FolderScope
    Folder scope passed to Get-EXOMailboxFolderStatistics, for example All, Inbox, SentItems, DeletedItems or Calendar. Default All.
.PARAMETER TopFolders
    Number of largest folders (by FolderSize) to keep per mailbox. Default 10; 0 keeps every folder.
.PARAMETER MinimumSizeMB
    Folders smaller than this size in MB are skipped. Default 0.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOMailboxFolderSizes_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMailboxFolderSizes.ps1 -Identity megan.bowen@contoso.com
    Reports the ten largest folders of one mailbox and writes .\Reports\EXOMailboxFolderSizes_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOMailboxFolderSizes.ps1 -InputCsv .\LargeMailboxes.csv -TopFolders 0 -MinimumSizeMB 500 -PassThru | Sort-Object -Property FolderSizeMB -Descending
    Lists every folder of 500 MB or more in the listed mailboxes, largest first, in addition to the CSV.
.EXAMPLE
    PS> .\Get-EXOMailboxFolderSizes.ps1 -FolderScope DeletedItems -TopFolders 1 -OutputPath C:\Temp\DeletedItems.csv
    Reports the Deleted Items folder of every user mailbox (one row per mailbox) to find who never empties it.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients or Global Reader (the report is read-only)
    Category    : Mailbox content & settings
    Changes     : No
    Notes       : One folder statistics call per mailbox; a tenant-wide run over thousands of mailboxes takes hours.
                  FolderSizeMB counts the items in the folder itself, FolderAndSubfolderSizeMB includes child folders -
                  do not add both. The folder-type totals cover every folder scanned, not only the exported top rows.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-exomailboxfolderstatistics
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
    [ValidateSet('All', 'Archive', 'Calendar', 'Clutter', 'Contacts', 'ConversationHistory', 'DeletedItems', 'Drafts', 'Inbox', 'JunkEmail',
        'Journal', 'LegacyArchiveJournals', 'ManagedCustomFolder', 'NonIpmRoot', 'Notes', 'Outbox', 'Personal', 'RecoverableItems',
        'RssSubscriptions', 'SentItems', 'SyncIssues', 'Tasks')]
    [string]$FolderScope = 'All',

    [Parameter()]
    [ValidateRange(0, 10000)]
    [int]$TopFolders = 10,

    [Parameter()]
    [ValidateRange(0, 1048576)]
    [double]$MinimumSizeMB = 0,

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

function ConvertTo-MB {
    <# Converts Exchange size text such as "1.5 GB (1,610,612,736 bytes)" to MB with 2 decimals; unparseable values return 0. #>
    param([Parameter()][AllowNull()]$Size)
    if ($null -ne $Size -and $Size.ToString() -match '\(([\d,]+) bytes\)') {
        return [math]::Round(([double]($Matches[1] -replace ',', '')) / 1MB, 2)
    }
    return [double]0
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMailboxFolderSizes_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails')
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    Write-Warning 'No -Identity or -InputCsv specified: every user mailbox in the tenant is scanned, one call per mailbox. This can take a long time.'
    try { foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -Properties $mailboxProperties -ErrorAction Stop)) { $mailboxes.Add($mailbox) } }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$typeTotals = @{}
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    Write-Progress -Activity 'Reading folder statistics' -Status "$index of $($mailboxes.Count) - $($mailbox.DisplayName)" -PercentComplete (($index / $mailboxes.Count) * 100)
    try { $folders = @(Get-EXOMailboxFolderStatistics -Identity $mailbox.UserPrincipalName -FolderScope $FolderScope -IncludeOldestAndNewestItems -ErrorAction Stop) }
    catch { Write-Warning "Could not read folder statistics for '$($mailbox.UserPrincipalName)': $($_.Exception.Message)"; continue }

    $rows = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($folder in $folders) {
        $sizeMB = ConvertTo-MB -Size $folder.FolderSize
        $type = [string]$folder.FolderType
        if (-not $typeTotals.ContainsKey($type)) { $typeTotals[$type] = [PSCustomObject]@{ FolderType = $type; Folders = 0; Items = 0; SizeMB = [double]0 } }
        $typeTotals[$type].Folders++
        $typeTotals[$type].Items += [int]$folder.ItemsInFolder
        $typeTotals[$type].SizeMB += $sizeMB
        if ($sizeMB -lt $MinimumSizeMB) { continue }
        $rows.Add([PSCustomObject]@{
                DisplayName                = $mailbox.DisplayName
                UserPrincipalName          = $mailbox.UserPrincipalName
                FolderPath                 = [string]$folder.FolderPath
                FolderType                 = $type
                ItemsInFolder              = [int]$folder.ItemsInFolder
                FolderSizeMB               = $sizeMB
                ItemsInFolderAndSubfolders = [int]$folder.ItemsInFolderAndSubfolders
                FolderAndSubfolderSizeMB   = ConvertTo-MB -Size $folder.FolderAndSubfolderSize
                OldestItemReceivedDate     = $folder.OldestItemReceivedDate
                NewestItemReceivedDate     = $folder.NewestItemReceivedDate
            })
    }
    $sorted = @($rows | Sort-Object -Property FolderSizeMB -Descending)
    if ($TopFolders -gt 0) { $sorted = @($sorted | Select-Object -First $TopFolders) }
    foreach ($row in $sorted) { $results.Add($row) }
}
Write-Progress -Activity 'Reading folder statistics' -Completed

if ($results.Count -eq 0) { Write-Warning 'No folders matched the selection; nothing to export.'; return }
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Mailbox folder size summary ($($mailboxes.Count) mailboxes, $($results.Count) folders exported)" -ForegroundColor Cyan
Write-Host '  Largest folders:' -ForegroundColor White
foreach ($row in @($results | Sort-Object -Property FolderSizeMB -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,12:N2} MB  {1,9:N0} items  {2} - {3}' -f $row.FolderSizeMB, $row.ItemsInFolder, $row.UserPrincipalName, $row.FolderPath)
}
Write-Host '  Totals by folder type (all folders scanned):' -ForegroundColor White
foreach ($total in @($typeTotals.Values | Sort-Object -Property SizeMB -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,12:N2} MB  {1,9:N0} items  {2,6:N0} folders  {3}' -f $total.SizeMB, $total.Items, $total.Folders, $total.FolderType)
}
Write-Host ('  Report: {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
