<#
.SYNOPSIS
    Reports the status of Exchange Online migration batches and, optionally, of every user inside them.
.DESCRIPTION
    Reads all migration batches (or the ones given with -Identity) with Get-MigrationBatch: status, type, user counts (total,
    synced, finalized, failed, active), timeline (created, started, initial sync, last sync, complete after), notification
    recipients and source endpoint. With -IncludeUsers it adds Get-MigrationUser and Get-MigrationUserStatistics for each
    user (status, items synced and skipped, estimated size, bytes transferred, progress, error, last successful sync).
    Batches are written to -OutputPath and users to <report>_Users.csv; -OnlyProblems keeps the failed or stopped ones.
.PARAMETER Identity
    One or more migration batch names to report instead of all batches.
.PARAMETER IncludeUsers
    Also report every migration user with its statistics (one Get-MigrationUserStatistics call per user).
.PARAMETER OnlyProblems
    Report only batches with failures, errors, stopped or corrupted states and, with -IncludeUsers, only users in that state.
.PARAMETER OutputPath
    Path of the batch CSV report. Defaults to .\Reports\EXOMigrationBatches_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the batch objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMigrationBatchStatus.ps1
    Reports every migration batch with its counters and timeline.
.EXAMPLE
    PS> .\Get-EXOMigrationBatchStatus.ps1 -Identity 'Wave 3' -IncludeUsers -OnlyProblems
    Lists the failed or stopped users of the batch "Wave 3" with their error text in the _Users.csv file.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Migration role (Recipient Management or Organization Management role group), or Exchange Administrator
    Category    : Administration, audit & migration
    Changes     : No
    Notes       : Sizes are parsed from the "x GB (y bytes)" text into GB with two decimals. Per-user statistics are slow for large
                  batches; combine -Identity with -IncludeUsers. Use Get-MigrationUserStatistics -IncludeReport (or -IncludeSkippedItems)
                  for the detailed failure report of a single user, and Start-MigrationUser / Set-MigrationBatch to retry or complete.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-migrationbatch
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Identity,

    [Parameter()]
    [switch]$IncludeUsers,

    [Parameter()]
    [switch]$OnlyProblems,

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

function ConvertTo-Gigabytes {
    <# Parses a "1.5 GB (1,610,612,736 bytes)" size into GB with two decimals; returns $null when no byte count is present. #>
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Size
    )
    if ([string]$Size -match '\(([\d,\.]+) bytes\)') { return [math]::Round(([double]($Matches[1] -replace '[,\.]', '')) / 1GB, 2) }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMigrationBatches_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$usersPath = [System.IO.Path]::Combine([string]$outputFolder, ([System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_Users.csv'))

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$batches = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($id in @($Identity)) {
    try { $batches.AddRange(@(Get-MigrationBatch -Identity $id -ErrorAction Stop)) }
    catch { Write-Warning "Migration batch '$id' was not found: $($_.Exception.Message)" }
}
if (@($Identity).Count -eq 0) {
    try { $batches.AddRange(@(Get-MigrationBatch -ErrorAction Stop)) }
    catch { throw "Failed to read the migration batches: $($_.Exception.Message)" }
}
Write-Verbose "Retrieved $($batches.Count) migration batch(es)."

$problemPattern = 'Fail|Error|Stopped|Corrupt'
$results = New-Object -TypeName System.Collections.Generic.List[object]
$userResults = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($batch in $batches) {
    $isProblem = ([int]$batch.FailedCount -gt 0 -or [string]$batch.Status -match $problemPattern)
    if ($OnlyProblems -and -not $isProblem) { continue }
    $results.Add([PSCustomObject]@{
            Identity            = [string]$batch.Identity
            Status              = [string]$batch.Status
            MigrationType       = [string]$batch.MigrationType
            TotalCount          = [int]$batch.TotalCount
            SyncedCount         = [int]$batch.SyncedCount
            FinalizedCount      = [int]$batch.FinalizedCount
            FailedCount         = [int]$batch.FailedCount
            ActiveCount         = [int]$batch.ActiveCount
            CreationDateTime    = $batch.CreationDateTime
            StartDateTime       = $batch.StartDateTime
            InitialSyncDateTime = $batch.InitialSyncDateTime
            LastSyncedDateTime  = $batch.LastSyncedDateTime
            CompleteAfter       = $batch.CompleteAfter
            NotificationEmails  = (@($batch.NotificationEmails | ForEach-Object { [string]$_ }) -join '; ')
            SourceEndpoint      = [string]$batch.SourceEndpoint
            IsProblem           = $isProblem
        })
    if (-not $IncludeUsers) { continue }

    try { $users = @(Get-MigrationUser -BatchId ([string]$batch.Identity) -ResultSize Unlimited -ErrorAction Stop) }
    catch { Write-Warning "Users of batch '$($batch.Identity)' could not be read: $($_.Exception.Message)"; continue }
    $index = 0
    foreach ($user in $users) {
        $index++
        Write-Progress -Activity "Reading migration user statistics - $($batch.Identity)" -Status "$index of $($users.Count) - $($user.Identity)" -PercentComplete (($index / $users.Count) * 100)
        try { $stats = Get-MigrationUserStatistics -Identity ([string]$user.Identity) -ErrorAction Stop }
        catch { Write-Warning "Statistics for '$($user.Identity)' could not be read: $($_.Exception.Message)"; continue }
        $errorText = [string]$stats.Error
        if ($errorText -eq '') { $errorText = [string]$stats.ErrorSummary }
        $errorText = ($errorText -replace '\s+', ' ').Trim()
        if ($errorText.Length -gt 300) { $errorText = $errorText.Substring(0, 300) + '...' }
        $userProblem = ([string]$stats.Status -match $problemPattern -or $errorText -ne '')
        if ($OnlyProblems -and -not $userProblem) { continue }
        $userResults.Add([PSCustomObject]@{
                Batch                        = [string]$batch.Identity
                Identity                     = [string]$stats.Identity
                EmailAddress                 = [string]$stats.EmailAddress
                Status                       = [string]$stats.Status
                StatusSummary                = [string]$stats.StatusSummary
                SyncedItemCount              = $stats.SyncedItemCount
                SkippedItemCount             = $stats.SkippedItemCount
                EstimatedTotalTransferSizeGB = ConvertTo-Gigabytes -Size $stats.EstimatedTotalTransferSize
                BytesTransferredGB           = ConvertTo-Gigabytes -Size $stats.BytesTransferred
                PercentageComplete           = $stats.PercentageComplete
                LastSuccessfulSyncTime       = $stats.LastSuccessfulSyncTime
                Error                        = $errorText
                IsProblem                    = $userProblem
            })
    }
    Write-Progress -Activity "Reading migration user statistics - $($batch.Identity)" -Completed
}

if ($results.Count -eq 0) { Write-Warning 'No migration batches matched; nothing to export.'; return }
$results | Sort-Object -Property IsProblem, Identity -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($IncludeUsers -and $userResults.Count -gt 0) { $userResults | Sort-Object -Property IsProblem, Batch, Identity -Descending | Export-Csv -Path $usersPath -NoTypeInformation -Encoding UTF8 }
$problemBatches = @($results | Where-Object { $_.IsProblem }).Count
$byStatus = (@($results | Group-Object -Property Status | Sort-Object -Property Count -Descending | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', ')

Write-Host "Migration batch summary ($($results.Count) batches)" -ForegroundColor Cyan
Write-Host ('  Batches by status   : {0}' -f $byStatus)
$failedUsers = [int]($results | Measure-Object -Property FailedCount -Sum).Sum
Write-Host ('  Users total/synced  : {0} / {1}' -f ($results | Measure-Object -Property TotalCount -Sum).Sum, ($results | Measure-Object -Property SyncedCount -Sum).Sum)
Write-Host ('  Users finalized     : {0}' -f ($results | Measure-Object -Property FinalizedCount -Sum).Sum)
Write-Host ('  Users failed        : {0}' -f $failedUsers) -ForegroundColor $(if ($failedUsers -gt 0) { 'Red' } else { 'Green' })
Write-Host ('  Problem batches     : {0}' -f $problemBatches) -ForegroundColor $(if ($problemBatches -gt 0) { 'Yellow' } else { 'Green' })
if ($IncludeUsers) {
    $problemUsers = @($userResults | Where-Object { $_.IsProblem })
    Write-Host ('  User rows exported  : {0} ({1} with problems)' -f $userResults.Count, $problemUsers.Count) -ForegroundColor $(if ($problemUsers.Count -gt 0) { 'Yellow' } else { 'Green' })
    foreach ($problemUser in ($problemUsers | Select-Object -First 10)) { Write-Host ('    {0} [{1}] {2}' -f $problemUser.Identity, $problemUser.Status, $problemUser.Error) -ForegroundColor DarkGray }
    if ($userResults.Count -gt 0) { Write-Host ('  Users CSV           : {0}' -f $usersPath) }
}
Write-Host ('  Report              : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
