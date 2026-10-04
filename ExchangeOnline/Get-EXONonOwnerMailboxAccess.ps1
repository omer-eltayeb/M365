<#
.SYNOPSIS
    Reports mailbox actions performed by someone other than the mailbox owner (admins and delegates) from the unified audit log.
.DESCRIPTION
    Searches the unified audit log (Search-UnifiedAuditLog with ReturnLargeSet paging) for the mailbox audit record types
    ExchangeItem, ExchangeItemGroup and ExchangeItemAggregated and the operations that reveal access or changes: FolderBind,
    MessageBind, SendAs, SendOnBehalf, Update, Move, MoveToDeletedItems, SoftDelete, HardDelete, Create and the folder
    permission / inbox rule changes. AuditData is parsed and only non-owner logons (LogonType 1 Admin, 2 Delegate and others)
    are kept unless -IncludeOwner is used. Writes a CSV and prints who accessed whose mailbox.
.PARAMETER DaysBack
    Number of days to search back from now (1-180; Audit Standard keeps 180 days). Default: 7.
.PARAMETER MailboxOwner
    One or more mailbox owner UPNs (wildcards allowed); only actions in those mailboxes are returned.
.PARAMETER LogonUser
    One or more UPNs of the acting users (admins or delegates); passed to the search as a server-side filter.
.PARAMETER IncludeOwner
    Also keep actions performed by the mailbox owner (LogonType 0), which are normally noise for this report.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXONonOwnerMailboxAccess_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXONonOwnerMailboxAccess.ps1
    Reports every admin or delegate action in any mailbox over the last 7 days.
.EXAMPLE
    PS> .\Get-EXONonOwnerMailboxAccess.ps1 -MailboxOwner ceo@contoso.com -DaysBack 30 -PassThru | Format-Table CreationTimeUtc, LogonUser, Operation, Subject
    Shows who touched the CEO mailbox in the last 30 days and what they did.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Organization Management / Compliance Management) in Exchange Online
    Category    : Administration, audit & migration
    Changes     : No
    Notes       : Mailbox auditing is on by default, but only the default action sets are logged (see Get-EXOMailboxAuditStatus.ps1);
                  FolderBind and MessageBind for delegates are recorded only when they were added to AuditDelegate. Records can take
                  up to 24 hours to appear. One ReturnLargeSet session returns at most 50,000 records per record type. Times are UTC.
.LINK
    https://learn.microsoft.com/purview/audit-mailboxes
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 7,

    [Parameter()]
    [string[]]$MailboxOwner,

    [Parameter()]
    [string[]]$LogonUser,

    [Parameter()]
    [switch]$IncludeOwner,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXONonOwnerMailboxAccess_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$endDate = (Get-Date).ToUniversalTime()
$startDate = $endDate.AddDays(-$DaysBack)
$operations = @('FolderBind', 'MessageBind', 'SendAs', 'SendOnBehalf', 'Update', 'Move', 'MoveToDeletedItems', 'SoftDelete', 'HardDelete', 'Create',
    'UpdateFolderPermissions', 'UpdateInboxRules', 'AddFolderPermissions', 'ModifyFolderPermissions', 'RemoveFolderPermissions')
$records = New-Object -TypeName System.Collections.Generic.List[object]
$seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'

# RecordType accepts one value per search, so each type gets its own ReturnLargeSet session (50,000 records at most each).
foreach ($recordType in @('ExchangeItem', 'ExchangeItemGroup', 'ExchangeItemAggregated')) {
    $searchParams = @{
        RecordType     = $recordType
        Operations     = $operations
        StartDate      = $startDate
        EndDate        = $endDate
        SessionId      = [guid]::NewGuid().ToString()
        SessionCommand = 'ReturnLargeSet'
        ResultSize     = 5000
        ErrorAction    = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('LogonUser')) { $searchParams['UserIds'] = $LogonUser }
    $expected = 0
    $fetched = 0
    $page = 0
    do {
        $page++
        Write-Progress -Activity 'Searching the unified audit log' -Status "$recordType - page $page - $fetched of $expected records" -PercentComplete 0
        try { $batch = @(Search-UnifiedAuditLog @searchParams) }
        catch { Write-Warning "Audit log search ($recordType, page $page) failed: $($_.Exception.Message)"; break }
        if ($batch.Count -eq 0) { break }
        if ($page -eq 1) {
            $expected = [int]$batch[0].ResultCount
            if ($expected -ge 50000) { Write-Warning "$recordType holds 50,000 or more records; one session returns at most 50,000. Reduce -DaysBack or add filters." }
        }
        $fetched += $batch.Count
        foreach ($entry in $batch) { if ($seen.Add([string]$entry.Identity)) { $records.Add($entry) } }
        Write-Verbose "$recordType page ${page}: $($batch.Count) records ($fetched of $expected)."
    } while ($fetched -lt $expected -and $page -lt 10)
}
Write-Progress -Activity 'Searching the unified audit log' -Completed

$logonTypeNames = @{ '0' = 'Owner'; '1' = 'Admin'; '2' = 'Delegate'; '3' = 'Transport'; '4' = 'SystemService'; '5' = 'BestAccess'; '6' = 'DelegatedAdmin' }
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    $audit = $null
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Verbose "Could not parse AuditData for record $($record.Identity): $($_.Exception.Message)"; continue }

    $logonTypeCode = [string]$audit.LogonType
    if ($logonTypeCode -eq '0' -and -not $IncludeOwner) { continue }
    $owner = [string]$audit.MailboxOwnerUPN
    if ($PSBoundParameters.ContainsKey('MailboxOwner') -and @($MailboxOwner | Where-Object { $owner -like $_ }).Count -eq 0) { continue }

    # Folder and subject live in different places depending on the operation (bind, single item update, bulk delete/move).
    $folder = [string]$audit.Folder.Path
    $subject = [string]$audit.Item.Subject
    if ($folder -eq '') { $folder = [string]$audit.Item.ParentFolder.Path }
    $affected = @($audit.AffectedItems | Where-Object { $null -ne $_ })
    if ($affected.Count -gt 0) {
        if ($subject -eq '') {
            $subject = (@($affected | Select-Object -First 3 | ForEach-Object { [string]$_.Subject }) -join ' | ')
            if ($affected.Count -gt 3) { $subject += " (+$($affected.Count - 3) more)" }
        }
        if ($folder -eq '') { $folder = [string]$affected[0].ParentFolder.Path }
    }
    if ($folder -eq '') { $folder = [string]@($audit.Folders)[0].Path }
    $clientInfo = [string]$audit.ClientInfoString
    if ($clientInfo.Length -gt 100) { $clientInfo = $clientInfo.Substring(0, 100) + '...' }
    if ($subject.Length -gt 200) { $subject = $subject.Substring(0, 200) + '...' }
    $logonTypeName = $logonTypeCode
    if ($logonTypeNames.ContainsKey($logonTypeCode)) { $logonTypeName = $logonTypeNames[$logonTypeCode] }

    $results.Add([PSCustomObject]@{
            CreationTimeUtc  = $record.CreationDate
            Operation        = [string]$audit.Operation
            MailboxOwnerUPN  = $owner
            LogonUser        = [string]$audit.UserId
            LogonType        = $logonTypeName
            ClientIPAddress  = [string]$audit.ClientIPAddress
            ClientInfoString = $clientInfo
            Folder           = $folder
            Subject          = $subject
            ResultStatus     = [string]$audit.ResultStatus
            RecordType       = [string]$record.RecordType
            RecordId         = [string]$record.Identity
        })
}

if ($results.Count -eq 0) { Write-Warning "No non-owner mailbox access records matched in the last $DaysBack day(s); nothing to export."; return }
$results | Sort-Object -Property CreationTimeUtc -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Non-owner mailbox access summary ($($results.Count) actions, $startDate to $endDate UTC)" -ForegroundColor Cyan
Write-Host ('  Records fetched / matched : {0} / {1}' -f $records.Count, $results.Count)
Write-Host ('  Mailboxes accessed        : {0}' -f @($results | Select-Object -Property MailboxOwnerUPN -Unique).Count)
Write-Host ('  Acting users              : {0}' -f @($results | Select-Object -Property LogonUser -Unique).Count)
$byLogonType = (@($results | Group-Object -Property LogonType | Sort-Object -Property Count -Descending | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', ')
Write-Host ('  By logon type             : {0}' -f $byLogonType)
Write-Host '  Who accessed whose mailbox (top 15):' -ForegroundColor Cyan
$pairs = $results | Group-Object -Property LogonUser, MailboxOwnerUPN | Sort-Object -Property Count -Descending | Select-Object -First 15
foreach ($pair in $pairs) {
    $sample = $pair.Group[0]
    $actions = (@($pair.Group | Group-Object -Property Operation | Sort-Object -Property Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }) -join ', ')
    Write-Host ('    {0} -> {1} ({2}): {3}' -f $sample.LogonUser, $sample.MailboxOwnerUPN, $sample.LogonType, $actions)
}
Write-Host ('  Report                    : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
