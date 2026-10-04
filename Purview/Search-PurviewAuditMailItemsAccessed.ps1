<#
.SYNOPSIS
    Reports MailItemsAccessed mailbox audit events (who read which mail, from where) for compromised-account investigations.
.DESCRIPTION
    Searches RecordType ExchangeItemAggregated / operation MailItemsAccessed one day at a time with Search-UnifiedAuditLog
    (ReturnLargeSet paging), parses AuditData and flattens accessor, mailbox owner, logon type, access type (Bind or Sync),
    throttling, folders, message count, client, IP, session and application IDs into one row per record (or per message with
    -IncludeMessageIds). Flags sync, throttled, non-owner and unknown-IP access; exports a CSV and prints counts by accessor, IP and type.
.PARAMETER DaysBack
    Number of days to search back from now (default 7, maximum 180). Ignored when -StartDate is used.
.PARAMETER StartDate
    Start of the search window (UTC). Use with -EndDate instead of -DaysBack.
.PARAMETER EndDate
    End of the search window (UTC). Defaults to now.
.PARAMETER UserIds
    Accessor user principal names to filter on. Strongly recommended: MailItemsAccessed is the highest-volume audit event.
.PARAMETER IncludeMessageIds
    Emit one row per accessed message (InternetMessageId and folder path) instead of one row per aggregated record.
.PARAMETER KnownIpPrefixes
    Known-good IP prefixes such as 203.0.113., 2001:db8:. Access from any other address is flagged with IsUnknownIp.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewAuditMailItemsAccessed_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the flattened records to the pipeline.
.EXAMPLE
    PS> .\Search-PurviewAuditMailItemsAccessed.ps1 -UserIds alex@contoso.com -DaysBack 14
    Shows every mailbox access by (or on behalf of) one user in the last two weeks, grouped by IP and access type.
.EXAMPLE
    PS> .\Search-PurviewAuditMailItemsAccessed.ps1 -UserIds alex@contoso.com -DaysBack 3 -IncludeMessageIds -KnownIpPrefixes 203.0.113. -PassThru | Where-Object IsUnknownIp
    Lists the individual messages bound from unknown IP addresses during the last three days of a suspected compromise.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); unified audit log ingestion must be enabled
    Category    : Audit log scenarios
    Changes     : No
    Notes       : MailItemsAccessed exists only for mailboxes whose user holds an Office 365 / Microsoft 365 E3 or E5 licence (an Audit
                  (Premium) event before 2024). Bind records aggregate 2 minutes of accesses; Sync means an Outlook desktop client downloaded
                  a whole folder (treat every item as exposed). Above 1,000 records in 24 hours a mailbox is throttled (IsThrottled).
                  Times are UTC; the window is sliced per day because a ReturnLargeSet session returns at most 50,000 records.
.LINK
    https://learn.microsoft.com/purview/audit-log-investigate-accounts
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'DaysBack')]
param(
    [Parameter(ParameterSetName = 'DaysBack')]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 7,

    [Parameter(Mandatory = $true, ParameterSetName = 'Dates')]
    [datetime]$StartDate,

    [Parameter(ParameterSetName = 'Dates')]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [string[]]$UserIds,

    [Parameter()]
    [switch]$IncludeMessageIds,

    [Parameter()]
    [string[]]$KnownIpPrefixes,

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

function Search-AuditRecords {
    <# Pages through Search-UnifiedAuditLog with ReturnLargeSet and returns de-duplicated records. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter()]
        [string[]]$RecordType,

        [Parameter()]
        [string[]]$Operations,

        [Parameter()]
        [string[]]$UserIds,

        [Parameter()]
        [string]$FreeText
    )
    $sessionId = [guid]::NewGuid().ToString()
    $records = New-Object -TypeName System.Collections.Generic.List[object]
    $seen = @{}
    do {
        $searchParams = @{ StartDate = $StartDate; EndDate = $EndDate; SessionId = $sessionId; SessionCommand = 'ReturnLargeSet'; ResultSize = 5000; ErrorAction = 'Stop' }
        if ($RecordType) { $searchParams['RecordType'] = $RecordType }
        if ($Operations) { $searchParams['Operations'] = $Operations }
        if ($UserIds) { $searchParams['UserIds'] = $UserIds }
        if ($FreeText) { $searchParams['FreeText'] = $FreeText }
        $page = @(Search-UnifiedAuditLog @searchParams)
        foreach ($record in $page) {
            if (-not $seen.ContainsKey($record.Identity)) {
                $seen[$record.Identity] = $true
                $records.Add($record)
            }
        }
    } while ($page.Count -gt 0)
    return $records
}
#endregion Helpers

#region Main
if ($PSCmdlet.ParameterSetName -eq 'DaysBack') { $StartDate = (Get-Date).AddDays(-$DaysBack) }
if ($EndDate -le $StartDate) { throw 'EndDate must be later than StartDate.' }
if (($EndDate - $StartDate).TotalDays -gt 90) { Write-Warning 'Window longer than 90 days: records beyond Audit (Standard) retention need Audit (Premium) retention policies.' }
if (-not $UserIds) { Write-Warning 'No -UserIds given: MailItemsAccessed is very high volume and tenant-wide searches easily exceed 50,000 records per day.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewAuditMailItemsAccessed_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }
# One search session per day keeps every slice under the 50,000-record ReturnLargeSet ceiling.
$records = New-Object -TypeName System.Collections.Generic.List[object]
$totalDays = [int][math]::Ceiling(($EndDate - $StartDate).TotalDays)
for ($day = 0; $day -lt $totalDays; $day++) {
    $sliceStart = $StartDate.AddDays($day)
    $sliceEnd = $StartDate.AddDays($day + 1)
    if ($sliceEnd -gt $EndDate) { $sliceEnd = $EndDate }
    Write-Progress -Activity 'Audit log search' -Status ('Day {0}/{1} ({2:yyyy-MM-dd}): {3} records' -f ($day + 1), $totalDays, $sliceStart, $records.Count) -PercentComplete (100 * $day / $totalDays)
    try { $records.AddRange(@(Search-AuditRecords -StartDate $sliceStart -EndDate $sliceEnd -RecordType 'ExchangeItemAggregated' -Operations 'MailItemsAccessed' -UserIds $UserIds)) }
    catch { Write-Warning ('Search for {0:yyyy-MM-dd} failed: {1}' -f $sliceStart, $_.Exception.Message) }
}
Write-Progress -Activity 'Audit log search' -Completed
$logonTypes = @{ '0' = 'Owner'; '1' = 'Admin'; '2' = 'Delegate'; '3' = 'Transport'; '4' = 'ServiceAccount'; '6' = 'DelegatedAdmin' }
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "Could not parse AuditData for record $($record.Identity); skipped."; continue }
    $accessType = [string](@($audit.OperationProperties | Where-Object { $_.Name -eq 'MailAccessType' } | Select-Object -First 1).Value)
    $folders = @($audit.Folders | Where-Object { $null -ne $_ })
    $clientIp = [string]$audit.ClientIPAddress
    $row = [PSCustomObject]@{
        CreationTime      = [datetime]$record.CreationDate
        UserId            = [string]$audit.UserId
        MailboxOwnerUPN   = [string]$audit.MailboxOwnerUPN
        LogonType         = $(if ($logonTypes.ContainsKey([string]$audit.LogonType)) { $logonTypes[[string]$audit.LogonType] } else { [string]$audit.LogonType })
        MailAccessType    = $accessType
        IsThrottled       = ([string](@($audit.OperationProperties | Where-Object { $_.Name -eq 'IsThrottled' } | Select-Object -First 1).Value) -eq 'True')
        Folders           = (@($folders | ForEach-Object { $_.Path }) -join '; ')
        MessageCount      = [int](@($folders | ForEach-Object { @($_.FolderItems | Where-Object { $null -ne $_ }).Count }) | Measure-Object -Sum).Sum
        InternetMessageId = ''
        ClientInfoString  = ([string]$audit.ClientInfoString).Substring(0, [math]::Min(150, ([string]$audit.ClientInfoString).Length))
        ClientIPAddress   = $clientIp
        SessionId         = [string]$audit.SessionId
        AppId             = [string]$audit.AppId
        ClientAppId       = [string]$audit.ClientAppId
        IsSync            = ($accessType -eq 'Sync')
        IsNonOwner        = ([string]$audit.LogonType -ne '0')
        IsUnknownIp       = [bool]($KnownIpPrefixes -and $clientIp -and -not @($KnownIpPrefixes | Where-Object { $clientIp -like ($_ + '*') }).Count)
    }
    $items = @()  # with -IncludeMessageIds each bound message becomes its own row; Sync records carry no items and stay as one row
    if ($IncludeMessageIds) { $items = @($folders | ForEach-Object { $folder = $_; @($_.FolderItems) | Where-Object { $_ } | ForEach-Object { @{ Path = $folder.Path; Id = $_.InternetMessageId } } }) }
    if ($items.Count -eq 0) { $results.Add($row) }
    else { foreach ($item in $items) { $copy = $row.PSObject.Copy(); $copy.Folders = [string]$item.Path; $copy.InternetMessageId = [string]$item.Id; $results.Add($copy) } }
}
$results = @($results | Sort-Object -Property CreationTime)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
Write-Host 'MailItemsAccessed summary' -ForegroundColor Cyan
Write-Host ('  Window : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} UTC, {2} row(s) in {3} day slice(s)' -f $StartDate, $EndDate, $results.Count, $totalDays)
$flagCounts = 'IsSync', 'IsNonOwner', 'IsThrottled', 'IsUnknownIp' | ForEach-Object { '{0} {1}' -f $_.Substring(2), @($results | Where-Object -Property $_ -EQ $true).Count }
Write-Host ('  Flags  : {0}' -f ($flagCounts -join '   ')) -ForegroundColor Yellow
foreach ($section in @(@('By accessor', 'UserId', 10), @('By client IP address', 'ClientIPAddress', 10), @('By access type', 'MailAccessType', 5))) {
    Write-Host ('  {0}:' -f $section[0])
    $groups = $results | Group-Object -Property $section[1] | Sort-Object -Property Count -Descending | Select-Object -First $section[2]
    foreach ($group in $groups) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
}
Write-Host ('  Report : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
