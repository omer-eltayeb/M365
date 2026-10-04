<#
.SYNOPSIS
    Reports mailbox and archive size, item counts and quota usage for Exchange Online mailboxes.
.DESCRIPTION
    Enumerates mailboxes with the REST-backed Get-EXOMailbox cmdlet, then calls Get-EXOMailboxStatistics for
    the primary mailbox and - when an archive is active - for the archive mailbox. Sizes are parsed from the
    "1.5 GB (1,610,612,736 bytes)" text that Exchange returns and converted to GB. Each row shows total size,
    ProhibitSendReceiveQuota, percent of quota, archive size, litigation hold, retention policy and the last
    user activity. Rows at or above -ThresholdPercent are flagged NearQuota and listed in the console summary.
    Writes a CSV report and optionally emits the objects to the pipeline.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID). When omitted, every mailbox in
    the tenant is processed.
.PARAMETER RecipientTypeDetails
    Limit the report to one or more mailbox types: UserMailbox, SharedMailbox, RoomMailbox, EquipmentMailbox.
.PARAMETER ThresholdPercent
    Percentage of ProhibitSendReceiveQuota at or above which a mailbox is flagged NearQuota. Default 80.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOMailboxSize_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMailboxSizeReport.ps1
    Reports every mailbox, writes .\Reports\EXOMailboxSize_<timestamp>.csv and lists mailboxes at 80 % or more of quota.
.EXAMPLE
    PS> .\Get-EXOMailboxSizeReport.ps1 -RecipientTypeDetails SharedMailbox -ThresholdPercent 90 -OutputPath C:\Temp\SharedMailboxes.csv
    Reports shared mailboxes only (handy for the 50 GB unlicensed shared mailbox limit) and flags those at 90 % or more.
.EXAMPLE
    PS> .\Get-EXOMailboxSizeReport.ps1 -Identity user1@contoso.com, user2@contoso.com -PassThru | Format-Table DisplayName, TotalSizeGB, PercentOfQuota
    Reports two mailboxes and shows the key columns on screen.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator, or View-Only Recipients for the read-only report
    Category    : Mailbox lifecycle & compliance
    Changes     : No
    Notes       : One statistics call per mailbox plus one per active archive; expect roughly 1-2 seconds per
                  mailbox in large tenants. LastUserActionTime is empty for mailboxes that were never used.
                  Unlimited quotas (for example auto-expanding archives) leave QuotaGB and PercentOfQuota empty.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-exomailboxstatistics
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-exomailbox
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$Identity,

    [Parameter()]
    [ValidateSet('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox')]
    [string[]]$RecipientTypeDetails,

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
    <# Converts Exchange size text such as "1.5 GB (1,610,612,736 bytes)" to GB with 2 decimals. "Unlimited" and empty values return $null. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Size
    )
    if ($null -eq $Size) { return $null }
    $text = $Size.ToString()
    if ($text -match '\(([\d,\.]+)\s+bytes\)') {
        $bytes = [double]($Matches[1] -replace '[,\.]', '')
        return [math]::Round($bytes / 1GB, 2)
    }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMailboxSize_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

$mailboxProperties = @(
    'DisplayName', 'UserPrincipalName', 'PrimarySmtpAddress', 'RecipientTypeDetails', 'ExchangeGuid', 'ArchiveStatus', 'ArchiveGuid',
    'ProhibitSendReceiveQuota', 'ProhibitSendQuota', 'IssueWarningQuota', 'LitigationHoldEnabled', 'RetentionPolicy', 'WhenCreated'
)

Write-Verbose 'Retrieving mailboxes.'
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSBoundParameters.ContainsKey('Identity')) {
    foreach ($id in $Identity) {
        try {
            $mailbox = Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop
            # Honour -RecipientTypeDetails even when explicit identities are supplied.
            if ($PSBoundParameters.ContainsKey('RecipientTypeDetails') -and $RecipientTypeDetails -notcontains [string]$mailbox.RecipientTypeDetails) {
                Write-Verbose "Skipping '$id' because it is a $($mailbox.RecipientTypeDetails)."
                continue
            }
            $mailboxes.Add($mailbox)
        }
        catch {
            Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)"
        }
    }
}
else {
    $getParams = @{ ResultSize = 'Unlimited'; Properties = $mailboxProperties; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('RecipientTypeDetails')) { $getParams['RecipientTypeDetails'] = $RecipientTypeDetails }
    try {
        foreach ($mailbox in (Get-EXOMailbox @getParams)) { $mailboxes.Add($mailbox) }
    }
    catch {
        throw "Failed to retrieve mailboxes: $($_.Exception.Message)"
    }
}
Write-Verbose "Found $($mailboxes.Count) mailbox(es)."

$results = New-Object -TypeName System.Collections.Generic.List[object]
$now = Get-Date
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    Write-Progress -Activity 'Collecting mailbox statistics' -Status "$index of $($mailboxes.Count) - $($mailbox.DisplayName)" -PercentComplete (($index / $mailboxes.Count) * 100)

    try {
        $stats = Get-EXOMailboxStatistics -ExchangeGuid $mailbox.ExchangeGuid -Properties LastUserActionTime, TotalDeletedItemSize -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not read statistics for '$($mailbox.UserPrincipalName)': $($_.Exception.Message)"
        continue
    }

    $archiveEnabled = ([string]$mailbox.ArchiveStatus -eq 'Active')
    $archiveSizeGB = $null
    $archiveItemCount = $null
    if ($archiveEnabled) {
        try {
            $archiveStats = Get-EXOMailboxStatistics -ExchangeGuid $mailbox.ExchangeGuid -Archive -ErrorAction Stop
            $archiveSizeGB = ConvertTo-GB -Size $archiveStats.TotalItemSize
            $archiveItemCount = $archiveStats.ItemCount
        }
        catch {
            Write-Warning "Could not read archive statistics for '$($mailbox.UserPrincipalName)': $($_.Exception.Message)"
        }
    }

    $totalSizeGB = ConvertTo-GB -Size $stats.TotalItemSize
    $quotaGB = ConvertTo-GB -Size $mailbox.ProhibitSendReceiveQuota
    $percentOfQuota = $null
    if ($null -ne $totalSizeGB -and $null -ne $quotaGB -and $quotaGB -gt 0) {
        $percentOfQuota = [math]::Round(($totalSizeGB / $quotaGB) * 100, 1)
    }

    $lastUserAction = $null
    $daysSinceLastActivity = $null
    if ($null -ne $stats.LastUserActionTime) {
        $lastUserAction = [datetime]$stats.LastUserActionTime
        $daysSinceLastActivity = [int][math]::Floor((New-TimeSpan -Start $lastUserAction -End $now).TotalDays)
    }

    $results.Add([PSCustomObject]@{
            DisplayName           = $mailbox.DisplayName
            UserPrincipalName     = $mailbox.UserPrincipalName
            MailboxType           = [string]$mailbox.RecipientTypeDetails
            TotalSizeGB           = $totalSizeGB
            ItemCount             = $stats.ItemCount
            DeletedItemSizeGB     = ConvertTo-GB -Size $stats.TotalDeletedItemSize
            QuotaGB               = $quotaGB
            PercentOfQuota        = $percentOfQuota
            NearQuota             = ($null -ne $percentOfQuota -and $percentOfQuota -ge $ThresholdPercent)
            ArchiveEnabled        = $archiveEnabled
            ArchiveSizeGB         = $archiveSizeGB
            ArchiveItemCount      = $archiveItemCount
            LitigationHold        = [bool]$mailbox.LitigationHoldEnabled
            RetentionPolicy       = [string]$mailbox.RetentionPolicy
            LastUserActionTime    = $lastUserAction
            DaysSinceLastActivity = $daysSinceLastActivity
            WhenCreated           = $mailbox.WhenCreated
        })
}
Write-Progress -Activity 'Collecting mailbox statistics' -Completed

if ($results.Count -eq 0) {
    Write-Warning 'No mailbox statistics were collected; nothing to export.'
    return
}

$results | Sort-Object -Property PercentOfQuota, TotalSizeGB -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$nearQuota = @($results | Where-Object { $_.NearQuota } | Sort-Object -Property PercentOfQuota -Descending)
$totalGB = ($results | Where-Object { $null -ne $_.TotalSizeGB } | Measure-Object -Property TotalSizeGB -Sum).Sum
$archiveGB = ($results | Where-Object { $null -ne $_.ArchiveSizeGB } | Measure-Object -Property ArchiveSizeGB -Sum).Sum
$archiveCount = @($results | Where-Object { $_.ArchiveEnabled }).Count

Write-Host ''
Write-Host 'Mailbox size report summary' -ForegroundColor Cyan
Write-Host ('  Mailboxes reported     : {0}' -f $results.Count)
Write-Host ('  Primary mailbox total  : {0:N2} GB' -f [double]$totalGB)
Write-Host ('  Archives enabled       : {0} ({1:N2} GB)' -f $archiveCount, [double]$archiveGB)
Write-Host ('  At or above {0}% quota : {1}' -f $ThresholdPercent, $nearQuota.Count) -ForegroundColor $(if ($nearQuota.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $nearQuota) {
    Write-Host ('    {0,6:N1}%  {1} ({2}) - {3:N2} of {4:N2} GB' -f $row.PercentOfQuota, $row.DisplayName, $row.UserPrincipalName, $row.TotalSizeGB, $row.QuotaGB) -ForegroundColor Yellow
}
Write-Host ('  Report                 : {0}' -f $OutputPath)

if ($PassThru) {
    $results
}
#endregion Main
