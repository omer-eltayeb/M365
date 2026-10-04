<#
.SYNOPSIS
    Finds user (and optionally shared) mailboxes with no activity for a given number of days.
.DESCRIPTION
    Enumerates mailboxes with Get-EXOMailbox and reads LastUserActionTime and LastInteractionTime from
    Get-EXOMailboxStatistics (LastLogonTime is ignored because background services keep it fresh). Mailboxes idle for
    -DaysInactive days or more are reported as Inactive; mailboxes that never recorded activity and are older than the
    threshold are NeverUsed. Size, sign-in state, license and holds are included to guide the clean-up decision.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) to evaluate instead of all mailboxes.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to evaluate.
.PARAMETER IncludeShared
    Also evaluate shared mailboxes. The default scope is user mailboxes only.
.PARAMETER DaysInactive
    Number of days without activity after which a mailbox is reported. Default 90.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOInactiveMailboxes_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOInactiveMailboxes.ps1
    Reports user mailboxes idle for 90 days or more and writes .\Reports\EXOInactiveMailboxes_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOInactiveMailboxes.ps1 -DaysInactive 180 -IncludeShared -OutputPath C:\Temp\StaleMailboxes.csv -Verbose
    Reports user and shared mailboxes idle for six months and shows each statistics call as it happens.
.EXAMPLE
    PS> .\Get-EXOInactiveMailboxes.ps1 -InputCsv .\Leavers.csv -DaysInactive 30 -PassThru | Where-Object { $_.Licensed }
    Checks the leavers listed in the CSV and returns those that still consume a license.
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
    Notes       : One Get-EXOMailboxStatistics call per mailbox - expect about one second per mailbox. AccountDisabled
                  mirrors the Entra ID "Block sign-in" state. Activity timestamps are maintained by the Mailbox Assistant and
                  can lag real usage by a few hours. Check the hold columns before removing licenses - held mailboxes must stay.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-exomailboxstatistics
.LINK
    https://learn.microsoft.com/purview/inactive-mailboxes-in-office-365
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
    [switch]$IncludeShared,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOInactiveMailboxes_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails', 'ExchangeGuid', 'AccountDisabled', 'SKUAssigned',
    'LitigationHoldEnabled', 'InPlaceHolds', 'WhenCreated', 'WhenMailboxCreated')
$recipientTypes = @('UserMailbox')
if ($IncludeShared) { $recipientTypes += 'SharedMailbox' }

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
        foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails $recipientTypes -Properties $mailboxProperties -ErrorAction Stop)) {
            $mailboxes.Add($mailbox)
        }
    }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}
Write-Verbose "Evaluating $($mailboxes.Count) mailbox(es) against a $DaysInactive-day threshold."

$results = New-Object -TypeName System.Collections.Generic.List[object]
$now = Get-Date
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    Write-Progress -Activity 'Reading mailbox activity' -Status "$index of $($mailboxes.Count) - $($mailbox.DisplayName)" -PercentComplete (($index / $mailboxes.Count) * 100)
    try {
        $stats = Get-EXOMailboxStatistics -ExchangeGuid $mailbox.ExchangeGuid -Properties LastUserActionTime, LastInteractionTime -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not read statistics for '$($mailbox.UserPrincipalName)': $($_.Exception.Message)"
        continue
    }

    # The two timestamps are maintained independently, so the newer one is the safest "last activity" value;
    # never-used mailboxes are measured from their creation date so brand-new mailboxes are not reported.
    $activity = @($stats.LastUserActionTime, $stats.LastInteractionTime | Where-Object { $null -ne $_ } | ForEach-Object { [datetime]$_ } | Sort-Object -Descending)
    if ($activity.Count -gt 0) {
        $status = 'Inactive'
        $referenceDate = $activity[0]
    }
    else {
        $status = 'NeverUsed'
        $referenceDate = $mailbox.WhenMailboxCreated
        if ($null -eq $referenceDate) { $referenceDate = $mailbox.WhenCreated }
    }
    $daysIdle = [int][math]::Floor((New-TimeSpan -Start ([datetime]$referenceDate) -End $now).TotalDays)
    if ($daysIdle -lt $DaysInactive) { continue }

    $results.Add([PSCustomObject]@{
            DisplayName         = $mailbox.DisplayName
            UserPrincipalName   = $mailbox.UserPrincipalName
            MailboxType         = [string]$mailbox.RecipientTypeDetails
            Status              = $status
            LastUserActionTime  = $stats.LastUserActionTime
            LastInteractionTime = $stats.LastInteractionTime
            DaysInactive        = $daysIdle
            SizeGB              = ConvertTo-GB -Size $stats.TotalItemSize
            ItemCount           = $stats.ItemCount
            AccountDisabled     = [bool]$mailbox.AccountDisabled
            Licensed            = ($mailbox.SKUAssigned -eq $true)
            LitigationHold      = [bool]$mailbox.LitigationHoldEnabled
            InPlaceHoldCount    = @($mailbox.InPlaceHolds | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
            WhenCreated         = $mailbox.WhenCreated
        })
}
Write-Progress -Activity 'Reading mailbox activity' -Completed

if ($results.Count -eq 0) {
    Write-Host "No mailboxes have been inactive for $DaysInactive days or more (scanned $($mailboxes.Count)); nothing to export." -ForegroundColor Green
    return
}
$results | Sort-Object -Property DaysInactive -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$totalGB = ($results | Where-Object { $null -ne $_.SizeGB } | Measure-Object -Property SizeGB -Sum).Sum

Write-Host ''
Write-Host "Inactive mailbox summary ($DaysInactive-day threshold)" -ForegroundColor Cyan
Write-Host ('  Mailboxes scanned      : {0}' -f $mailboxes.Count)
Write-Host ('  Inactive               : {0} ({1} never used)' -f $results.Count, @($results | Where-Object { $_.Status -eq 'NeverUsed' }).Count) -ForegroundColor Yellow
Write-Host ('  Still licensed         : {0}' -f @($results | Where-Object { $_.Licensed }).Count)
Write-Host ('  Sign-in still enabled  : {0}' -f @($results | Where-Object { -not $_.AccountDisabled }).Count)
Write-Host ('  On hold (must preserve): {0}' -f @($results | Where-Object { $_.LitigationHold -or $_.InPlaceHoldCount -gt 0 }).Count)
Write-Host ('  Total size             : {0:N2} GB' -f [double]$totalGB)
Write-Host ('  Report                 : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
