<#
.SYNOPSIS
    Sets custom storage quotas and deleted item retention on Exchange Online mailboxes with a before/after report.
.DESCRIPTION
    Reads the current quotas and RetainDeletedItemsFor of each selected mailbox with Get-EXOMailbox and compares them
    with the requested values. The default run is a pre-flight report (current -> new); -Apply runs Set-Mailbox (with
    -UseDatabaseQuotaDefaults $false so custom quotas take effect) wrapped in ShouldProcess. The resulting quota set must
    satisfy warning < send < send/receive; mailboxes that would violate this are skipped.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID).
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to process.
.PARAMETER IssueWarningQuotaGB
    New IssueWarningQuota in GB (0.1 - 100), the size at which the user receives a warning.
.PARAMETER ProhibitSendQuotaGB
    New ProhibitSendQuota in GB (0.1 - 100), the size at which the user can no longer send.
.PARAMETER ProhibitSendReceiveQuotaGB
    New ProhibitSendReceiveQuota in GB (0.1 - 100), the size at which the mailbox also rejects incoming mail.
.PARAMETER RetainDeletedItemsForDays
    Days that deleted items stay recoverable in the Deletions folder (0 - 30, Exchange Online default 14).
.PARAMETER Apply
    Perform the changes. Without this switch the script is read-only and reports the differences.
.PARAMETER OutputPath
    Path of the CSV results file. Defaults to .\Reports\EXOMailboxQuotas_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\Set-EXOMailboxQuotas.ps1 -InputCsv .\Executives.csv -IssueWarningQuotaGB 90 -ProhibitSendQuotaGB 95 -ProhibitSendReceiveQuotaGB 100
    Pre-flight only: shows the current and proposed quotas of the listed mailboxes without changing anything.
.EXAMPLE
    PS> .\Set-EXOMailboxQuotas.ps1 -Identity adele.vance@contoso.com -RetainDeletedItemsForDays 30 -Apply
    Extends deleted item retention of one mailbox to the 30-day maximum after confirmation. Add -WhatIf to only show the call.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator (Mail Recipients role) for -Apply; View-Only Recipients for the pre-flight report
    Category    : Mailbox content & settings
    Changes     : Yes
    Notes       : Exchange Online rejects quotas above the licensed maximum (50 GB for Plan 1 / E3 and shared mailboxes,
                  100 GB for Plan 2 / E5, 2 GB for Kiosk). A later license or mailbox plan change may reapply the plan defaults.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/set-mailbox
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [ValidateRange(0.1, 100)]
    [double]$IssueWarningQuotaGB,

    [Parameter()]
    [ValidateRange(0.1, 100)]
    [double]$ProhibitSendQuotaGB,

    [Parameter()]
    [ValidateRange(0.1, 100)]
    [double]$ProhibitSendReceiveQuotaGB,

    [Parameter()]
    [ValidateRange(0, 30)]
    [int]$RetainDeletedItemsForDays,

    [Parameter()]
    [switch]$Apply,

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
    <# Converts Exchange size text such as "49.5 GB (53,150,220,288 bytes)" to GB with 2 decimals; "Unlimited" or empty returns $null. #>
    param([Parameter()][AllowNull()]$Size)
    if ($null -ne $Size -and $Size.ToString() -match '\(([\d,]+) bytes\)') { return [math]::Round(([double]($Matches[1] -replace ',', '')) / 1GB, 2) }
    return $null
}
#endregion Helpers

#region Main
$quotaMap = [ordered]@{ IssueWarningQuotaGB = 'IssueWarningQuota'; ProhibitSendQuotaGB = 'ProhibitSendQuota'; ProhibitSendReceiveQuotaGB = 'ProhibitSendReceiveQuota' }
$setParams = @{}
if ($PSBoundParameters.ContainsKey('RetainDeletedItemsForDays')) { $setParams['RetainDeletedItemsFor'] = '{0}.00:00:00' -f $RetainDeletedItemsForDays }
$suppliedQuotas = @($quotaMap.Keys | Where-Object { $PSBoundParameters.ContainsKey($_) } | ForEach-Object { Get-Variable -Name $_ -ValueOnly })
if ($suppliedQuotas.Count -eq 0 -and $setParams.Count -eq 0) { throw 'Specify at least one of -IssueWarningQuotaGB, -ProhibitSendQuotaGB, -ProhibitSendReceiveQuotaGB or -RetainDeletedItemsForDays.' }
for ($i = 1; $i -lt $suppliedQuotas.Count; $i++) { if ($suppliedQuotas[$i - 1] -ge $suppliedQuotas[$i]) { throw 'Quotas must increase: warning < send < send/receive.' } }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMailboxQuotas_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

# Set-Mailbox parses "95.5GB" culture-invariantly, so the numbers must not be formatted with a locale decimal comma.
foreach ($paramName in $quotaMap.Keys) {
    if ($PSBoundParameters.ContainsKey($paramName)) { $setParams[$quotaMap[$paramName]] = [string]::Format([cultureinfo]::InvariantCulture, '{0}GB', (Get-Variable -Name $paramName -ValueOnly)) }
}
if ($suppliedQuotas.Count -gt 0) { $setParams['UseDatabaseQuotaDefaults'] = $false }
try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'IssueWarningQuota', 'ProhibitSendQuota', 'ProhibitSendReceiveQuota', 'UseDatabaseQuotaDefaults', 'RetainDeletedItemsFor')
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    Write-Warning 'No -Identity or -InputCsv specified: every user mailbox in the tenant is in scope.'
    try { foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -Properties $mailboxProperties -ErrorAction Stop)) { $mailboxes.Add($mailbox) } }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $upn = $mailbox.UserPrincipalName
    Write-Progress -Activity 'Processing mailbox quotas' -Status "$index of $($mailboxes.Count) - $upn" -PercentComplete (($index / $mailboxes.Count) * 100)
    $row = [ordered]@{ DisplayName = $mailbox.DisplayName; UserPrincipalName = $upn; UseDatabaseQuotaDefaults = [bool]$mailbox.UseDatabaseQuotaDefaults }
    $row['RetainDeletedItemsFor'] = [string]$mailbox.RetainDeletedItemsFor
    $newRetain = $setParams['RetainDeletedItemsFor']
    $changes = @()
    $chain = @()
    foreach ($paramName in $quotaMap.Keys) {
        $property = $quotaMap[$paramName]
        $currentGB = ConvertTo-GB -Size $mailbox.$property
        $newGB = $currentGB
        if ($PSBoundParameters.ContainsKey($paramName)) { $newGB = Get-Variable -Name $paramName -ValueOnly }
        if ($newGB -ne $currentGB) { $changes += ('{0} {1} -> {2} GB' -f $property, $currentGB, $newGB) }
        if ($null -ne $newGB) { $chain += $newGB }
        $row[$property + 'GB'] = $currentGB
        $row['New' + $property + 'GB'] = $newGB
    }
    if ($setParams.ContainsKey('UseDatabaseQuotaDefaults') -and $mailbox.UseDatabaseQuotaDefaults) { $changes += 'UseDatabaseQuotaDefaults True -> False' }
    if ($null -ne $newRetain -and $newRetain -ne $row.RetainDeletedItemsFor) { $changes += ('RetainDeletedItemsFor {0} -> {1}' -f $row.RetainDeletedItemsFor, $newRetain) }

    # $quotaMap is ordered warning, send, send/receive; Exchange requires strictly increasing values on the resulting set.
    $ordered = (($chain -join ' ') -eq (@($chain | Sort-Object -Unique) -join ' '))

    $status = 'Already compliant'
    if (-not $ordered) { $status = ('Skipped: resulting quotas {0} GB are not in increasing order' -f ($chain -join ' / ')) }
    elseif ($changes.Count -gt 0 -and -not $Apply) { $status = 'Would change' }
    elseif ($changes.Count -gt 0 -and $PSCmdlet.ShouldProcess($upn, ('Set mailbox quotas: {0}' -f ($changes -join '; ')))) {
        try { Set-Mailbox -Identity $upn @setParams -ErrorAction Stop; $status = 'Changed' }
        catch { $status = "Failed: $($_.Exception.Message)"; Write-Warning "Could not update '$upn': $($_.Exception.Message)" }
    }
    elseif ($changes.Count -gt 0) { $status = 'Not confirmed' }

    $row['Changes'] = ($changes -join '; ')
    $row['Status'] = $status
    $results.Add([PSCustomObject]$row)
}
Write-Progress -Activity 'Processing mailbox quotas' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes could be evaluated; nothing to export.'; return }
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Mailbox quota summary ($($results.Count) mailboxes evaluated)" -ForegroundColor Cyan
foreach ($state in @('Already compliant', 'Would change', 'Changed', 'Not confirmed', 'Skipped*', 'Failed*')) {
    $count = @($results | Where-Object { $_.Status -like $state }).Count
    Write-Host ('  {0,-18}: {1}' -f $state.TrimEnd('*'), $count) -ForegroundColor $(if ($count -gt 0 -and $state.EndsWith('*')) { 'Yellow' } else { 'White' })
}
if (-not $Apply) { Write-Host '  Pre-flight only - re-run with -Apply to change the quotas.' -ForegroundColor Yellow }
Write-Host ('  {0,-18}: {1}' -f 'Results', $OutputPath)

if ($PassThru) { $results }
#endregion Main
