<#
.SYNOPSIS
    Places selected mailboxes on litigation hold (or releases them) with duration, owner and notice details.
.DESCRIPTION
    Reads the current hold state and license of each selected mailbox with Get-EXOMailbox. The default run is a pre-flight
    report: hold state, date, owner, duration and whether the license (Plan 2 or Exchange Online Archiving, derived from
    PersistedCapabilities) supports litigation hold. -Enable runs Set-Mailbox -LitigationHoldEnabled $true with the optional
    -DurationDays, -HoldOwner, -RetentionComment and -RetentionUrl; -Disable releases the hold. Results are written to CSV.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID).
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to process.
.PARAMETER Enable
    Place the selected mailboxes on litigation hold (or update the hold settings of mailboxes already on hold).
.PARAMETER Disable
    Release the litigation hold on the selected mailboxes. Exchange applies a 30-day delay hold afterwards.
.PARAMETER DurationDays
    Hold duration in days, counted from the date each item was received or created. Omit for an unlimited hold.
.PARAMETER HoldOwner
    Person responsible for the hold (for example the legal contact), stored in LitigationHoldOwner.
.PARAMETER RetentionComment
    Text shown to the user in Outlook explaining why the mailbox is on hold.
.PARAMETER RetentionUrl
    URL shown next to the comment in Outlook, typically an intranet page describing the hold.
.PARAMETER OutputPath
    Path of the CSV results file. Defaults to .\Reports\EXOLitigationHold_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\Set-EXOLitigationHold.ps1 -InputCsv .\Custodians.csv
    Pre-flight only: reports the current hold state and license suitability of every custodian in the CSV.
.EXAMPLE
    PS> .\Set-EXOLitigationHold.ps1 -InputCsv .\Custodians.csv -Enable -DurationDays 2555 -HoldOwner legal@contoso.com -RetentionComment 'Case 2026-014' -Confirm:$false
    Places all custodians on a seven-year hold owned by Legal without prompting for each mailbox.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator with the Legal Hold role (Organization Management or Discovery Management) for -Enable / -Disable; View-Only Recipients for the report
    Category    : Mailbox lifecycle & compliance
    Changes     : Yes
    Notes       : Litigation hold requires Exchange Online Plan 2, or Plan 1 plus Exchange Online Archiving (shared mailboxes too).
                  Holds take up to 60 minutes to become effective. Releasing a hold sets DelayHoldApplied for 30 days (clear early
                  with Set-Mailbox -RemoveDelayHoldApplied). Prefer Purview retention policies or eDiscovery holds for org-wide use.
.LINK
    https://learn.microsoft.com/purview/ediscovery-create-a-litigation-hold
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Identity')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$Enable,

    [Parameter()]
    [switch]$Disable,

    [Parameter()]
    [ValidateRange(1, 24855)]
    [int]$DurationDays,

    [Parameter()]
    [string]$HoldOwner,

    [Parameter()]
    [string]$RetentionComment,

    [Parameter()]
    [string]$RetentionUrl,

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
if ($Enable -and $Disable) { throw 'Use either -Enable or -Disable, not both.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOLitigationHold_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$selection = @($Identity)
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}

# Optional hold settings are only sent when supplied, so an -Enable on a mailbox already on hold keeps its existing values.
$holdSettings = @{}
if ($PSBoundParameters.ContainsKey('DurationDays')) { $holdSettings['LitigationHoldDuration'] = $DurationDays }
if ($HoldOwner) { $holdSettings['LitigationHoldOwner'] = $HoldOwner }
if ($RetentionComment) { $holdSettings['RetentionComment'] = $RetentionComment }
if ($RetentionUrl) { $holdSettings['RetentionUrl'] = $RetentionUrl }
$durationText = 'unlimited'
if ($PSBoundParameters.ContainsKey('DurationDays')) { $durationText = "$DurationDays days" }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails', 'SKUAssigned', 'PersistedCapabilities', 'LitigationHoldEnabled',
    'LitigationHoldDate', 'LitigationHoldOwner', 'LitigationHoldDuration', 'DelayHoldApplied')
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($id in $selection) {
    $index++
    Write-Progress -Activity 'Processing litigation holds' -Status "$index of $($selection.Count) - $id" -PercentComplete (($index / $selection.Count) * 100)
    try { $mailbox = Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop }
    catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)"; continue }

    $upn = $mailbox.UserPrincipalName
    $holdBefore = [bool]$mailbox.LitigationHoldEnabled
    $capabilities = @($mailbox.PersistedCapabilities | ForEach-Object { [string]$_ })
    $holdLicense = 'Not supported by license (Plan 1 or Kiosk)'
    if ($mailbox.SKUAssigned -ne $true) { $holdLicense = 'Unlicensed' }
    elseif ($capabilities -contains 'BPOS_S_Enterprise') { $holdLicense = 'Plan 2' }
    elseif ($capabilities -contains 'BPOS_S_ArchiveAddOn' -or $capabilities -contains 'BPOS_S_Archive') { $holdLicense = 'Exchange Online Archiving' }
    $licenseOk = ($holdLicense -eq 'Plan 2' -or $holdLicense -eq 'Exchange Online Archiving')

    $result = 'Report only'
    if ($Enable) {
        if ($holdBefore -and $holdSettings.Count -eq 0) { $result = 'Already on hold' }
        else {
            if (-not $licenseOk) { Write-Warning "'$upn' is $holdLicense - litigation hold requires Plan 2 or Exchange Online Archiving." }
            if ($PSCmdlet.ShouldProcess($upn, "Enable litigation hold ($durationText)")) {
                try {
                    # Exchange prints a "may take up to 60 minutes" warning for every mailbox; the summary covers that once.
                    Set-Mailbox -Identity $upn -LitigationHoldEnabled $true @holdSettings -WarningAction SilentlyContinue -ErrorAction Stop
                    $result = $(if ($holdBefore) { 'Hold updated' } else { 'Hold enabled' })
                }
                catch { $result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not enable the hold on '$upn': $($_.Exception.Message)" }
            }
            else { $result = 'Not confirmed' }
        }
    }
    elseif ($Disable) {
        if (-not $holdBefore) { $result = 'Not on hold' }
        elseif ($PSCmdlet.ShouldProcess($upn, 'Disable litigation hold')) {
            try { Set-Mailbox -Identity $upn -LitigationHoldEnabled $false -WarningAction SilentlyContinue -ErrorAction Stop; $result = 'Hold disabled' }
            catch { $result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not disable the hold on '$upn': $($_.Exception.Message)" }
        }
        else { $result = 'Not confirmed' }
    }

    $results.Add([PSCustomObject]@{
            DisplayName            = $mailbox.DisplayName
            UserPrincipalName      = $upn
            MailboxType            = [string]$mailbox.RecipientTypeDetails
            HoldLicense            = $holdLicense
            LitigationHoldBefore   = $holdBefore
            LitigationHoldDate     = $mailbox.LitigationHoldDate
            LitigationHoldOwner    = [string]$mailbox.LitigationHoldOwner
            LitigationHoldDuration = [string]$mailbox.LitigationHoldDuration
            DelayHoldApplied       = [bool]$mailbox.DelayHoldApplied
            Result                 = $result
        })
}
Write-Progress -Activity 'Processing litigation holds' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes could be evaluated; nothing to export.'; return }
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$failed = @($results | Where-Object { $_.Result -like 'Failed*' }).Count

Write-Host "Litigation hold summary ($($results.Count) mailboxes evaluated)" -ForegroundColor Cyan
Write-Host ('  On hold before the run : {0}' -f @($results | Where-Object { $_.LitigationHoldBefore }).Count)
Write-Host ('  Enabled or updated     : {0}' -f @($results | Where-Object { $_.Result -in @('Hold enabled', 'Hold updated') }).Count) -ForegroundColor Green
Write-Host ('  Disabled               : {0}' -f @($results | Where-Object { $_.Result -eq 'Hold disabled' }).Count)
Write-Host ('  License not suitable   : {0}' -f @($results | Where-Object { $_.HoldLicense -notin @('Plan 2', 'Exchange Online Archiving') }).Count) -ForegroundColor Yellow
Write-Host ('  Failed                 : {0}' -f $failed) -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' })
if (-not ($Enable -or $Disable)) { Write-Host '  Report only - re-run with -Enable or -Disable to change holds.' -ForegroundColor Yellow }
Write-Host ('  Results                : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
