<#
.SYNOPSIS
    Converts user mailboxes to shared mailboxes (or back to regular) after a licensing and size pre-flight check.
.DESCRIPTION
    Reads each selected mailbox with Get-EXOMailbox and Get-EXOMailboxStatistics and works out the license impact: a
    shared mailbox over 50 GB, with an archive or on hold must keep an Exchange Online Plan 2 (or Plan 1 + Archiving)
    license, otherwise the license can be reclaimed. Without -ToShared or -ToRegular only this pre-flight assessment is
    reported. -ToShared runs Set-Mailbox -Type Shared and can hide the mailbox from the GAL and grant FullAccess
    delegates in the same step; -ToRegular reverses the conversion (-WhatIf / -Confirm supported). Results go to CSV.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID) to convert.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to convert.
.PARAMETER ToShared
    Convert the selected user mailboxes to shared mailboxes. Every change supports -WhatIf and -Confirm.
.PARAMETER ToRegular
    Convert the selected shared mailboxes back to regular user mailboxes (a license must be assigned within 30 days).
.PARAMETER HideFromAddressList
    With -ToShared, also set HiddenFromAddressListsEnabled so the converted mailbox disappears from the GAL.
.PARAMETER GrantFullAccessTo
    With -ToShared, recipients (UPN or SMTP address) that receive FullAccess on the converted mailbox.
.PARAMETER NoAutoMapping
    Grant FullAccess with AutoMapping disabled so Outlook does not add the mailbox to the delegates' profiles automatically.
.PARAMETER OutputPath
    Path of the CSV results file. Defaults to .\Reports\EXOMailboxConversion_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\Convert-EXOMailboxToShared.ps1 -InputCsv .\Leavers.csv
    Pre-flight only: shows size, holds and whether each leaver's license can be removed after conversion.
.EXAMPLE
    PS> .\Convert-EXOMailboxToShared.ps1 -Identity jsmith@contoso.com -ToShared -HideFromAddressList -GrantFullAccessTo manager@contoso.com -NoAutoMapping
    Converts the mailbox to shared, hides it from the GAL and gives the manager FullAccess without Outlook auto-mapping.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator (or Mail Recipients role) to convert; View-Only Recipients for the pre-flight report
    Category    : Mailbox lifecycle & compliance
    Changes     : Yes
    Notes       : Never delete the Entra user after converting - the shared mailbox lives in that account. Block sign-in instead
                  (Update-MgUser -UserId <upn> -AccountEnabled:$false) and remove the license only when LicenseGuidance allows it.
.LINK
    https://learn.microsoft.com/exchange/recipients-in-exchange-online/convert-a-mailbox
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
    [switch]$ToShared,

    [Parameter()]
    [switch]$ToRegular,

    [Parameter()]
    [switch]$HideFromAddressList,

    [Parameter()]
    [string[]]$GrantFullAccessTo,

    [Parameter()]
    [switch]$NoAutoMapping,

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
if ($ToShared -and $ToRegular) { throw 'Use either -ToShared or -ToRegular, not both.' }
$targetType = 'Shared'
if ($ToRegular) { $targetType = 'Regular' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMailboxConversion_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$trustees = New-Object -TypeName System.Collections.Generic.List[string]
if ($targetType -eq 'Shared' -and $PSBoundParameters.ContainsKey('GrantFullAccessTo')) {
    # Resolve delegates once up front so a typo does not surface halfway through the batch.
    foreach ($trustee in $GrantFullAccessTo) {
        try { $trustees.Add([string](Get-EXORecipient -Identity $trustee -Properties PrimarySmtpAddress -ErrorAction Stop | Select-Object -First 1).PrimarySmtpAddress) }
        catch { Write-Warning "Trustee '$trustee' was not found; FullAccess will not be granted to it." }
    }
}
$selection = @($Identity)
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails', 'ExchangeGuid', 'SKUAssigned', 'ArchiveStatus', 'LitigationHoldEnabled', 'InPlaceHolds', 'AccountDisabled')
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($id in $selection) {
    $index++
    Write-Progress -Activity "Evaluating mailboxes for conversion to $targetType" -Status "$index of $($selection.Count) - $id" -PercentComplete (($index / $selection.Count) * 100)
    try {
        $mailbox = Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop
        $stats = Get-EXOMailboxStatistics -ExchangeGuid $mailbox.ExchangeGuid -ErrorAction Stop
    }
    catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)"; continue }

    $upn = $mailbox.UserPrincipalName
    $guid = [string]$mailbox.ExchangeGuid
    $typeBefore = [string]$mailbox.RecipientTypeDetails
    $sizeGB = $null
    if ("$($stats.TotalItemSize)" -match '\(([\d,\.]+)\s+bytes\)') { $sizeGB = [math]::Round(([double]($Matches[1] -replace '[,\.]', '')) / 1GB, 2) }
    $onHold = ([bool]$mailbox.LitigationHoldEnabled -or @($mailbox.InPlaceHolds | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0)

    # Decide whether the mailbox is a valid candidate and what the conversion means for its license.
    $convert = $true
    if ($targetType -eq 'Shared') {
        if ($typeBefore -eq 'SharedMailbox') { $convert = $false; $guidance = 'Already a shared mailbox' }
        elseif ($typeBefore -ne 'UserMailbox') { $convert = $false; $guidance = "Not a user mailbox ($typeBefore)" }
        elseif ($null -ne $sizeGB -and $sizeGB -gt 50) { $guidance = 'Keep the license: mailbox is over the 50 GB unlicensed limit' }
        elseif ($onHold -or [string]$mailbox.ArchiveStatus -eq 'Active') { $guidance = 'Keep the license: archive or hold requires Plan 2 / Exchange Online Archiving' }
        else { $guidance = 'License can be removed after conversion' }
    }
    else {
        if ($typeBefore -ne 'SharedMailbox') { $convert = $false; $guidance = "Not a shared mailbox ($typeBefore)" }
        elseif ($mailbox.SKUAssigned -ne $true) { $guidance = 'Assign an Exchange Online license within 30 days or the mailbox will be disabled' }
        else { $guidance = 'Licensed - ready to convert' }
    }

    $result = 'Report only'
    if (-not $convert) { $result = 'Skipped' }
    elseif ($ToShared -or $ToRegular) {
        $operation = "Convert $typeBefore to $targetType mailbox"
        $setParams = @{ Identity = $guid; Type = $targetType; ErrorAction = 'Stop' }
        if ($targetType -eq 'Shared' -and $HideFromAddressList) { $setParams['HiddenFromAddressListsEnabled'] = $true; $operation += ', hide from address lists' }
        if ($trustees.Count -gt 0) { $operation += ", grant FullAccess to $($trustees -join ', ')" }
        if ($PSCmdlet.ShouldProcess($upn, $operation)) {
            try {
                Set-Mailbox @setParams
                foreach ($trustee in $trustees) { Add-MailboxPermission -Identity $guid -User $trustee -AccessRights FullAccess -AutoMapping (-not $NoAutoMapping) -ErrorAction Stop | Out-Null }
                $result = 'Converted'
            }
            catch { $result = "Failed: $($_.Exception.Message)"; Write-Warning "Conversion of '$upn' failed: $($_.Exception.Message)" }
        }
        else { $result = 'Not confirmed' }
    }

    $results.Add([PSCustomObject]@{
            DisplayName       = $mailbox.DisplayName
            UserPrincipalName = $upn
            TypeBefore        = $typeBefore
            SizeGB            = $sizeGB
            Licensed          = ($mailbox.SKUAssigned -eq $true)
            OnHold            = $onHold
            SignInBlocked     = [bool]$mailbox.AccountDisabled
            LicenseGuidance   = $guidance
            FullAccessGranted = $(if ($result -eq 'Converted') { $trustees -join '; ' } else { '' })
            Result            = $result
        })
}
Write-Progress -Activity "Evaluating mailboxes for conversion to $targetType" -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes could be evaluated; nothing to export.'; return }
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$failed = @($results | Where-Object { $_.Result -like 'Failed*' }).Count
Write-Host "Mailbox conversion summary (target type: $targetType, $($results.Count) evaluated)" -ForegroundColor Cyan
Write-Host ('  Converted         : {0}' -f @($results | Where-Object { $_.Result -eq 'Converted' }).Count) -ForegroundColor Green
Write-Host ('  Skipped / failed  : {0} / {1}' -f @($results | Where-Object { $_.Result -eq 'Skipped' }).Count, $failed) -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Gray' })
Write-Host ('  Must keep license : {0}' -f @($results | Where-Object { $_.LicenseGuidance -like 'Keep*' }).Count) -ForegroundColor Yellow
if (-not ($ToShared -or $ToRegular)) { Write-Host '  Pre-flight only - re-run with -ToShared or -ToRegular to apply the conversion.' -ForegroundColor Yellow }
Write-Host ('  Results           : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
