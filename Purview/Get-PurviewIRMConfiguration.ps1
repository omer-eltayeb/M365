<#
.SYNOPSIS
    Audits the Exchange Online IRM / Azure Rights Management configuration against recommended values.
.DESCRIPTION
    Reads Get-IRMConfiguration and turns every relevant setting (licensing, Outlook on the web Encrypt button, PDF
    encryption, journal report decryption, transport decryption, eDiscovery super user, search, automatic service
    updates and the RMS locations) into a Setting / Value / Recommended / Status / Recommendation row, and exports the
    Azure RMS templates (Get-RMSTemplate) to a second CSV. -TestSender runs Test-IRMConfiguration for a mailbox and
    prints the result. -SetRecommended enables the Encrypt button, PDF encryption and attachment decryption for
    Encrypt-Only mail with Set-IRMConfiguration; every change is wrapped in ShouldProcess. Read-only otherwise.
.PARAMETER TestSender
    User principal name of a mailbox to validate with Test-IRMConfiguration -Sender (template acquisition, encryption, decryption).
.PARAMETER SetRecommended
    Apply Set-IRMConfiguration -SimplifiedClientAccessEnabled $true -EnablePdfEncryption $true -DecryptAttachmentForEncryptOnly $true.
.PARAMETER OutputPath
    Path of the settings CSV. Defaults to .\Reports\PurviewIRMConfiguration_yyyyMMdd-HHmm.csv; templates go to <base>_Templates.csv.
.PARAMETER PassThru
    Also emit the setting rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewIRMConfiguration.ps1
    Exports the IRM settings with recommendations and the RMS templates, and prints which settings need review.
.EXAMPLE
    PS> .\Get-PurviewIRMConfiguration.ps1 -TestSender alex@contoso.com -Verbose
    Additionally runs the end-to-end IRM test for the given mailbox and prints each test step with its PASS / FAIL result.
.EXAMPLE
    PS> .\Get-PurviewIRMConfiguration.ps1 -SetRecommended -WhatIf
    Shows the Set-IRMConfiguration change that would be made without applying it.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Organization Configuration role (Exchange Online) for Set-IRMConfiguration; View-Only Organization Management is enough for the report
    Category    : Information protection
    Changes     : Optional (-SetRecommended)
    Notes       : Opens an Exchange Online session (Connect-ExchangeOnline). Azure RMS must be activated and AzureRMSLicensingEnabled
                  must be True before the Outlook on the web settings can be enabled; Get-RMSTemplate fails until then. The
                  recommendations reflect Microsoft Purview Message Encryption defaults - TransportDecryptionSetting Mandatory
                  and ExternalLicensingEnabled False are valid, deliberate choices in some organisations.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-irmconfiguration
.LINK
    https://learn.microsoft.com/powershell/module/exchange/set-irmconfiguration
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+$')]
    [string]$TestSender,

    [Parameter()]
    [switch]$SetRecommended,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewIRMConfiguration_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($outputFolder)) { $outputFolder = '.' }
$templatePath = Join-Path -Path $outputFolder -ChildPath ('{0}_Templates.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath))

try {
    Connect-ExchangeIfNeeded
    $config = Get-IRMConfiguration -ErrorAction Stop
}
catch {
    throw "Unable to connect to Exchange Online or read the IRM configuration: $($_.Exception.Message)"
}

if ($SetRecommended) {
    if ($config.AzureRMSLicensingEnabled -ne $true) {
        Write-Warning 'AzureRMSLicensingEnabled is False; Exchange Online cannot reach Azure RMS, so the recommended settings may be rejected.'
    }
    $change = 'Set SimplifiedClientAccessEnabled, EnablePdfEncryption and DecryptAttachmentForEncryptOnly to True'
    if ($PSCmdlet.ShouldProcess('IRM configuration', $change)) {
        try {
            Set-IRMConfiguration -SimplifiedClientAccessEnabled $true -EnablePdfEncryption $true -DecryptAttachmentForEncryptOnly $true -ErrorAction Stop
            $config = Get-IRMConfiguration -ErrorAction Stop
            Write-Host 'Recommended IRM settings applied.' -ForegroundColor Green
        }
        catch {
            Write-Warning "Set-IRMConfiguration failed: $($_.Exception.Message)"
        }
    }
}

# Setting, recommended value ($null = informational) and why it matters.
$checks = @(
    @('InternalLicensingEnabled', $true, 'Required for IRM and sensitivity label encryption inside Exchange Online (OWA, transport rules, journaling).'),
    @('ExternalLicensingEnabled', $true, 'Lets protected mail reach external recipients through Microsoft Purview Message Encryption.'),
    @('AzureRMSLicensingEnabled', $true, 'Connects Exchange Online to Azure Rights Management; every other IRM feature depends on it.'),
    @('SimplifiedClientAccessEnabled', $true, 'Shows the Encrypt button in Outlook on the web.'),
    @('SimplifiedClientAccessEncryptOnlyDisabled', $false, 'Keeps the Encrypt-Only option available in Outlook on the web.'),
    @('SimplifiedClientAccessDoNotForwardDisabled', $false, 'Keeps the Do Not Forward option available in Outlook on the web.'),
    @('EnablePdfEncryption', $true, 'Encrypts PDF attachments together with the protected message.'),
    @('DecryptAttachmentForEncryptOnly', $true, 'Lets recipients of Encrypt-Only mail open downloaded attachments without the portal.'),
    @('JournalReportDecryptionEnabled', $true, 'Adds a decrypted copy to journal reports so archiving and eDiscovery can read protected mail.'),
    @('TransportDecryptionSetting', 'Optional', 'Lets transport rules and DLP inspect protected mail; Disabled bypasses inspection, Mandatory rejects undecryptable mail.'),
    @('EDiscoverySuperUserEnabled', $true, 'Lets eDiscovery managers decrypt protected messages in search results.'),
    @('SearchEnabled', $true, 'Indexes protected messages so Outlook and eDiscovery searches find them.'),
    @('AutomaticServiceUpdateEnabled', $true, 'Picks up new Azure RMS features and templates such as Encrypt-Only automatically.'),
    @('RMSOnlineKeySharingLocation', $null, 'Populated automatically once Azure RMS is connected (informational).'),
    @('LicensingLocation', $null, 'Azure RMS licensing URL(s) imported with the trusted publishing domain (informational).')
)
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($check in $checks) {
    $value = $config.($check[0])
    $valueText = (@($value | ForEach-Object { [string]$_ }) -join ';')
    $status = 'Info'
    if ($null -ne $check[1]) { $status = $(if ($valueText -eq [string]$check[1]) { 'OK' } else { 'Review' }) }
    elseif ([string]::IsNullOrWhiteSpace($valueText) -and $config.AzureRMSLicensingEnabled -eq $true) { $status = 'Review' }
    $rows.Add([PSCustomObject]@{
            Setting        = $check[0]
            Value          = $valueText
            Recommended    = [string]$check[1]
            Status         = $status
            Recommendation = $check[2]
        })
}
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$templates = @()
try {
    $templates = @(Get-RMSTemplate -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Name = [string]$_.Name; Description = [string]$_.Description; Type = [string]$_.Type; TemplateGuid = [string]$_.TemplateGuid }
        })
    if ($templates.Count -gt 0) { $templates | Export-Csv -Path $templatePath -NoTypeInformation -Encoding UTF8 }
}
catch {
    Write-Warning "Get-RMSTemplate failed (Azure RMS not connected?): $($_.Exception.Message)"
}

if ($PSBoundParameters.ContainsKey('TestSender')) {
    try {
        $test = Test-IRMConfiguration -Sender $TestSender -ErrorAction Stop
        Write-Host ''
        Write-Host ('Test-IRMConfiguration for {0}' -f $TestSender) -ForegroundColor Cyan
        foreach ($line in @([string]$test.Results -split "`r?`n")) {
            if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Host ('  {0}' -f $line.Trim()) -ForegroundColor $(if ($line -match 'FAIL') { 'Yellow' } else { 'Gray' }) }
        }
    }
    catch {
        Write-Warning "Test-IRMConfiguration failed for ${TestSender}: $($_.Exception.Message)"
    }
}

$review = @($rows | Where-Object { $_.Status -eq 'Review' })
Write-Host ''
Write-Host 'IRM configuration summary' -ForegroundColor Cyan
Write-Host ('  Settings OK     : {0}' -f @($rows | Where-Object { $_.Status -eq 'OK' }).Count)
Write-Host ('  Settings to fix : {0}' -f $review.Count) -ForegroundColor $(if ($review.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $review) { Write-Host ('    {0} = {1} (recommended {2})' -f $row.Setting, $row.Value, $row.Recommended) -ForegroundColor Yellow }
Write-Host ('  RMS templates   : {0}' -f $templates.Count)
Write-Host ('  Report          : {0}' -f $OutputPath)
if ($templates.Count -gt 0) { Write-Host ('  Templates       : {0}' -f $templatePath) }

if ($PassThru) {
    $rows
}
#endregion Main
