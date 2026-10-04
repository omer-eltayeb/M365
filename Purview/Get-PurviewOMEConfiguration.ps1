<#
.SYNOPSIS
    Documents Microsoft Purview Message Encryption (OME) branding templates and the transport rules that use them.
.DESCRIPTION
    Reads every OME configuration (Get-OMEConfiguration) from Exchange Online - email, portal, disclaimer, introduction
    and button texts, background colour, logo size, social ID sign-in, one-time passcode, external mail expiry, privacy
    statement URL - plus the mail flow rules that apply rights protection or a custom OME template (Get-TransportRule).
    Writes the templates to -OutputPath and the rules to <base>_TransportRules.csv. -ExportBranding saves each logo to
    -OutputFolder; -Set updates one template's text, colour or logo with Set-OMEConfiguration (ShouldProcess).
.PARAMETER ExportBranding
    Write the logo of every template that has one to -OutputFolder (format detected from the image header).
.PARAMETER OutputFolder
    Folder for exported logos. Defaults to the folder of -OutputPath.
.PARAMETER Set
    Apply the given text, colour and image values to the template named by -Identity. Nothing is changed without it.
.PARAMETER Identity
    OME configuration to modify with -Set. Defaults to the built-in template "OME Configuration".
.PARAMETER EmailText
    Text shown above the instructions in the encrypted mail notification (max 1024 characters).
.PARAMETER PortalText
    Text shown at the top of the encrypted message portal (max 128 characters).
.PARAMETER DisclaimerText
    Disclaimer text in the notification mail (max 1024 characters).
.PARAMETER BackgroundColor
    Background colour as "#RRGGBB" or a supported colour name.
.PARAMETER ImagePath
    Logo file (.png, .jpg, .bmp or .tiff; ideally 170x70 pixels and under 40 KB) uploaded with Set-OMEConfiguration -Image.
.PARAMETER OutputPath
    Path of the templates CSV. Defaults to .\Reports\PurviewOMEConfiguration_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the template rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewOMEConfiguration.ps1 -ExportBranding
    Exports all OME templates and their mail flow rules to CSV and saves every logo next to the report.
.EXAMPLE
    PS> .\Get-PurviewOMEConfiguration.ps1 -Set -EmailText 'You have received a protected message from Contoso.' -BackgroundColor '#0F4C81' -ImagePath .\logo.png
    Updates the default template's notification text, colour and logo after confirmation (add -WhatIf to preview), then exports the result.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Organization Configuration role (Exchange Online) for -Set; View-Only Organization Management is enough for the report
    Category    : Information protection
    Changes     : Optional (-Set)
    Notes       : Opens an Exchange Online session (Connect-ExchangeOnline). Custom templates (New-OMEConfiguration) and external mail
                  expiry need Microsoft 365 Advanced Message Encryption (E5 / E5 Compliance); the default template cannot set an
                  expiry. Logos are stored as bytes without a file name, so the export sniffs the format from the image header.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-omeconfiguration
.LINK
    https://learn.microsoft.com/powershell/module/exchange/set-omeconfiguration
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$ExportBranding,

    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [switch]$Set,

    [Parameter()]
    [string]$Identity = 'OME Configuration',

    [Parameter()]
    [string]$EmailText,

    [Parameter()]
    [string]$PortalText,

    [Parameter()]
    [string]$DisclaimerText,

    [Parameter()]
    [string]$BackgroundColor,

    [Parameter()]
    [string]$ImagePath,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewOMEConfiguration_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($outputFolder)) { $outputFolder = '.' }
if ([string]::IsNullOrWhiteSpace($OutputFolder)) { $OutputFolder = $outputFolder }
if ($ExportBranding -and -not (Test-Path -Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null }
$rulePath = Join-Path -Path $outputFolder -ChildPath ('{0}_TransportRules.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath))

try { Connect-ExchangeIfNeeded; $configs = @(Get-OMEConfiguration -ErrorAction Stop) }
catch { throw "Unable to connect to Exchange Online or read the OME configuration: $($_.Exception.Message)" }

if ($Set) {
    # Set-OMEConfiguration has its own confirmation pause; the ShouldProcess call below already covers it.
    $setParams = @{ Identity = $Identity; ErrorAction = 'Stop'; Confirm = $false }
    foreach ($name in 'EmailText', 'PortalText', 'DisclaimerText', 'BackgroundColor') { if ($PSBoundParameters.ContainsKey($name)) { $setParams[$name] = $PSBoundParameters[$name] } }
    if ($PSBoundParameters.ContainsKey('ImagePath')) {
        $imageFile = Get-Item -Path $ImagePath -ErrorAction Stop
        if ($imageFile.Extension -notin '.png', '.jpg', '.jpeg', '.bmp', '.tif', '.tiff') { throw 'The logo must be a .png, .jpg, .bmp or .tiff file.' }
        if ($imageFile.Length -gt 40KB) { Write-Warning ('{0} is {1:N0} bytes; Microsoft recommends a logo under 40 KB (about 170x70 pixels).' -f $imageFile.Name, $imageFile.Length) }
        $setParams['Image'] = [System.IO.File]::ReadAllBytes($imageFile.FullName)
    }
    $changes = @($setParams.Keys | Where-Object { $_ -notin 'Identity', 'ErrorAction', 'Confirm' } | Sort-Object)
    if ($changes.Count -eq 0) { throw '-Set requires at least one of -EmailText, -PortalText, -DisclaimerText, -BackgroundColor or -ImagePath.' }
    if ($PSCmdlet.ShouldProcess($Identity, ('Set OME configuration ({0})' -f ($changes -join ', ')))) {
        try {
            Set-OMEConfiguration @setParams
            $configs = @(Get-OMEConfiguration -ErrorAction Stop)
            Write-Host ("OME configuration '{0}' updated: {1}" -f $Identity, ($changes -join ', ')) -ForegroundColor Green
        }
        catch { Write-Warning "Set-OMEConfiguration failed for '${Identity}': $($_.Exception.Message)" }
    }
}

$ruleRows = @()
try {
    $ruleRows = @(Get-TransportRule -ResultSize Unlimited -ErrorAction Stop | Where-Object { $_.ApplyRightsProtectionTemplate -or $_.ApplyRightsProtectionCustomizationTemplate } | ForEach-Object {
            [PSCustomObject]@{
                Name = [string]$_.Name; State = [string]$_.State; Mode = [string]$_.Mode; Priority = $_.Priority; WhenChanged = $_.WhenChanged
                RightsProtectionTemplate = [string]$_.ApplyRightsProtectionTemplate; OMECustomizationTemplate = [string]$_.ApplyRightsProtectionCustomizationTemplate
            }
        })
}
catch { Write-Warning "Transport rules could not be read (Transport Rules role needed): $($_.Exception.Message)" }

# Logos are stored as bytes only; the first two bytes identify the format for the export file name.
$signatures = @{ '89-50' = '.png'; 'FF-D8' = '.jpg'; '42-4D' = '.bmp'; '47-49' = '.gif'; '49-49' = '.tif'; '4D-4D' = '.tif' }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$exported = 0
foreach ($config in $configs) {
    $image = @()
    if ($null -ne $config.Image) { $image = [byte[]]$config.Image }
    $expiry = @($config.PSObject.Properties | Where-Object { $_.Name -in 'ExternalMailExpiryInDays', 'ExternalMailExpiryInterval' }) | Select-Object -First 1
    $rows.Add([PSCustomObject]@{
            Identity                 = [string]$config.Identity
            EmailText                = [string]$config.EmailText
            PortalText               = [string]$config.PortalText
            DisclaimerText           = [string]$config.DisclaimerText
            IntroductionText         = [string]$config.IntroductionText
            ReadButtonText           = [string]$config.ReadButtonText
            BackgroundColor          = [string]$config.BackgroundColor
            ImageBytes               = $image.Count
            SocialIdSignIn           = $config.SocialIdSignIn
            OTPEnabled               = $config.OTPEnabled
            ExternalMailExpiryInDays = $(if ($null -ne $expiry) { [string]$expiry.Value } else { $null })
            PrivacyStatementUrl      = [string]$config.PrivacyStatementUrl
            UsedByTransportRules     = (@($ruleRows | Where-Object { $_.OMECustomizationTemplate -eq [string]$config.Identity } | ForEach-Object { $_.Name }) -join ';')
        })
    if ($ExportBranding -and $image.Count -ge 2) {
        $key = [System.BitConverter]::ToString($image, 0, 2)
        $extension = $(if ($signatures.ContainsKey($key)) { $signatures[$key] } else { '.bin' })
        $logoPath = Join-Path -Path $OutputFolder -ChildPath ('OME_{0}{1}' -f ([string]$config.Identity -replace '[^\w\-]+', '_'), $extension)
        try { [System.IO.File]::WriteAllBytes($logoPath, $image); $exported++; Write-Verbose "Logo of '$($config.Identity)' written to $logoPath." }
        catch { Write-Warning "Could not write ${logoPath}: $($_.Exception.Message)" }
    }
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($ruleRows.Count -gt 0) { $ruleRows | Export-Csv -Path $rulePath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'OME configuration summary' -ForegroundColor Cyan
Write-Host ('  Templates        : {0} ({1} with a custom logo)' -f $rows.Count, @($rows | Where-Object { $_.ImageBytes -gt 0 }).Count)
Write-Host ('  Mail flow rules  : {0} apply rights protection or an OME template' -f $ruleRows.Count)
if ($ExportBranding) { Write-Host ('  Logos exported   : {0} to {1}' -f $exported, $OutputFolder) }
Write-Host ('  Report           : {0}' -f $OutputPath)
if ($ruleRows.Count -gt 0) { Write-Host ('  Rules report     : {0}' -f $rulePath) }

if ($PassThru) {
    $rows
}
#endregion Main
