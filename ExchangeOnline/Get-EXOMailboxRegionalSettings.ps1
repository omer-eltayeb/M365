<#
.SYNOPSIS
    Reports language, time zone and date/time format of Exchange Online mailboxes and flags unconfigured or deviating ones.
.DESCRIPTION
    Runs Get-MailboxRegionalConfiguration once per selected mailbox and reports Language, TimeZone, DateFormat and
    TimeFormat. Mailboxes with an empty Language or TimeZone (never configured by the user or an admin) are flagged
    NotConfigured; with -ExpectedTimeZone / -ExpectedLanguage every deviation is flagged as a mismatch. Mailboxes come
    from -Identity, a CSV with a UserPrincipalName column or - with a warning - every user mailbox. Writes a CSV report.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID).
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER ExpectedTimeZone
    Windows time zone ID the mailboxes should use, for example 'W. Europe Standard Time'. Deviations are flagged TimeZoneMismatch.
.PARAMETER ExpectedLanguage
    Culture name the mailboxes should use, for example 'en-GB' or 'de-DE'. Deviations are flagged LanguageMismatch.
.PARAMETER VerifyDefaultFolderNameLanguage
    Also check whether the default folder names (Inbox, Sent Items ...) match the mailbox language; adds one column.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOMailboxRegionalSettings_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOMailboxRegionalSettings.ps1 -ExpectedTimeZone 'GMT Standard Time' -ExpectedLanguage 'en-GB'
    Reports every user mailbox, flags those still unconfigured or on another time zone / language and writes the CSV.
.EXAMPLE
    PS> .\Get-EXOMailboxRegionalSettings.ps1 -InputCsv .\NewStarters.csv -VerifyDefaultFolderNameLanguage -PassThru | Where-Object { $_.Issues }
    Lists new starters whose regional settings or folder names still need attention.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients or Global Reader (the report is read-only)
    Category    : Mailbox content & settings
    Changes     : No
    Notes       : Language and TimeZone stay empty until the user picks them at first sign-in to Outlook on the web or an
                  admin sets them (Set-EXOMailboxRegionalSettings.ps1); such mailboxes get English folder names and UTC
                  meeting times in OWA. Get-MailboxRegionalConfiguration is a legacy RPS cmdlet - one call per mailbox, slow at scale.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-mailboxregionalconfiguration
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
    [string]$ExpectedTimeZone,

    [Parameter()]
    [string]$ExpectedLanguage,

    [Parameter()]
    [switch]$VerifyDefaultFolderNameLanguage,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOMailboxRegionalSettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'RecipientTypeDetails')
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    Write-Warning 'No -Identity or -InputCsv specified: every user mailbox in the tenant is queried, one call per mailbox. This can take a long time.'
    try { foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -Properties $mailboxProperties -ErrorAction Stop)) { $mailboxes.Add($mailbox) } }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $upn = $mailbox.UserPrincipalName
    Write-Progress -Activity 'Reading regional configuration' -Status "$index of $($mailboxes.Count) - $upn" -PercentComplete (($index / $mailboxes.Count) * 100)
    try { $config = Get-MailboxRegionalConfiguration -Identity $upn -VerifyDefaultFolderNameLanguage:$VerifyDefaultFolderNameLanguage -ErrorAction Stop }
    catch { Write-Warning "Could not read the regional configuration of '$upn': $($_.Exception.Message)"; continue }

    $language = [string]$config.Language
    $timeZone = [string]$config.TimeZone
    $issues = @()
    if ([string]::IsNullOrWhiteSpace($language) -or [string]::IsNullOrWhiteSpace($timeZone)) { $issues += 'Not configured' }
    $languageMismatch = (-not [string]::IsNullOrWhiteSpace($ExpectedLanguage) -and $language -ne $ExpectedLanguage)
    if ($languageMismatch) { $issues += ('Language {0} (expected {1})' -f $(if ($language) { $language } else { 'empty' }), $ExpectedLanguage) }
    $timeZoneMismatch = (-not [string]::IsNullOrWhiteSpace($ExpectedTimeZone) -and $timeZone -ne $ExpectedTimeZone)
    if ($timeZoneMismatch) { $issues += ('TimeZone {0} (expected {1})' -f $(if ($timeZone) { $timeZone } else { 'empty' }), $ExpectedTimeZone) }
    $folderNamesMatch = $null
    if ($VerifyDefaultFolderNameLanguage) {
        $folderNamesMatch = [bool]$config.DefaultFolderNameMatchingUserLanguage
        if (-not $folderNamesMatch -and $language) { $issues += 'Default folder names do not match the language' }
    }

    $results.Add([PSCustomObject]@{
            DisplayName                     = $mailbox.DisplayName
            UserPrincipalName               = $upn
            MailboxType                     = [string]$mailbox.RecipientTypeDetails
            Language                        = $language
            TimeZone                        = $timeZone
            DateFormat                      = [string]$config.DateFormat
            TimeFormat                      = [string]$config.TimeFormat
            DefaultFolderNamesMatchLanguage = $folderNamesMatch
            NotConfigured                   = ($issues -contains 'Not configured')
            LanguageMismatch                = $languageMismatch
            TimeZoneMismatch                = $timeZoneMismatch
            Issues                          = ($issues -join '; ')
        })
}
Write-Progress -Activity 'Reading regional configuration' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes could be evaluated; nothing to export.'; return }
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$notConfigured = @($results | Where-Object { $_.NotConfigured }).Count
$withIssues = @($results | Where-Object { $_.Issues }).Count

Write-Host "Mailbox regional settings summary ($($results.Count) mailboxes evaluated)" -ForegroundColor Cyan
Write-Host ('  Not configured      : {0}' -f $notConfigured) -ForegroundColor $(if ($notConfigured -gt 0) { 'Yellow' } else { 'Green' })
if ($ExpectedLanguage) { Write-Host ('  Language mismatches : {0} (expected {1})' -f @($results | Where-Object { $_.LanguageMismatch }).Count, $ExpectedLanguage) }
if ($ExpectedTimeZone) { Write-Host ('  Time zone mismatches: {0} (expected {1})' -f @($results | Where-Object { $_.TimeZoneMismatch }).Count, $ExpectedTimeZone) }
Write-Host ('  Mailboxes with issues: {0}' -f $withIssues) -ForegroundColor $(if ($withIssues -gt 0) { 'Yellow' } else { 'Green' })
Write-Host '  Time zones in use:' -ForegroundColor White
foreach ($group in @($results | Group-Object -Property TimeZone | Sort-Object -Property Count -Descending | Select-Object -First 8)) {
    Write-Host ('    {0,6}  {1}' -f $group.Count, $(if ($group.Name) { $group.Name } else { '(empty)' }))
}
Write-Host '  Languages in use:' -ForegroundColor White
foreach ($group in @($results | Group-Object -Property Language | Sort-Object -Property Count -Descending | Select-Object -First 8)) {
    Write-Host ('    {0,6}  {1}' -f $group.Count, $(if ($group.Name) { $group.Name } else { '(empty)' }))
}
Write-Host ('  Report: {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
