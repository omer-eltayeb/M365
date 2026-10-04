<#
.SYNOPSIS
    Sets language, time zone and date/time format on Exchange Online mailboxes, optionally localising default folder names.
.DESCRIPTION
    Compares the current Get-MailboxRegionalConfiguration values of each selected mailbox with the requested settings and
    reports the differences (current -> new); -Apply writes only the differing settings with Set-MailboxRegionalConfiguration
    inside ShouldProcess. Settings come from the parameters; with -InputCsv optional Language / TimeZone / DateFormat /
    TimeFormat columns override them per user. Time zone IDs are validated against the Windows time zone list up front.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID).
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column and optional Language, TimeZone, DateFormat and TimeFormat columns.
.PARAMETER Language
    Culture name to set, for example 'en-GB' or 'de-DE'.
.PARAMETER TimeZone
    Windows time zone ID to set, for example 'W. Europe Standard Time' or 'GMT Standard Time'.
.PARAMETER DateFormat
    Short date format valid for the language, for example 'dd/MM/yyyy' or 'dd.MM.yyyy'.
.PARAMETER TimeFormat
    Time format valid for the language, for example 'HH:mm' or 'h:mm tt'.
.PARAMETER LocalizeDefaultFolderName
    Rename the default folders (Inbox, Sent Items ...) to the mailbox language. Counts as a change on every selected mailbox.
.PARAMETER OnlyUnconfigured
    Skip mailboxes whose Language and TimeZone are already set, so user choices made in Outlook on the web are kept.
.PARAMETER Apply
    Perform the changes. Without this switch the script is read-only and reports the differences.
.PARAMETER OutputPath
    Path of the CSV results file. Defaults to .\Reports\EXOMailboxRegionalSettings_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\Set-EXOMailboxRegionalSettings.ps1 -Language en-GB -TimeZone 'GMT Standard Time' -DateFormat dd/MM/yyyy -TimeFormat HH:mm -OnlyUnconfigured
    Pre-flight only: lists every user mailbox that never had regional settings and shows what would be set.
.EXAMPLE
    PS> .\Set-EXOMailboxRegionalSettings.ps1 -InputCsv .\Offices.csv -Language de-DE -DateFormat dd.MM.yyyy -TimeFormat HH:mm -LocalizeDefaultFolderName -Apply
    Applies German settings to the listed users, with the TimeZone column of the CSV deciding each user's zone, and renames their default folders.
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
    Notes       : When changing the language also pass -DateFormat / -TimeFormat valid for that culture or Exchange rejects
                  the call. Time zone validation needs a Windows host (skipped on Linux/macOS). One RPS call per mailbox.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/set-mailboxregionalconfiguration
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
    [string]$Language,

    [Parameter()]
    [string]$TimeZone,

    [Parameter()]
    [string]$DateFormat,

    [Parameter()]
    [string]$TimeFormat,

    [Parameter()]
    [switch]$LocalizeDefaultFolderName,

    [Parameter()]
    [switch]$OnlyUnconfigured,

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
#endregion Helpers

#region Main
$settingNames = @('Language', 'TimeZone', 'DateFormat', 'TimeFormat')
$defaults = @{}
foreach ($name in $settingNames) { if ($PSBoundParameters.ContainsKey($name)) { $defaults[$name] = Get-Variable -Name $name -ValueOnly } }
$csvRows = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') { $csvRows = @(Import-Csv -Path $InputCsv | Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserPrincipalName) }) }
if ($PSCmdlet.ParameterSetName -eq 'Csv' -and $csvRows.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
$csvColumns = @($csvRows | Select-Object -First 1 | ForEach-Object { $_.PSObject.Properties.Name } | Where-Object { $settingNames -contains $_ })
if ($defaults.Count -eq 0 -and $csvColumns.Count -eq 0 -and -not $LocalizeDefaultFolderName) { throw 'Nothing to set: pass a setting parameter, matching CSV columns or -LocalizeDefaultFolderName.' }

# Exchange expects Windows time zone IDs; only a Windows host can validate them (Linux/macOS .NET lists IANA IDs).
$requestedZones = @(@($defaults['TimeZone']) + @($csvRows | ForEach-Object { [string]$_.TimeZone }) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
if ($requestedZones.Count -gt 0 -and $env:OS -eq 'Windows_NT') {
    $unknownZones = @($requestedZones | Where-Object { @([System.TimeZoneInfo]::GetSystemTimeZones().Id) -notcontains $_ })
    if ($unknownZones.Count -gt 0) { throw "Unknown time zone ID(s): $($unknownZones -join ', '). List valid IDs with [System.TimeZoneInfo]::GetSystemTimeZones() | Select-Object Id." }
}
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
$targets = New-Object -TypeName System.Collections.Generic.List[object]   # resolved mailbox + its CSV row, so per-user overrides survive identity resolution
if ($PSCmdlet.ParameterSetName -eq 'All') {
    Write-Warning 'No -Identity or -InputCsv specified: every user mailbox in the tenant is in scope, one call per mailbox.'
    try { foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -ErrorAction Stop)) { $targets.Add([PSCustomObject]@{ Mailbox = $mailbox; Row = $null }) } }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}
else {
    $entries = @($Identity | ForEach-Object { [PSCustomObject]@{ Id = $_; Row = $null } })
    if ($csvRows.Count -gt 0) { $entries = @($csvRows | ForEach-Object { [PSCustomObject]@{ Id = [string]$_.UserPrincipalName; Row = $_ } }) }
    foreach ($entry in $entries) {
        try { $targets.Add([PSCustomObject]@{ Mailbox = (Get-EXOMailbox -Identity $entry.Id -ErrorAction Stop); Row = $entry.Row }) }
        catch { Write-Warning "Mailbox '$($entry.Id)' was not found or is not accessible: $($_.Exception.Message)" }
    }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($target in $targets) {
    $index++
    $upn = $target.Mailbox.UserPrincipalName
    Write-Progress -Activity 'Processing regional settings' -Status "$index of $($targets.Count) - $upn" -PercentComplete (($index / $targets.Count) * 100)
    try { $config = Get-MailboxRegionalConfiguration -Identity $upn -ErrorAction Stop }
    catch { Write-Warning "Could not read the regional configuration of '$upn': $($_.Exception.Message)"; continue }

    $desired = $defaults.Clone()
    foreach ($name in $csvColumns) {
        $value = [string]$target.Row.$name
        if (-not [string]::IsNullOrWhiteSpace($value)) { $desired[$name] = $value.Trim() }
    }
    $setParams = @{}
    $changes = @()
    $row = [ordered]@{ DisplayName = $target.Mailbox.DisplayName; UserPrincipalName = $upn }
    foreach ($name in $settingNames) {
        $current = [string]$config.$name
        $new = $current
        if ($desired.ContainsKey($name) -and $desired[$name] -ne $current) {
            $new = $desired[$name]
            $setParams[$name] = $new
            $changes += ('{0} {1} -> {2}' -f $name, $(if ($current) { $current } else { '(empty)' }), $new)
        }
        $row[$name] = $current
        $row['New' + $name] = $new
    }
    if ($LocalizeDefaultFolderName) { $setParams['LocalizeDefaultFolderName'] = $true; $changes += 'Localize default folder names' }

    $status = 'Already compliant'
    if ($OnlyUnconfigured -and $row.Language -and $row.TimeZone) { $status = 'Skipped: already configured' }
    elseif ($changes.Count -gt 0 -and -not $Apply) { $status = 'Would change' }
    elseif ($changes.Count -gt 0 -and $PSCmdlet.ShouldProcess($upn, ('Set regional configuration: {0}' -f ($changes -join '; ')))) {
        try { Set-MailboxRegionalConfiguration -Identity $upn @setParams -ErrorAction Stop; $status = 'Changed' }
        catch { $status = "Failed: $($_.Exception.Message)"; Write-Warning "Could not update '$upn': $($_.Exception.Message)" }
    }
    elseif ($changes.Count -gt 0) { $status = 'Not confirmed' }

    $row['Changes'] = ($changes -join '; ')
    $row['Status'] = $status
    $results.Add([PSCustomObject]$row)
}
Write-Progress -Activity 'Processing regional settings' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes could be evaluated; nothing to export.'; return }
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Mailbox regional settings summary ($($results.Count) mailboxes evaluated)" -ForegroundColor Cyan
foreach ($state in @('Already compliant', 'Would change', 'Changed', 'Not confirmed', 'Skipped*', 'Failed*')) {
    $count = @($results | Where-Object { $_.Status -like $state }).Count
    Write-Host ('  {0,-18}: {1}' -f $state.TrimEnd('*'), $count) -ForegroundColor $(if ($count -gt 0 -and $state -eq 'Failed*') { 'Red' } else { 'White' })
}
if (-not $Apply) { Write-Host '  Pre-flight only - re-run with -Apply to change the settings.' -ForegroundColor Yellow }
Write-Host ('  {0,-18}: {1}' -f 'Results', $OutputPath)

if ($PassThru) { $results }
#endregion Main
