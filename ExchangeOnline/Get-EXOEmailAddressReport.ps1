<#
.SYNOPSIS
    Reports every e-mail address (primary, alias, SIP, SPO, X500) of all Exchange Online recipients with per-domain totals.
.DESCRIPTION
    Reads all recipients with Get-EXORecipient -ResultSize Unlimited (mailboxes, groups, contacts, mail users ...) and
    expands EmailAddresses into one row per address: Recipient, RecipientType, Address (prefix removed), AddressType,
    Domain and whether the same address exists on more than one recipient. -Domain limits the report to one domain
    (useful before removing an accepted domain), -Address finds the owner of a single address. The summary lists
    addresses per domain, recipients with more than -MaxAliases aliases and duplicate addresses. Writes a CSV report.
.PARAMETER Domain
    Only report addresses in this domain, for example contoso.com. The query is filtered server-side.
.PARAMETER Address
    Exact e-mail address to look up (any type); reports the recipient(s) holding it.
.PARAMETER IncludeX500
    Include X500 addresses (legacy Exchange DNs kept after migrations). Excluded by default.
.PARAMETER MaxAliases
    Recipients with more smtp aliases than this are listed in the summary. Default 10.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOEmailAddresses_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOEmailAddressReport.ps1
    Exports every SMTP, SIP and SPO address in the tenant to .\Reports\EXOEmailAddresses_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOEmailAddressReport.ps1 -Domain fabrikam.com -PassThru | Where-Object { $_.AddressType -eq 'SMTP (primary)' }
    Lists recipients whose primary address is still in fabrikam.com, for example before that domain is removed.
.EXAMPLE
    PS> .\Get-EXOEmailAddressReport.ps1 -Address sales@contoso.com
    Shows which recipient owns sales@contoso.com and as which address type.
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
    Notes       : A full run produces one row per address (often 3-5 per mailbox); large tenants yield hundreds of
                  thousands of rows. Exchange enforces unique SMTP addresses, so duplicates usually involve SIP/SPO
                  entries or recipients in different recipient types - review them before migrations.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-exorecipient
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')]
    [string]$Domain,

    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+$')]
    [string]$Address,

    [Parameter()]
    [switch]$IncludeX500,

    [Parameter()]
    [ValidateRange(1, 400)]
    [int]$MaxAliases = 10,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOEmailAddresses_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

# EmailAddresses values carry a prefix (SMTP:, smtp:, SIP: ...), so the server-side filter matches on the suffix only;
# the exact match is applied client-side below.
$recipientParams = @{ ResultSize = 'Unlimited'; Properties = @('DisplayName', 'RecipientTypeDetails', 'PrimarySmtpAddress', 'EmailAddresses'); ErrorAction = 'Stop' }
if ($Address) { $recipientParams['Filter'] = "EmailAddresses -like '*:{0}'" -f ($Address -replace "'", "''") }
elseif ($Domain) { $recipientParams['Filter'] = "EmailAddresses -like '*@{0}'" -f ($Domain -replace "'", "''") }
Write-Verbose "Querying recipients$(if ($recipientParams.ContainsKey('Filter')) { ' with filter ' + $recipientParams['Filter'] })."
try { $recipients = @(Get-EXORecipient @recipientParams) }
catch { throw "Failed to retrieve recipients: $($_.Exception.Message)" }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($recipient in $recipients) {
    $index++
    if ($index % 100 -eq 0) { Write-Progress -Activity 'Expanding e-mail addresses' -Status "$index of $($recipients.Count) recipients" -PercentComplete (($index / $recipients.Count) * 100) }
    $addresses = @($recipient.EmailAddresses | ForEach-Object { [string]$_ })
    $aliasCount = @($addresses | Where-Object { $_ -cmatch '^smtp:' }).Count
    foreach ($entry in $addresses) {
        $prefix = ''
        $value = $entry
        if ($entry -match '^([^:]+):(.*)$') { $prefix = $Matches[1]; $value = $Matches[2] }
        if ($prefix -ceq 'SMTP') { $type = 'SMTP (primary)' }
        elseif ($prefix -ceq 'smtp') { $type = 'smtp (alias)' }
        elseif ($prefix -eq 'SIP') { $type = 'SIP' }
        elseif ($prefix -eq 'SPO') { $type = 'SPO' }
        elseif ($prefix -eq 'X500') { $type = 'X500' }
        else { $type = "Other ($prefix)" }
        if ($type -eq 'X500' -and -not $IncludeX500) { continue }
        $addressDomain = ''
        if ($value -match '@([^@>]+)$') { $addressDomain = $Matches[1].ToLowerInvariant() }
        if ($Domain -and $addressDomain -ne $Domain) { continue }
        if ($Address -and $value -ne $Address) { continue }
        $results.Add([PSCustomObject]@{
                Recipient           = [string]$recipient.DisplayName
                RecipientType       = [string]$recipient.RecipientTypeDetails
                PrimarySmtpAddress  = [string]$recipient.PrimarySmtpAddress
                Address             = $value
                AddressType         = $type
                Domain              = $addressDomain
                RecipientAliasCount = $aliasCount
                IsDuplicate         = $false
            })
    }
}
Write-Progress -Activity 'Expanding e-mail addresses' -Completed
if ($results.Count -eq 0) { Write-Warning 'No addresses matched the selection; nothing to export.'; return }

# The same address on two different recipients (any type) is a conflict; the same value as SMTP and SIP on one recipient is normal.
$duplicates = @($results | Group-Object -Property { $_.Address.ToLowerInvariant() } | Where-Object { @($_.Group | Select-Object -ExpandProperty PrimarySmtpAddress -Unique).Count -gt 1 })
$duplicateKeys = @{}
foreach ($group in $duplicates) { $duplicateKeys[$group.Name] = $true }
foreach ($row in $results) { if ($duplicateKeys.ContainsKey($row.Address.ToLowerInvariant())) { $row.IsDuplicate = $true } }

$results | Sort-Object -Property Domain, Address | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$recipientCount = @($results | Select-Object -ExpandProperty PrimarySmtpAddress -Unique).Count
$aliasHeavy = @($results | Where-Object { $_.RecipientAliasCount -gt $MaxAliases } | Sort-Object -Property PrimarySmtpAddress -Unique | Sort-Object -Property RecipientAliasCount -Descending)

Write-Host "E-mail address summary ($($results.Count) addresses on $recipientCount recipients)" -ForegroundColor Cyan
Write-Host '  Addresses per domain (primary / alias / other):' -ForegroundColor White
foreach ($group in @($results | Group-Object -Property Domain | Sort-Object -Property Count -Descending | Select-Object -First 15)) {
    $primary = @($group.Group | Where-Object { $_.AddressType -eq 'SMTP (primary)' }).Count
    $alias = @($group.Group | Where-Object { $_.AddressType -eq 'smtp (alias)' }).Count
    $domainName = $group.Name
    if (-not $domainName) { $domainName = '(no domain)' }
    Write-Host ('    {0,8:N0}  {1}  ({2:N0} / {3:N0} / {4:N0})' -f $group.Count, $domainName, $primary, $alias, ($group.Count - $primary - $alias))
}
Write-Host ('  Recipients with more than {0} aliases: {1}' -f $MaxAliases, $aliasHeavy.Count) -ForegroundColor $(if ($aliasHeavy.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in @($aliasHeavy | Select-Object -First 10)) {
    Write-Host ('    {0,5} aliases  {1} ({2})' -f $row.RecipientAliasCount, $row.PrimarySmtpAddress, $row.RecipientType) -ForegroundColor Yellow
}
Write-Host ('  Duplicate addresses: {0}' -f $duplicates.Count) -ForegroundColor $(if ($duplicates.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($group in @($duplicates | Select-Object -First 10)) {
    Write-Host ('    {0}  on  {1}' -f $group.Name, (@($group.Group | ForEach-Object { '{0} [{1}]' -f $_.PrimarySmtpAddress, $_.AddressType } | Sort-Object -Unique) -join ', ')) -ForegroundColor Yellow
}
Write-Host ('  Report: {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
