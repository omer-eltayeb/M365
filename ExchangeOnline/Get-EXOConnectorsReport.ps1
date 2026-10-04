<#
.SYNOPSIS
    Inventories inbound and outbound connectors, flags risky configurations and optionally validates outbound connectors.
.DESCRIPTION
    Reads every connector with Get-InboundConnector and Get-OutboundConnector and writes one CSV with a Direction column:
    type (Partner / OnPremises), scoping (sender domains and IPs, recipient domains, smart hosts), TLS settings, Enhanced
    Filtering skip lists, validation state and the last change date. RiskFlags marks inbound Partner connectors that are
    neither restricted by IP address nor by certificate and do not require TLS (anyone could spoof the partner's domains),
    connectors that treat mail as internal, and outbound connectors without TLS or without a successful validation.
    With -Validate each enabled outbound connector is tested with Validate-OutboundConnector, which sends a test message.
.PARAMETER Validate
    Run Validate-OutboundConnector against every enabled outbound connector. A test message is sent to the validation
    recipients, so the call is wrapped in ShouldProcess and -WhatIf / -Confirm work.
.PARAMETER ValidationRecipients
    External mailbox addresses that receive the validation message. When omitted, the recipients stored on each connector
    (ValidationRecipients) are used; connectors without any are skipped with a warning.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOConnectors_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the connector objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOConnectorsReport.ps1
    Writes every inbound and outbound connector to .\Reports\EXOConnectors_<timestamp>.csv and prints the risk flags found.
.EXAMPLE
    PS> .\Get-EXOConnectorsReport.ps1 -Validate -ValidationRecipients admin@partner.example -WhatIf
    Shows which outbound connectors would be validated and who would receive the test message, without sending anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator or Global Reader for the report; Exchange Administrator (Remote and Accepted
                  Domains role) for -Validate.
    Category    : Mail flow & organization
    Changes     : Optional (-Validate)
    Notes       : Validate-OutboundConnector checks smart hosts / MX and TLS and then delivers a test message to the validation
                  recipients, which must be outside the organization. Outbound connectors in test mode are only returned by
                  Get-OutboundConnector -IncludeTestModeConnectors and are therefore not listed here.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-inboundconnector
.LINK
    https://learn.microsoft.com/powershell/module/exchange/validate-outboundconnector
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$Validate,

    [Parameter()]
    [string[]]$ValidationRecipients,

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

function Join-Value {
    <# Joins a multi-valued connector property with ';' and strips the smtp: prefix / ;1 suffix Exchange adds to domain entries. #>
    param(
        [Parameter()]
        [object]$Value
    )
    return (@(foreach ($item in @($Value)) { ([string]$item -replace '^smtp:', '') -replace ';\d+$', '' }) -join ';')
}

function ConvertTo-ConnectorRow {
    <# Shapes an inbound or outbound connector into one common column layout; properties the other direction lacks stay empty. #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Direction,

        [Parameter(Mandatory = $true)]
        [object]$Connector
    )
    return [PSCustomObject]@{
        Direction = $Direction; Name = $Connector.Name; Enabled = [bool]$Connector.Enabled; ConnectorType = [string]$Connector.ConnectorType
        ConnectorSource = [string]$Connector.ConnectorSource; RiskFlags = $null; CloudServicesMailEnabled = [bool]$Connector.CloudServicesMailEnabled
        SenderDomains = Join-Value -Value $Connector.SenderDomains; SenderIPAddresses = Join-Value -Value $Connector.SenderIPAddresses
        RequireTls = $Connector.RequireTls; RestrictDomainsToIPAddresses = $Connector.RestrictDomainsToIPAddresses
        RestrictDomainsToCertificate = $Connector.RestrictDomainsToCertificate; TlsSenderCertificateName = [string]$Connector.TlsSenderCertificateName
        TreatMessagesAsInternal = $Connector.TreatMessagesAsInternal; EFSkipLastIP = $Connector.EFSkipLastIP; EFSkipIPs = Join-Value -Value $Connector.EFSkipIPs
        RecipientDomains = Join-Value -Value $Connector.RecipientDomains; SmartHosts = Join-Value -Value $Connector.SmartHosts
        TlsSettings = [string]$Connector.TlsSettings; TlsDomain = [string]$Connector.TlsDomain; UseMXRecord = $Connector.UseMXRecord
        IsTransportRuleScoped = $Connector.IsTransportRuleScoped; RouteAllMessagesViaOnPremises = $Connector.RouteAllMessagesViaOnPremises
        IsValidated = $Connector.IsValidated; LastValidationTimestamp = $Connector.LastValidationTimestamp
        ValidationRecipients = Join-Value -Value $Connector.ValidationRecipients; ValidationResult = $null
        Comment = [string]$Connector.Comment; WhenChanged = $Connector.WhenChanged
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOConnectors_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

try {
    $inbound = @(Get-InboundConnector -ErrorAction Stop)
    $outbound = @(Get-OutboundConnector -ErrorAction Stop)
}
catch {
    throw "Failed to read the connectors: $($_.Exception.Message)"
}
Write-Verbose "Found $($inbound.Count) inbound and $($outbound.Count) outbound connector(s)."

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($connector in $inbound) {
    $row = ConvertTo-ConnectorRow -Direction 'Inbound' -Connector $connector
    $flags = @()
    # A domain-scoped Partner connector that is pinned neither to IPs nor to a certificate accepts the partner's domains from anyone.
    if ($row.ConnectorType -eq 'Partner' -and -not $row.RestrictDomainsToIPAddresses -and -not $row.RestrictDomainsToCertificate) { $flags += 'UnrestrictedPartnerConnector' }
    if (-not $row.RequireTls) { $flags += 'TlsNotRequired' }
    if ($row.TreatMessagesAsInternal) { $flags += 'TreatsMailAsInternal' }
    $row.RiskFlags = ($flags -join ';')
    $rows.Add($row)
}
foreach ($connector in $outbound) {
    $row = ConvertTo-ConnectorRow -Direction 'Outbound' -Connector $connector
    $flags = @()
    if ([string]::IsNullOrWhiteSpace($row.TlsSettings)) { $flags += 'TlsNotEnforced' }
    if (-not $row.IsValidated) { $flags += 'NotValidated' }
    $row.RiskFlags = ($flags -join ';')
    $rows.Add($row)
}

if ($Validate) {
    foreach ($row in @($rows | Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled })) {
        $recipients = @($ValidationRecipients)
        if ($recipients.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($row.ValidationRecipients)) { $recipients = @($row.ValidationRecipients -split ';') }
        if ($recipients.Count -eq 0) {
            Write-Warning "Skipping validation of '$($row.Name)': no -ValidationRecipients given and none stored on the connector."
            continue
        }
        if ($PSCmdlet.ShouldProcess($row.Name, "Validate outbound connector (sends a test message to $($recipients -join ', '))")) {
            try {
                $result = Validate-OutboundConnector -Identity $row.Name -Recipients $recipients -ErrorAction Stop
                Write-Verbose (($result | Out-String).Trim())
                $refreshed = Get-OutboundConnector -Identity $row.Name -ErrorAction Stop
                $row.IsValidated = $refreshed.IsValidated
                $row.LastValidationTimestamp = $refreshed.LastValidationTimestamp
                $row.ValidationResult = 'Succeeded'
            }
            catch {
                Write-Warning "Validation of '$($row.Name)' failed: $($_.Exception.Message)"
                $row.ValidationResult = 'Failed: ' + $_.Exception.Message
            }
        }
    }
}

if ($rows.Count -gt 0) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No connectors were found; no CSV written.'
}

$flagged = @($rows | Where-Object { -not [string]::IsNullOrEmpty($_.RiskFlags) })
Write-Host ''
Write-Host 'Connector summary' -ForegroundColor Cyan
Write-Host ('  Inbound connectors  : {0} (enabled {1})' -f $inbound.Count, @($rows | Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled }).Count)
Write-Host ('  Outbound connectors : {0} (enabled {1})' -f $outbound.Count, @($rows | Where-Object { $_.Direction -eq 'Outbound' -and $_.Enabled }).Count)
Write-Host ('  Connectors flagged  : {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($item in $flagged) {
    Write-Host ('    {0,-8} {1,-40} {2}' -f $item.Direction, $item.Name, $item.RiskFlags) -ForegroundColor Yellow
}
if ($Validate) { Write-Host ('  Validated           : {0}' -f @($rows | Where-Object { $_.ValidationResult -eq 'Succeeded' }).Count) -ForegroundColor Green }
if ($rows.Count -gt 0) { Write-Host ('  Report              : {0}' -f $OutputPath) }

if ($PassThru) {
    $rows
}
#endregion Main
