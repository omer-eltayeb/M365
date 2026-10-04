<#
.SYNOPSIS
    Reports accepted domains and remote domains, flags risky settings and optionally checks each MX record in DNS.
.DESCRIPTION
    Reads the accepted domains (Get-AcceptedDomain: type, default and initial domain, subdomain matching, authentication
    type, coexistence / outbound-only flags, catch-all recipient) and the remote domains (Get-RemoteDomain: out-of-office,
    auto-reply, auto-forward, delivery / non-delivery reports, meeting forward notifications, TNEF, character sets and
    trusted mail settings) and writes two CSV files. Flags: InternalRelay accepted domains (mail for unknown recipients is
    relayed on), and remote domains - above all the catch-all Default (*) entry - that allow automatic forwarding to the
    internet. With -CheckDns the MX records of every accepted domain are resolved and compared with the Exchange Online
    Protection endpoints (*.mail.protection.outlook.com or *.mx.microsoft).
.PARAMETER CheckDns
    Resolve the MX records of each accepted domain with Resolve-DnsName (Windows only; skipped with a warning elsewhere).
.PARAMETER OutputPath
    Path of the accepted-domains CSV. Defaults to .\Reports\EXODomains_yyyyMMdd-HHmm.csv; the remote domains are written
    next to it with the suffix _RemoteDomains.csv.
.PARAMETER PassThru
    Also emits the accepted-domain objects followed by the remote-domain objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOAcceptedAndRemoteDomains.ps1
    Writes EXODomains_<timestamp>.csv and EXODomains_<timestamp>_RemoteDomains.csv to .\Reports and prints the flags found.
.EXAMPLE
    PS> .\Get-EXOAcceptedAndRemoteDomains.ps1 -CheckDns -PassThru | Where-Object { $_.MxPointsToEop -eq $false }
    Lists the accepted domains whose MX record does not point to Exchange Online Protection (third-party gateway or stale DNS).
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator or Global Reader (View-Only Organization Management).
    Category    : Mail flow & organization
    Changes     : No
    Notes       : AutoForwardEnabled on the Default remote domain is only one of three controls for external auto-forwarding;
                  the outbound spam filter policy (AutoForwardingMode) and mail flow rules also apply. Resolve-DnsName belongs
                  to the Windows DnsClient module, so -CheckDns is unavailable on Linux and macOS.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-accepteddomain
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-remotedomain
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$CheckDns,

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

function Get-MxRecordText {
    <# Returns the MX hosts of a domain ordered by preference as "10 host1;20 host2", or an error marker when the lookup fails. #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )
    try {
        $records = @(Resolve-DnsName -Name $DomainName -Type MX -ErrorAction Stop | Where-Object { $_.Type -eq 'MX' } | Sort-Object -Property Preference)
        return (@($records | ForEach-Object { '{0} {1}' -f $_.Preference, ([string]$_.NameExchange).TrimEnd('.') }) -join ';')
    }
    catch {
        Write-Verbose "MX lookup for $DomainName failed: $($_.Exception.Message)"
        return 'LOOKUP FAILED'
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXODomains_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$remotePath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_RemoteDomains.csv')

if ($CheckDns -and $null -eq (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
    Write-Warning 'Resolve-DnsName is not available on this platform; MX records are not checked.'
    $CheckDns = $false
}

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

try {
    $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop | Sort-Object -Property DomainName)
    $remoteDomains = @(Get-RemoteDomain -ErrorAction Stop | Sort-Object -Property DomainName)
}
catch {
    throw "Failed to read the domain configuration: $($_.Exception.Message)"
}
Write-Verbose "Found $($acceptedDomains.Count) accepted domain(s) and $($remoteDomains.Count) remote domain(s)."

$acceptedRows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($domain in $acceptedDomains) {
    $index++
    $domainName = [string]$domain.DomainName
    Write-Progress -Activity 'Processing accepted domains' -Status $domainName -PercentComplete (($index / $acceptedDomains.Count) * 100)
    $flags = @()
    if ([string]$domain.DomainType -eq 'InternalRelay') { $flags += 'InternalRelay' }
    if (-not [string]::IsNullOrEmpty([string]$domain.CatchAllRecipientID)) { $flags += 'CatchAllRecipient' }
    $row = [ordered]@{
        DomainName           = $domainName
        DomainType           = [string]$domain.DomainType
        Default              = [bool]$domain.Default
        InitialDomain        = [bool]$domain.InitialDomain
        MatchSubDomains      = [bool]$domain.MatchSubDomains
        AuthenticationType   = [string]$domain.AuthenticationType
        EmailOnly            = $domain.EmailOnly
        IsCoexistenceDomain  = [bool]$domain.IsCoexistenceDomain
        OutboundOnly         = [bool]$domain.OutboundOnly
        CatchAllRecipientID  = [string]$domain.CatchAllRecipientID
        Flags                = ($flags -join ';')
        WhenChanged          = $domain.WhenChanged
    }
    if ($CheckDns) {
        $row['MxRecords'] = Get-MxRecordText -DomainName $domainName
        $row['MxPointsToEop'] = ($row['MxRecords'] -like '*.mail.protection.outlook.com*' -or $row['MxRecords'] -like '*.mx.microsoft*')
    }
    $acceptedRows.Add([PSCustomObject]$row)
}
Write-Progress -Activity 'Processing accepted domains' -Completed

$remoteRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($domain in $remoteDomains) {
    $isDefault = ([string]$domain.DomainName -eq '*')
    $flags = @()
    if ($domain.AutoForwardEnabled) { $flags += $(if ($isDefault) { 'ExternalAutoForwardAllowed' } else { 'AutoForwardAllowed' }) }
    if ($domain.AutoReplyEnabled -and $isDefault) { $flags += 'AutoReplyToInternet' }
    $remoteRows.Add([PSCustomObject]@{
            DomainName                        = [string]$domain.DomainName
            Name                              = $domain.Name
            IsDefault                         = $isDefault
            IsInternal                        = [bool]$domain.IsInternal
            AllowedOOFType                    = [string]$domain.AllowedOOFType
            AutoReplyEnabled                  = [bool]$domain.AutoReplyEnabled
            AutoForwardEnabled                = [bool]$domain.AutoForwardEnabled
            DeliveryReportEnabled             = [bool]$domain.DeliveryReportEnabled
            NDREnabled                        = [bool]$domain.NDREnabled
            MeetingForwardNotificationEnabled = [bool]$domain.MeetingForwardNotificationEnabled
            TNEFEnabled                       = $domain.TNEFEnabled
            CharacterSet                      = [string]$domain.CharacterSet
            NonMimeCharacterSet               = [string]$domain.NonMimeCharacterSet
            TrustedMailOutboundEnabled        = [bool]$domain.TrustedMailOutboundEnabled
            TrustedMailInboundEnabled         = [bool]$domain.TrustedMailInboundEnabled
            Flags                             = ($flags -join ';')
            WhenChanged                       = $domain.WhenChanged
        })
}

if ($acceptedRows.Count -gt 0) { $acceptedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
if ($remoteRows.Count -gt 0) { $remoteRows | Export-Csv -Path $remotePath -NoTypeInformation -Encoding UTF8 }

$relayDomains = @($acceptedRows | Where-Object { $_.DomainType -eq 'InternalRelay' })
$forwardingDomains = @($remoteRows | Where-Object { $_.AutoForwardEnabled })
$defaultRemote = $remoteRows | Where-Object { $_.IsDefault } | Select-Object -First 1
Write-Host ''
Write-Host 'Domain configuration summary' -ForegroundColor Cyan
Write-Host ('  Accepted domains           : {0} (authoritative {1}, internal relay {2})' -f $acceptedRows.Count, ($acceptedRows.Count - $relayDomains.Count), $relayDomains.Count)
Write-Host ('  Default domain             : {0}' -f (@($acceptedRows | Where-Object { $_.Default } | Select-Object -ExpandProperty DomainName) -join ', '))
if ($CheckDns) {
    $notEop = @($acceptedRows | Where-Object { -not $_.MxPointsToEop })
    Write-Host ('  MX not pointing to EOP     : {0}' -f $notEop.Count) -ForegroundColor $(if ($notEop.Count -gt 0) { 'Yellow' } else { 'Green' })
    foreach ($item in $notEop) { Write-Host ('    {0,-40} {1}' -f $item.DomainName, $item.MxRecords) -ForegroundColor Yellow }
}
Write-Host ('  Remote domains             : {0}' -f $remoteRows.Count)
Write-Host ('  Remote domains auto-forward: {0}' -f $forwardingDomains.Count) -ForegroundColor $(if ($forwardingDomains.Count -gt 0) { 'Yellow' } else { 'Green' })
if ($null -ne $defaultRemote -and $defaultRemote.AutoForwardEnabled) {
    Write-Warning 'The Default (*) remote domain allows automatic forwarding to any external domain. Consider Set-RemoteDomain Default -AutoForwardEnabled $false.'
}
Write-Host ('  Reports                    : {0}; {1}' -f $OutputPath, $remotePath)

if ($PassThru) {
    $acceptedRows
    $remoteRows
}
#endregion Main
