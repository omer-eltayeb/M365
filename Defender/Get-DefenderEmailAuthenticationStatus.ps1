<#
.SYNOPSIS
    Scores SPF, DKIM and DMARC for every accepted domain by combining Exchange Online DKIM settings with live DNS lookups.
.DESCRIPTION
    Lists the accepted domains (Get-AcceptedDomain, *.onmicrosoft.com excluded unless -IncludeOnMicrosoft), reads the DKIM
    signing configuration (Get-DkimSigningConfig) and resolves the MX, SPF (TXT v=spf1), DMARC (_dmarc TXT) and DKIM
    selector CNAME records in DNS - with Resolve-DnsName on Windows, or the Google Public DNS JSON API elsewhere so the
    script also works in PowerShell 7 on Linux or macOS. Each domain gets a 0-100 score, an A-F grade and the list of
    findings (missing SPF, soft fail, DKIM disabled, DMARC p=none, pct below 100, no aggregate reporting, ...) in CSV.
.PARAMETER IncludeOnMicrosoft
    Also check the *.onmicrosoft.com domains (Microsoft manages their DKIM, so they normally score high).
.PARAMETER DnsServer
    DNS server used by Resolve-DnsName. Default 8.8.8.8; use an internal resolver if outbound DNS is blocked.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderEmailAuthentication_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderEmailAuthenticationStatus.ps1
    Checks every custom accepted domain and prints the grade distribution plus the domains without SPF, DKIM or DMARC enforcement.
.EXAMPLE
    PS> .\Get-DefenderEmailAuthenticationStatus.ps1 -IncludeOnMicrosoft -DnsServer 10.0.0.53 -PassThru | Where-Object { $_.Grade -ne 'A' }
    Checks all accepted domains through an internal resolver and returns the ones that lost points, with their findings.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Reader, Global Reader or View-Only Organization Management (Exchange Online PowerShell session)
    Category    : Email threat operations
    Changes     : No
    Notes       : The score is a weighted checklist, not a standard: SPF missing -30, ~all -5, ?all -15, no all -10, +all -30,
                  SPF without the EOP include -15, DKIM missing or disabled -20, DKIM CNAMEs wrong -10, DMARC missing -25,
                  p=none -15, p=quarantine -5, pct<100 -5, no rua -5. An MX outside EOP is only annotated (third-party gateway).
.LINK
    https://learn.microsoft.com/defender-office-365/email-authentication-about
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeOnMicrosoft,

    [Parameter()]
    [string]$DnsServer = '8.8.8.8',

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

function Resolve-DnsRecord {
    <# Returns TXT, CNAME or MX record data via Resolve-DnsName (Windows) or the Google Public DNS JSON API; a missing name or lookup error yields an empty array. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('TXT', 'CNAME', 'MX')]
        [string]$Type
    )
    try {
        if ($script:HasResolveDnsName) {
            $records = @(Resolve-DnsName -Name $Name -Type $Type -Server $DnsServer -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq $Type })
            return @($records | ForEach-Object { if ($Type -eq 'TXT') { -join $_.Strings } elseif ($Type -eq 'MX') { [string]$_.NameExchange } else { [string]$_.NameHost } })
        }
        $typeCode = @{ TXT = 16; CNAME = 5; MX = 15 }[$Type]
        $response = Invoke-RestMethod -Method GET -Uri ('https://dns.google/resolve?name={0}&type={1}' -f [uri]::EscapeDataString($Name), $Type) -ErrorAction Stop
        $answers = @($response.Answer | Where-Object { $_.type -eq $typeCode } | ForEach-Object { [string]$_.data })
        if ($Type -eq 'TXT') { return @($answers | ForEach-Object { ($_ -replace '"\s*"', '') -replace '"', '' }) }
        return @($answers | ForEach-Object { $(if ($Type -eq 'MX') { ($_ -split '\s+')[-1] } else { $_ }).TrimEnd('.') })
    }
    catch { Write-Verbose "DNS lookup $Type $Name returned nothing: $($_.Exception.Message)"; return @() }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderEmailAuthentication_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$script:HasResolveDnsName = ($null -ne (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue))
if (-not $script:HasResolveDnsName) { Write-Warning 'Resolve-DnsName is not available on this platform; DNS checks use the Google Public DNS JSON API and -DnsServer is ignored.' }

try {
    Connect-ExchangeIfNeeded
    $domains = @(Get-AcceptedDomain -ErrorAction Stop)
}
catch {
    throw "Unable to connect to Exchange Online or read the accepted domains: $($_.Exception.Message)"
}
if (-not $IncludeOnMicrosoft) { $domains = @($domains | Where-Object { [string]$_.DomainName -notlike '*.onmicrosoft.com' }) }
if ($domains.Count -eq 0) { throw 'No custom accepted domains were found; use -IncludeOnMicrosoft to check the initial domain.' }

$dkimConfigs = @{}
try { foreach ($config in @(Get-DkimSigningConfig -ErrorAction Stop)) { $dkimConfigs[([string]$config.Domain).ToLowerInvariant()] = $config } }
catch { Write-Warning "Could not read the DKIM signing configurations; DKIM is reported as not configured: $($_.Exception.Message)" }
# Penalty tables keep the scoring readable: SPF by the qualifier of its all mechanism (a bare "all" means "+all"), DMARC by policy.
$spfPolicyNames = @{ '-' = 'hard'; '~' = 'soft'; '?' = 'neutral'; '+' = 'pass-all'; none = 'none' }
$spfPenalties = @{ hard = 0; soft = 5; neutral = 15; 'pass-all' = 30; none = 10 }
$dmarcPenalties = @{ reject = 0; quarantine = 5; none = 15 }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($accepted in $domains) {
    $index++; $name = ([string]$accepted.DomainName).ToLowerInvariant()
    Write-Progress -Activity 'Checking email authentication' -Status $name -PercentComplete (($index / $domains.Count) * 100)
    $findings = New-Object -TypeName System.Collections.Generic.List[string]; $score = 100

    $mxHosts = @(Resolve-DnsRecord -Name $name -Type MX)
    $mxToEop = (@($mxHosts | Where-Object { $_ -like '*.mail.protection.outlook.com' -or $_ -like '*.mail.protection.office365.us' }).Count -gt 0)
    if ($mxHosts.Count -eq 0) { $findings.Add('No MX record'); $score -= 10 }
    elseif (-not $mxToEop) { $findings.Add('MX does not point to Exchange Online Protection (third-party gateway or non-mail domain)') }

    $spfRecords = @(Resolve-DnsRecord -Name $name -Type TXT | Where-Object { $_ -match '^v=spf1(\s|$)' })
    $spf = $spfRecords | Select-Object -First 1
    $spfPolicy = 'none'; $spfIncludesEop = $false
    if ($null -eq $spf) { $findings.Add('No SPF record'); $score -= 30 }
    else {
        if ($spfRecords.Count -gt 1) { $findings.Add('Multiple SPF records (invalid - evaluates to permerror)'); $score -= 20 }
        $spfIncludesEop = ($spf -match 'include:spf\.protection\.(outlook\.com|office365\.us)')
        $spfPolicy = $spfPolicyNames[$(if (($spf -replace '\sall\s*$', ' +all') -match '\s([-~?+])all\s*$') { $Matches[1] } else { 'none' })]
        if ($spfPenalties[$spfPolicy] -gt 0) { $findings.Add("SPF all mechanism is '$spfPolicy' (no hard fail)"); $score -= $spfPenalties[$spfPolicy] }
        if ($mxToEop -and -not $spfIncludesEop) { $findings.Add('SPF does not include spf.protection.outlook.com'); $score -= 15 }
    }

    $config = $dkimConfigs[$name]
    $dkimEnabled = ($null -ne $config -and [string]$config.Enabled -eq 'True'); $dkimDnsOk = $null
    if ($null -eq $config) { $findings.Add('No DKIM signing configuration (see Enable-DefenderDkimForDomains.ps1)'); $score -= 20 }
    else {
        $selectorsOk = foreach ($n in 1, 2) { @(Resolve-DnsRecord -Name "selector$n._domainkey.$name" -Type CNAME) -contains [string]$config."Selector${n}CNAME" }
        $dkimDnsOk = (@($selectorsOk) -notcontains $false)
        if (-not $dkimEnabled) { $findings.Add('DKIM signing is disabled'); $score -= 20 }
        if (-not $dkimDnsOk) { $findings.Add('DKIM selector1/selector2 CNAME records missing or pointing elsewhere'); $score -= 10 }
    }

    $dmarc = @(Resolve-DnsRecord -Name "_dmarc.$name" -Type TXT | Where-Object { $_ -match '^v=DMARC1' }) | Select-Object -First 1
    $dmarcPolicy = $null; $dmarcSubPolicy = $null; $dmarcPct = $null; $dmarcRua = $null
    if ($null -eq $dmarc) { $findings.Add('No DMARC record'); $score -= 25 }
    else {
        if ($dmarc -match '(?:^|;)\s*p\s*=\s*(\w+)') { $dmarcPolicy = $Matches[1].ToLowerInvariant() }
        if ($dmarc -match '(?:^|;)\s*sp\s*=\s*(\w+)') { $dmarcSubPolicy = $Matches[1].ToLowerInvariant() }
        if ($dmarc -match '(?:^|;)\s*rua\s*=\s*([^;]+)') { $dmarcRua = $Matches[1].Trim() }
        $dmarcPct = $(if ($dmarc -match '(?:^|;)\s*pct\s*=\s*(\d+)') { [int]$Matches[1] } else { 100 })
        if ($null -eq $dmarcPolicy -or -not $dmarcPenalties.ContainsKey($dmarcPolicy)) { $findings.Add('DMARC policy tag (p=) missing or invalid'); $score -= 20 }
        elseif ($dmarcPenalties[$dmarcPolicy] -gt 0) { $findings.Add("DMARC p=$dmarcPolicy (not enforcing reject)"); $score -= $dmarcPenalties[$dmarcPolicy] }
        if ($dmarcPct -lt 100) { $findings.Add("DMARC pct=$dmarcPct (partial enforcement)"); $score -= 5 }
        if ($null -eq $dmarcRua) { $findings.Add('DMARC has no rua address (no aggregate reports)'); $score -= 5 }
    }

    $rows.Add([PSCustomObject]@{
            Domain               = $name
            MxToEop              = $mxToEop
            SpfRecord            = $spf
            SpfIncludesEop       = $spfIncludesEop
            SpfPolicy            = $spfPolicy
            DkimEnabled          = $dkimEnabled
            DkimStatus           = $(if ($null -ne $config) { [string]$config.Status } else { 'NotConfigured' })
            DkimDnsOk            = $dkimDnsOk
            DmarcPolicy          = $dmarcPolicy
            DmarcSubdomainPolicy = $dmarcSubPolicy
            DmarcPct             = $dmarcPct
            DmarcRua             = $dmarcRua
            Score                = [math]::Max($score, 0)
            Grade                = $(if ($score -ge 90) { 'A' } elseif ($score -ge 80) { 'B' } elseif ($score -ge 70) { 'C' } elseif ($score -ge 60) { 'D' } else { 'F' })
            Findings             = ($findings -join '; ')
        })
}
Write-Progress -Activity 'Checking email authentication' -Completed
if (@($rows | Where-Object { $_.MxToEop -or $null -ne $_.SpfRecord }).Count -eq 0) { Write-Warning "No DNS answers for any domain; check connectivity to $DnsServer or use -DnsServer." }
$rows | Sort-Object -Property Score, Domain | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host ('Email authentication summary - {0} domain(s)' -f $rows.Count) -ForegroundColor Cyan
foreach ($group in ($rows | Group-Object -Property Grade | Sort-Object -Property Name)) {
    Write-Host ('  Grade {0} : {1,4}   {2}' -f $group.Name, $group.Count, (@($group.Group | Select-Object -First 6 -ExpandProperty Domain) -join ', '))
}
Write-Host ('  Domains without DMARC enforcement (p=none or missing): {0}' -f @($rows | Where-Object { $_.DmarcPolicy -ne 'quarantine' -and $_.DmarcPolicy -ne 'reject' }).Count)
Write-Host ('  Report: {0}' -f $OutputPath)

if ($PassThru) { $rows }
#endregion Main
