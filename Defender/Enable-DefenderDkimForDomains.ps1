<#
.SYNOPSIS
    Prepares, enables or rotates DKIM signing for custom accepted domains and prints the CNAME records the DNS team must publish.
.DESCRIPTION
    For the domains given with -Domain (default: every custom accepted domain) the script reads Get-DkimSigningConfig and
    creates a disabled signing configuration with New-DkimSigningConfig where none exists, which generates the selector
    key pairs and the two CNAME targets (selector1._domainkey and selector2._domainkey). With -Enable it verifies the
    CNAME records in public DNS (Resolve-DnsName on Windows, Google Public DNS JSON API elsewhere, unless -SkipDnsCheck)
    and then runs Set-DkimSigningConfig -Enabled $true; with -Rotate it schedules a key rotation (Rotate-DkimSigningConfig).
    Every change is wrapped in ShouldProcess; one result object per domain with the CNAME records is written to the pipeline.
.PARAMETER Domain
    One or more accepted domains to process. Default: all accepted domains except *.onmicrosoft.com.
.PARAMETER Enable
    Enable signing for domains whose configuration exists but is disabled (after the CNAME records are in DNS).
.PARAMETER Rotate
    Rotate the signing keys of domains where DKIM is enabled. The CNAME records do not change; the new key goes live on RotateOnDate.
.PARAMETER KeySize
    RSA key size for new configurations and rotations: 1024 or 2048 (default, recommended).
.PARAMETER SkipDnsCheck
    Do not verify the selector CNAME records before enabling (Exchange Online still validates them server-side).
.PARAMETER DnsServer
    DNS server used by Resolve-DnsName for the CNAME check. Default 8.8.8.8.
.EXAMPLE
    PS> .\Enable-DefenderDkimForDomains.ps1
    Creates the (disabled) DKIM configuration for every custom domain that lacks one and prints the CNAME records to publish.
.EXAMPLE
    PS> .\Enable-DefenderDkimForDomains.ps1 -Domain contoso.com -Enable
    Verifies both selector CNAME records for contoso.com in DNS and, after confirmation, turns DKIM signing on.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Administrator or Exchange Administrator (Exchange Online PowerShell session)
    Category    : Email threat operations
    Changes     : Yes
    Notes       : Creating the configuration does not change mail flow; messages keep the *.onmicrosoft.com signature until
                  signing is enabled. Publish both CNAME records and allow for DNS propagation before -Enable - Exchange Online
                  rejects the enable if it cannot see them. Rotations take effect after about four days; no DNS change is needed.
.LINK
    https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$Domain,

    [Parameter()]
    [switch]$Enable,

    [Parameter()]
    [switch]$Rotate,

    [Parameter()]
    [ValidateSet(1024, 2048)]
    [int]$KeySize = 2048,

    [Parameter()]
    [switch]$SkipDnsCheck,

    [Parameter()]
    [string]$DnsServer = '8.8.8.8'
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

function Resolve-CnameTarget {
    <# Returns the CNAME target of a host via Resolve-DnsName (Windows) or the Google Public DNS JSON API; $null when it does not resolve. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    try {
        if ($script:HasResolveDnsName) {
            $target = Resolve-DnsName -Name $Name -Type CNAME -Server $DnsServer -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1 -ExpandProperty NameHost
        }
        else {
            $response = Invoke-RestMethod -Method GET -Uri ('https://dns.google/resolve?name={0}&type=CNAME' -f [uri]::EscapeDataString($Name)) -ErrorAction Stop
            $target = $response.Answer | Where-Object { $_.type -eq 5 } | Select-Object -First 1 -ExpandProperty data
        }
        if ([string]::IsNullOrWhiteSpace([string]$target)) { return $null }
        return ([string]$target).TrimEnd('.')
    }
    catch { Write-Verbose "CNAME lookup for $Name failed: $($_.Exception.Message)"; return $null }
}
#endregion Helpers

#region Main
if ($Enable -and $Rotate) { throw 'Use either -Enable or -Rotate in one run, not both.' }
$script:HasResolveDnsName = ($null -ne (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue))
if ($Enable -and -not $SkipDnsCheck -and -not $script:HasResolveDnsName) { Write-Warning 'Resolve-DnsName is unavailable; the CNAME check uses the Google Public DNS JSON API (-DnsServer ignored).' }

try {
    Connect-ExchangeIfNeeded
    $accepted = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() } | Where-Object { $_ -notlike '*.onmicrosoft.com' })
    $configs = @{}
    foreach ($config in @(Get-DkimSigningConfig -ErrorAction Stop)) { $configs[([string]$config.Domain).ToLowerInvariant()] = $config }
}
catch {
    throw "Unable to read accepted domains or DKIM configuration from Exchange Online: $($_.Exception.Message)"
}
$targets = $accepted
if ($PSBoundParameters.ContainsKey('Domain')) {
    $targets = @($Domain | ForEach-Object { $_.Trim().ToLowerInvariant() } | Select-Object -Unique)
    foreach ($unknown in @($targets | Where-Object { $accepted -notcontains $_ })) { Write-Warning "'$unknown' is not a custom accepted domain of this tenant and is skipped." }
    $targets = @($targets | Where-Object { $accepted -contains $_ })
}
if ($targets.Count -eq 0) { throw 'No custom accepted domains to process.' }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($name in $targets) {
    $config = $configs[$name]
    $row = [PSCustomObject]@{
        Domain          = $name
        ConfigExisted   = ($null -ne $config)
        Enabled         = ($null -ne $config -and [string]$config.Enabled -eq 'True')
        Status          = $(if ($null -ne $config) { [string]$config.Status } else { $null })
        Selector1Host   = "selector1._domainkey.$name"
        Selector1Target = $null
        Selector2Host   = "selector2._domainkey.$name"
        Selector2Target = $null
        DnsVerified     = $null
        RotateOnDate    = $null
        Action          = 'None'
        Result          = 'Unchanged'
        Message         = $null
    }
    $rows.Add($row)
    try {
        if ($null -eq $config) {
            $row.Action = 'CreateConfig'
            if (-not $PSCmdlet.ShouldProcess($name, "Create DKIM signing configuration (disabled, $KeySize-bit keys)")) { $row.Result = 'Skipped'; $row.Message = 'Not confirmed'; continue }
            New-DkimSigningConfig -DomainName $name -Enabled $false -KeySize $KeySize -ErrorAction Stop | Out-Null
            $config = Get-DkimSigningConfig -Identity $name -ErrorAction Stop
            $row.Result = 'Created'; $row.Message = 'Publish both CNAME records, then run again with -Enable'
        }
        $row.Selector1Target = [string]$config.Selector1CNAME; $row.Selector2Target = [string]$config.Selector2CNAME
        $row.Status = [string]$config.Status; $row.RotateOnDate = $config.RotateOnDate

        if ($Enable -and -not $row.Enabled) {
            $row.Action = 'Enable'
            if (-not $SkipDnsCheck) {
                # Both selectors must resolve to the exact targets Exchange Online generated; otherwise the enable call fails server-side anyway.
                $row.DnsVerified = (@(foreach ($n in 1, 2) { (Resolve-CnameTarget -Name $row."Selector${n}Host") -eq $row."Selector${n}Target" }) -notcontains $false)
                if (-not $row.DnsVerified) { $row.Result = 'Blocked'; $row.Message = 'Selector CNAME records missing or wrong in DNS; publish them and wait, or use -SkipDnsCheck'; continue }
            }
            if (-not $PSCmdlet.ShouldProcess($name, 'Enable DKIM signing')) { $row.Result = 'Skipped'; $row.Message = 'Not confirmed'; continue }
            Set-DkimSigningConfig -Identity $name -Enabled $true -ErrorAction Stop
            $row.Enabled = $true; $row.Result = 'Enabled'; $row.Message = 'Outbound mail from this domain is now DKIM signed'
        }
        elseif ($Enable) { $row.Message = 'DKIM signing is already enabled' }
        elseif (-not $row.Enabled -and $row.Result -eq 'Unchanged') { $row.Message = 'Configuration exists but signing is disabled; publish the CNAME records and run with -Enable' }

        if ($Rotate) {
            $row.Action = 'Rotate'
            if (-not $row.Enabled) { $row.Result = 'Skipped'; $row.Message = 'DKIM is not enabled for this domain; enable it before rotating keys'; continue }
            if (-not $PSCmdlet.ShouldProcess($name, "Rotate DKIM signing keys ($KeySize-bit)")) { $row.Result = 'Skipped'; $row.Message = 'Not confirmed'; continue }
            Rotate-DkimSigningConfig -Identity $name -KeySize $KeySize -ErrorAction Stop
            $row.RotateOnDate = (Get-DkimSigningConfig -Identity $name -ErrorAction Stop).RotateOnDate
            $row.Result = 'RotationScheduled'; $row.Message = 'The new key becomes active on RotateOnDate; no DNS change is needed'
        }
    }
    catch {
        $row.Result = 'Failed'; $row.Message = $_.Exception.Message
        if ($_.Exception.Message -match 'CNAME') { $row.Message += ' - Exchange Online cannot see the CNAME records yet; allow up to 48 hours for DNS propagation.' }
        Write-Warning "$name ($($row.Action)): $($row.Message)"
    }
}

Write-Host ''
Write-Host ('DKIM signing - {0} domain(s) processed' -f $rows.Count) -ForegroundColor Cyan
foreach ($group in ($rows | Group-Object -Property Result | Sort-Object -Property Name)) {
    Write-Host ('  {0,-18} {1,4}' -f $group.Name, $group.Count) -ForegroundColor $(if ($group.Name -eq 'Failed') { 'Red' } else { 'Gray' })
}
$pending = @($rows | Where-Object { -not $_.Enabled -and -not [string]::IsNullOrEmpty($_.Selector1Target) })
if ($pending.Count -gt 0) {
    Write-Host ''
    Write-Host 'CNAME records to publish (host -> target) for domains that are not signing yet:' -ForegroundColor Yellow
    foreach ($row in $pending) {
        Write-Host ('  {0} -> {1}' -f $row.Selector1Host, $row.Selector1Target)
        Write-Host ('  {0} -> {1}' -f $row.Selector2Host, $row.Selector2Target)
    }
}

$rows
#endregion Main
