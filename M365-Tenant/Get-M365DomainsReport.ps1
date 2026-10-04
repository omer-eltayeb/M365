<#
.SYNOPSIS
    Reports every domain in the tenant with verification, authentication type, services and password policy, plus DNS and federation details.
.DESCRIPTION
    Lists the domains through GET /domains (Microsoft Graph v1.0) with default/initial/verified flags, Managed or
    Federated authentication, supported services, password validity and the pending state operation. -IncludeDnsRecords
    exports the DNS records Microsoft expects (/domains/{id}/serviceConfigurationRecords, plus verificationDnsRecords for
    unverified domains) to <OutputPath base>_DnsRecords.csv and -VerifyDns resolves each one with Resolve-DnsName.
    -IncludeFederation reads /domains/{id}/federationConfiguration for federated domains and flags token-signing
    certificates that are expired or expire within -CertificateWarningDays.
.PARAMETER IncludeDnsRecords
    Also export the expected DNS records for every domain to <OutputPath base>_DnsRecords.csv.
.PARAMETER VerifyDns
    Resolve every expected record in public DNS and add a DnsStatus column (implies -IncludeDnsRecords). Needs
    Resolve-DnsName (DnsClient module, Windows); skipped with a warning on other platforms.
.PARAMETER IncludeFederation
    For federated domains, add issuer URI, passive sign-in URI, MFA behaviour, signed-request requirement and the
    expiry of the current token-signing certificate.
.PARAMETER CertificateWarningDays
    Days before expiry at which a federation signing certificate is flagged. Default 30.
.PARAMETER OutputPath
    Path of the domains CSV. Defaults to .\Reports\M365Domains_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the domain objects (and the DNS record objects with -IncludeDnsRecords) to the pipeline.
.EXAMPLE
    PS> .\Get-M365DomainsReport.ps1
    Exports all domains with their flags, services and password policy and lists unverified domains.
.EXAMPLE
    PS> .\Get-M365DomainsReport.ps1 -IncludeDnsRecords -VerifyDns -IncludeFederation -OutputPath C:\Temp\Domains.csv
    Also writes C:\Temp\Domains_DnsRecords.csv with the resolved status of every expected record and reports the federation certificates.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Domain.Read.All (delegated). Global Reader or Domain Name Administrator can read domains and federation settings.
    Category    : Tenant configuration & health
    Changes     : No
    Notes       : A passwordValidityPeriodInDays of 2147483647 means passwords never expire. -VerifyDns uses the DNS servers
                  of the machine running the script, so records behind split-brain DNS can show as Mismatch. DNS records and
                  federation settings cost one request per domain; a 200 ms pause between domains avoids throttling.
.LINK
    https://learn.microsoft.com/graph/api/domain-list
.LINK
    https://learn.microsoft.com/graph/api/domain-list-serviceconfigurationrecords
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeDnsRecords,

    [Parameter()]
    [switch]$VerifyDns,

    [Parameter()]
    [switch]$IncludeFederation,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$CertificateWarningDays = 30,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-GraphIfNeeded {
    <# Connects to Microsoft Graph only when there is no usable session for the required scopes. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )
    $context = Get-MgContext
    $missingScopes = @()
    if ($null -ne $context) {
        $missingScopes = @($Scopes | Where-Object { $context.Scopes -notcontains $_ })
    }
    if ($null -eq $context -or $missingScopes.Count -gt 0) {
        Write-Verbose "Connecting to Microsoft Graph with scopes: $($Scopes -join ', ')"
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
    }
    else {
        Write-Verbose "Reusing existing Microsoft Graph session for $($context.Account)."
    }
}

function Invoke-GraphPaged {
    <# GET helper that follows @odata.nextLink and returns every item in 'value'. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Headers
    )
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $requestParams = @{ Method = 'GET'; Uri = $nextLink; OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($null -ne $Headers) { $requestParams['Headers'] = $Headers }
        $response = Invoke-MgGraphRequest @requestParams
        if ($null -ne $response.PSObject.Properties['value']) {
            foreach ($item in $response.value) { $results.Add($item) }
        }
        elseif ($null -ne $response) {
            $results.Add($response)
        }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}

function Test-ExpectedDnsRecord {
    <# Resolves one expected record in public DNS and returns Match, Mismatch (with the values found) or NotFound. #>
    param([Parameter(Mandatory = $true)][string]$Label, [Parameter(Mandatory = $true)][string]$Type, [Parameter(Mandatory = $true)][string]$Expected)
    $answerProperty = @{ MX = 'NameExchange'; TXT = 'Strings'; CNAME = 'NameHost'; SRV = 'NameTarget' }
    try {
        # TXT answers arrive as 255-character chunks in Strings; joining them restores long SPF/DKIM values.
        $found = @(Resolve-DnsName -Name $Label -Type $Type -DnsOnly -ErrorAction Stop | Where-Object { [string]$_.Type -eq $Type } |
                ForEach-Object { (@($_.($answerProperty[$Type])) -join '').TrimEnd('.') })
    }
    catch {
        return 'NotFound'
    }
    if ($found -contains $Expected.TrimEnd('.')) { return 'Match' }
    if ($found.Count -eq 0) { return 'NotFound' }
    return 'Mismatch (found: {0})' -f ($found -join ' | ')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365Domains_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$dnsOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_DnsRecords.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))
if ($VerifyDns) { $IncludeDnsRecords = $true }
if ($VerifyDns -and $null -eq (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
    Write-Warning 'Resolve-DnsName is not available on this platform (DnsClient module, Windows only); DNS verification skipped.'
    $VerifyDns = $false
}

try {
    Connect-GraphIfNeeded -Scopes @('Domain.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0'
$domainSelect = 'id,authenticationType,availabilityStatus,isAdminManaged,isDefault,isInitial,isRoot,isVerified,' +
    'passwordNotificationWindowInDays,passwordValidityPeriodInDays,state,supportedServices'
try {
    $domains = @(Invoke-GraphPaged -Uri ('{0}/domains?$select={1}' -f $graphV1, $domainSelect))
}
catch {
    throw "Failed to read domains: $($_.Exception.Message)"
}

$nowUtc = [datetime]::UtcNow
$valueProperty = @{ MX = 'mailExchange'; TXT = 'text'; CNAME = 'canonicalName'; SRV = 'nameTarget' }
$domainRows = New-Object -TypeName System.Collections.Generic.List[object]
$dnsRows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($domain in ($domains | Sort-Object -Property @{ Expression = 'isDefault'; Descending = $true }, @{ Expression = 'isVerified'; Descending = $true }, id)) {
    $index++
    Write-Progress -Activity 'Processing domains' -Status $domain.id -PercentComplete (($index / $domains.Count) * 100)
    $findings = New-Object -TypeName System.Collections.Generic.List[string]
    if (-not $domain.isVerified) { $findings.Add('Domain is not verified') }
    $dnsStatus = $null
    $federation = $null
    $certificateExpiry = $null
    $nextCertificateStaged = $null
    try {
        if ($IncludeDnsRecords) {
            # Verification records exist only until the domain is verified; service records apply to verified domains.
            $recordSets = @(@{ Purpose = 'ServiceConfiguration'; Uri = '{0}/domains/{1}/serviceConfigurationRecords' -f $graphV1, $domain.id })
            if (-not $domain.isVerified) { $recordSets += @{ Purpose = 'Verification'; Uri = '{0}/domains/{1}/verificationDnsRecords' -f $graphV1, $domain.id } }
            $matched = 0
            $checked = 0
            foreach ($recordSet in $recordSets) {
                foreach ($record in @(Invoke-GraphPaged -Uri $recordSet.Uri)) {
                    $type = ([string]$record.recordType).ToUpper()
                    $expected = $null
                    if ($valueProperty.ContainsKey($type)) { $expected = [string]$record.($valueProperty[$type]) }
                    $value = $expected
                    if ($type -eq 'SRV') { $value = '{0}:{1}' -f $expected, $record.port }
                    $status = $null
                    if ($VerifyDns -and -not [string]::IsNullOrWhiteSpace($expected)) {
                        $status = Test-ExpectedDnsRecord -Label ([string]$record.label) -Type $type -Expected $expected
                        $checked++
                        if ($status -eq 'Match') { $matched++ }
                    }
                    $dnsRows.Add([PSCustomObject]@{
                            Domain           = $domain.id
                            Purpose          = $recordSet.Purpose
                            RecordType       = $type
                            Label            = $record.label
                            Ttl              = $record.ttl
                            SupportedService = $record.supportedService
                            IsOptional       = [bool]$record.isOptional
                            Value            = $value
                            DnsStatus        = $status
                        })
                }
            }
            if ($VerifyDns) {
                $dnsStatus = '{0} of {1} records match' -f $matched, $checked
                if ($matched -lt $checked) { $findings.Add(('{0} expected DNS record(s) missing or different' -f ($checked - $matched))) }
            }
        }
        if ($IncludeFederation -and [string]$domain.authenticationType -eq 'Federated') {
            $federation = @(Invoke-GraphPaged -Uri ('{0}/domains/{1}/federationConfiguration' -f $graphV1, $domain.id)) | Select-Object -First 1
            if (-not [string]::IsNullOrWhiteSpace($federation.signingCertificate)) {
                $certificateBytes = [System.Convert]::FromBase64String($federation.signingCertificate)
                $certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $certificateBytes)
                $certificateExpiry = $certificate.NotAfter.ToUniversalTime()
                $nextCertificateStaged = -not [string]::IsNullOrWhiteSpace($federation.nextSigningCertificate)
                $daysLeft = [int][math]::Floor(($certificateExpiry - $nowUtc).TotalDays)
                if ($daysLeft -lt 0) { $findings.Add('Federation signing certificate has expired') }
                elseif ($daysLeft -le $CertificateWarningDays -and -not $nextCertificateStaged) {
                    $findings.Add(('Federation signing certificate expires in {0} days; no next certificate staged' -f $daysLeft))
                }
            }
        }
    }
    catch {
        Write-Warning "Domain $($domain.id): $($_.Exception.Message)"
        $findings.Add('Details could not be read: ' + $_.Exception.Message)
    }
    if ($IncludeDnsRecords -or $IncludeFederation) { Start-Sleep -Milliseconds 200 }
    $domainRows.Add([PSCustomObject]@{
            Domain                           = $domain.id
            IsDefault                        = [bool]$domain.isDefault
            IsInitial                        = [bool]$domain.isInitial
            IsVerified                       = [bool]$domain.isVerified
            IsRoot                           = [bool]$domain.isRoot
            IsAdminManaged                   = [bool]$domain.isAdminManaged
            AuthenticationType               = $domain.authenticationType
            AvailabilityStatus               = $domain.availabilityStatus
            SupportedServices                = (@($domain.supportedServices) -join ';')
            PasswordValidityPeriodInDays     = $domain.passwordValidityPeriodInDays
            PasswordNotificationWindowInDays = $domain.passwordNotificationWindowInDays
            StateStatus                      = $domain.state.status
            StateOperation                   = $domain.state.operation
            DnsStatus                        = $dnsStatus
            FederationIssuerUri              = $federation.issuerUri
            FederationPassiveSignInUri       = $federation.passiveSignInUri
            FederationIdpMfaBehavior         = $federation.federatedIdpMfaBehavior
            FederationSignedRequestRequired  = $federation.isSignedAuthenticationRequestRequired
            SigningCertificateExpiry         = $certificateExpiry
            NextSigningCertificateStaged     = $nextCertificateStaged
            Finding                          = ($findings -join '; ')
        })
}
Write-Progress -Activity 'Processing domains' -Completed

$domainRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($dnsRows.Count -gt 0) { $dnsRows | Export-Csv -Path $dnsOutputPath -NoTypeInformation -Encoding UTF8 }
$flagged = @($domainRows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Finding) })
$flagColor = 'Green'
if ($flagged.Count -gt 0) { $flagColor = 'Yellow' }
Write-Host ''
Write-Host 'Domain summary' -ForegroundColor Cyan
$verifiedCount = @($domainRows | Where-Object { $_.IsVerified }).Count
$federatedCount = @($domainRows | Where-Object { $_.AuthenticationType -eq 'Federated' }).Count
Write-Host ('  Domains         : {0} ({1} verified, {2} federated)' -f $domainRows.Count, $verifiedCount, $federatedCount)
if ($IncludeDnsRecords) { Write-Host ('  DNS records     : {0} -> {1}' -f $dnsRows.Count, $dnsOutputPath) }
Write-Host ('  Domains flagged : {0}' -f $flagged.Count) -ForegroundColor $flagColor
foreach ($row in $flagged) { Write-Host ('    {0,-40} {1}' -f $row.Domain, $row.Finding) -ForegroundColor Yellow }
Write-Host ('  Report          : {0}' -f $OutputPath)

if ($PassThru) {
    $domainRows
    if ($IncludeDnsRecords) { $dnsRows }
}
#endregion Main
