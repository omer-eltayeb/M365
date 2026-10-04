<#
.SYNOPSIS
    Reports the token-signing certificates of SAML enterprise applications that are expired or expiring soon.
.DESCRIPTION
    Lists service principals through Microsoft Graph (GET /servicePrincipals with a trimmed $select), keeps the ones configured for
    SAML single sign-on and returns one row per key credential (usage Sign or Verify) with its thumbprint, validity window, remaining
    days and a status of Expired, ExpiringSoon (within -DaysUntilExpiry) or Valid. The certificate that matches
    preferredTokenSigningKeyThumbprint is marked as the active signing certificate, and the notification e-mail addresses and
    login URL of the app are included so the report can be routed to the application owner.
.PARAMETER DaysUntilExpiry
    Certificates expiring within this many days are reported as ExpiringSoon. Default 60.
.PARAMETER IncludeValid
    Also exports certificates that are valid for longer than -DaysUntilExpiry.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraSamlCertificateExpiry_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraSamlCertificateExpiry.ps1
    Exports the SAML signing certificates that are expired or expire within 60 days to the default CSV.
.EXAMPLE
    PS> .\Get-EntraSamlCertificateExpiry.ps1 -DaysUntilExpiry 90 -IncludeValid -OutputPath C:\Temp\SamlCertificates.csv -Verbose
    Uses a 90-day window, includes healthy certificates and saves the report to the given file.
.EXAMPLE
    PS> .\Get-EntraSamlCertificateExpiry.ps1 -PassThru | Where-Object { $_.IsActiveSigningCert } | Format-Table AppName, EndDateTime, DaysRemaining
    Shows only the active signing certificate of each affected app.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Application.Read.All (delegated)
    Category    : Applications & consent
    Changes     : No
    Notes       : Entra ID stores every SAML certificate as a Sign and a Verify key credential with the same thumbprint, so each
                  certificate produces two rows. Apps configured for SAML before preferredSingleSignOnMode existed can have that
                  property empty; they are still included when a preferred token-signing thumbprint is set. Rotating the certificate
                  must be coordinated with the application owner, because the service provider needs the new public key.
.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-list
.LINK
    https://learn.microsoft.com/entra/identity/enterprise-apps/tutorial-manage-certificates-for-federated-single-sign-on
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysUntilExpiry = 60,

    [Parameter()]
    [switch]$IncludeValid,

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

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([Parameter()][object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function ConvertTo-Thumbprint {
    <# Converts a key credential customKeyIdentifier (base64 text or bytes) to an upper-case hex thumbprint. #>
    param([Parameter()][object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try {
        $bytes = $Value
        if ($Value -is [string]) { $bytes = [Convert]::FromBase64String($Value) }
        return ([System.BitConverter]::ToString([byte[]]$bytes) -replace '-', '')
    }
    catch { return [string]$Value }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraSamlCertificateExpiry_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('Application.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# preferredSingleSignOnMode is not filterable server-side, so every service principal is read once and filtered locally.
$select = 'id,appId,displayName,accountEnabled,preferredSingleSignOnMode,preferredTokenSigningKeyThumbprint,keyCredentials,notificationEmailAddresses,loginUrl'
Write-Verbose 'Retrieving service principals.'
try { $servicePrincipals = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals?$select={0}&$top=999' -f $select)) }
catch { throw "Failed to list service principals: $($_.Exception.Message)" }

# Older SAML apps can have an empty preferredSingleSignOnMode; a preferred signing thumbprint still identifies them as SAML.
$samlApps = @($servicePrincipals | Where-Object {
        $_.preferredSingleSignOnMode -eq 'saml' -or
        ([string]::IsNullOrEmpty($_.preferredSingleSignOnMode) -and -not [string]::IsNullOrEmpty($_.preferredTokenSigningKeyThumbprint))
    })
Write-Verbose "Evaluating certificates of $($samlApps.Count) SAML applications."

$now = [datetime]::UtcNow
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$appsWithoutCertificate = New-Object -TypeName System.Collections.Generic.List[string]
foreach ($app in $samlApps) {
    $certificates = @($app.keyCredentials | Where-Object { $null -ne $_ })
    if ($certificates.Count -eq 0) { $appsWithoutCertificate.Add($app.displayName); continue }
    foreach ($certificate in $certificates) {
        $thumbprint = ConvertTo-Thumbprint -Value $certificate.customKeyIdentifier
        $end = ConvertTo-UtcDateTime -Value $certificate.endDateTime
        $daysRemaining = $null
        $status = 'Valid'
        if ($null -ne $end) {
            # Floor keeps "expires later today" at 0 days and anything already past as a negative number.
            $daysRemaining = [int][math]::Floor(($end - $now).TotalDays)
            if ($daysRemaining -lt 0) { $status = 'Expired' }
            elseif ($daysRemaining -le $DaysUntilExpiry) { $status = 'ExpiringSoon' }
        }
        if ($status -eq 'Valid' -and -not $IncludeValid) { continue }
        $rows.Add([PSCustomObject]@{
            AppName             = $app.displayName
            AppId               = $app.appId
            ObjectId            = $app.id
            AccountEnabled      = $app.accountEnabled
            Usage               = $certificate.usage
            Thumbprint          = $thumbprint
            IsActiveSigningCert = (-not [string]::IsNullOrEmpty($thumbprint) -and $thumbprint -eq $app.preferredTokenSigningKeyThumbprint)
            StartDateTime       = ConvertTo-UtcDateTime -Value $certificate.startDateTime
            EndDateTime         = $end
            DaysRemaining       = $daysRemaining
            Status              = $status
            NotificationEmails  = (@($app.notificationEmailAddresses) -join ';')
            LoginUrl            = $app.loginUrl
        })
    }
}

$sortedRows = @($rows | Sort-Object -Property DaysRemaining, AppName, Usage)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning ('No SAML certificates are expired or expiring within {0} days; no CSV was written.' -f $DaysUntilExpiry) }

$activeAtRisk = @($sortedRows | Where-Object { $_.IsActiveSigningCert -and $_.Usage -eq 'Sign' -and $_.Status -ne 'Valid' })
Write-Host ''
Write-Host 'SAML certificate expiry summary' -ForegroundColor Cyan
Write-Host ('  Service principals scanned      : {0}' -f $servicePrincipals.Count)
Write-Host ('  SAML applications               : {0} ({1} without any certificate)' -f $samlApps.Count, $appsWithoutCertificate.Count)
Write-Host ('  Expired certificate rows        : {0}' -f @($sortedRows | Where-Object { $_.Status -eq 'Expired' }).Count) -ForegroundColor Red
Write-Host ('  Expiring within {0,3} days        : {1}' -f $DaysUntilExpiry, @($sortedRows | Where-Object { $_.Status -eq 'ExpiringSoon' }).Count) -ForegroundColor Yellow
if ($IncludeValid) { Write-Host ('  Valid certificate rows          : {0}' -f @($sortedRows | Where-Object { $_.Status -eq 'Valid' }).Count) -ForegroundColor Green }
Write-Host ('  Active signing certs at risk    : {0} app(s)' -f $activeAtRisk.Count) -ForegroundColor Yellow
Write-Host ('  Rows exported                   : {0} -> {1}' -f $sortedRows.Count, $OutputPath)
if ($appsWithoutCertificate.Count -gt 0) {
    Write-Warning ('{0} SAML application(s) have no signing certificate and cannot issue tokens: {1}' -f $appsWithoutCertificate.Count, ($appsWithoutCertificate -join ', '))
}

if ($PassThru) { $sortedRows }
#endregion Main
