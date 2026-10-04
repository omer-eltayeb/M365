<#
.SYNOPSIS
    Creates an app registration with certificate credential and Graph application permissions for unattended scripts.
.DESCRIPTION
    Resolves the requested Microsoft Graph application permission names to appRole IDs on the Graph service principal, then
    POSTs /applications (single tenant, requiredResourceAccess), POSTs /servicePrincipals for it and attaches a certificate to
    keyCredentials (PATCH /applications/{id}) from a .cer file or from a new self-signed certificate created on Windows with
    New-SelfSignedCertificate. Optionally adds Exchange.ManageAsApp for Exchange Online PowerShell and grants tenant-wide admin
    consent through /servicePrincipals/{id}/appRoleAssignments. Prints the AppId, TenantId and Thumbprint together with the
    ready-to-paste Connect-MgGraph and Connect-ExchangeOnline commands.
.PARAMETER DisplayName
    Name of the app registration, for example 'Intune-Reporting-Automation'.
.PARAMETER ApplicationPermissions
    Microsoft Graph application permission names, for example 'DeviceManagementManagedDevices.Read.All', 'User.Read.All'.
.PARAMETER ExchangeManageAsApp
    Also request Office 365 Exchange Online > Exchange.ManageAsApp (app-only Exchange Online PowerShell).
.PARAMETER CertificatePath
    Existing public certificate (.cer) to register as credential. Mutually exclusive with -CreateSelfSignedCertificate.
.PARAMETER CreateSelfSignedCertificate
    Create a self-signed certificate in Cert:\CurrentUser\My (Windows only) and export its .cer file.
.PARAMETER CertificateValidityYears
    Lifetime of the self-signed certificate. Default 2.
.PARAMETER CertificateOutputFolder
    Folder for the exported .cer (and .pfx) files. Defaults to the current folder.
.PARAMETER PfxPassword
    When given, the self-signed certificate is also exported as a password-protected .pfx for other machines.
.PARAMETER GrantAdminConsent
    Grant admin consent for every requested application permission (needs Privileged Role Administrator or Global Administrator).
.EXAMPLE
    PS> .\New-M365GraphAppRegistrationForAutomation.ps1 -DisplayName 'Intune-Reports' -ApplicationPermissions 'DeviceManagementManagedDevices.Read.All' -CreateSelfSignedCertificate -GrantAdminConsent
    Creates the app, the service principal and a two-year certificate, grants consent and prints the Connect-MgGraph command.
.EXAMPLE
    PS> .\New-M365GraphAppRegistrationForAutomation.ps1 -DisplayName 'EXO-Automation' -ApplicationPermissions 'Mail.Send' -ExchangeManageAsApp -CertificatePath .\exo.cer -WhatIf
    Shows what would be created for an Exchange Online automation account without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication; Windows PKI module for -CreateSelfSignedCertificate
    Permissions : Application.ReadWrite.All, Directory.Read.All, plus AppRoleAssignment.ReadWrite.All with -GrantAdminConsent
                  (delegated); Application Administrator can create the app, consent needs Privileged Role Administrator.
    Category    : User lifecycle & tenant hygiene
    Changes     : Yes
    Notes       : Without -GrantAdminConsent (or when the grant is refused) the admin consent URL is printed instead. For
                  Exchange.ManageAsApp the service principal must additionally hold an Exchange role, for example the Exchange
                  Administrator directory role. Keep the private key on the automation host only; a .pfx export is optional.
                  New applications can take a minute to replicate, so the first sign-in may fail with AADSTS700016.
.LINK
    https://learn.microsoft.com/graph/api/application-post-applications
.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments
.LINK
    https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Existing')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 120)]
    [string]$DisplayName,

    [Parameter(Mandatory = $true)]
    [string[]]$ApplicationPermissions,

    [Parameter()]
    [switch]$ExchangeManageAsApp,

    [Parameter(Mandatory = $true, ParameterSetName = 'Existing')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$CertificatePath,

    [Parameter(ParameterSetName = 'SelfSigned')]
    [switch]$CreateSelfSignedCertificate,

    [Parameter(ParameterSetName = 'SelfSigned')]
    [ValidateRange(1, 5)]
    [int]$CertificateValidityYears = 2,

    [Parameter(ParameterSetName = 'SelfSigned')]
    [string]$CertificateOutputFolder = (Get-Location).Path,

    [Parameter(ParameterSetName = 'SelfSigned')]
    [securestring]$PfxPassword,

    [Parameter()]
    [switch]$GrantAdminConsent
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

function Invoke-GraphJson {
    <# Sends a JSON body with the given method and returns the parsed response. #>
    param([string]$Method, [string]$Uri, [hashtable]$Body)
    return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body (ConvertTo-Json -InputObject $Body -Depth 8) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
}
#endregion Helpers

#region Main
$graphAppId = '00000003-0000-0000-c000-000000000000'          # Microsoft Graph
$exchangeAppId = '00000002-0000-0ff1-ce00-000000000000'       # Office 365 Exchange Online
$exchangeManageAsAppRoleId = 'dc50a0fb-09a3-484d-be87-e023b12c6440'
if ($CreateSelfSignedCertificate -and $null -eq (Get-Command -Name New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
    throw '-CreateSelfSignedCertificate needs the Windows PKI module (New-SelfSignedCertificate). On other platforms create the certificate with openssl and pass -CertificatePath.'
}
$scopes = @('Application.ReadWrite.All', 'Directory.Read.All')
if ($GrantAdminConsent) { $scopes += 'AppRoleAssignment.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Could not connect to Microsoft Graph: $($_.Exception.Message)" }
$graphBase = 'https://graph.microsoft.com/v1.0'
$tenantId = (Get-MgContext).TenantId

# Resolve permission names to appRole IDs on the Graph service principal; unknown names stop the script before anything is created.
$graphSp = @(Invoke-GraphPaged -Uri "$graphBase/servicePrincipals?`$filter=appId eq '$graphAppId'&`$select=id,appRoles")[0]
if ($null -eq $graphSp) { throw 'The Microsoft Graph service principal was not found in this tenant.' }
$graphRoles = @(foreach ($name in $ApplicationPermissions) {
    $role = $graphSp.appRoles | Where-Object { $_.value -eq $name -and $_.allowedMemberTypes -contains 'Application' } | Select-Object -First 1
    if ($null -eq $role) { throw "'$name' is not a Microsoft Graph application permission (check spelling and case, for example User.Read.All)." }
    [PSCustomObject]@{ Name = $name; Id = $role.id; ResourceId = $graphSp.id }
})
$requiredResourceAccess = @(@{ resourceAppId = $graphAppId; resourceAccess = @($graphRoles | ForEach-Object { @{ id = $_.Id; type = 'Role' } }) })
$exchangeSpId = $null
if ($ExchangeManageAsApp) {
    $exchangeSpId = @(Invoke-GraphPaged -Uri "$graphBase/servicePrincipals?`$filter=appId eq '$exchangeAppId'&`$select=id")[0].id
    if ($null -eq $exchangeSpId) { throw 'The Office 365 Exchange Online service principal was not found; Exchange Online is not provisioned in this tenant.' }
    $requiredResourceAccess += @{ resourceAppId = $exchangeAppId; resourceAccess = @(@{ id = $exchangeManageAsAppRoleId; type = 'Role' }) }
}
$safeName = $DisplayName.Replace("'", "''")
$existing = @(Invoke-GraphPaged -Uri "$graphBase/applications?`$filter=displayName eq '$safeName'&`$select=id")
if ($existing.Count -gt 0) { throw "An application named '$DisplayName' already exists (id $($existing[0].id)). Choose another name." }

$summary = "Create app registration with {0} Graph permission(s){1}" -f $graphRoles.Count, $(if ($ExchangeManageAsApp) { ' and Exchange.ManageAsApp' } else { '' })
if (-not $PSCmdlet.ShouldProcess($DisplayName, $summary)) { return }

$app = Invoke-GraphJson -Method POST -Uri "$graphBase/applications" -Body @{
    displayName            = $DisplayName
    signInAudience         = 'AzureADMyOrg'
    notes                  = 'Unattended automation (certificate credential). Created by New-M365GraphAppRegistrationForAutomation.ps1.'
    requiredResourceAccess = $requiredResourceAccess
}
Write-Verbose "Application created: $($app.appId) (object $($app.id))."
$servicePrincipal = $null
for ($attempt = 1; $attempt -le 5 -and $null -eq $servicePrincipal; $attempt++) {
    try { $servicePrincipal = Invoke-GraphJson -Method POST -Uri "$graphBase/servicePrincipals" -Body @{ appId = $app.appId } }
    catch {
        # The new application may not have replicated yet; retry a few times before giving up.
        if ($attempt -eq 5) { throw "Service principal could not be created: $($_.Exception.Message)" }
        Start-Sleep -Seconds (5 * $attempt)
    }
}

if ($CreateSelfSignedCertificate) {
    if (-not (Test-Path -Path $CertificateOutputFolder)) { New-Item -Path $CertificateOutputFolder -ItemType Directory -Force | Out-Null }
    $certParams = @{
        Subject = "CN=$DisplayName"; CertStoreLocation = 'Cert:\CurrentUser\My'; KeyExportPolicy = 'Exportable'; KeySpec = 'Signature'
        KeyLength = 2048; KeyAlgorithm = 'RSA'; HashAlgorithm = 'SHA256'; NotAfter = (Get-Date).AddYears($CertificateValidityYears)
    }
    $certificate = New-SelfSignedCertificate @certParams
    $cerPath = Join-Path -Path $CertificateOutputFolder -ChildPath "$DisplayName.cer"
    Export-Certificate -Cert $certificate -FilePath $cerPath -Force | Out-Null
    if ($null -ne $PfxPassword) {
        $pfxPath = Join-Path -Path $CertificateOutputFolder -ChildPath "$DisplayName.pfx"
        Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $PfxPassword -Force | Out-Null
        Write-Warning "Private key exported to $pfxPath - store it securely and delete it after import."
    }
}
else {
    $certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (Resolve-Path -Path $CertificatePath).Path
    $cerPath = $CertificatePath
}
$keyCredential = @{
    type          = 'AsymmetricX509Cert'
    usage         = 'Verify'
    key           = [Convert]::ToBase64String($certificate.GetRawCertData())
    displayName   = $certificate.Subject
    startDateTime = $certificate.NotBefore.ToUniversalTime().ToString('o')
    endDateTime   = $certificate.NotAfter.ToUniversalTime().ToString('o')
}
Invoke-GraphJson -Method PATCH -Uri "$graphBase/applications/$($app.id)" -Body @{ keyCredentials = @($keyCredential) } | Out-Null
Write-Verbose "Certificate $($certificate.Thumbprint) attached (valid until $($certificate.NotAfter.ToString('yyyy-MM-dd')))."

$consentUrl = "https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$($app.appId)"
$consentState = "Not granted - open $consentUrl"
if ($GrantAdminConsent -and $PSCmdlet.ShouldProcess($DisplayName, 'Grant tenant-wide admin consent for all requested application permissions')) {
    $grants = @($graphRoles | ForEach-Object { @{ principalId = $servicePrincipal.id; resourceId = $_.ResourceId; appRoleId = $_.Id } })
    if ($ExchangeManageAsApp) { $grants += @{ principalId = $servicePrincipal.id; resourceId = $exchangeSpId; appRoleId = $exchangeManageAsAppRoleId } }
    $granted = 0
    foreach ($grant in $grants) {
        try { Invoke-GraphJson -Method POST -Uri "$graphBase/servicePrincipals/$($servicePrincipal.id)/appRoleAssignments" -Body $grant | Out-Null; $granted++ }
        catch { Write-Warning "Consent for appRole $($grant.appRoleId) failed (needs Privileged Role Administrator): $($_.Exception.Message)" }
    }
    $consentState = if ($granted -eq $grants.Count) { 'Granted' } else { "Partial ($granted of $($grants.Count)) - finish at $consentUrl" }
}

$initialDomain = @(Invoke-GraphPaged -Uri "$graphBase/organization?`$select=verifiedDomains")[0].verifiedDomains | Where-Object { $_.isInitial } | Select-Object -First 1 -ExpandProperty name
$result = [PSCustomObject]@{
    DisplayName            = $DisplayName
    AppId                  = $app.appId
    ObjectId               = $app.id
    ServicePrincipalId     = $servicePrincipal.id
    TenantId               = $tenantId
    Thumbprint             = $certificate.Thumbprint
    CertificateExpires     = $certificate.NotAfter
    CertificatePath        = $cerPath
    AdminConsent           = $consentState
    ConnectGraphCommand    = "Connect-MgGraph -ClientId $($app.appId) -TenantId $tenantId -CertificateThumbprint $($certificate.Thumbprint)"
    ConnectExchangeCommand = 'n/a'
}
if ($ExchangeManageAsApp) {
    $result.ConnectExchangeCommand = "Connect-ExchangeOnline -AppId $($app.appId) -CertificateThumbprint $($certificate.Thumbprint) -Organization $initialDomain"
}
Write-Host "App registration '$DisplayName' is ready. Admin consent: $consentState" -ForegroundColor Cyan
Write-Host $result.ConnectGraphCommand -ForegroundColor Green
if ($ExchangeManageAsApp) {
    Write-Host $result.ConnectExchangeCommand -ForegroundColor Green
    Write-Host 'Exchange.ManageAsApp also needs an Exchange role: assign the Exchange Administrator directory role to the service principal.' -ForegroundColor Yellow
}
$result
#endregion Main
