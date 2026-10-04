<#
.SYNOPSIS
    Audits every app registration for risky authentication settings and credential hygiene and reports one row per finding.
.DESCRIPTION
    Lists all app registrations through Microsoft Graph (GET /applications with a trimmed $select) and evaluates each one for
    insecure redirect URIs (http, wildcard, the deprecated urn:ietf:wg:oauth:2.0:oob and localhost), implicit grant settings,
    public client flows, multi-tenant or personal account sign-in audiences, too many or long-lived client secrets,
    registrations without credentials or redirect URIs (possibly unused) and exposed APIs with pre-authorized client apps.
    Every finding becomes one row with a Severity of High, Medium or Info, so the CSV can be filtered and assigned for remediation.
.PARAMETER MaxSecrets
    Registrations with more client secrets than this number get a SecretCount finding. Default 2.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraAppRegistrationSecurityAudit_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the finding objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraAppRegistrationSecurityAudit.ps1
    Audits every app registration and exports all findings to the default CSV.
.EXAMPLE
    PS> .\Get-EntraAppRegistrationSecurityAudit.ps1 -MaxSecrets 1 -PassThru | Where-Object { $_.Severity -eq 'High' } | Format-Table AppName, Finding, Detail
    Flags registrations with more than one secret and shows only the high-severity findings on screen.
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
    Notes       : Findings are indicators, not verdicts: a multi-tenant audience or a localhost redirect URI can be intentional.
                  Only app registrations (application objects) are audited; settings on enterprise apps (service principals) are
                  not covered. Secret values are never returned by Graph, only their metadata.
.LINK
    https://learn.microsoft.com/graph/api/application-list
.LINK
    https://learn.microsoft.com/entra/identity-platform/reply-url
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(0, 100)]
    [int]$MaxSecrets = 2,

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

function Add-Finding {
    <# Adds one finding row for the given application to the script-level findings list. #>
    param([object]$App, [string]$Finding, [ValidateSet('High', 'Medium', 'Info')][string]$Severity, [string]$Detail)
    $script:findings.Add([PSCustomObject]@{
        AppName         = $App.displayName
        AppId           = $App.appId
        ObjectId        = $App.id
        Finding         = $Finding
        Severity        = $Severity
        Detail          = $Detail
        SignInAudience  = $App.signInAudience
        CreatedDateTime = ConvertTo-UtcDateTime -Value $App.createdDateTime
    })
}
#endregion Helpers

#region Main
$script:findings = New-Object -TypeName System.Collections.Generic.List[object]
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraAppRegistrationSecurityAudit_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('Application.Read.All')
    $select = 'id,appId,displayName,signInAudience,web,spa,publicClient,isFallbackPublicClient,requiredResourceAccess,createdDateTime,passwordCredentials,keyCredentials,identifierUris,api'
    Write-Verbose 'Retrieving app registrations.'
    $applications = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/applications?$select={0}&$top=999' -f $select))
}
catch { throw "Failed to list app registrations from Microsoft Graph: $($_.Exception.Message)" }

$processed = 0
foreach ($app in $applications) {
    $processed++
    if ($processed % 50 -eq 0) { Write-Progress -Activity 'Auditing app registrations' -Status "$processed of $($applications.Count)" -PercentComplete (($processed / $applications.Count) * 100) }
    $redirectUris = @()
    foreach ($platform in @('web', 'spa', 'publicClient')) {
        foreach ($uri in @($app.$platform.redirectUris)) { if (-not [string]::IsNullOrWhiteSpace($uri)) { $redirectUris += [PSCustomObject]@{ Platform = $platform; Uri = $uri } } }
    }
    foreach ($redirect in $redirectUris) {
        $detail = '{0}: {1}' -f $redirect.Platform, $redirect.Uri
        if ($redirect.Uri -like 'http://*') {
            # http is only acceptable for loopback redirects used by desktop or development clients.
            if ($redirect.Uri -match '^http://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)') { Add-Finding -App $app -Finding 'LocalhostRedirectUri' -Severity 'Info' -Detail $detail }
            else { Add-Finding -App $app -Finding 'HttpRedirectUri' -Severity 'High' -Detail $detail }
        }
        if ($redirect.Uri.Contains('*')) { Add-Finding -App $app -Finding 'WildcardRedirectUri' -Severity 'High' -Detail $detail }
        if ($redirect.Uri -eq 'urn:ietf:wg:oauth:2.0:oob') { Add-Finding -App $app -Finding 'UrnOobRedirectUri' -Severity 'Medium' -Detail ('{0} (deprecated out-of-band flow)' -f $detail) }
    }
    $implicit = $app.web.implicitGrantSettings; $audience = [string]$app.signInAudience
    $multiTenant = $audience -in @('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount')
    if ($implicit.enableAccessTokenIssuance -eq $true) { Add-Finding -App $app -Finding 'ImplicitAccessTokenEnabled' -Severity 'High' -Detail 'Implicit grant issues access tokens; use PKCE.' }
    if ($implicit.enableIdTokenIssuance -eq $true) { Add-Finding -App $app -Finding 'ImplicitIdTokenEnabled' -Severity 'Medium' -Detail 'Implicit grant issues ID tokens; only legacy SPAs need this.' }
    if ($app.isFallbackPublicClient -eq $true) { Add-Finding -App $app -Finding 'PublicClientFlowsAllowed' -Severity 'Medium' -Detail 'Public client flows are allowed (ROPC and device code).' }
    if ($multiTenant) { Add-Finding -App $app -Finding 'MultiTenant' -Severity 'Medium' -Detail "signInAudience $audience lets users of any Microsoft Entra tenant sign in." }
    if ($audience -like '*PersonalMicrosoftAccount') { Add-Finding -App $app -Finding 'PersonalAccounts' -Severity 'Medium' -Detail "signInAudience $audience lets personal accounts sign in." }

    $secrets = @($app.passwordCredentials | Where-Object { $null -ne $_ })
    $certificates = @($app.keyCredentials | Where-Object { $null -ne $_ })
    if ($secrets.Count -gt $MaxSecrets) { Add-Finding -App $app -Finding 'SecretCount' -Severity 'Medium' -Detail ('{0} secrets, threshold {1}; prefer certificates.' -f $secrets.Count, $MaxSecrets) }
    foreach ($secret in $secrets) {
        $start = ConvertTo-UtcDateTime -Value $secret.startDateTime
        $end = ConvertTo-UtcDateTime -Value $secret.endDateTime
        if ($null -ne $start -and $null -ne $end -and ($end - $start).TotalDays -gt 730) {
            $detail = "Secret '{0}' is valid for {1} days ({2:yyyy-MM-dd} to {3:yyyy-MM-dd})." -f $secret.displayName, [int]($end - $start).TotalDays, $start, $end
            Add-Finding -App $app -Finding 'LongLivedSecret' -Severity 'Medium' -Detail $detail
        }
    }
    if ($secrets.Count -eq 0 -and $certificates.Count -eq 0 -and $redirectUris.Count -eq 0) {
        Add-Finding -App $app -Finding 'NoCredentialsNoRedirects' -Severity 'Info' -Detail 'No credentials and no redirect URIs; the registration is possibly unused and could be removed.'
    }
    $preAuthorized = @($app.api.preAuthorizedApplications | Where-Object { $null -ne $_ })
    if ($preAuthorized.Count -gt 0) {
        $clientList = @($preAuthorized | ForEach-Object { '{0} ({1} scope(s))' -f $_.appId, @($_.delegatedPermissionIds).Count }) -join '; '
        $detail = 'API {0}: {1} pre-authorized client app(s) skip consent: {2}' -f (@($app.identifierUris) -join ' '), $preAuthorized.Count, $clientList
        Add-Finding -App $app -Finding 'ExposesApi' -Severity 'Info' -Detail $detail
    }
}
Write-Progress -Activity 'Auditing app registrations' -Completed

$severityOrder = @{ High = 0; Medium = 1; Info = 2 }
$sortedFindings = @($findings | Sort-Object -Property @{ Expression = { $severityOrder[$_.Severity] } }, AppName, Finding)
if ($sortedFindings.Count -gt 0) { $sortedFindings | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No findings were produced; no CSV was written.' }

Write-Host ''
Write-Host 'App registration security audit summary' -ForegroundColor Cyan
Write-Host ('  App registrations scanned : {0}' -f $applications.Count)
Write-Host ('  Apps with findings        : {0}' -f @($sortedFindings | Select-Object -ExpandProperty AppId -Unique).Count)
Write-Host ('  High severity findings    : {0}' -f @($sortedFindings | Where-Object { $_.Severity -eq 'High' }).Count) -ForegroundColor Red
Write-Host ('  Medium severity findings  : {0}' -f @($sortedFindings | Where-Object { $_.Severity -eq 'Medium' }).Count) -ForegroundColor Yellow
Write-Host ('  Info findings             : {0}' -f @($sortedFindings | Where-Object { $_.Severity -eq 'Info' }).Count)
foreach ($bucket in @($sortedFindings | Group-Object -Property Finding | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-27}: {1}' -f $bucket.Name, $bucket.Count)
}
Write-Host ('  Rows exported             : {0} -> {1}' -f $sortedFindings.Count, $OutputPath)

if ($PassThru) { $sortedFindings }
#endregion Main
