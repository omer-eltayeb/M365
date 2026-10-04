<#
.SYNOPSIS
    Inventories every service principal in the tenant and classifies it by kind, origin and SSO configuration.
.DESCRIPTION
    Lists all service principals through Microsoft Graph (GET /servicePrincipals with a trimmed $select) and classifies each
    one by Kind (Application, ManagedIdentity, Legacy, SocialIdp) and Origin (Microsoft first-party, ThisTenant, OtherTenant),
    adding the SSO mode, whether user assignment is required, whether it is listed as an enterprise app and whether it is
    hidden from My Apps. Microsoft first-party apps are excluded by default. With -IncludeSignInActivity the beta report
    GET /reports/servicePrincipalSignInActivities is joined on appId to add last sign-in dates and days since the last sign-in.
.PARAMETER ExcludeMicrosoft
    Excludes Microsoft first-party service principals. Default $true; pass -ExcludeMicrosoft $false to include them.
.PARAMETER Kind
    Restricts the inventory to one or more kinds: Application, ManagedIdentity, Legacy, SocialIdp. Default: all kinds.
.PARAMETER IncludeSignInActivity
    Adds LastSignInDateTime, LastDelegatedSignIn, LastAppOnlySignIn and DaysSinceLastSignIn (beta report; needs AuditLog.Read.All).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraServicePrincipalInventory_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraServicePrincipalInventory.ps1
    Exports all non-Microsoft service principals with their classification to the default CSV.
.EXAMPLE
    PS> .\Get-EntraServicePrincipalInventory.ps1 -Kind Application -IncludeSignInActivity -OutputPath C:\Temp\EnterpriseApps.csv -Verbose
    Exports only enterprise applications, enriched with their last sign-in dates, to the given file.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Application.Read.All, Directory.Read.All (delegated); AuditLog.Read.All is added with -IncludeSignInActivity.
    Category    : Applications & consent
    Changes     : No
    Notes       : -IncludeSignInActivity uses the beta endpoint /reports/servicePrincipalSignInActivities, which can change
                  without notice and needs Microsoft Entra ID P1 or P2; apps with no recorded sign-in have an empty LastSignInDateTime.
.LINK
    https://learn.microsoft.com/graph/api/serviceprincipal-list
.LINK
    https://learn.microsoft.com/graph/api/reportroot-list-serviceprincipalsigninactivities
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [bool]$ExcludeMicrosoft = $true,

    [Parameter()]
    [ValidateSet('Application', 'ManagedIdentity', 'Legacy', 'SocialIdp')]
    [string[]]$Kind,

    [Parameter()]
    [switch]$IncludeSignInActivity,

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
#endregion Helpers

#region Main
$requiredScopes = @('Application.Read.All', 'Directory.Read.All')
if ($IncludeSignInActivity) { $requiredScopes += 'AuditLog.Read.All' }
# Service principals owned by these two tenants are Microsoft first-party applications.
$microsoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraServicePrincipalInventory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
    $tenantId = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id')[0].id
}
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$select = 'id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,createdDateTime,signInAudience,tags,' +
    'preferredSingleSignOnMode,appRoleAssignmentRequired,homepage,replyUrls,notes,servicePrincipalNames'
Write-Verbose 'Retrieving service principals.'
try {
    $servicePrincipals = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals?$select={0}&$top=999' -f $select))
}
catch { throw "Failed to list service principals: $($_.Exception.Message)" }

$signInByAppId = @{}
if ($IncludeSignInActivity) {
    # beta: v1.0 has no sign-in activity report for service principals.
    try {
        foreach ($activity in @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities')) {
            if (-not [string]::IsNullOrEmpty($activity.appId)) { $signInByAppId[$activity.appId] = $activity }
        }
    }
    catch { Write-Warning "Sign-in activity could not be retrieved, the sign-in columns will be empty: $($_.Exception.Message)" }
}

$now = [datetime]::UtcNow
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$excludedMicrosoft = 0
foreach ($sp in $servicePrincipals) {
    $origin = 'OtherTenant'
    if ($microsoftTenantIds -contains $sp.appOwnerOrganizationId) { $origin = 'Microsoft' }
    elseif ([string]::IsNullOrEmpty($sp.appOwnerOrganizationId) -or $sp.appOwnerOrganizationId -eq $tenantId) { $origin = 'ThisTenant' }
    if ($ExcludeMicrosoft -and $origin -eq 'Microsoft') { $excludedMicrosoft++; continue }
    if ($Kind.Count -gt 0 -and $Kind -notcontains $sp.servicePrincipalType) { continue }

    $activity = $null
    if (-not [string]::IsNullOrEmpty($sp.appId)) { $activity = $signInByAppId[$sp.appId] }
    $lastSignIn = ConvertTo-UtcDateTime -Value $activity.lastSignInActivity.lastSignInDateTime
    $daysSinceLastSignIn = $null
    if ($null -ne $lastSignIn) { $daysSinceLastSignIn = [int][math]::Floor(($now - $lastSignIn).TotalDays) }
    $tags = @($sp.tags)
    $rows.Add([PSCustomObject]@{
        DisplayName           = $sp.displayName
        AppId                 = $sp.appId
        ObjectId              = $sp.id
        Kind                  = $sp.servicePrincipalType
        Origin                = $origin
        AccountEnabled        = $sp.accountEnabled
        IsEnterpriseApp       = ($tags -contains 'WindowsAzureActiveDirectoryIntegratedApp')
        HideFromMyApps        = ($tags -contains 'HideApp')
        AssignmentRequired    = $sp.appRoleAssignmentRequired
        SsoMode               = $sp.preferredSingleSignOnMode
        SignInAudience        = $sp.signInAudience
        CreatedDateTime       = ConvertTo-UtcDateTime -Value $sp.createdDateTime
        LastSignInDateTime    = $lastSignIn
        LastDelegatedSignIn   = ConvertTo-UtcDateTime -Value $activity.delegatedClientSignInActivity.lastSignInDateTime
        LastAppOnlySignIn     = ConvertTo-UtcDateTime -Value $activity.applicationAuthenticationClientSignInActivity.lastSignInDateTime
        DaysSinceLastSignIn   = $daysSinceLastSignIn
        Homepage              = $sp.homepage
        ReplyUrls             = (@($sp.replyUrls) -join ';')
        ServicePrincipalNames = (@($sp.servicePrincipalNames) -join ';')
        Notes                 = $sp.notes
    })
}

$sortedRows = @($rows | Sort-Object -Property Kind, DisplayName)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No service principals matched the filters; no CSV was written.' }

$kindCounts = @($sortedRows | Group-Object -Property Kind | Sort-Object -Property Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count })
Write-Host 'Service principal inventory summary' -ForegroundColor Cyan
Write-Host ('  Service principals in tenant : {0} ({1} Microsoft first-party excluded)' -f $servicePrincipals.Count, $excludedMicrosoft)
Write-Host ('  By kind                      : {0}' -f ($kindCounts -join ', '))
Write-Host ('  From other tenants           : {0}' -f @($sortedRows | Where-Object { $_.Origin -eq 'OtherTenant' }).Count)
Write-Host ('  Disabled                     : {0}' -f @($sortedRows | Where-Object { $_.AccountEnabled -eq $false }).Count) -ForegroundColor Yellow
if ($IncludeSignInActivity) { Write-Host ('  No sign-in recorded          : {0}' -f @($sortedRows | Where-Object { $null -eq $_.LastSignInDateTime }).Count) -ForegroundColor Yellow }
Write-Host ('  Rows exported                : {0} -> {1}' -f $sortedRows.Count, $OutputPath)

if ($PassThru) { $sortedRows }
#endregion Main
