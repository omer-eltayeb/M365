<#
.SYNOPSIS
    Reports the Microsoft Entra cross-tenant access policy: default settings and every partner-specific configuration.
.DESCRIPTION
    Reads the default cross-tenant access policy (GET /policies/crossTenantAccessPolicy/default) and all partner configurations
    (GET /policies/crossTenantAccessPolicy/partners), resolves each partner tenant id to its name and default domain through
    /tenantRelationships/findTenantInformationByTenantId and summarises per row the inbound and outbound B2B collaboration and
    B2B direct connect settings, inbound trust (MFA, compliant and hybrid joined devices), automatic user consent, service provider
    and multitenant organization flags. With -IncludeIdentitySync the inbound cross-tenant synchronization setting is added.
    Settings a partner does not override show '(default)'. The result is exported to CSV and optionally as JSON per partner.
.PARAMETER IncludeIdentitySync
    Also reads /partners/{id}/identitySynchronization to report whether inbound user synchronization is allowed (one call per partner).
.PARAMETER ExportJsonFolder
    When set, the raw default policy and every partner configuration are also saved as JSON files in this folder.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraCrossTenantAccessPolicy_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraCrossTenantAccessPolicy.ps1
    Exports the default policy and all partner configurations and prints a one-line summary per partner.
.EXAMPLE
    PS> .\Get-EntraCrossTenantAccessPolicy.ps1 -IncludeIdentitySync -ExportJsonFolder C:\Backup\CrossTenant -Verbose
    Adds the cross-tenant synchronization state and keeps a JSON copy of every configuration in C:\Backup\CrossTenant.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Policy.Read.All, CrossTenantInformation.ReadBasic.All (delegated); Global Reader or Security Reader.
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : Partner names come from the public tenant information endpoint; when a lookup fails the tenant id is shown instead.
                  identitySynchronization returns 404 for partners without cross-tenant synchronization, which is reported as False.
.LINK
    https://learn.microsoft.com/graph/api/crosstenantaccesspolicy-list-partners
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeIdentitySync,

    [Parameter()]
    [string]$ExportJsonFolder,

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

function Format-AccessSetting {
    <# Summarises a B2B collaboration or direct connect setting as 'users: allowed (all) / apps: blocked (3 selected)'. #>
    param([object]$Setting)
    if ($null -eq $Setting) { return '(default)' }
    $parts = foreach ($section in @(@{ Label = 'users'; Value = $Setting.usersAndGroups }, @{ Label = 'apps'; Value = $Setting.applications })) {
        if ($null -eq $section.Value) { '{0}: (default)' -f $section.Label; continue }
        $targets = @($section.Value.targets | Where-Object { $null -ne $_ })
        $scope = 'all'
        if ($targets.Count -gt 0 -and $targets[0].target -notlike 'All*') { $scope = '{0} selected' -f $targets.Count }
        '{0}: {1} ({2})' -f $section.Label, $section.Value.accessType, $scope
    }
    return ($parts -join ' / ')
}

function Get-ValueOrDefault {
    <# Returns the value, or '(default)' when the partner configuration does not override the default policy ($null). #>
    param([object]$Value)
    if ($null -eq $Value) { return '(default)' }
    return $Value
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraCrossTenantAccessPolicy_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
foreach ($folder in @((Split-Path -Path $OutputPath -Parent), $ExportJsonFolder)) {
    if (-not [string]::IsNullOrWhiteSpace($folder) -and -not (Test-Path -Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
}

try { Connect-GraphIfNeeded -Scopes @('Policy.Read.All', 'CrossTenantInformation.ReadBasic.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$v1 = 'https://graph.microsoft.com/v1.0'
$policyUri = "$v1/policies/crossTenantAccessPolicy"
try {
    $defaultPolicy = Invoke-MgGraphRequest -Method GET -Uri "$policyUri/default" -OutputType PSObject -ErrorAction Stop
    $partners = @(Invoke-GraphPaged -Uri "$policyUri/partners")
}
catch { throw "Failed to read the cross-tenant access policy: $($_.Exception.Message)" }
Write-Verbose "Loaded the default policy and $($partners.Count) partner configurations."

# The default policy is reported as the first row so partner rows can be compared against it.
$configurations = @([PSCustomObject]@{ Name = '(default policy)'; Domain = $null; Source = $defaultPolicy; File = 'Default.json' })
$processed = 0
foreach ($partner in $partners) {
    $processed++
    Write-Progress -Activity 'Resolving partner tenants' -Status $partner.tenantId -PercentComplete (($processed / $partners.Count) * 100)
    $name = [string]$partner.tenantId
    $domain = $null
    try {
        $tenantInfo = Invoke-MgGraphRequest -Method GET -Uri ("$v1/tenantRelationships/findTenantInformationByTenantId(tenantId='{0}')" -f $partner.tenantId) -OutputType PSObject -ErrorAction Stop
        if (-not [string]::IsNullOrEmpty($tenantInfo.displayName)) { $name = $tenantInfo.displayName }
        $domain = $tenantInfo.defaultDomainName
        Start-Sleep -Milliseconds 200
    }
    catch { Write-Warning ('Tenant information for {0} could not be resolved: {1}' -f $partner.tenantId, $_.Exception.Message) }
    $configurations += [PSCustomObject]@{ Name = $name; Domain = $domain; Source = $partner; File = ('Partner_{0}.json' -f $partner.tenantId) }
}
Write-Progress -Activity 'Resolving partner tenants' -Completed

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($configuration in $configurations) {
    $source = $configuration.Source
    $syncAllowed = $null
    if ($IncludeIdentitySync -and -not [string]::IsNullOrEmpty($source.tenantId)) {
        # A 404 here simply means no cross-tenant synchronization is configured for the partner.
        try {
            $sync = Invoke-MgGraphRequest -Method GET -Uri ('{0}/partners/{1}/identitySynchronization' -f $policyUri, $source.tenantId) -OutputType PSObject -ErrorAction Stop
            $syncAllowed = [bool]$sync.userSyncInbound.isSyncAllowed
        }
        catch { $syncAllowed = $false; Write-Verbose ('No identity synchronization configuration for {0}: {1}' -f $configuration.Name, $_.Exception.Message) }
    }
    if (-not [string]::IsNullOrWhiteSpace($ExportJsonFolder)) {
        try { $source | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path -Path $ExportJsonFolder -ChildPath $configuration.File) -Encoding UTF8 }
        catch { Write-Warning ('Configuration "{0}" could not be saved as JSON: {1}' -f $configuration.Name, $_.Exception.Message) }
    }
    $rows.Add([PSCustomObject]@{
        Partner                     = $configuration.Name
        TenantId                    = $source.tenantId
        Domain                      = $configuration.Domain
        InboundB2BCollab            = Format-AccessSetting -Setting $source.b2bCollaborationInbound
        OutboundB2BCollab           = Format-AccessSetting -Setting $source.b2bCollaborationOutbound
        InboundDirectConnect        = Format-AccessSetting -Setting $source.b2bDirectConnectInbound
        OutboundDirectConnect       = Format-AccessSetting -Setting $source.b2bDirectConnectOutbound
        InboundTrustMfa             = Get-ValueOrDefault -Value $source.inboundTrust.isMfaAccepted
        InboundTrustCompliantDevice = Get-ValueOrDefault -Value $source.inboundTrust.isCompliantDeviceAccepted
        InboundTrustHybridJoined    = Get-ValueOrDefault -Value $source.inboundTrust.isHybridAzureADJoinedDeviceAccepted
        AutoConsentInbound          = Get-ValueOrDefault -Value $source.automaticUserConsentSettings.inboundAllowed
        AutoConsentOutbound         = Get-ValueOrDefault -Value $source.automaticUserConsentSettings.outboundAllowed
        IsServiceProvider           = $source.isServiceProvider
        IsInMultiTenantOrganization = $source.isInMultiTenantOrganization
        InboundUserSyncAllowed      = $syncAllowed
    })
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host 'Cross-tenant access policy summary' -ForegroundColor Cyan
foreach ($row in $rows) {
    Write-Host ('  {0,-40} in: {1,-45} trust MFA: {2}' -f $row.Partner, $row.InboundB2BCollab, $row.InboundTrustMfa)
}
Write-Host ('  Partner configurations : {0} -> {1}' -f $partners.Count, $OutputPath)
$trusting = @($rows | Where-Object { $_.InboundTrustMfa -eq $true -or $_.InboundTrustCompliantDevice -eq $true })
if ($trusting.Count -gt 0) { Write-Host ('  Configurations trusting partner MFA or device claims: {0}' -f $trusting.Count) -ForegroundColor Yellow }
$directConnect = @($rows | Where-Object { $_.InboundDirectConnect -like 'users: allowed*' })
if ($directConnect.Count -gt 0) { Write-Host ('  Configurations allowing inbound B2B direct connect: {0}' -f $directConnect.Count) -ForegroundColor Yellow }

if ($PassThru) { $rows }
#endregion Main
