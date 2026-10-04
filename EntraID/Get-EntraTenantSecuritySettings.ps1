<#
.SYNOPSIS
    Takes a snapshot of the tenant-wide Microsoft Entra security settings and highlights settings that deserve attention.
.DESCRIPTION
    Reads security defaults (/policies/identitySecurityDefaultsEnforcementPolicy), the authorization policy (guest access level,
    invitations, self-service sign-up, legacy MSOnline PowerShell, default user permissions, user consent), the authentication
    methods policy, password protection and Microsoft 365 group creation (/groupSettings), the default cross-tenant access policy,
    the device registration policy (beta) and the Conditional Access policy counts. Every setting becomes one row, exported to CSV.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraTenantSecuritySettings_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the setting objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraTenantSecuritySettings.ps1
    Exports the snapshot and prints every setting that has a recommendation.
.EXAMPLE
    PS> .\Get-EntraTenantSecuritySettings.ps1 -PassThru | Where-Object { $_.Recommendation } | Format-Table -AutoSize
    Shows only the settings with a recommendation in the console.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Policy.Read.All, Directory.Read.All (delegated); Global Reader or Security Reader is sufficient.
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : The device registration policy is only available on the beta endpoint and may change. Recommendations are
                  generic hardening hints, not a compliance verdict; each section is read independently, so a failing call only
                  removes its own rows. Password protection shows the service defaults when the setting was never customised.
.LINK
    https://learn.microsoft.com/graph/api/authorizationpolicy-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
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

function Get-GraphObject {
    <# GET of a single resource; a failure is reported as a warning and returns $null so the snapshot continues. #>
    param([string]$Uri, [string]$Name)
    try { return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop }
    catch { Write-Warning ('{0} could not be read: {1}' -f $Name, $_.Exception.Message); return $null }
}

function Add-Setting {
    <# Records one Setting / Value row; the advice becomes the recommendation when the value matches -Bad (wildcards allowed) or -When is true. #>
    param([string]$Area, [string]$Name, [object]$Value, [string]$Bad, [bool]$When = $false, [string]$Advice)
    $recommendation = ''
    if ($When -or (-not [string]::IsNullOrEmpty($Bad) -and [string]$Value -like $Bad)) { $recommendation = $Advice }
    $script:Rows.Add([PSCustomObject]@{ Area = $Area; Setting = $Name; Value = [string]$Value; Recommendation = $recommendation })
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraTenantSecuritySettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('Policy.Read.All', 'Directory.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$script:Rows = New-Object -TypeName System.Collections.Generic.List[object]
$v1 = 'https://graph.microsoft.com/v1.0'

$caPolicies = @()
try { $caPolicies = @(Invoke-GraphPaged -Uri "$v1/identity/conditionalAccess/policies?`$select=id,state") }
catch { Write-Warning "Conditional Access policies could not be read: $($_.Exception.Message)" }
$caEnabled = @($caPolicies | Where-Object { $_.state -eq 'enabled' }).Count
$caReportOnly = @($caPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
$caSummary = '{0} / {1} / {2}' -f $caEnabled, $caReportOnly, ($caPolicies.Count - $caEnabled - $caReportOnly)
Add-Setting -Area 'Baseline' -Name 'Conditional Access policies (enabled / report-only / off)' -Value $caSummary -When ($caReportOnly -gt 0) -Advice 'Enable the report-only policies that are ready'
$securityDefaults = Get-GraphObject -Uri "$v1/policies/identitySecurityDefaultsEnforcementPolicy" -Name 'Security defaults policy'
if ($null -ne $securityDefaults) {
    $unprotected = -not $securityDefaults.isEnabled -and $caEnabled -eq 0
    Add-Setting -Area 'Baseline' -Name 'Security defaults enabled' -Value $securityDefaults.isEnabled -When $unprotected -Advice 'Warning: no security defaults and no Conditional Access policy'
}
$authz = Get-GraphObject -Uri "$v1/policies/authorizationPolicy" -Name 'Authorization policy'
if ($null -ne $authz) {
    $guestRoles = @{ 'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'Same as members'; '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Limited (default)'; '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'Restricted' }
    $guestLevel = $guestRoles[[string]$authz.guestUserRoleId]
    if ([string]::IsNullOrEmpty($guestLevel)) { $guestLevel = [string]$authz.guestUserRoleId }
    $perms = $authz.defaultUserRolePermissions
    $consent = (@($perms.permissionGrantPoliciesAssigned) -join '; ')
    Add-Setting -Area 'Guests' -Name 'Guest user access level' -Value $guestLevel -Bad 'Same as members' -Advice 'Fix: guests see the full directory; use Limited or Restricted access'
    Add-Setting -Area 'Guests' -Name 'Who can invite guests' -Value $authz.allowInvitesFrom -Bad 'everyone' -Advice 'Consider limiting guest invitations to admins and guest inviters'
    Add-Setting -Area 'Sign-up' -Name 'Email-verified users can join the tenant' -Value $authz.allowEmailVerifiedUsersToJoinOrganization -Bad 'True' -Advice 'Consider disabling self-service join'
    Add-Setting -Area 'Sign-up' -Name 'Email-based subscriptions allowed' -Value $authz.allowedToSignUpEmailBasedSubscriptions -Bad 'True' -Advice 'Consider disabling self-service trials'
    Add-Setting -Area 'Legacy' -Name 'MSOnline PowerShell blocked for users' -Value $authz.blockMsolPowerShell -Bad 'False' -Advice 'Consider blocking the legacy MSOnline PowerShell module for users'
    Add-Setting -Area 'User permissions' -Name 'Users can register applications' -Value $perms.allowedToCreateApps -Bad 'True' -Advice 'Consider restricting app registration to admins'
    Add-Setting -Area 'User permissions' -Name 'Users can create security groups' -Value $perms.allowedToCreateSecurityGroups -Bad 'True' -Advice 'Consider restricting security group creation'
    Add-Setting -Area 'User permissions' -Name 'Users can read other users' -Value $perms.allowedToReadOtherUsers
    Add-Setting -Area 'App consent' -Name 'User consent policy' -Value $consent -Bad '*user-default-legacy*' -Advice 'Fix: users can consent to any app; switch to low-impact consent'
}
$authMethods = Get-GraphObject -Uri "$v1/policies/authenticationMethodsPolicy" -Name 'Authentication methods policy'
if ($null -ne $authMethods) {
    foreach ($method in @($authMethods.authenticationMethodConfigurations | Sort-Object -Property id)) {
        $telephony = $method.id -in @('Sms', 'Voice') -and $method.state -eq 'enabled'
        Add-Setting -Area 'Auth methods' -Name ('Method: ' + $method.id) -Value $method.state -When $telephony -Advice 'Consider replacing SMS and voice with Authenticator or passkeys'
    }
    $campaign = $authMethods.registrationEnforcement.authenticationMethodsRegistrationCampaign.state
    Add-Setting -Area 'Auth methods' -Name 'Registration campaign (Authenticator nudge)' -Value $campaign -Bad 'disabled' -Advice 'Consider enabling the registration campaign'
    $migration = [string]$authMethods.policyMigrationState
    Add-Setting -Area 'Auth methods' -Name 'Legacy MFA/SSPR policy migration' -Value $migration -When ($migration -ne 'migrationComplete') -Advice 'Finish the Authentication methods policy migration'
}

$groupSettings = @()
try { $groupSettings = @(Invoke-GraphPaged -Uri "$v1/groupSettings") }
catch { Write-Warning "Group settings (password protection) could not be read: $($_.Exception.Message)" }
# Directory settings are matched by well-known template ids; password protection only exists once saved, so defaults are assumed.
$passwordSetting = $groupSettings | Where-Object { $_.templateId -eq '5cf42378-d67d-4f36-ba46-e8b86229381d' } | Select-Object -First 1
$password = @{ LockoutThreshold = '10 (default)'; LockoutDurationInSeconds = '60 (default)'; EnableBannedPasswordCheckOnPremises = 'False (default)'
    BannedPasswordCheckOnPremisesMode = 'Audit (default)' }
foreach ($value in @($passwordSetting.values)) { $password[[string]$value.name] = [string]$value.value }
$bannedCount = @(([string]$password['BannedPasswordList'] -split "`t") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
$lockout = '{0} / {1}' -f $password['LockoutThreshold'], $password['LockoutDurationInSeconds']
$onPremises = '{0} ({1})' -f $password['EnableBannedPasswordCheckOnPremises'], $password['BannedPasswordCheckOnPremisesMode']
Add-Setting -Area 'Passwords' -Name 'Smart lockout threshold / duration (seconds)' -Value $lockout
Add-Setting -Area 'Passwords' -Name 'Custom banned password list entries' -Value $bannedCount -Bad '0' -Advice 'Consider adding organisation-specific terms to the banned password list'
Add-Setting -Area 'Passwords' -Name 'On-premises password protection (mode)' -Value $onPremises -Bad '*Audit*' -Advice 'Hybrid tenants: enable on-premises password protection in Enforce mode'
$unifiedSetting = $groupSettings | Where-Object { $_.templateId -eq '62375ab9-6b52-47ed-826b-58e47e0e304b' } | Select-Object -First 1
$groupCreation = 'True (default)'
if ($null -ne $unifiedSetting) { $groupCreation = [string]($unifiedSetting.values | Where-Object { $_.name -eq 'EnableGroupCreation' } | Select-Object -First 1).value }
Add-Setting -Area 'User permissions' -Name 'Users can create Microsoft 365 groups' -Value $groupCreation -Bad 'True*' -Advice 'Consider restricting Microsoft 365 group creation to a security group'
$crossTenant = Get-GraphObject -Uri "$v1/policies/crossTenantAccessPolicy/default" -Name 'Default cross-tenant access policy'
if ($null -ne $crossTenant) {
    $inbound = $crossTenant.b2bCollaborationInbound
    $outbound = $crossTenant.b2bCollaborationOutbound
    $directConnect = $crossTenant.b2bDirectConnectInbound.usersAndGroups.accessType
    $trust = $crossTenant.inboundTrust
    $trustText = '{0} / {1} / {2}' -f $trust.isMfaAccepted, $trust.isCompliantDeviceAccepted, $trust.isHybridAzureADJoinedDeviceAccepted
    Add-Setting -Area 'Cross-tenant' -Name 'Default inbound B2B collaboration (users / apps)' -Value ('{0} / {1}' -f $inbound.usersAndGroups.accessType, $inbound.applications.accessType)
    Add-Setting -Area 'Cross-tenant' -Name 'Default outbound B2B collaboration (users / apps)' -Value ('{0} / {1}' -f $outbound.usersAndGroups.accessType, $outbound.applications.accessType)
    Add-Setting -Area 'Cross-tenant' -Name 'Default inbound B2B direct connect (users)' -Value $directConnect -Bad 'allowed' -Advice 'Consider allowing direct connect per partner only'
    Add-Setting -Area 'Cross-tenant' -Name 'Default inbound trust (MFA / compliant / hybrid joined)' -Value $trustText
}
# beta: the device registration policy (join/register permissions, MFA, quota, LAPS) is not exposed on v1.0.
$deviceRegistration = Get-GraphObject -Uri 'https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy' -Name 'Device registration policy (beta)'
if ($null -ne $deviceRegistration) {
    $scopePattern = '^#microsoft\.graph\.(\w+)DeviceRegistrationMembership$'
    $joinScope = ([string]$deviceRegistration.azureADJoin.allowedToJoin.'@odata.type') -replace $scopePattern, '$1'
    $registerScope = ([string]$deviceRegistration.azureADRegistration.allowedToRegister.'@odata.type') -replace $scopePattern, '$1'
    Add-Setting -Area 'Devices' -Name 'Users may join / register devices (all, enumerated, no)' -Value ('{0} / {1}' -f $joinScope, $registerScope)
    Add-Setting -Area 'Devices' -Name 'MFA required to join or register' -Value $deviceRegistration.multiFactorAuthConfiguration -Bad 'notRequired' -Advice 'Consider requiring MFA for registration'
    Add-Setting -Area 'Devices' -Name 'Maximum devices per user' -Value $deviceRegistration.userDeviceQuota
    Add-Setting -Area 'Devices' -Name 'Windows LAPS enabled' -Value $deviceRegistration.localAdminPassword.isEnabled -Bad 'False' -Advice 'Consider enabling Windows LAPS'
}

$script:Rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$flagged = @($script:Rows | Where-Object { -not [string]::IsNullOrEmpty($_.Recommendation) })
Write-Host ('Tenant security settings snapshot: {0} settings -> {1}' -f $script:Rows.Count, $OutputPath) -ForegroundColor Cyan
Write-Host ('  Recommendations: {0}' -f $flagged.Count) -ForegroundColor $(if ($flagged.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in $flagged) { Write-Host ('    {0,-58} {1,-20} {2}' -f $row.Setting, $row.Value, $row.Recommendation) -ForegroundColor Yellow }

if ($PassThru) { $script:Rows }
#endregion Main
