<#
.SYNOPSIS
    Reviews the tenant's user consent, app registration and admin consent workflow settings and exports pending consent requests.
.DESCRIPTION
    Reads the authorization policy (GET /policies/authorizationPolicy) to determine the user consent mode from the assigned
    permission grant policies, whether users can consent to risky apps, register applications, create security groups and read
    other users, and whether group owners can consent. Reads the admin consent workflow (GET /policies/adminConsentRequestPolicy)
    with its reviewers resolved to names, and lists the consent requests users submitted (GET /identityGovernance/appConsent/
    appConsentRequests). Settings with recommendations go to the main CSV, the requests to a second CSV suffixed _PendingRequests.
.PARAMETER OutputPath
    Path of the settings CSV. Defaults to .\Reports\EntraConsentSettings_yyyyMMdd-HHmm.csv; the requests are written next to it.
.PARAMETER PassThru
    Also emits the settings objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraConsentSettingsAndRequests.ps1
    Prints the consent settings with recommendations and writes the settings and the consent requests to the default CSV files.
.EXAMPLE
    PS> .\Get-EntraConsentSettingsAndRequests.ps1 -OutputPath C:\Temp\ConsentSettings.csv -PassThru | Where-Object { $_.Recommendation -ne 'OK' }
    Saves both reports under C:\Temp and shows only the settings that deserve attention.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Policy.Read.All, ConsentRequest.Read.All, User.Read.All (delegated)
    Category    : Applications & consent
    Changes     : No
    Notes       : The consent request list is empty when the admin consent workflow has never been enabled. The requests CSV contains
                  every request with its status (InProgress, Completed, Expired); the summary counts the InProgress ones. Reviewers
                  defined through a role query are shown as the raw query because they resolve to a dynamic set of users.
.LINK
    https://learn.microsoft.com/graph/api/authorizationpolicy-get
.LINK
    https://learn.microsoft.com/graph/api/appconsentapprovalroute-list-appconsentrequests
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

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([Parameter()][object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Add-SettingRow {
    <# Adds one settings row; the recommendation is kept only when -When is true (default), an empty recommendation means OK. #>
    param([string]$Setting, [object]$Value, [string]$Recommendation, [bool]$When = $true)
    if (-not $When -or [string]::IsNullOrEmpty($Recommendation)) { $Recommendation = 'OK' }
    $script:settings.Add([PSCustomObject]@{ Setting = $Setting; Value = [string]$Value; Recommendation = $Recommendation })
}

function Resolve-ReviewerName {
    <# Turns an admin consent reviewer query (/users/{id} or /groups/{id}/...) into a readable name; other queries are returned as-is. #>
    param([string]$Query)
    if ($Query -notmatch '^/(users|groups)/([^/?]+)') { return $Query }
    $collection = $Matches[1]; $objectId = $Matches[2]
    $select = 'displayName'; if ($collection -eq 'users') { $select = 'userPrincipalName' }
    try { $object = Invoke-MgGraphRequest -Method GET -Uri ('{0}/{1}/{2}?$select={3}' -f $script:graphV1, $collection, $objectId, $select) -OutputType PSObject -ErrorAction Stop }
    catch { Write-Warning "Reviewer '$Query' could not be resolved: $($_.Exception.Message)"; return $Query }
    if ($collection -eq 'users') { return $object.userPrincipalName }
    return '{0} (group)' -f $object.displayName
}
#endregion Helpers

#region Main
$script:graphV1 = 'https://graph.microsoft.com/v1.0'
$script:settings = New-Object -TypeName System.Collections.Generic.List[object]
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraConsentSettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$requestsPath = '{0}_PendingRequests.csv' -f [System.IO.Path]::ChangeExtension($OutputPath, $null)

try {
    Connect-GraphIfNeeded -Scopes @('Policy.Read.All', 'ConsentRequest.Read.All', 'User.Read.All')
    Write-Verbose 'Reading the authorization policy and the admin consent request policy.'
    $authorizationPolicy = Invoke-MgGraphRequest -Method GET -Uri "$graphV1/policies/authorizationPolicy" -OutputType PSObject -ErrorAction Stop
    $consentRequestPolicy = Invoke-MgGraphRequest -Method GET -Uri "$graphV1/policies/adminConsentRequestPolicy" -OutputType PSObject -ErrorAction Stop
}
catch { throw "Failed to read the consent policies from Microsoft Graph: $($_.Exception.Message)" }

# The user consent mode is encoded in which ManagePermissionGrantsForSelf policy is assigned to the default user role.
$userPermissions = $authorizationPolicy.defaultUserRolePermissions; $canCreateApps = ($userPermissions.allowedToCreateApps -eq $true)
$grantPolicies = @($userPermissions.permissionGrantPoliciesAssigned | Where-Object { -not [string]::IsNullOrEmpty($_) })
$selfPolicies = @($grantPolicies | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' })
$ownerPolicies = @($grantPolicies | Where-Object { $_ -like 'ManagePermissionGrantsForOwnedResource.*' })
$workflowEnabled = ($consentRequestPolicy.isEnabled -eq $true); $notifyReviewers = ($consentRequestPolicy.notifyReviewers -eq $true)
$riskyConsent = ($authorizationPolicy.allowUserConsentForRiskyApps -eq $true)
$consentMode = 'Disabled (admin consent required for every app)'
$consentAdvice = $null
if ($selfPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') {
    $consentMode = 'AllowAll (users can consent to any app and permission - not recommended)'
    $consentAdvice = 'Restrict user consent to verified publishers and low-impact permissions, or disable it and enable the admin consent workflow.'
}
elseif ($selfPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-low') { $consentMode = 'VerifiedPublishersLowImpact (recommended)' }
elseif ($selfPolicies.Count -gt 0) { $consentMode = 'Custom ({0})' -f ($selfPolicies -join ';') }
elseif (-not $workflowEnabled) { $consentAdvice = 'User consent is disabled and the admin consent workflow is off, so users have no way to request access.' }
Add-SettingRow -Setting 'UserConsentMode' -Value $consentMode -Recommendation $consentAdvice
Add-SettingRow -Setting 'PermissionGrantPoliciesAssigned' -Value ($grantPolicies -join ';')
$ownerValue = 'Disabled'; if ($ownerPolicies.Count -gt 0) { $ownerValue = $ownerPolicies -join ';' }
Add-SettingRow -Setting 'GroupOwnerConsent' -Value $ownerValue -Recommendation 'Group owners can consent for Teams/chat apps; confirm this is intended.' -When ($ownerPolicies.Count -gt 0)
Add-SettingRow -Setting 'AllowUserConsentForRiskyApps' -Value $riskyConsent -Recommendation 'Set to false; risky apps should never get user consent.' -When $riskyConsent
Add-SettingRow -Setting 'UsersCanRegisterApplications' -Value $canCreateApps -Recommendation 'Consider limiting app registration to the Application Developer role.' -When $canCreateApps
Add-SettingRow -Setting 'UsersCanCreateSecurityGroups' -Value $userPermissions.allowedToCreateSecurityGroups
Add-SettingRow -Setting 'UsersCanReadOtherUsers' -Value $userPermissions.allowedToReadOtherUsers

$reviewers = @()
foreach ($reviewer in @($consentRequestPolicy.reviewers)) { if ($null -ne $reviewer) { $reviewers += Resolve-ReviewerName -Query ([string]$reviewer.query) } }
Add-SettingRow -Setting 'AdminConsentWorkflowEnabled' -Value $workflowEnabled -Recommendation 'Enable it so users can request access to apps they cannot consent to.' -When (-not $workflowEnabled)
Add-SettingRow -Setting 'AdminConsentReviewers' -Value ($reviewers -join ';') -Recommendation 'Add at least one reviewer or requests are never seen.' -When ($workflowEnabled -and -not $reviewers)
Add-SettingRow -Setting 'NotifyReviewers' -Value $notifyReviewers -Recommendation 'Enable reviewer notifications so requests do not sit unnoticed.' -When ($workflowEnabled -and -not $notifyReviewers)
Add-SettingRow -Setting 'RemindersEnabled' -Value $consentRequestPolicy.remindersEnabled
Add-SettingRow -Setting 'RequestDurationInDays' -Value $consentRequestPolicy.requestDurationInDays

$requestRows = New-Object -TypeName System.Collections.Generic.List[object]
try {
    foreach ($request in @(Invoke-GraphPaged -Uri "$graphV1/identityGovernance/appConsent/appConsentRequests?`$expand=userConsentRequests")) {
        foreach ($userRequest in @($request.userConsentRequests | Where-Object { $null -ne $_ })) {
            $requester = $userRequest.createdBy.user.displayName
            if ([string]::IsNullOrEmpty($requester)) { $requester = $userRequest.createdBy.user.id }
            $requestRows.Add([PSCustomObject]@{
                AppDisplayName  = $request.appDisplayName
                AppId           = $request.appId
                PendingScopes   = (@($request.pendingScopes | ForEach-Object { $_.displayName }) -join ' ')
                Requester       = $requester
                Reason          = $userRequest.reason
                Status          = $userRequest.status
                CreatedDateTime = ConvertTo-UtcDateTime -Value $userRequest.createdDateTime
            })
        }
    }
}
catch { Write-Warning "Consent requests could not be read (the list exists only after the admin consent workflow was enabled): $($_.Exception.Message)" }
$pendingCount = @($requestRows | Where-Object { $_.Status -eq 'InProgress' }).Count
Add-SettingRow -Setting 'PendingConsentRequests' -Value $pendingCount -Recommendation 'Approve or deny the pending requests before they expire.' -When ($pendingCount -gt 0)

$settings | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($requestRows.Count -gt 0) { $requestRows | Sort-Object -Property Status, CreatedDateTime | Export-Csv -Path $requestsPath -NoTypeInformation -Encoding UTF8 }
Write-Host 'Consent settings' -ForegroundColor Cyan
foreach ($setting in $settings) {
    $colour = 'Green'; if ($setting.Recommendation -ne 'OK') { $colour = 'Yellow' }
    Write-Host ('  {0,-32}: {1}' -f $setting.Setting, $setting.Value) -ForegroundColor $colour
    if ($setting.Recommendation -ne 'OK') { Write-Host ('  {0,-32}  -> {1}' -f '', $setting.Recommendation) -ForegroundColor Yellow }
}
Write-Host ('  Settings needing attention      : {0}' -f @($settings | Where-Object { $_.Recommendation -ne 'OK' }).Count)
Write-Host ('  Consent requests                : {0} ({1} pending)' -f $requestRows.Count, $pendingCount)
Write-Host ('  Settings report                 : {0}' -f $OutputPath)
if ($requestRows.Count -gt 0) { Write-Host ('  Requests report                 : {0}' -f $requestsPath) }

if ($PassThru) { $settings }
#endregion Main
