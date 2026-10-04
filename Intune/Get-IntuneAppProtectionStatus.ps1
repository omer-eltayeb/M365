<#
.SYNOPSIS
    Reports the app protection (MAM) status of every managed app registration: user, app, device, last sync, flags and policy gaps.
.DESCRIPTION
    Lists the managed app registrations created when users sign in to Intune-protected apps (Microsoft Graph beta
    /deviceAppManagement/managedAppRegistrations expanded with appliedPolicies and intendedPolicies, or /users/{id}/managedAppRegistrations
    for one user). Each row shows the user (userId resolved to UPN once per user), app identifier, platform, device, SDK and OS versions,
    last check-in, flagged reasons (for example a rooted device), applied and intended policies, and a PolicyGap column (intended, not applied).
.PARAMETER UserPrincipalName
    Report the registrations of a single user instead of the whole tenant.
.PARAMETER OnlyFlagged
    Return only registrations with at least one flagged reason.
.PARAMETER StaleDays
    Return only registrations whose last check-in is older than this many days (or that never checked in).
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneAppProtectionStatus_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneAppProtectionStatus.ps1
    Exports every managed app registration in the tenant and prints counts of flagged and policy-gap registrations.
.EXAMPLE
    PS> .\Get-IntuneAppProtectionStatus.ps1 -UserPrincipalName user@contoso.com -PassThru | Format-Table AppIdentifier, DeviceName, LastSync, PolicyGap
    Shows which protected apps one user has registered, when they last checked in and whether policies are still pending.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementApps.Read.All and User.ReadBasic.All (delegated) plus an Intune RBAC role with "Managed apps" read permission.
    Category    : Apps & app protection
    Changes     : No
    Notes       : The registration collection with appliedPolicies/intendedPolicies exists only on the beta endpoint and may change.
                  Registrations are per user, app and device, so one device produces several rows. A policy gap normally clears after
                  the app's next check-in; a persistent gap points to an app never relaunched or a user outside the policy assignment.
.LINK
    https://learn.microsoft.com/graph/api/intune-mam-managedappregistration-list?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [switch]$OnlyFlagged,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleDays,

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

$script:upnCache = @{}
function Get-CachedUserPrincipalName {
    <# Resolves a user object id to its UPN once and caches it; deleted users are reported as '<deleted user>'. #>
    param([string]$UserId)
    if ([string]::IsNullOrEmpty($UserId)) { return $null }
    if (-not $script:upnCache.ContainsKey($UserId)) {
        $uri = 'https://graph.microsoft.com/v1.0/users/{0}?$select=userPrincipalName' -f $UserId
        try { $script:upnCache[$UserId] = [string](Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop).userPrincipalName }
        catch {
            if ($_.Exception.Message -match 'Request_ResourceNotFound|does not exist') { $script:upnCache[$UserId] = '<deleted user>' }
            else { $script:upnCache[$UserId] = $UserId; Write-Warning ('Could not resolve user {0}: {1}' -f $UserId, $_.Exception.Message) }
        }
        Start-Sleep -Milliseconds 200
    }
    return $script:upnCache[$UserId]
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneAppProtectionStatus_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementApps.Read.All', 'User.ReadBasic.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

# beta: managedAppRegistrations with appliedPolicies/intendedPolicies is not exposed on v1.0.
$uri = 'https://graph.microsoft.com/beta/deviceAppManagement/managedAppRegistrations?$expand=appliedPolicies,intendedPolicies'
if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $userUri = 'https://graph.microsoft.com/v1.0/users/{0}?$select=id,userPrincipalName' -f [uri]::EscapeDataString($UserPrincipalName)
    try { $user = Invoke-MgGraphRequest -Method GET -Uri $userUri -OutputType PSObject -ErrorAction Stop }
    catch { throw "User '$UserPrincipalName' could not be resolved: $($_.Exception.Message)" }
    $script:upnCache[[string]$user.id] = [string]$user.userPrincipalName
    $uri = 'https://graph.microsoft.com/beta/users/{0}/managedAppRegistrations?$expand=appliedPolicies,intendedPolicies' -f $user.id
}
try { $registrations = @(Invoke-GraphPaged -Uri $uri) }
catch { throw "Failed to list managed app registrations: $($_.Exception.Message)" }

$nowUtc = (Get-Date).ToUniversalTime(); $staleBefore = $null
if ($PSBoundParameters.ContainsKey('StaleDays')) { $staleBefore = $nowUtc.AddDays(-$StaleDays) }
$rows = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($registration in $registrations) {
    $index++
    if ($index % 50 -eq 0) {
        Write-Progress -Activity 'Processing managed app registrations' -Status ('{0} of {1}' -f $index, $registrations.Count) -PercentComplete ([int](($index / $registrations.Count) * 100))
    }
    $lastSync = $null
    if ($registration.lastSyncDateTime) { $lastSync = ([datetime]$registration.lastSyncDateTime).ToUniversalTime(); if ($lastSync.Year -le 1) { $lastSync = $null } }
    # 'none' is a real enum value for a healthy device, so it is dropped rather than reported as a flag.
    $flags = @($registration.flaggedReasons | Where-Object { $_ -and $_ -ne 'none' })
    if ($OnlyFlagged -and $flags.Count -eq 0) { continue }
    if ($null -ne $staleBefore -and $null -ne $lastSync -and $lastSync -gt $staleBefore) { continue }

    $applied = @($registration.appliedPolicies)
    $intended = @($registration.intendedPolicies)
    $appliedIds = @($applied | ForEach-Object { [string]$_.id })
    $gap = @($intended | Where-Object { $appliedIds -notcontains [string]$_.id } | ForEach-Object { $_.displayName })
    $identifier = $registration.appIdentifier
    $appId = $null
    if ($null -ne $identifier) { $appId = @($identifier.bundleId, $identifier.packageId, $identifier.windowsAppId) | Where-Object { $_ } | Select-Object -First 1 }
    $daysSinceSync = $null
    if ($null -ne $lastSync) { $daysSinceSync = [int]($nowUtc - $lastSync).TotalDays }

    $rows.Add([PSCustomObject]@{
            UserPrincipalName    = Get-CachedUserPrincipalName -UserId ([string]$registration.userId)
            AppIdentifier        = $appId
            Platform             = ([string]$registration.'@odata.type') -replace '^#microsoft\.graph\.', '' -replace 'ManagedAppRegistration$', ''
            DeviceName           = $registration.deviceName
            DeviceType           = $registration.deviceType
            DeviceTag            = $registration.deviceTag
            ManagementSdkVersion = $registration.managementSdkVersion
            PlatformVersion      = $registration.platformVersion
            LastSync             = $lastSync
            DaysSinceSync        = $daysSinceSync
            FlaggedReasons       = ($flags -join '; ')
            AppliedPolicies      = (@($applied | ForEach-Object { $_.displayName }) -join '; ')
            IntendedPolicies     = (@($intended | ForEach-Object { $_.displayName }) -join '; ')
            PolicyGap            = ($gap -join '; ')
            RegistrationId       = $registration.id
        })
}
Write-Progress -Activity 'Processing managed app registrations' -Completed

if ($rows.Count -gt 0) {
    $rows | Sort-Object -Property UserPrincipalName, AppIdentifier | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else { Write-Warning 'No managed app registrations matched the specified criteria.' }

$flaggedCount = @($rows | Where-Object { $_.FlaggedReasons }).Count
$gapCount = @($rows | Where-Object { $_.PolicyGap }).Count
$flaggedColour = 'Green'; if ($flaggedCount -gt 0) { $flaggedColour = 'Red' }
$gapColour = 'Green'; if ($gapCount -gt 0) { $gapColour = 'Yellow' }
Write-Host ("`nRegistrations returned : {0} (of {1} read)" -f $rows.Count, $registrations.Count) -ForegroundColor Cyan
Write-Host ('Flagged devices        : {0}' -f $flaggedCount) -ForegroundColor $flaggedColour
Write-Host ('With policy gap        : {0}' -f $gapCount) -ForegroundColor $gapColour
foreach ($group in ($rows | Group-Object -Property Platform | Sort-Object -Property Name)) { Write-Host ('  {0,-10} {1,6}' -f $group.Name, $group.Count) }

if ($PassThru) { $rows }
#endregion Main
