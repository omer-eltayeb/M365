<#
.SYNOPSIS
    Reports when cloud user passwords expire, based on the domain password validity period and each user's last password change.
.DESCRIPTION
    Reads the password policy of every verified domain (GET /domains: passwordValidityPeriodInDays, where 2147483647 means never)
    and every enabled member user (GET /users with lastPasswordChangeDateTime, passwordPolicies and onPremisesSyncEnabled). For each
    user the script computes PasswordExpiresOn and DaysUntilExpiry and assigns a Status: NeverExpires (domain policy or the user's
    DisablePasswordExpiration policy), Expired, ExpiringSoon (within -WarnDays), Ok or ManagedOnPremises (synced accounts follow the
    on-premises AD policy). The result is exported to CSV; -ExpiringWithinDays narrows it to passwords that expire within that many days.
.PARAMETER WarnDays
    Number of days before expiry at which a password is reported as ExpiringSoon. Default 14.
.PARAMETER ExpiringWithinDays
    Only report users whose password has expired or expires within this many days.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraPasswordExpiry_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraPasswordExpiryReport.ps1
    Exports the password expiry status of every enabled member user.
.EXAMPLE
    PS> .\Get-EntraPasswordExpiryReport.ps1 -ExpiringWithinDays 7 -PassThru | Sort-Object DaysUntilExpiry
    Lists the users whose password expires in the next 7 days (or has already expired), soonest first, for a reminder campaign.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, Domain.Read.All (delegated)
    Category    : Users & authentication
    Changes     : No
    Notes       : A domain without an explicit policy uses the Microsoft 365 default of 90 days. Password-hash-synced users are
                  reported as ManagedOnPremises unless the EnforceCloudPasswordPolicyForPasswordSyncedUsers feature is enabled, in which
                  case the cloud calculation applies to them too. Guests are not included because they authenticate at their home tenant.
.LINK
    https://learn.microsoft.com/graph/api/domain-list
.LINK
    https://learn.microsoft.com/graph/api/user-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$WarnDays = 14,

    [Parameter()]
    [ValidateRange(0, 3650)]
    [int]$ExpiringWithinDays,

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
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraPasswordExpiry_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('User.Read.All', 'Domain.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0'
$neverExpires = 2147483647

$policies = @{}
$defaultValidity = 90
try {
    foreach ($domain in (Invoke-GraphPaged -Uri "$v1/domains?`$select=id,passwordValidityPeriodInDays,passwordNotificationWindowInDays,isDefault")) {
        # A domain without an explicit policy inherits the Microsoft 365 default of 90 days.
        $validity = 90
        if ($null -ne $domain.passwordValidityPeriodInDays) { $validity = [int]$domain.passwordValidityPeriodInDays }
        $policies[([string]$domain.id).ToLowerInvariant()] = $validity
        if ($domain.isDefault) { $defaultValidity = $validity }
        Write-Verbose ('Domain {0}: validity {1} days, notification window {2} days.' -f $domain.id, $validity, $domain.passwordNotificationWindowInDays)
    }
}
catch { throw "Failed to read the domain password policies: $($_.Exception.Message)" }

$select = 'id,displayName,userPrincipalName,lastPasswordChangeDateTime,passwordPolicies,onPremisesSyncEnabled'
$uri = "$v1/users?`$filter=userType eq 'Member' and accountEnabled eq true&`$select=$select&`$count=true&`$top=999"
try { $users = @(Invoke-GraphPaged -Uri $uri -Headers @{ ConsistencyLevel = 'eventual' }) }
catch { throw "Failed to list users: $($_.Exception.Message)" }
Write-Verbose "Evaluating $($users.Count) enabled member accounts."

$now = [datetime]::UtcNow
$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($user in ($users | Sort-Object -Property userPrincipalName)) {
    $processed++
    if ($processed % 200 -eq 0) { Write-Progress -Activity 'Calculating password expiry' -Status "$processed of $($users.Count)" -PercentComplete (($processed / $users.Count) * 100) }
    $domain = ([string]$user.userPrincipalName).Split('@')[-1].ToLowerInvariant()
    $validity = $defaultValidity
    if ($policies.ContainsKey($domain)) { $validity = $policies[$domain] }
    $lastChange = ConvertTo-UtcDateTime -Value $user.lastPasswordChangeDateTime
    $expiresOn = $null
    $daysUntil = $null
    if ($user.onPremisesSyncEnabled) { $status = 'ManagedOnPremises' }
    elseif ($validity -eq $neverExpires -or ([string]$user.passwordPolicies) -match 'DisablePasswordExpiration') { $status = 'NeverExpires' }
    elseif ($null -eq $lastChange) { $status = 'Unknown' }
    else {
        $expiresOn = $lastChange.AddDays($validity)
        $daysUntil = [int][math]::Floor(($expiresOn - $now).TotalDays)
        if ($daysUntil -lt 0) { $status = 'Expired' } elseif ($daysUntil -le $WarnDays) { $status = 'ExpiringSoon' } else { $status = 'Ok' }
    }
    if ($PSBoundParameters.ContainsKey('ExpiringWithinDays') -and ($null -eq $daysUntil -or $daysUntil -gt $ExpiringWithinDays)) { continue }
    $validityDays = $validity
    if ($validity -eq $neverExpires) { $validityDays = $null }
    $results.Add([PSCustomObject]@{
        DisplayName                = $user.displayName
        UserPrincipalName          = $user.userPrincipalName
        Domain                     = $domain
        Status                     = $status
        LastPasswordChangeDateTime = $lastChange
        PasswordValidityDays       = $validityDays
        PasswordExpiresOn          = $expiresOn
        DaysUntilExpiry            = $daysUntil
        PasswordPolicies           = $user.passwordPolicies
        OnPremisesSyncEnabled      = [bool]$user.onPremisesSyncEnabled
        Id                         = $user.id
    })
}
Write-Progress -Activity 'Calculating password expiry' -Completed

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No users matched the criteria; no CSV was written.' }

Write-Host ''
Write-Host 'Password expiry summary' -ForegroundColor Cyan
Write-Host ('  Enabled member users : {0}' -f $users.Count)
Write-Host ('  Reported             : {0}' -f $results.Count)
foreach ($group in ($results | Group-Object -Property Status | Sort-Object -Property Name)) {
    $colour = 'Gray'
    if ($group.Name -eq 'Expired') { $colour = 'Red' } elseif ($group.Name -eq 'ExpiringSoon') { $colour = 'Yellow' }
    Write-Host ('    {0,-18}: {1}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
Write-Host ('  Report               : {0}' -f $OutputPath)

if ($PassThru) {
    $results
}
#endregion Main
