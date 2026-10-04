<#
.SYNOPSIS
    Reports the registered authentication methods (Authenticator, phone, FIDO2, Windows Hello, TAP, etc.) of users and flags password-only accounts.
.DESCRIPTION
    Resolves the target users from -UserPrincipalName, the members of -GroupName or every enabled member user (-All), then reads
    GET /users/{id}/authentication/methods for each of them. The @odata.type of every method becomes a MethodType plus a readable
    Detail (Authenticator device name/tag/app version, phone type and masked number, FIDO2 model, Windows Hello key strength, e-mail
    address, TAP lifetime, platform credential). One row per method is exported to CSV; users with only a password are flagged PasswordOnly.
.PARAMETER UserPrincipalName
    One or more UPNs to report on.
.PARAMETER GroupName
    Display name of a group; the methods of all its direct user members are reported.
.PARAMETER All
    Reports every enabled member user in the tenant. One Graph call per user, so this takes a while in large tenants.
.PARAMETER ShowPhoneNumbers
    Shows full phone numbers; by default all digits except the last three are masked.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraUserAuthMethods_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraUserAuthenticationMethods.ps1 -UserPrincipalName 'jane.doe@contoso.com' -PassThru | Format-Table MethodType, Detail, CreatedDateTime
    Shows what Jane has registered, for example before resetting her MFA.
.EXAMPLE
    PS> .\Get-EntraUserAuthenticationMethods.ps1 -All -PassThru | Where-Object PasswordOnly | Select-Object -Unique UserPrincipalName
    Exports the methods of every enabled user and lists those who have not registered any second factor yet.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : UserAuthenticationMethod.Read.All, User.Read.All (delegated); GroupMember.Read.All with -GroupName. Authentication Administrator role.
    Category    : Users & authentication
    Changes     : No
    Notes       : Reading the methods of admin accounts needs Privileged Authentication Administrator. Phone numbers are personal data;
                  keep unmasked exports only as long as needed. For a tenant-wide overview without per-user calls use Get-EntraMFARegistrationReport.ps1.
.LINK
    https://learn.microsoft.com/graph/api/authentication-list-methods
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(DefaultParameterSetName = 'Upn')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Upn', Position = 0)]
    [string[]]$UserPrincipalName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Group')]
    [string]$GroupName,

    [Parameter(Mandatory = $true, ParameterSetName = 'All')]
    [switch]$All,

    [Parameter()]
    [switch]$ShowPhoneNumbers,

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

function Get-MethodDetail {
    <# Builds a one-line description from the type-specific properties of an authentication method. #>
    param([object]$Method, [string]$Type)
    switch ($Type) {
        'microsoftAuthenticator' { return ('{0} (device tag {1}, app {2})' -f $Method.displayName, $Method.deviceTag, $Method.phoneAppVersion) }
        'phone' {
            $number = [string]$Method.phoneNumber
            if (-not $ShowPhoneNumbers) { $number = $number -replace '\d(?=\d{3})', 'x' }
            return ('{0}: {1}, SMS sign-in {2}' -f $Method.phoneType, $number, $Method.smsSignInState)
        }
        'fido2' { return ('{0} ({1}, attestation {2})' -f $Method.displayName, $Method.model, $Method.attestationLevel) }
        'windowsHelloForBusiness' { return ('{0} (key strength {1})' -f $Method.displayName, $Method.keyStrength) }
        'email' { return [string]$Method.emailAddress }
        'softwareOath' { return 'Software OATH token' }
        'temporaryAccessPass' { return ('Lifetime {0} min, usable {1}, one-time {2}' -f $Method.lifetimeInMinutes, $Method.isUsable, $Method.isUsableOnce) }
        'password' { return 'Password' }
        'platformCredential' { return ('{0} ({1}, key strength {2})' -f $Method.displayName, $Method.platform, $Method.keyStrength) }
        default { return $Type }
    }
}
#endregion Helpers

#region Main
$requiredScopes = @('UserAuthenticationMethod.Read.All', 'User.Read.All')
if ($PSCmdlet.ParameterSetName -eq 'Group') { $requiredScopes += 'GroupMember.Read.All' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraUserAuthMethods_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0'
$userSelect = 'id,displayName,userPrincipalName'
$users = New-Object -TypeName System.Collections.Generic.List[object]
try {
    switch ($PSCmdlet.ParameterSetName) {
        'Upn' {
            foreach ($upn in $UserPrincipalName) {
                try { $users.Add((Invoke-MgGraphRequest -Method GET -Uri "$v1/users/$($upn.Trim() -replace '#', '%23')?`$select=$userSelect" -OutputType PSObject -ErrorAction Stop)) }
                catch { Write-Warning ('{0}: {1}' -f $upn, $_.Exception.Message) }
            }
        }
        'Group' {
            $groups = @(Invoke-GraphPaged -Uri ("{0}/groups?`$filter=displayName eq '{1}'&`$select=id" -f $v1, ($GroupName -replace "'", "''")))
            if ($groups.Count -ne 1) { throw "Group '$GroupName' matched $($groups.Count) groups; use a unique display name." }
            foreach ($member in (Invoke-GraphPaged -Uri "$v1/groups/$($groups[0].id)/members/microsoft.graph.user?`$select=$userSelect&`$top=999")) { $users.Add($member) }
        }
        'All' {
            Write-Warning 'Reading the methods of every enabled member user needs one Graph call per user; expect several minutes in large tenants.'
            $uri = "$v1/users?`$filter=userType eq 'Member' and accountEnabled eq true&`$select=$userSelect&`$count=true&`$top=999"
            foreach ($member in (Invoke-GraphPaged -Uri $uri -Headers @{ ConsistencyLevel = 'eventual' })) { $users.Add($member) }
        }
    }
}
catch { throw "Failed to resolve the target users: $($_.Exception.Message)" }
if ($users.Count -eq 0) { throw 'No users to report on were found.' }
$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($user in $users) {
    $processed++
    Write-Progress -Activity 'Reading authentication methods' -Status $user.userPrincipalName -PercentComplete (($processed / $users.Count) * 100)
    try { $methods = @(Invoke-GraphPaged -Uri "$v1/users/$($user.id)/authentication/methods") }
    catch { Write-Warning ('{0}: could not read the methods. {1}' -f $user.userPrincipalName, $_.Exception.Message); continue }
    $passwordOnly = ($methods.Count -gt 0 -and @($methods | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' }).Count -eq 0)
    foreach ($method in $methods) {
        $type = ([string]$method.'@odata.type') -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''
        $results.Add([PSCustomObject]@{
            UserPrincipalName = $user.userPrincipalName
            DisplayName       = $user.displayName
            MethodType        = $type.Substring(0, 1).ToUpperInvariant() + $type.Substring(1)
            Detail            = Get-MethodDetail -Method $method -Type $type
            CreatedDateTime   = ConvertTo-UtcDateTime -Value $method.createdDateTime
            MethodId          = $method.id
            PasswordOnly      = $passwordOnly
        })
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading authentication methods' -Completed
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No authentication methods were returned; no CSV was written.' }

Write-Host ('Authentication method summary for {0} user(s)' -f $users.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property MethodType | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-24}: {1}' -f $group.Name, $group.Count)
}
Write-Host ('  Password-only users     : {0}' -f @($results | Where-Object { $_.PasswordOnly } | Select-Object -ExpandProperty UserPrincipalName -Unique).Count) -ForegroundColor Yellow
Write-Host ('  Report                  : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
