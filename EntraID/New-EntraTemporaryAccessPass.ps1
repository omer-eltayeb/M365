<#
.SYNOPSIS
    Issues Temporary Access Passes (TAP) for one or more users, within the limits of the tenant's TAP policy.
.DESCRIPTION
    Reads the Temporary Access Pass policy (GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass)
    to make sure the method is enabled and to clamp -LifetimeMinutes to the allowed range (or use the policy default when omitted) and to
    enforce one-time use when the policy requires it. For every user given by -UserPrincipalName or -InputCsv an existing TAP is removed
    first (only one is allowed per user) and a new one is created with POST /users/{upn}/authentication/temporaryAccessPassMethods.
    The pass is returned in the output objects; with -OutputPath it is also written to a CSV, which must be handled as a secret.
    Every user is wrapped in ShouldProcess (-WhatIf / -Confirm).
.PARAMETER UserPrincipalName
    One or more UPNs of the users who receive a TAP.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column (for example new starters on their first day).
.PARAMETER LifetimeMinutes
    Validity of the pass in minutes. Omitted or 0 uses the policy default; values outside the policy minimum/maximum are clamped.
.PARAMETER IsUsableOnce
    Makes the pass usable for a single sign-in only (forced when the tenant policy requires one-time use).
.PARAMETER StartDateTime
    Moment from which the pass becomes valid (local time, converted to UTC). Default is immediately.
.PARAMETER OutputPath
    Optional CSV path for the issued passes. The file contains clear-text credentials; no CSV is written unless this is specified.
.EXAMPLE
    PS> .\New-EntraTemporaryAccessPass.ps1 -UserPrincipalName 'jane.doe@contoso.com' -IsUsableOnce
    Issues a one-time TAP with the policy's default lifetime after confirmation and shows it on screen.
.EXAMPLE
    PS> .\New-EntraTemporaryAccessPass.ps1 -InputCsv C:\Temp\starters.csv -LifetimeMinutes 480 -StartDateTime '2026-10-06 08:00' -OutputPath C:\Secure\taps.csv -Confirm:$false
    Creates eight-hour passes for all new starters that become valid on Monday morning and saves them for the onboarding desk.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : UserAuthenticationMethod.ReadWrite.All, Policy.Read.All (delegated). Authentication Administrator role; Privileged
                  Authentication Administrator for users that hold admin roles.
    Category    : Users & authentication
    Changes     : Yes
    Notes       : The user must be in scope of the TAP policy (includeTargets), otherwise the creation fails. A TAP is a credential:
                  hand it over through a verified channel, never by plain e-mail, and delete any CSV as soon as it has been used.
                  Passes that are not one-time can be reused until they expire; prefer -IsUsableOnce for helpdesk scenarios.
.LINK
    https://learn.microsoft.com/graph/api/authentication-post-temporaryaccesspassmethods
.LINK
    https://learn.microsoft.com/graph/api/resources/temporaryaccesspassauthenticationmethodconfiguration
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Upn')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Upn', Position = 0)]
    [string[]]$UserPrincipalName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [ValidateRange(0, 43200)]
    [int]$LifetimeMinutes = 0,

    [Parameter()]
    [switch]$IsUsableOnce,

    [Parameter()]
    [datetime]$StartDateTime,

    [Parameter()]
    [string]$OutputPath
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
$targets = @($UserPrincipalName)
if ($PSCmdlet.ParameterSetName -eq 'Csv') { $targets = @(Import-Csv -Path $InputCsv | ForEach-Object { ([string]$_.UserPrincipalName).Trim() } | Where-Object { $_ }) }
if ($targets.Count -eq 0) { throw 'No user principal names were provided.' }
try { Connect-GraphIfNeeded -Scopes @('UserAuthenticationMethod.ReadWrite.All', 'Policy.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0'
$policyUri = "$v1/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass"
try { $policy = Invoke-MgGraphRequest -Method GET -Uri $policyUri -OutputType PSObject -ErrorAction Stop }
catch { throw "Unable to read the Temporary Access Pass policy: $($_.Exception.Message)" }
if ($policy.state -ne 'enabled') { throw 'Temporary Access Pass is disabled in this tenant (Microsoft Entra admin center > Protection > Authentication methods > Policies).' }
$lifetime = $LifetimeMinutes
if ($lifetime -le 0) { $lifetime = [int]$policy.defaultLifetimeInMinutes }
$minimum = [int]$policy.minimumLifetimeInMinutes
$maximum = [int]$policy.maximumLifetimeInMinutes
if ($lifetime -lt $minimum -or $lifetime -gt $maximum) {
    $lifetime = [math]::Min([math]::Max($lifetime, $minimum), $maximum)
    Write-Warning "The requested lifetime is outside the policy range ($minimum-$maximum minutes) and was clamped to $lifetime minutes."
}
$usableOnce = [bool]$IsUsableOnce
if ($policy.isUsableOnce -and -not $usableOnce) { Write-Warning 'The tenant policy enforces one-time passes; IsUsableOnce has been set to true.'; $usableOnce = $true }
Write-Verbose ('TAP policy: default {0} min, range {1}-{2} min, one-time enforced {3}.' -f $policy.defaultLifetimeInMinutes, $minimum, $maximum, [bool]$policy.isUsableOnce)

$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($upn in $targets) {
    $processed++
    Write-Progress -Activity 'Issuing Temporary Access Passes' -Status $upn -PercentComplete (($processed / $targets.Count) * 100)
    $tapUri = '{0}/users/{1}/authentication/temporaryAccessPassMethods' -f $v1, ($upn -replace '#', '%23')
    $result = [PSCustomObject]@{ UserPrincipalName = $upn; TemporaryAccessPass = $null; StartDateTime = $null; LifetimeMinutes = $lifetime
        IsUsableOnce = $usableOnce; Result = $null; Error = $null }
    $results.Add($result)
    try { $existing = @(Invoke-GraphPaged -Uri $tapUri) }
    catch { $result.Result = 'Failed'; $result.Error = "Lookup failed: $($_.Exception.Message)"; Write-Warning ('{0}: {1}' -f $upn, $result.Error); continue }
    $action = 'Issue Temporary Access Pass ({0} minutes, one-time use: {1})' -f $lifetime, $usableOnce
    if ($existing.Count -gt 0) { $action += ' and replace the existing pass' }
    if (-not $PSCmdlet.ShouldProcess($upn, $action)) { $result.Result = 'WhatIf'; continue }
    try {
        foreach ($old in $existing) {
            # Only one TAP can exist per user, so the current one has to go before a new pass can be created.
            Write-Warning ('{0} already has a Temporary Access Pass (created {1}, usable {2}); it is being replaced.' -f $upn, $old.createdDateTime, $old.isUsable)
            Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/{1}' -f $tapUri, $old.id) -ErrorAction Stop | Out-Null
        }
        $body = @{ lifetimeInMinutes = $lifetime; isUsableOnce = $usableOnce }
        if ($PSBoundParameters.ContainsKey('StartDateTime')) { $body['startDateTime'] = $StartDateTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
        $tap = Invoke-MgGraphRequest -Method POST -Uri $tapUri -Body $body -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
        $result.TemporaryAccessPass = $tap.temporaryAccessPass
        $result.StartDateTime = ConvertTo-UtcDateTime -Value $tap.startDateTime
        $result.LifetimeMinutes = [int]$tap.lifetimeInMinutes
        $result.IsUsableOnce = [bool]$tap.isUsableOnce
        $result.Result = 'Issued'
    }
    catch {
        $result.Result = 'Failed'
        $result.Error = $_.Exception.Message
        Write-Warning ('{0}: TAP not issued (is the user in scope of the TAP policy?). {1}' -f $upn, $_.Exception.Message)
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Issuing Temporary Access Passes' -Completed

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputFolder = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Warning "$OutputPath contains Temporary Access Passes in clear text. Treat it like a password list: share it only through a secure channel and delete it after use."
}
Write-Host ('Temporary Access Pass summary for {0} user(s): lifetime {1} minutes, one-time use {2}' -f $targets.Count, $lifetime, $usableOnce) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) { Write-Host ('  {0,-8}: {1}' -f $group.Name, $group.Count) }
$results
#endregion Main
