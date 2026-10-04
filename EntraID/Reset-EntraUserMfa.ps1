<#
.SYNOPSIS
    Removes all registered MFA / passwordless methods of a user so they must re-register, optionally issuing a Temporary Access Pass.
.DESCRIPTION
    Lists GET /users/{upn}/authentication/methods and deletes every method except the password through its type-specific collection
    (microsoftAuthenticatorMethods, phoneMethods, fido2Methods, softwareOathMethods, emailMethods, windowsHelloForBusinessMethods,
    temporaryAccessPassMethods, platformCredentialMethods). Because the default sign-in method can only be removed after the others,
    failed deletions are retried in a second pass. -KeepFido2 preserves security keys. With -IssueTemporaryAccessPass a one-time TAP
    (POST /users/{upn}/authentication/temporaryAccessPassMethods) is created and printed once so the user can register new methods.
    Every user is wrapped in ShouldProcess (-WhatIf / -Confirm); one result object per method is emitted.
.PARAMETER UserPrincipalName
    One or more UPNs of the users whose methods are reset.
.PARAMETER KeepFido2
    Keeps registered FIDO2 security keys and only removes the other methods.
.PARAMETER IssueTemporaryAccessPass
    Creates a one-time Temporary Access Pass after the reset and prints it to the console (it is not stored anywhere).
.PARAMETER TapLifetimeMinutes
    Lifetime of the Temporary Access Pass in minutes. Default 60; must be within the limits of the tenant's TAP policy.
.EXAMPLE
    PS> .\Reset-EntraUserMfa.ps1 -UserPrincipalName 'jane.doe@contoso.com' -WhatIf
    Shows which methods would be removed for Jane without deleting anything.
.EXAMPLE
    PS> .\Reset-EntraUserMfa.ps1 -UserPrincipalName 'jane.doe@contoso.com' -IssueTemporaryAccessPass -TapLifetimeMinutes 120
    Removes Jane's methods after confirmation (lost phone scenario) and prints a two-hour one-time TAP for her to re-register.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : UserAuthenticationMethod.ReadWrite.All (delegated). Authentication Administrator role; Privileged Authentication
                  Administrator to reset the methods of users that hold admin roles.
    Category    : Users & authentication
    Changes     : Yes
    Notes       : Verify the caller's identity through your helpdesk process before resetting MFA - this is a classic social-engineering
                  target. Issuing a TAP requires the Temporary Access Pass policy to be enabled for the user. If a method still refuses
                  to be deleted, use "Require re-register multifactor authentication" on the user in the Microsoft Entra admin center.
.LINK
    https://learn.microsoft.com/graph/api/authentication-list-methods
.LINK
    https://learn.microsoft.com/graph/api/authentication-post-temporaryaccesspassmethods
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$UserPrincipalName,

    [Parameter()]
    [switch]$KeepFido2,

    [Parameter()]
    [switch]$IssueTemporaryAccessPass,

    [Parameter()]
    [ValidateRange(10, 43200)]
    [int]$TapLifetimeMinutes = 60
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

function Add-ResultRow {
    <# Appends one result row (per method or per action) and mirrors failures to the console. #>
    param([string]$Upn, [string]$MethodType, [string]$MethodId, [string]$Result, [string]$Detail)
    $script:Results.Add([PSCustomObject]@{ UserPrincipalName = $Upn; MethodType = $MethodType; MethodId = $MethodId; Result = $Result; Detail = $Detail })
    if ($Result -eq 'Failed') { Write-Warning ('{0} - {1}: {2}' -f $Upn, $MethodType, $Detail) }
}

function Get-MethodTypeName {
    <# Turns '#microsoft.graph.fido2AuthenticationMethod' into 'fido2'. #>
    param([object]$Method)
    return ([string]$Method.'@odata.type') -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''
}
#endregion Helpers

#region Main
try { Connect-GraphIfNeeded -Scopes @('UserAuthenticationMethod.ReadWrite.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0'
$script:Results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($upn in $UserPrincipalName) {
    $processed++
    $upn = $upn.Trim()
    Write-Progress -Activity 'Resetting authentication methods' -Status $upn -PercentComplete (($processed / $UserPrincipalName.Count) * 100)
    $authPath = '{0}/users/{1}/authentication' -f $v1, ($upn -replace '#', '%23')
    try { $methods = @(Invoke-GraphPaged -Uri "$authPath/methods") }
    catch { Add-ResultRow -Upn $upn -MethodType 'Lookup' -Result 'Failed' -Detail $_.Exception.Message; continue }
    $targets = @($methods | Where-Object { (Get-MethodTypeName -Method $_) -ne 'password' -and -not ($KeepFido2 -and (Get-MethodTypeName -Method $_) -eq 'fido2') })
    $typeList = (@($targets | ForEach-Object { Get-MethodTypeName -Method $_ }) | Sort-Object -Unique) -join ', '
    if ($targets.Count -eq 0) {
        Add-ResultRow -Upn $upn -MethodType 'None' -Result 'Skipped' -Detail 'No removable authentication methods are registered'
    }
    elseif ($PSCmdlet.ShouldProcess($upn, "Remove $($targets.Count) authentication method(s): $typeList")) {
        $pending = $targets
        # The user's default sign-in method can only be deleted once the other methods are gone, so failures get a second pass.
        foreach ($pass in 1, 2) {
            $retry = @()
            foreach ($method in $pending) {
                $type = Get-MethodTypeName -Method $method
                try {
                    Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/{1}Methods/{2}' -f $authPath, $type, $method.id) -ErrorAction Stop | Out-Null
                    Add-ResultRow -Upn $upn -MethodType $type -MethodId $method.id -Result 'Removed' -Detail $method.displayName
                }
                catch {
                    if ($pass -eq 1) { $retry += $method }
                    else { Add-ResultRow -Upn $upn -MethodType $type -MethodId $method.id -Result 'Failed' -Detail $_.Exception.Message }
                }
            }
            $pending = $retry
        }
    }
    else {
        foreach ($method in $targets) { Add-ResultRow -Upn $upn -MethodType (Get-MethodTypeName -Method $method) -MethodId $method.id -Result 'WhatIf' }
    }
    if ($IssueTemporaryAccessPass -and $PSCmdlet.ShouldProcess($upn, "Issue a one-time Temporary Access Pass valid for $TapLifetimeMinutes minutes")) {
        try {
            $body = @{ lifetimeInMinutes = $TapLifetimeMinutes; isUsableOnce = $true }
            $tap = Invoke-MgGraphRequest -Method POST -Uri "$authPath/temporaryAccessPassMethods" -Body $body -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
            Write-Host ('Temporary Access Pass for {0}: {1}' -f $upn, $tap.temporaryAccessPass) -ForegroundColor Yellow
            Write-Host ('  valid {0} minutes from {1} (UTC), one-time use - shown once and not stored anywhere' -f $tap.lifetimeInMinutes, $tap.startDateTime) -ForegroundColor Yellow
            Add-ResultRow -Upn $upn -MethodType 'temporaryAccessPass' -MethodId $tap.id -Result 'Issued' -Detail ('Valid {0} minutes, one-time use' -f $tap.lifetimeInMinutes)
        }
        catch { Add-ResultRow -Upn $upn -MethodType 'temporaryAccessPass' -Result 'Failed' -Detail "TAP not issued (is the TAP policy enabled for this user?): $($_.Exception.Message)" }
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Resetting authentication methods' -Completed

Write-Host ('MFA reset summary for {0} user(s)' -f $UserPrincipalName.Count) -ForegroundColor Cyan
foreach ($group in ($script:Results | Group-Object -Property Result | Sort-Object -Property Name)) { Write-Host ('  {0,-8}: {1}' -f $group.Name, $group.Count) }
$script:Results
#endregion Main
