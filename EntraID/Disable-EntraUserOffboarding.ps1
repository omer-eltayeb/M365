<#
.SYNOPSIS
    Offboards user identities: disables the account, revokes sessions, resets the password, removes groups, manager, licenses and MFA methods.
.DESCRIPTION
    Runs the identity part of a leaver process for one or more users (-UserPrincipalName or -InputCsv with a UserPrincipalName column).
    Default steps: Disable (PATCH /users/{id} accountEnabled=false), RevokeSessions (POST /users/{id}/revokeSignInSessions), ResetPassword
    (random password, not stored), RemoveGroups (GET /users/{id}/memberOf/microsoft.graph.group, DELETE /groups/{gid}/members/{uid}/$ref; dynamic,
    synced and Exchange-managed groups are skipped) and ClearManager (DELETE /users/{id}/manager/$ref); any of them can be left out with -Skip.
    -RemoveLicenses (POST /users/{id}/assignLicense) and -RemoveAuthenticationMethods (DELETE every registered method) are opt-in. One result
    object per user and step is emitted; the set of steps per user is wrapped in ShouldProcess (-WhatIf / -Confirm).
.PARAMETER UserPrincipalName
    One or more UPNs of the users to offboard.
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column.
.PARAMETER Skip
    Default steps to leave out: RevokeSessions, ResetPassword, RemoveGroups, ClearManager. The Disable step always runs.
.PARAMETER RemoveLicenses
    Also removes every directly assigned license (group-based licenses must be removed by changing the group membership).
.PARAMETER RemoveAuthenticationMethods
    Also deletes all registered authentication methods (Authenticator, phone, FIDO2, OATH, e-mail, Windows Hello, TAP, platform credential).
.EXAMPLE
    PS> .\Disable-EntraUserOffboarding.ps1 -UserPrincipalName 'leaver@contoso.com' -WhatIf
    Lists every step that would run for the user without changing anything.
.EXAMPLE
    PS> .\Disable-EntraUserOffboarding.ps1 -InputCsv C:\Temp\leavers.csv -RemoveLicenses -RemoveAuthenticationMethods -Skip ClearManager -Confirm:$false
    Offboards everyone in the file without prompting, keeps the manager link for HR reporting, and frees the licenses.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.ReadWrite.All, Group.ReadWrite.All (delegated); UserAuthenticationMethod.ReadWrite.All only with -RemoveAuthenticationMethods. User Administrator role.
    Category    : Users & authentication
    Changes     : Yes
    Notes       : If mail must be retained, convert the mailbox to a shared mailbox in Exchange Online BEFORE removing the license
                  (Set-Mailbox -Type Shared), otherwise it is deleted with the license. Accounts synced from on-premises AD must be disabled
                  and reset in Active Directory (both steps are skipped). Admin accounts need Privileged Authentication Administrator.
.LINK
    https://learn.microsoft.com/graph/api/user-revokesigninsessions
.LINK
    https://learn.microsoft.com/graph/api/group-delete-members
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
    [ValidateSet('RevokeSessions', 'ResetPassword', 'RemoveGroups', 'ClearManager')]
    [string[]]$Skip = @(),

    [Parameter()]
    [switch]$RemoveLicenses,

    [Parameter()]
    [switch]$RemoveAuthenticationMethods
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

function Add-StepResult {
    <# Appends one per-step result row and mirrors failures to the console. #>
    param([string]$Upn, [string]$Step, [string]$Result, [string]$Detail)
    $script:Results.Add([PSCustomObject]@{ UserPrincipalName = $Upn; Step = $Step; Result = $Result; Detail = $Detail })
    if ($Result -eq 'Failed') { Write-Warning ('{0} - {1}: {2}' -f $Upn, $Step, $Detail) }
}

function Invoke-Step {
    <# Runs one step when it is selected and records Success or Failed; a failing step never aborts the remaining steps of the user. #>
    param([string]$Upn, [string]$Step, [scriptblock]$Action)
    if ($script:Steps -notcontains $Step) { return }
    try { $detail = & $Action; Add-StepResult -Upn $Upn -Step $Step -Result 'Success' -Detail ([string]$detail) }
    catch { Add-StepResult -Upn $Upn -Step $Step -Result 'Failed' -Detail $_.Exception.Message }
}
#endregion Helpers

#region Main
$targets = @($UserPrincipalName)
if ($PSCmdlet.ParameterSetName -eq 'Csv') { $targets = @(Import-Csv -Path $InputCsv | ForEach-Object { ([string]$_.UserPrincipalName).Trim() } | Where-Object { $_ }) }
if ($targets.Count -eq 0) { throw 'No user principal names were provided.' }
$script:Steps = @('Disable') + @(@('RevokeSessions', 'ResetPassword', 'RemoveGroups', 'ClearManager') | Where-Object { $Skip -notcontains $_ })
if ($RemoveLicenses) { $script:Steps += 'RemoveLicenses' }
if ($RemoveAuthenticationMethods) { $script:Steps += 'RemoveAuthenticationMethods' }
$requiredScopes = @('User.ReadWrite.All')
if ($script:Steps -contains 'RemoveGroups') { $requiredScopes += 'Group.ReadWrite.All' }
if ($RemoveAuthenticationMethods) { $requiredScopes += 'UserAuthenticationMethod.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0'
$script:Results = New-Object -TypeName System.Collections.Generic.List[object]
$actionText = 'Offboard identity ({0})' -f ($script:Steps -join ', ')
$processed = 0
foreach ($upn in $targets) {
    $processed++
    Write-Progress -Activity 'Offboarding users' -Status $upn -PercentComplete (($processed / $targets.Count) * 100)
    $uri = '{0}/users/{1}?$select=id,accountEnabled,onPremisesSyncEnabled,assignedLicenses' -f $v1, ($upn -replace '#', '%23')
    try { $user = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop }
    catch { Add-StepResult -Upn $upn -Step 'Lookup' -Result 'Failed' -Detail $_.Exception.Message; continue }
    if (-not $PSCmdlet.ShouldProcess($upn, $actionText)) { foreach ($step in $script:Steps) { Add-StepResult -Upn $upn -Step $step -Result 'WhatIf' }; continue }
    $userUri = '{0}/users/{1}' -f $v1, $user.id
    $patchParams = @{ Method = 'PATCH'; Uri = $userUri; ContentType = 'application/json'; ErrorAction = 'Stop' }
    if ($user.onPremisesSyncEnabled) {
        Add-StepResult -Upn $upn -Step 'Disable' -Result 'Skipped' -Detail 'Synced from on-premises AD; disable it in Active Directory'
        if ($script:Steps -contains 'ResetPassword') { Add-StepResult -Upn $upn -Step 'ResetPassword' -Result 'Skipped' -Detail 'Synced from on-premises AD; reset it in Active Directory' }
    }
    else {
        Invoke-Step -Upn $upn -Step 'Disable' -Action { Invoke-MgGraphRequest @patchParams -Body @{ accountEnabled = $false } | Out-Null; 'Account disabled' }
        Invoke-Step -Upn $upn -Step 'ResetPassword' -Action {
            # 24 random bytes (192 bits) as Base64 plus a fixed suffix that satisfies every complexity class; the value is never stored.
            $bytes = New-Object -TypeName byte[] -ArgumentList 24
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
            $passwordBody = @{ passwordProfile = @{ password = ('{0}!Aa1' -f [System.Convert]::ToBase64String($bytes)); forceChangePasswordNextSignIn = $true } }
            Invoke-MgGraphRequest @patchParams -Body $passwordBody | Out-Null
            'Password replaced by a random value'
        }
    }
    Invoke-Step -Upn $upn -Step 'RevokeSessions' -Action { Invoke-MgGraphRequest -Method POST -Uri "$userUri/revokeSignInSessions" -ErrorAction Stop | Out-Null; 'Refresh tokens invalidated' }
    Invoke-Step -Upn $upn -Step 'RemoveGroups' -Action {
        $groups = @(Invoke-GraphPaged -Uri "$userUri/memberOf/microsoft.graph.group?`$select=id,displayName,groupTypes,membershipRule,onPremisesSyncEnabled,mailEnabled")
        $removed = @(); $skipped = @()
        foreach ($group in $groups) {
            # Dynamic, on-premises synced and Exchange-managed (mail-enabled, non-Microsoft 365) groups cannot be changed through Graph.
            $locked = $null -ne $group.membershipRule -or $group.onPremisesSyncEnabled -or ($group.mailEnabled -and @($group.groupTypes) -notcontains 'Unified')
            if ($locked) { $skipped += $group.displayName; continue }
            try { Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/groups/{1}/members/{2}/$ref' -f $v1, $group.id, $user.id) -ErrorAction Stop | Out-Null; $removed += $group.displayName }
            catch { $skipped += ('{0} ({1})' -f $group.displayName, $_.Exception.Message) }
        }
        'Removed {0}: {1}; skipped {2}: {3}' -f $removed.Count, ($removed -join ', '), $skipped.Count, ($skipped -join ', ')
    }
    Invoke-Step -Upn $upn -Step 'ClearManager' -Action {
        try { Invoke-MgGraphRequest -Method DELETE -Uri "$userUri/manager/`$ref" -ErrorAction Stop | Out-Null; 'Manager reference removed' }
        catch { if ($_.Exception.Message -match 'NotFound') { 'No manager was assigned' } else { throw } }
    }
    Invoke-Step -Upn $upn -Step 'RemoveLicenses' -Action {
        $skuIds = @($user.assignedLicenses | ForEach-Object { $_.skuId })
        if ($skuIds.Count -eq 0) { return 'No licenses were assigned' }
        Invoke-MgGraphRequest -Method POST -Uri "$userUri/assignLicense" -Body @{ addLicenses = @(); removeLicenses = $skuIds } -ContentType 'application/json' -ErrorAction Stop | Out-Null
        '{0} license(s) removed' -f $skuIds.Count
    }
    Invoke-Step -Upn $upn -Step 'RemoveAuthenticationMethods' -Action {
        $pending = @(Invoke-GraphPaged -Uri "$userUri/authentication/methods" | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' }); $removed = 0
        # The default sign-in method can only be deleted once the other methods are gone, so failures get a second pass.
        foreach ($pass in 1, 2) {
            $retry = @()
            foreach ($method in $pending) {
                # Every method type has its own collection, e.g. fido2AuthenticationMethod -> fido2Methods.
                $collection = ($method.'@odata.type' -replace '^#microsoft\.graph\.', '') -replace 'AuthenticationMethod$', 'Methods'
                try { Invoke-MgGraphRequest -Method DELETE -Uri "$userUri/authentication/$collection/$($method.id)" -ErrorAction Stop | Out-Null; $removed++ }
                catch { $retry += $method }
            }
            $pending = $retry
        }
        if ($pending.Count -gt 0) { throw ('{0} removed, {1} could not be removed' -f $removed, $pending.Count) }
        '{0} authentication method(s) removed' -f $removed
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Offboarding users' -Completed
Write-Host ('Offboarding summary for {0} user(s): {1}' -f $targets.Count, ($script:Steps -join ', ')) -ForegroundColor Cyan
foreach ($group in ($script:Results | Group-Object -Property Result | Sort-Object -Property Name)) { Write-Host ('  {0,-8}: {1}' -f $group.Name, $group.Count) }
$script:Results
#endregion Main
