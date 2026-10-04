<#
.SYNOPSIS
    Validates Microsoft Entra emergency access (break-glass) accounts against Microsoft's recommended configuration.
.DESCRIPTION
    Finds the emergency access accounts (by -UserPrincipalName or by -NamePattern over GET /users) and runs one Pass/Fail/Warning
    check per account: AccountEnabled, CloudOnly, PasswordAge, PasswordNeverExpires, ExcludedFromAllCaPolicies (every enabled policy in
    GET /identity/conditionalAccess/policies excludes the user directly, via a transitive group or via a role), GlobalAdministratorActive
    (GET /roleManagement/directory/roleAssignments), AuthenticationMethods (GET /users/{id}/authentication/methods) and RecentSignIns
    (GET /auditLogs/signIns, last 30 days). Writes one CSV row per account and check and prints the results per account.
.PARAMETER UserPrincipalName
    One or more UPNs of the emergency access accounts. When omitted, accounts are discovered with -NamePattern.
.PARAMETER NamePattern
    Wildcard patterns matched against UPN and display name to discover the accounts. Default '*breakglass*', '*emergency*'.
.PARAMETER AllowOldPassword
    Do not warn when the password is older than 365 days (for accounts protected by FIDO2 keys with a long, vaulted password).
.PARAMETER ExpectFido2
    Fail the AuthenticationMethods check when no FIDO2 key is registered; otherwise it only warns when no phishing-resistant method exists.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraBreakGlassCheck_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the check result objects to the pipeline.
.EXAMPLE
    PS> .\Test-EntraBreakGlassAccounts.ps1
    Discovers accounts whose UPN or display name contains 'breakglass' or 'emergency' and prints every check per account.
.EXAMPLE
    PS> .\Test-EntraBreakGlassAccounts.ps1 -UserPrincipalName bg-admin01@contoso.onmicrosoft.com, bg-admin02@contoso.onmicrosoft.com -ExpectFido2
    Validates two named accounts and fails the authentication check unless a FIDO2 key is registered.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, Policy.Read.All, RoleManagement.Read.Directory, UserAuthenticationMethod.Read.All, AuditLog.Read.All,
                  GroupMember.Read.All (delegated).
    Category    : Sign-ins, audit & risk
    Changes     : No
    Notes       : Follows Microsoft's emergency access guidance: cloud-only, permanently active Global Administrator, excluded from every
                  Conditional Access policy, phishing-resistant authentication, no routine sign-ins. GlobalAdministratorActive checks direct
                  active assignments only. -NamePattern enumerates all users (prefer -UserPrincipalName in very large tenants).
.LINK
    https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$UserPrincipalName,

    [Parameter()]
    [string[]]$NamePattern = @('*breakglass*', '*emergency*'),

    [Parameter()]
    [switch]$AllowOldPassword,

    [Parameter()]
    [switch]$ExpectFido2,

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

function New-CheckResult {
    <# Builds one Pass/Fail/Warning row for an account check. #>
    param([object]$Account, [string]$Check, [string]$Status, [string]$Detail)
    return [PSCustomObject]@{ UserPrincipalName = $Account.userPrincipalName; DisplayName = $Account.displayName; Check = $Check; Status = $Status; Detail = $Detail }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraBreakGlassCheck_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('User.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'UserAuthenticationMethod.Read.All', 'AuditLog.Read.All', 'GroupMember.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$v1 = 'https://graph.microsoft.com/v1.0'
$select = 'id,userPrincipalName,displayName,accountEnabled,onPremisesSyncEnabled,lastPasswordChangeDateTime,passwordPolicies'
$accounts = @()
if ($PSBoundParameters.ContainsKey('UserPrincipalName')) {
    foreach ($upn in $UserPrincipalName) {
        try { $accounts += Invoke-MgGraphRequest -Method GET -Uri ('{0}/users/{1}?$select={2}' -f $v1, [uri]::EscapeDataString($upn), $select) -OutputType PSObject -ErrorAction Stop }
        catch { Write-Warning "User $upn could not be read: $($_.Exception.Message)" }
    }
}
else {
    try { $allUsers = Invoke-GraphPaged -Uri ('{0}/users?$select={1}&$top=999' -f $v1, $select) }
    catch { throw "Failed to enumerate users: $($_.Exception.Message)" }
    $accounts = @($allUsers | Where-Object { $user = $_; @($NamePattern | Where-Object { $user.userPrincipalName -like $_ -or $user.displayName -like $_ }).Count -gt 0 })
}
if ($accounts.Count -eq 0) { throw 'No emergency access accounts were found. Pass -UserPrincipalName or adjust -NamePattern.' }
try { $caPolicies = @(Invoke-GraphPaged -Uri ('{0}/identity/conditionalAccess/policies?$select=id,displayName,state,conditions' -f $v1) | Where-Object { $_.state -eq 'enabled' }) }
catch { throw "Failed to read Conditional Access policies: $($_.Exception.Message)" }

$gaRoleId = '62e90394-69f5-4237-9190-012177145e10'
$phishingResistant = @('fido2AuthenticationMethod', 'windowsHelloForBusinessAuthenticationMethod', 'x509CertificateAuthenticationMethod', 'platformCredentialAuthenticationMethod')
$since = [datetime]::UtcNow.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($account in $accounts) {
    Write-Progress -Activity 'Testing emergency access accounts' -Status $account.userPrincipalName
    $status = 'Fail'; if ($account.accountEnabled -eq $true) { $status = 'Pass' }
    $results.Add((New-CheckResult -Account $account -Check 'AccountEnabled' -Status $status -Detail ('accountEnabled = {0}' -f $account.accountEnabled)))
    $status = 'Pass'; if ($account.onPremisesSyncEnabled -eq $true) { $status = 'Fail' }
    $results.Add((New-CheckResult -Account $account -Check 'CloudOnly' -Status $status -Detail 'Must not be synchronised from on-premises AD (an on-premises outage or compromise must not affect it)'))
    $status = 'Warning'; $detail = 'lastPasswordChangeDateTime is not available'
    if ($null -ne $account.lastPasswordChangeDateTime) {
        $passwordAgeDays = [int]([datetime]::UtcNow - ([datetime]$account.lastPasswordChangeDateTime).ToUniversalTime()).TotalDays
        $status = 'Pass'; $detail = 'Password last changed {0} days ago' -f $passwordAgeDays
        if ($passwordAgeDays -gt 365 -and -not $AllowOldPassword) { $status = 'Warning'; $detail += ' (older than 365 days: rotate it or pass -AllowOldPassword)' }
    }
    $results.Add((New-CheckResult -Account $account -Check 'PasswordAge' -Status $status -Detail $detail))
    $status = 'Warning'; if (([string]$account.passwordPolicies) -like '*DisablePasswordExpiration*') { $status = 'Pass' }
    $results.Add((New-CheckResult -Account $account -Check 'PasswordNeverExpires' -Status $status -Detail ('passwordPolicies = {0}' -f $account.passwordPolicies)))
    # Exclusions can be direct, through any transitive group membership or through a role the account holds.
    try { $groupIds = @(Invoke-GraphPaged -Uri ('{0}/users/{1}/transitiveMemberOf/microsoft.graph.group?$select=id' -f $v1, $account.id) | Select-Object -ExpandProperty id) }
    catch { Write-Warning "Group membership of $($account.userPrincipalName) could not be read: $($_.Exception.Message)"; $groupIds = @() }
    try { $roleIds = @(Invoke-GraphPaged -Uri ('{0}/roleManagement/directory/roleAssignments?$filter=principalId eq ''{1}''' -f $v1, $account.id) | Select-Object -ExpandProperty roleDefinitionId) }
    catch { Write-Warning "Role assignments of $($account.userPrincipalName) could not be read: $($_.Exception.Message)"; $roleIds = @() }
    $notExcluded = @($caPolicies | Where-Object {
        $users = $_.conditions.users
        $byGroup = @($users.excludeGroups | Where-Object { $groupIds -contains $_ }).Count -gt 0
        $byRole = @($users.excludeRoles | Where-Object { $roleIds -contains $_ }).Count -gt 0
        -not ($users.excludeUsers -contains $account.id -or $byGroup -or $byRole)
    })
    $status = 'Pass'; $detail = 'Excluded from all {0} enabled policies' -f $caPolicies.Count
    if ($notExcluded.Count -gt 0) { $status = 'Fail'; $detail = 'Not excluded from: ' + (@($notExcluded | Select-Object -ExpandProperty displayName) -join '; ') }
    $results.Add((New-CheckResult -Account $account -Check 'ExcludedFromAllCaPolicies' -Status $status -Detail $detail))
    $status = 'Fail'; if ($roleIds -contains $gaRoleId) { $status = 'Pass' }
    $results.Add((New-CheckResult -Account $account -Check 'GlobalAdministratorActive' -Status $status -Detail ('{0} active role assignment(s); GA must be permanent' -f $roleIds.Count)))
    try { $methods = @(Invoke-GraphPaged -Uri ('{0}/users/{1}/authentication/methods' -f $v1, $account.id) | ForEach-Object { ([string]$_.'@odata.type') -replace '^#microsoft\.graph\.', '' }) }
    catch { Write-Warning "Authentication methods of $($account.userPrincipalName) could not be read: $($_.Exception.Message)"; $methods = @() }
    $status = 'Pass'
    if ($ExpectFido2 -and $methods -notcontains 'fido2AuthenticationMethod') { $status = 'Fail' }
    elseif (@($methods | Where-Object { $phishingResistant -contains $_ }).Count -eq 0) { $status = 'Warning' }
    $results.Add((New-CheckResult -Account $account -Check 'AuthenticationMethods' -Status $status -Detail ('Registered: {0}' -f (@($methods | Sort-Object -Unique) -join ', '))))
    try { $signIns = @(Invoke-GraphPaged -Uri ('{0}/auditLogs/signIns?$filter=userId eq ''{1}'' and createdDateTime ge {2}' -f $v1, $account.id, $since)) }
    catch { Write-Warning "Sign-ins of $($account.userPrincipalName) could not be read: $($_.Exception.Message)"; $signIns = @() }
    $status = 'Pass'; $detail = 'No sign-ins in the last 30 days'
    if ($signIns.Count -gt 0) {
        $status = 'Warning'
        $detail = '{0} sign-in(s) in 30 days, latest {1:u} from {2}; confirm planned tests' -f $signIns.Count, ([datetime]$signIns[0].createdDateTime).ToUniversalTime(), $signIns[0].ipAddress
    }
    $results.Add((New-CheckResult -Account $account -Check 'RecentSignIns' -Status $status -Detail $detail))
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Testing emergency access accounts' -Completed
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
foreach ($account in $accounts) {
    $accountRows = @($results | Where-Object { $_.UserPrincipalName -eq $account.userPrincipalName })
    $colour = 'Green'
    if (@($accountRows | Where-Object { $_.Status -eq 'Fail' }).Count -gt 0) { $colour = 'Red' } elseif (@($accountRows | Where-Object { $_.Status -eq 'Warning' }).Count -gt 0) { $colour = 'Yellow' }
    Write-Host ('{0} ({1})' -f $account.userPrincipalName, $account.displayName) -ForegroundColor $colour
    foreach ($row in $accountRows) { Write-Host ('  {0,-8} {1,-26} {2}' -f $row.Status, $row.Check, $row.Detail) }
}
$failTotal = @($results | Where-Object { $_.Status -eq 'Fail' }).Count
Write-Host ('Break-glass check: {0} account(s), {1} check(s) failed -> {2}' -f $accounts.Count, $failTotal, $OutputPath) -ForegroundColor Cyan
if ($PassThru) { $results }
#endregion Main
