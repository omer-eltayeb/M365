<#
.SYNOPSIS
    Reports member accounts with no sign-in for a number of days (or ever) and optionally disables them or revokes their sessions.
.DESCRIPTION
    Lists member users whose last interactive sign-in is older than -DaysInactive with the server-side filter
    GET /users?$filter=signInActivity/lastSignInDateTime le <date>, then confirms client-side that the last non-interactive
    sign-in is also older. Accounts created before the threshold without any sign-in activity are added as NeverSignedIn.
    Guests are excluded and disabled accounts are skipped unless -IncludeDisabled is set. The result is exported to CSV.
    With -DisableAccounts (PATCH /users/{id} accountEnabled=false) and/or -RevokeSessions (POST /users/{id}/revokeSignInSessions)
    the flagged accounts are remediated; both honour -WhatIf / -Confirm and prompt by default.
.PARAMETER DaysInactive
    Days without any interactive or non-interactive sign-in after which a member is reported. Default 90.
.PARAMETER IncludeDisabled
    Also reports accounts that are already disabled; by default only enabled accounts are evaluated.
.PARAMETER DisableAccounts
    Disables every flagged cloud account. Accounts synchronised from on-premises Active Directory are skipped with a warning.
.PARAMETER RevokeSessions
    Invalidates every refresh token and browser session cookie of the flagged accounts, forcing them to authenticate again.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraInactiveUsers_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraInactiveUsers.ps1 -IncludeDisabled -PassThru | Where-Object Status -eq 'NeverSignedIn'
    Reports member accounts without a sign-in in the last 90 days plus older accounts that never signed in, and shows the latter.
.EXAMPLE
    PS> .\Get-EntraInactiveUsers.ps1 -DaysInactive 180 -DisableAccounts -RevokeSessions -WhatIf
    Shows which accounts inactive for 180 days would be disabled and signed out everywhere, without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, AuditLog.Read.All (delegated); User.ReadWrite.All only with -DisableAccounts / -RevokeSessions (User Administrator role).
    Category    : Users & authentication
    Changes     : Optional (-DisableAccounts / -RevokeSessions)
    Notes       : signInActivity requires Microsoft Entra ID P1/P2 and has only been tracked since April 2020, so very old accounts
                  can appear as NeverSignedIn. The never-signed-in check reads every member created before the threshold (slow in
                  large tenants). Service accounts sign in rarely; review the report before disabling anything.
.LINK
    https://learn.microsoft.com/graph/api/user-list
.LINK
    https://learn.microsoft.com/graph/api/user-revokesigninsessions
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [switch]$DisableAccounts,

    [Parameter()]
    [switch]$RevokeSessions,

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
$requiredScopes = @('User.Read.All', 'AuditLog.Read.All')
if ($DisableAccounts -or $RevokeSessions) { $requiredScopes += 'User.ReadWrite.All' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraInactiveUsers_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0'
$now = [datetime]::UtcNow
$threshold = $now.AddDays(-$DaysInactive)
$thresholdIso = $threshold.ToString('yyyy-MM-ddTHH:mm:ssZ')
$select = 'id,displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,createdDateTime,signInActivity'
$candidates = @{}
try {
    # The signInActivity filter cannot be combined with other filter properties, so userType and accountEnabled are checked client-side.
    foreach ($user in (Invoke-GraphPaged -Uri "$v1/users?`$filter=signInActivity/lastSignInDateTime le $thresholdIso&`$select=$select")) { $candidates[$user.id] = $user }
    # Accounts that never signed in carry no signInActivity and never match the filter above, so they are found by creation date.
    $uri = "$v1/users?`$filter=userType eq 'Member' and createdDateTime le $thresholdIso&`$select=$select&`$count=true"
    foreach ($user in (Invoke-GraphPaged -Uri $uri -Headers @{ ConsistencyLevel = 'eventual' })) {
        if ($candidates.ContainsKey($user.id)) { continue }
        if ($null -eq $user.signInActivity.lastSignInDateTime -and $null -eq $user.signInActivity.lastNonInteractiveSignInDateTime) { $candidates[$user.id] = $user }
    }
}
catch { throw "Failed to list users. signInActivity requires Microsoft Entra ID P1/P2 and AuditLog.Read.All. $($_.Exception.Message)" }
Write-Verbose "Evaluating $($candidates.Count) candidate accounts."
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($user in ($candidates.Values | Sort-Object -Property userPrincipalName)) {
    if ($user.userType -eq 'Guest' -or (-not $IncludeDisabled -and -not $user.accountEnabled)) { continue }
    $interactive = ConvertTo-UtcDateTime -Value $user.signInActivity.lastSignInDateTime
    $nonInteractive = ConvertTo-UtcDateTime -Value $user.signInActivity.lastNonInteractiveSignInDateTime
    $lastSeen = $interactive
    if ($null -ne $nonInteractive -and ($null -eq $lastSeen -or $nonInteractive -gt $lastSeen)) { $lastSeen = $nonInteractive }
    # A recent non-interactive sign-in (for example a token refresh) keeps the account active even when the interactive one is old.
    if ($null -ne $lastSeen -and $lastSeen -ge $threshold) { continue }
    $status = 'NeverSignedIn'
    $daysSince = $null
    if ($null -ne $lastSeen) { $status = 'Inactive'; $daysSince = [int][math]::Floor(($now - $lastSeen).TotalDays) }
    $results.Add([PSCustomObject]@{
        DisplayName           = $user.displayName
        UserPrincipalName     = $user.userPrincipalName
        Status                = $status
        AccountEnabled        = [bool]$user.accountEnabled
        OnPremisesSyncEnabled = [bool]$user.onPremisesSyncEnabled
        CreatedDateTime       = ConvertTo-UtcDateTime -Value $user.createdDateTime
        LastSignInDateTime    = $lastSeen
        DaysSinceLastSignIn   = $daysSince
        ActionTaken           = 'None'
        Id                    = $user.id
    })
}
if (($DisableAccounts -or $RevokeSessions) -and $results.Count -gt 0) {
    $processed = 0
    foreach ($row in $results) {
        $processed++
        Write-Progress -Activity 'Remediating inactive accounts' -Status $row.UserPrincipalName -PercentComplete (($processed / $results.Count) * 100)
        $actions = @()
        if ($RevokeSessions -and $PSCmdlet.ShouldProcess($row.UserPrincipalName, 'Revoke all sign-in sessions')) {
            try { Invoke-MgGraphRequest -Method POST -Uri ('{0}/users/{1}/revokeSignInSessions' -f $v1, $row.Id) -ErrorAction Stop | Out-Null; $actions += 'SessionsRevoked' }
            catch { $actions += 'RevokeFailed'; Write-Warning ('Revoking sessions failed for {0}: {1}' -f $row.UserPrincipalName, $_.Exception.Message) }
        }
        if ($DisableAccounts -and -not $row.AccountEnabled) { $actions += 'AlreadyDisabled' }
        elseif ($DisableAccounts -and $row.OnPremisesSyncEnabled) { $actions += 'SkippedSynced'; Write-Warning ('{0} is synced from on-premises AD; disable it there.' -f $row.UserPrincipalName) }
        elseif ($DisableAccounts -and $PSCmdlet.ShouldProcess($row.UserPrincipalName, 'Disable account')) {
            $body = @{ accountEnabled = $false }
            try { Invoke-MgGraphRequest -Method PATCH -Uri ('{0}/users/{1}' -f $v1, $row.Id) -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null; $actions += 'Disabled' }
            catch { $actions += 'DisableFailed'; Write-Warning ('Disabling {0} failed: {1}' -f $row.UserPrincipalName, $_.Exception.Message) }
        }
        if ($actions.Count -gt 0) { $row.ActionTaken = $actions -join '; ' }
        Start-Sleep -Milliseconds 200
    }
    Write-Progress -Activity 'Remediating inactive accounts' -Completed
}
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning ('No member accounts exceeded the {0}-day threshold; no CSV was written.' -f $DaysInactive) }
Write-Host ('Inactive user summary: {0} member accounts without a sign-in since {1:yyyy-MM-dd}' -f $results.Count, $threshold) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Status | Sort-Object -Property Name)) { Write-Host ('  {0,-15}: {1}' -f $group.Name, $group.Count) }
if ($DisableAccounts -or $RevokeSessions) {
    foreach ($group in ($results | Group-Object -Property ActionTaken | Sort-Object -Property Name)) { Write-Host ('  Action {0,-8}: {1}' -f $group.Name, $group.Count) }
}
Write-Host ('  Report         : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
