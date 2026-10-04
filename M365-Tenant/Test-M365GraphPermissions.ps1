<#
.SYNOPSIS
    Diagnoses the current Microsoft Graph session: account, scopes, missing permissions for a script, directory roles and probe calls.
.DESCRIPTION
    Reads Get-MgContext (account, delegated or app-only, tenant, granted scopes) and compares it with the scopes you need, given
    directly with -RequiredScopes or extracted from one or more scripts of this repository with -ScriptPath (the "Permissions :"
    header line and every $scopes = @(...) / += '...' assignment are parsed). Lists the signed-in user's active directory roles
    (/me/memberOf/microsoft.graph.directoryRole) and, with -IncludeEligible, the PIM-eligible roles
    (/roleManagement/directory/roleEligibilitySchedules). With -Probe it sends one harmless GET per common workload and reports
    the HTTP outcome. Emits rows (Check, Result, Detail); -ConnectWithMissing reconnects with the missing scopes added.
.PARAMETER RequiredScopes
    Scopes a task needs, for example 'User.Read.All', 'AuditLog.Read.All'.
.PARAMETER ScriptPath
    One or more .ps1 files from this repository whose required scopes are read from the header and the $scopes assignments.
.PARAMETER IncludeEligible
    Also list PIM-eligible directory roles of the signed-in user (requests RoleManagement.Read.Directory).
.PARAMETER Probe
    Send one GET with $top=1 to users, Intune managed devices, security alerts, sign-in logs and usage reports.
.PARAMETER ConnectWithMissing
    Run Connect-MgGraph again with the current scopes plus the missing ones.
.PARAMETER OutputPath
    Optional CSV path for the result rows (nothing is exported when omitted).
.EXAMPLE
    PS> .\Test-M365GraphPermissions.ps1 -Probe
    Shows who is signed in, which scopes the token carries, the user's directory roles and whether the five probe calls succeed.
.EXAMPLE
    PS> .\Test-M365GraphPermissions.ps1 -ScriptPath .\Get-M365TenantHealthScorecard.ps1 -ConnectWithMissing
    Reads the scopes that the scorecard needs, lists the ones the session lacks and reconnects with them added.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Whatever the current session holds (User.Read is requested when no session exists); RoleManagement.Read.Directory
                  with -IncludeEligible. Directory roles need Directory.Read.All or an equivalent scope in the session.
    Category    : User lifecycle & tenant hygiene
    Changes     : No
    Notes       : A scope reported as missing can still be covered by a broader one in the session (Directory.Read.All includes
                  User.Read.All, for example) - the probe calls show the real outcome. Role checks are skipped for app-only
                  sessions because /me does not exist there. Probe results of 403 usually mean a missing scope or Entra role.
.LINK
    https://learn.microsoft.com/powershell/microsoftgraph/authentication-commands
.LINK
    https://learn.microsoft.com/graph/api/rbacapplication-list-roleeligibilityschedules
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$RequiredScopes,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string[]]$ScriptPath,

    [Parameter()]
    [switch]$IncludeEligible,

    [Parameter()]
    [switch]$Probe,

    [Parameter()]
    [switch]$ConnectWithMissing,

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

function Add-Check {
    param([string]$Check, [string]$Result, [string]$Detail = '')
    $script:rows.Add([PSCustomObject]@{ Check = $Check; Result = $Result; Detail = $Detail })
}

function Get-ScriptScope {
    <# Extracts Graph scope names from a repository script: the Permissions header and every $scopes = @(...) or += '...' assignment. #>
    param([string]$Path)
    $text = Get-Content -Path $Path -Raw
    $found = New-Object -TypeName System.Collections.Generic.List[string]
    $scopeToken = '\b[A-Z][A-Za-z]*(?:-[A-Za-z]+)?(?:\.[A-Za-z]+)+\b'
    if ($text -match '(?ms)^\s*Permissions\s*:\s*(.+?)(?=^\s{4}\w+\s*:|^\.\w+)') {
        foreach ($match in [regex]::Matches($Matches[1], $scopeToken)) { $found.Add($match.Value) }
    }
    foreach ($block in [regex]::Matches($text, '(?s)(?:-Scopes|\$\w*[sS]copes\s*\+?=)\s*@\((.*?)\)')) {
        foreach ($match in [regex]::Matches($block.Groups[1].Value, $scopeToken)) { $found.Add($match.Value) }
    }
    foreach ($match in [regex]::Matches($text, '\$\w*[sS]copes\s*\+=\s*''(' + $scopeToken + ')''')) { $found.Add($match.Groups[1].Value) }
    return @($found | Select-Object -Unique)
}

function Get-HttpOutcome {
    <# Turns an Invoke-MgGraphRequest exception into a short status text such as '403 Forbidden'. #>
    param([string]$Message)
    if ($Message -match 'Forbidden|Authorization_RequestDenied|\b403\b') { return '403 Forbidden' }
    if ($Message -match 'Unauthorized|InvalidAuthenticationToken|\b401\b') { return '401 Unauthorized' }
    if ($Message -match 'NotFound|\b404\b') { return '404 NotFound' }
    if ($Message -match 'BadRequest|\b400\b') { return '400 BadRequest' }
    return 'Error'
}
#endregion Helpers

#region Main
$script:rows = New-Object -TypeName System.Collections.Generic.List[object]
$required = New-Object -TypeName System.Collections.Generic.List[string]
foreach ($scope in @($RequiredScopes)) { if (-not [string]::IsNullOrWhiteSpace($scope)) { $required.Add($scope.Trim()) } }
foreach ($path in @($ScriptPath)) {
    $parsed = Get-ScriptScope -Path $path
    Add-Check -Check "Scopes in $(Split-Path -Path $path -Leaf)" -Result $parsed.Count -Detail ($parsed -join ', ')
    foreach ($scope in $parsed) { $required.Add($scope) }
}
$required = @($required | Select-Object -Unique)

$context = Get-MgContext
if ($null -eq $context) {
    $initialScopes = @('User.Read') + $(if ($IncludeEligible) { @('RoleManagement.Read.Directory') } else { @() }) + $(if ($ConnectWithMissing) { $required } else { @() })
    try { Connect-GraphIfNeeded -Scopes @($initialScopes | Select-Object -Unique) } catch { throw "Could not connect to Microsoft Graph: $($_.Exception.Message)" }
    $context = Get-MgContext
}
elseif ($IncludeEligible -and $context.AuthType -ne 'AppOnly' -and $context.Scopes -notcontains 'RoleManagement.Read.Directory') {
    Write-Warning 'RoleManagement.Read.Directory is not in the session; eligible roles may show NoAccess (use -ConnectWithMissing -RequiredScopes RoleManagement.Read.Directory).'
}
$graphBase = 'https://graph.microsoft.com/v1.0'
$appOnly = $context.AuthType -eq 'AppOnly'
Add-Check -Check 'Account' -Result $(if ($appOnly) { $context.AppName } else { $context.Account }) -Detail "ClientId $($context.ClientId)"
Add-Check -Check 'Authentication' -Result $context.AuthType -Detail "TokenCredentialType $($context.TokenCredentialType); ContextScope $($context.ContextScope)"
Add-Check -Check 'Tenant' -Result $context.TenantId -Detail "Environment $($context.Environment)"
Add-Check -Check 'Granted scopes' -Result @($context.Scopes).Count -Detail (@($context.Scopes | Sort-Object) -join ', ')

$missing = @($required | Where-Object { $context.Scopes -notcontains $_ })
if ($required.Count -gt 0) {
    Add-Check -Check 'Required scopes' -Result $required.Count -Detail ($required -join ', ')
    $note = if ($missing.Count -eq 0) { 'All required scopes are present' } else { ($missing -join ', ') + ' (a broader scope in the session may still cover them)' }
    Add-Check -Check 'Missing scopes' -Result $(if ($missing.Count -eq 0) { 'OK' } else { "Missing $($missing.Count)" }) -Detail $note
}
if ($ConnectWithMissing -and $missing.Count -gt 0) {
    if ($appOnly) { Write-Warning 'App-only sessions cannot request extra scopes interactively; grant the application permissions instead.' }
    else {
        Connect-MgGraph -Scopes @(@($context.Scopes) + $missing | Select-Object -Unique) -NoWelcome -ErrorAction Stop | Out-Null
        $context = Get-MgContext
        $stillMissing = @($required | Where-Object { $context.Scopes -notcontains $_ })
        $reconnectResult = if ($stillMissing.Count -eq 0) { 'OK' } else { "Missing $($stillMissing.Count)" }
        Add-Check -Check 'Reconnected' -Result $reconnectResult -Detail "Session now holds $(@($context.Scopes).Count) scopes; not granted: $($stillMissing -join ', ')"
    }
}

if ($appOnly) { Add-Check -Check 'Directory roles' -Result 'Skipped' -Detail 'Not applicable to app-only sessions (/me is unavailable)' }
else {
    try {
        $roles = @(Invoke-GraphPaged -Uri "$graphBase/me/memberOf/microsoft.graph.directoryRole?`$select=displayName" | ForEach-Object { $_.displayName } | Sort-Object)
        Add-Check -Check 'Directory roles (active)' -Result $roles.Count -Detail $(if ($roles.Count -gt 0) { $roles -join ', ' } else { 'No active directory role' })
    }
    catch { Add-Check -Check 'Directory roles (active)' -Result (Get-HttpOutcome -Message $_.Exception.Message) -Detail $_.Exception.Message }
    if ($IncludeEligible) {
        try {
            $meId = (Invoke-MgGraphRequest -Method GET -Uri "$graphBase/me?`$select=id" -OutputType PSObject).id
            $eligibleUri = "$graphBase/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$meId'&`$expand=roleDefinition(`$select=displayName)"
            $eligible = @(Invoke-GraphPaged -Uri $eligibleUri | ForEach-Object { $_.roleDefinition.displayName } | Sort-Object -Unique)
            Add-Check -Check 'Directory roles (PIM eligible)' -Result $eligible.Count -Detail $(if ($eligible.Count -gt 0) { $eligible -join ', ' } else { 'No eligible assignment' })
        }
        catch { Add-Check -Check 'Directory roles (PIM eligible)' -Result (Get-HttpOutcome -Message $_.Exception.Message) -Detail $_.Exception.Message }
    }
}

if ($Probe) {
    $probes = @(
        @{ Name = 'Users'; Uri = "$graphBase/users?`$top=1&`$select=id"; Needs = 'User.Read.All or Directory.Read.All' }
        @{ Name = 'Intune managed devices'; Uri = "$graphBase/deviceManagement/managedDevices?`$top=1&`$select=id"; Needs = 'DeviceManagementManagedDevices.Read.All' }
        @{ Name = 'Security alerts'; Uri = "$graphBase/security/alerts_v2?`$top=1&`$select=id"; Needs = 'SecurityAlert.Read.All' }
        @{ Name = 'Sign-in logs'; Uri = "$graphBase/auditLogs/signIns?`$top=1"; Needs = 'AuditLog.Read.All and Entra ID P1' }
        @{ Name = 'Usage reports'; Uri = "$graphBase/reports/getOffice365ActiveUserCounts(period='D7')"; Needs = 'Reports.Read.All'; Csv = $true }
    )
    $tempCsv = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('GraphProbe_{0}.csv' -f [guid]::NewGuid())
    foreach ($item in $probes) {
        try {
            # Report endpoints answer with a CSV redirect, so they are downloaded to a temp file instead of being parsed as JSON.
            if ($item.Csv) { Invoke-MgGraphRequest -Method GET -Uri $item.Uri -OutputFilePath $tempCsv -ErrorAction Stop }
            else { Invoke-MgGraphRequest -Method GET -Uri $item.Uri -ErrorAction Stop | Out-Null }
            Add-Check -Check "Probe: $($item.Name)" -Result '200 OK' -Detail $item.Needs
        }
        catch { Add-Check -Check "Probe: $($item.Name)" -Result (Get-HttpOutcome -Message $_.Exception.Message) -Detail "Needs $($item.Needs)" }
        finally { if (Test-Path -Path $tempCsv) { Remove-Item -Path $tempCsv -Force -ErrorAction SilentlyContinue } }
    }
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputFolder = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) { New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null }
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
if ($missing.Count -gt 0) { Write-Host "Missing scopes: $($missing -join ', ')" -ForegroundColor Yellow }
$rows
#endregion Main
