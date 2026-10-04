<#
.SYNOPSIS
    Creates Microsoft Entra ID users in bulk from a CSV file, with optional manager, group memberships and license assignment.
.DESCRIPTION
    Reads a CSV with the columns DisplayName, UserPrincipalName, GivenName, Surname, JobTitle, Department, UsageLocation and the optional
    columns Password, ManagerUpn, Groups (semicolon-separated display names) and LicenseSku (skuPartNumber, e.g. ENTERPRISEPACK). Existing
    UPNs are skipped; the others are created with POST /users (enabled, mailNickname from the UPN prefix, password change at first sign-in
    unless -NoForceChange, 16-character random password when Password is empty), then the manager (PUT /users/{id}/manager/$ref), groups
    (POST /groups/{id}/members/$ref) and license (POST /users/{id}/assignLicense) are applied. ShouldProcess per user; results CSV with passwords.
.PARAMETER InputCsv
    Path of the CSV file. DisplayName and UserPrincipalName are mandatory; all other columns are optional.
.PARAMETER NoForceChange
    Does not force the user to change the password at first sign-in (default is to force the change).
.PARAMETER PasswordOutputPath
    Path of the results CSV that contains the generated passwords. Defaults to .\Reports\EntraNewUsers_yyyyMMdd-HHmm.csv.
.EXAMPLE
    PS> .\New-EntraUsersFromCsv.ps1 -InputCsv C:\Temp\newhires.csv -WhatIf
    Validates the file and shows which users would be created, without creating anything.
.EXAMPLE
    PS> .\New-EntraUsersFromCsv.ps1 -InputCsv C:\Temp\newhires.csv -PasswordOutputPath C:\Secure\newhires-result.csv -Confirm:$false
    Creates every user without prompting, assigns manager, groups and licenses, and writes the results including passwords to the file.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.ReadWrite.All (delegated); Group.ReadWrite.All when Groups is used; Organization.Read.All when LicenseSku is used (User Administrator role).
    Category    : Users & authentication
    Changes     : Yes
    Notes       : The results CSV contains clear-text passwords; store it securely and delete it after onboarding. Dynamic and synced groups are skipped.
.LINK
    https://learn.microsoft.com/graph/api/user-post-users
.LINK
    https://learn.microsoft.com/graph/api/user-assignlicense
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$NoForceChange,

    [Parameter()]
    [string]$PasswordOutputPath
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

function New-RandomPassword {
    <# Returns a 16-character password from a cryptographic RNG containing lower-case, upper-case, digit and symbol characters. #>
    # 64 characters (a power of two) so that 'byte % 64' is unbiased; look-alike characters l, I, O, 0 and 1 are left out.
    $alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object -TypeName byte[] -ArgumentList 16
    do {
        $rng.GetBytes($bytes)
        $password = -join ($bytes | ForEach-Object { $alphabet[$_ % 64] })
    } until ($password -cmatch '[a-z]' -and $password -cmatch '[A-Z]' -and $password -match '\d' -and $password -match '[!@#$%&*]')
    return $password
}

function Get-GraphUserId {
    <# Returns the object id for a UPN via GET /users/{upn}, or $null when the account does not exist (HTTP 404). #>
    param([string]$UserPrincipalName)
    try { return (Invoke-MgGraphRequest -Method GET -Uri ('{0}/users/{1}?$select=id' -f $v1, ($UserPrincipalName -replace '#', '%23')) -OutputType PSObject -ErrorAction Stop).id }
    catch {
        if ($_.Exception.Message -match 'NotFound|Request_ResourceNotFound' -or $_.ErrorDetails.Message -match 'Request_ResourceNotFound') { return $null }
        throw
    }
}
#endregion Helpers

#region Main
$rows = @(Import-Csv -Path $InputCsv)
if ($rows.Count -eq 0) { throw "The file $InputCsv contains no rows." }
foreach ($required in @('DisplayName', 'UserPrincipalName')) { if (@($rows[0].PSObject.Properties.Name) -notcontains $required) { throw "The CSV must contain a '$required' column." } }
$requiredScopes = @('User.ReadWrite.All')
if (@($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Groups) }).Count -gt 0) { $requiredScopes += 'Group.ReadWrite.All' }
if (@($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.LicenseSku) }).Count -gt 0) { $requiredScopes += 'Organization.Read.All' }
if ([string]::IsNullOrWhiteSpace($PasswordOutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $PasswordOutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraNewUsers_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $PasswordOutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0'
$skus = @{}; $groupCache = @{}
if ($requiredScopes -contains 'Organization.Read.All') {
    try { foreach ($sku in (Invoke-GraphPaged -Uri "$v1/subscribedSkus?`$select=skuId,skuPartNumber")) { $skus[$sku.skuPartNumber] = $sku.skuId } }
    catch { throw "Unable to read the tenant's subscribed SKUs: $($_.Exception.Message)" }
}
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($row in $rows) {
    $upn = ([string]$row.UserPrincipalName).Trim()
    $result = [PSCustomObject]@{ DisplayName = $row.DisplayName; UserPrincipalName = $upn; UserId = $null; InitialPassword = $null; Manager = $null
        Groups = $null; License = $null; Result = $null; Error = $null }
    $results.Add($result)
    Write-Progress -Activity 'Creating users' -Status $upn -PercentComplete (($results.Count / $rows.Count) * 100)
    if ($upn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$' -or [string]::IsNullOrWhiteSpace($row.DisplayName)) { $result.Result = 'Skipped (invalid row)'; continue }
    try { $result.UserId = Get-GraphUserId -UserPrincipalName $upn }
    catch { $result.Result = 'Failed'; $result.Error = "Lookup failed: $($_.Exception.Message)"; Write-Warning ('{0}: {1}' -f $upn, $result.Error); continue }
    if ($null -ne $result.UserId) { $result.Result = 'Skipped (already exists)'; continue }
    if (-not $PSCmdlet.ShouldProcess($upn, 'Create user')) { $result.Result = 'WhatIf'; continue }
    $password = [string]$row.Password
    if ([string]::IsNullOrWhiteSpace($password)) { $password = New-RandomPassword; $result.InitialPassword = $password }
    $body = @{ accountEnabled = $true; displayName = ([string]$row.DisplayName).Trim(); userPrincipalName = $upn; mailNickname = $upn.Split('@')[0]
        passwordProfile = @{ password = $password; forceChangePasswordNextSignIn = (-not $NoForceChange) } }
    foreach ($attribute in @('givenName', 'surname', 'jobTitle', 'department', 'usageLocation')) {
        if (-not [string]::IsNullOrWhiteSpace($row.$attribute)) { $body[$attribute] = ([string]$row.$attribute).Trim() }
    }
    try { $created = Invoke-MgGraphRequest -Method POST -Uri "$v1/users" -Body $body -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop; $result.Result = 'Created' }
    catch { $result.Result = 'Failed'; $result.Error = $_.Exception.Message; Write-Warning ('{0}: creation failed. {1}' -f $upn, $_.Exception.Message); continue }
    $result.UserId = $created.id
    $errors = @(); $added = @()
    if (-not [string]::IsNullOrWhiteSpace($row.ManagerUpn)) {
        try {
            $managerId = Get-GraphUserId -UserPrincipalName ([string]$row.ManagerUpn).Trim()
            if ($null -eq $managerId) { throw 'manager account was not found' }
            $reference = @{ '@odata.id' = "$v1/users/$managerId" }
            Invoke-MgGraphRequest -Method PUT -Uri "$v1/users/$($created.id)/manager/`$ref" -Body $reference -ContentType 'application/json' -ErrorAction Stop | Out-Null
            $result.Manager = ([string]$row.ManagerUpn).Trim()
        }
        catch { $errors += "Manager '$($row.ManagerUpn)' not set: $($_.Exception.Message)" }
    }
    foreach ($groupName in @(([string]$row.Groups) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        try {
            if (-not $groupCache.ContainsKey($groupName)) {   # resolve each name once; dynamic and synced groups are excluded because Graph cannot add members to them
                $groupUri = "{0}/groups?`$filter=displayName eq '{1}'&`$select=id,groupTypes,onPremisesSyncEnabled" -f $v1, ($groupName -replace "'", "''")
                $found = @(Invoke-GraphPaged -Uri $groupUri | Where-Object { @($_.groupTypes) -notcontains 'DynamicMembership' -and -not $_.onPremisesSyncEnabled })
                if ($found.Count -eq 1) { $groupCache[$groupName] = $found[0].id } else { $groupCache[$groupName] = $null }
            }
            if ($null -eq $groupCache[$groupName]) { throw 'group not found, ambiguous, dynamic or on-premises synced' }
            $reference = @{ '@odata.id' = "$v1/directoryObjects/$($created.id)" }
            Invoke-MgGraphRequest -Method POST -Uri "$v1/groups/$($groupCache[$groupName])/members/`$ref" -Body $reference -ContentType 'application/json' -ErrorAction Stop | Out-Null
            $added += $groupName
        }
        catch { $errors += "Group '$groupName' not added: $($_.Exception.Message)" }
    }
    $result.Groups = $added -join '; '
    if (-not [string]::IsNullOrWhiteSpace($row.LicenseSku)) {
        $skuName = ([string]$row.LicenseSku).Trim()
        try {
            if (-not $skus.ContainsKey($skuName)) { throw 'not a subscribed SKU (skuPartNumber) of this tenant' }
            if (-not $body.ContainsKey('usageLocation')) { throw 'UsageLocation is required before a license can be assigned' }
            $licenseBody = @{ addLicenses = @(@{ skuId = $skus[$skuName] }); removeLicenses = @() }
            Invoke-MgGraphRequest -Method POST -Uri "$v1/users/$($created.id)/assignLicense" -Body $licenseBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
            $result.License = $skuName
        }
        catch { $errors += "License '$skuName' not assigned: $($_.Exception.Message)" }
    }
    if ($errors.Count -gt 0) { $result.Error = $errors -join ' | '; Write-Warning ('{0}: {1}' -f $upn, $result.Error) }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Creating users' -Completed
$results | Export-Csv -Path $PasswordOutputPath -NoTypeInformation -Encoding UTF8
Write-Host ('User creation summary (results file: {0})' -f $PasswordOutputPath) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) { Write-Host ('  {0,-26}: {1}' -f $group.Name, $group.Count) }
if (@($results | Where-Object { $_.InitialPassword }).Count -gt 0) { Write-Warning "The results file contains generated passwords in clear text. Hand them over securely and delete it afterwards." }
$results | Select-Object -Property * -ExcludeProperty InitialPassword
#endregion Main
