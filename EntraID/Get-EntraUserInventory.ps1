<#
.SYNOPSIS
    Exports an inventory of Microsoft Entra ID users with licence count, manager, last sign-in and password age.
.DESCRIPTION
    Lists member users (add guests with -IncludeGuests) through Microsoft Graph (GET /users with $select and
    $expand=manager) and adds the number of assigned licences, the manager UPN, the most recent interactive or
    non-interactive sign-in, the days since that sign-in and the age of the current password. Sign-in activity
    needs Microsoft Entra ID P1/P2 plus AuditLog.Read.All; when Graph rejects that property the script warns and
    retries without it so the inventory still completes. -Department, -OnlyDisabled and -OnlyCloud narrow the
    result client-side. The result is exported to CSV and summarised on the console.
.PARAMETER IncludeGuests
    Includes guest accounts. By default only users with userType 'Member' are returned.
.PARAMETER Department
    Returns only users whose department matches this value; wildcards are supported, for example 'Sales*'.
.PARAMETER OnlyDisabled
    Returns only accounts that are disabled (accountEnabled = false).
.PARAMETER OnlyCloud
    Returns only cloud-managed accounts (onPremisesSyncEnabled is not true).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraUserInventory_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraUserInventory.ps1
    Exports every member user with licence count, manager, last sign-in and password age to .\Reports.
.EXAMPLE
    PS> .\Get-EntraUserInventory.ps1 -IncludeGuests -OnlyDisabled -OutputPath C:\Temp\DisabledUsers.csv -Verbose
    Lists disabled members and guests and saves them to the given CSV.
.EXAMPLE
    PS> .\Get-EntraUserInventory.ps1 -Department 'Finance*' -OnlyCloud -PassThru | Where-Object { $_.LicenseCount -eq 0 }
    Shows cloud-only Finance users that have no licence assigned.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, AuditLog.Read.All (delegated). AuditLog.Read.All is only used for the sign-in columns.
    Category    : Users & authentication
    Changes     : No
    Notes       : signInActivity requires Microsoft Entra ID P1 or P2; without it LastSignIn and DaysSinceLastSignIn stay
                  empty. Sign-ins before April 2020 are not tracked. Selecting signInActivity reduces the Graph page
                  size, so very large tenants take a few minutes to enumerate.
.LINK
    https://learn.microsoft.com/graph/api/user-list
.LINK
    https://learn.microsoft.com/graph/api/resources/signinactivity
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeGuests,

    [Parameter()]
    [string]$Department,

    [Parameter()]
    [switch]$OnlyDisabled,

    [Parameter()]
    [switch]$OnlyCloud,

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
    param(
        [Parameter()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}
#endregion Helpers

#region Main
$requiredScopes = @('User.Read.All', 'AuditLog.Read.All')

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraUserInventory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
}
catch {
    throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)"
}

$selectProperties = 'id,displayName,userPrincipalName,mail,userType,accountEnabled,createdDateTime,department,jobTitle,companyName,officeLocation,usageLocation,onPremisesSyncEnabled,lastPasswordChangeDateTime,assignedLicenses'
$queryTail = '&$expand=manager($select=displayName,userPrincipalName)'
if (-not $IncludeGuests) { $queryTail += "&`$filter=userType eq 'Member'" }

# signInActivity needs Entra ID P1/P2 and AuditLog.Read.All. Graph answers 403 or 400 when it cannot serve the property,
# in which case the inventory is retried without it instead of failing completely.
$signInAvailable = $true
Write-Verbose 'Retrieving users with sign-in activity.'
try {
    $users = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/users?`$select=$selectProperties,signInActivity$queryTail"
}
catch {
    if ($_.Exception.Message -notmatch '403|400|Forbidden|BadRequest') { throw "Failed to list users: $($_.Exception.Message)" }
    Write-Warning 'signInActivity is not available (Microsoft Entra ID P1/P2 and AuditLog.Read.All are required); continuing without sign-in data.'
    $signInAvailable = $false
    try {
        $users = Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/users?`$select=$selectProperties$queryTail"
    }
    catch {
        throw "Failed to list users: $($_.Exception.Message)"
    }
}
Write-Verbose "Retrieved $($users.Count) users."

$now = [datetime]::UtcNow
$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($user in $users) {
    $processed++
    if ($processed % 100 -eq 0) {
        Write-Progress -Activity 'Shaping user inventory' -Status "$processed of $($users.Count)" -PercentComplete (($processed / $users.Count) * 100)
    }
    if ($OnlyDisabled -and $user.accountEnabled) { continue }
    if ($OnlyCloud -and $user.onPremisesSyncEnabled -eq $true) { continue }
    if (-not [string]::IsNullOrEmpty($Department) -and $user.department -notlike $Department) { continue }

    $lastSignIn = $null
    if ($signInAvailable -and $null -ne $user.signInActivity) {
        $interactive = ConvertTo-UtcDateTime -Value $user.signInActivity.lastSignInDateTime
        $nonInteractive = ConvertTo-UtcDateTime -Value $user.signInActivity.lastNonInteractiveSignInDateTime
        $lastSignIn = $interactive
        if ($null -ne $nonInteractive -and ($null -eq $lastSignIn -or $nonInteractive -gt $lastSignIn)) { $lastSignIn = $nonInteractive }
    }
    $daysSinceSignIn = $null
    if ($null -ne $lastSignIn) { $daysSinceSignIn = [int][math]::Floor(($now - $lastSignIn).TotalDays) }
    $passwordChanged = ConvertTo-UtcDateTime -Value $user.lastPasswordChangeDateTime
    $passwordAgeDays = $null
    if ($null -ne $passwordChanged) { $passwordAgeDays = [int][math]::Floor(($now - $passwordChanged).TotalDays) }
    $licenseCount = 0
    if ($null -ne $user.assignedLicenses) { $licenseCount = @($user.assignedLicenses).Count }
    $managerUpn = $null
    if ($null -ne $user.manager) { $managerUpn = $user.manager.userPrincipalName }

    $results.Add([PSCustomObject]@{
        DisplayName                = $user.displayName
        UserPrincipalName          = $user.userPrincipalName
        Mail                       = $user.mail
        UserType                   = $user.userType
        AccountEnabled             = [bool]$user.accountEnabled
        Department                 = $user.department
        JobTitle                   = $user.jobTitle
        CompanyName                = $user.companyName
        OfficeLocation             = $user.officeLocation
        UsageLocation              = $user.usageLocation
        ManagerUpn                 = $managerUpn
        LicenseCount               = $licenseCount
        OnPremisesSyncEnabled      = ($user.onPremisesSyncEnabled -eq $true)
        CreatedDateTime            = ConvertTo-UtcDateTime -Value $user.createdDateTime
        LastSignIn                 = $lastSignIn
        DaysSinceLastSignIn        = $daysSinceSignIn
        LastPasswordChangeDateTime = $passwordChanged
        PasswordAgeDays            = $passwordAgeDays
        Id                         = $user.id
    })
}
Write-Progress -Activity 'Shaping user inventory' -Completed

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No users matched the selected filters; no CSV was written.'
}

Write-Host ''
Write-Host 'User inventory summary' -ForegroundColor Cyan
Write-Host ('  Users retrieved  : {0}' -f $users.Count)
Write-Host ('  Users exported   : {0}' -f $results.Count) -ForegroundColor Green
Write-Host ('  Disabled         : {0}' -f @($results | Where-Object { -not $_.AccountEnabled }).Count)
Write-Host ('  Guests           : {0}' -f @($results | Where-Object { $_.UserType -eq 'Guest' }).Count)
Write-Host ('  Unlicensed       : {0}' -f @($results | Where-Object { $_.LicenseCount -eq 0 }).Count)
Write-Host ('  Synced from AD   : {0}' -f @($results | Where-Object { $_.OnPremisesSyncEnabled }).Count)
Write-Host ('  Never signed in  : {0}' -f @($results | Where-Object { $null -eq $_.LastSignIn }).Count) -ForegroundColor Yellow
Write-Host ('  Report           : {0}' -f $OutputPath)

if ($PassThru) {
    $results
}
#endregion Main
