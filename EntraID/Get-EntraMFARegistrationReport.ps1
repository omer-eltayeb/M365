<#
.SYNOPSIS
    Reports the MFA, passwordless and SSPR registration posture of users in Microsoft Entra ID.
.DESCRIPTION
    Reads the authentication methods registration report through Microsoft Graph
    (GET /reports/authenticationMethods/userRegistrationDetails) and returns one row per user with the
    MFA, passwordless and SSPR registration state, the default MFA method and every registered method.
    Members are reported by default; guests can be added with -IncludeGuests. The result is exported to
    CSV and a console summary shows the MFA registration percentage, the passwordless-capable percentage
    and lists every administrator who has not registered MFA.
.PARAMETER OnlyNotRegistered
    Returns only users who are not registered for MFA. The summary percentages are still calculated over
    every user retrieved, so the posture numbers stay meaningful.
.PARAMETER AdminsOnly
    Returns only users who hold at least one Microsoft Entra administrator role (isAdmin = true).
.PARAMETER IncludeGuests
    Includes guest users. By default only users with userType 'member' are reported.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraMFARegistration_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraMFARegistrationReport.ps1
    Exports the registration state of all member users to .\Reports and prints the posture summary.
.EXAMPLE
    PS> .\Get-EntraMFARegistrationReport.ps1 -AdminsOnly -OnlyNotRegistered -OutputPath C:\Temp\AdminsWithoutMFA.csv -Verbose
    Lists administrators who have not registered MFA and saves them to the given CSV.
.EXAMPLE
    PS> .\Get-EntraMFARegistrationReport.ps1 -IncludeGuests -PassThru | Where-Object { -not $_.IsPasswordlessCapable }
    Includes guests and pipes the users that are not yet passwordless capable to the console.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AuditLog.Read.All, UserAuthenticationMethod.Read.All (delegated) plus the Reports Reader,
                  Security Reader or Global Reader role.
    Category    : Users & authentication
    Changes     : No
    Notes       : The registration report requires Microsoft Entra ID P1 or P2. Microsoft refreshes the report
                  data periodically, so registrations made in the last few hours may not be visible yet.
.LINK
    https://learn.microsoft.com/graph/api/authenticationmethodsroot-list-userregistrationdetails
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$OnlyNotRegistered,

    [Parameter()]
    [switch]$AdminsOnly,

    [Parameter()]
    [switch]$IncludeGuests,

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
$requiredScopes = @('AuditLog.Read.All', 'UserAuthenticationMethod.Read.All')

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraMFARegistration_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

# userType and isAdmin are filtered server-side to keep the download small. -OnlyNotRegistered is applied
# client-side so the summary percentages describe the whole population that was retrieved.
$filterParts = New-Object -TypeName System.Collections.Generic.List[string]
if (-not $IncludeGuests) { $filterParts.Add("userType eq 'member'") }
if ($AdminsOnly) { $filterParts.Add('isAdmin eq true') }

$uri = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails'
if ($filterParts.Count -gt 0) {
    $uri = '{0}?$filter={1}' -f $uri, ($filterParts -join ' and ')
}

Write-Verbose "Requesting $uri"
try {
    $registrations = Invoke-GraphPaged -Uri $uri
}
catch {
    throw "Failed to read the registration report. It requires Microsoft Entra ID P1/P2 and the Reports Reader, Security Reader or Global Reader role. $($_.Exception.Message)"
}
Write-Verbose "Retrieved $($registrations.Count) registration records."

$report = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($entry in $registrations) {
    $processed++
    if ($processed % 250 -eq 0) {
        Write-Progress -Activity 'Shaping registration details' -Status "$processed of $($registrations.Count)" -PercentComplete (($processed / $registrations.Count) * 100)
    }
    $report.Add([PSCustomObject]@{
        UserPrincipalName                            = $entry.userPrincipalName
        UserDisplayName                              = $entry.userDisplayName
        UserType                                     = $entry.userType
        IsAdmin                                      = [bool]$entry.isAdmin
        IsMfaRegistered                              = [bool]$entry.isMfaRegistered
        IsMfaCapable                                 = [bool]$entry.isMfaCapable
        IsPasswordlessCapable                        = [bool]$entry.isPasswordlessCapable
        IsSsprRegistered                             = [bool]$entry.isSsprRegistered
        IsSsprEnabled                                = [bool]$entry.isSsprEnabled
        IsSsprCapable                                = [bool]$entry.isSsprCapable
        IsSystemPreferredAuthenticationMethodEnabled = [bool]$entry.isSystemPreferredAuthenticationMethodEnabled
        SystemPreferredAuthenticationMethods         = (@($entry.systemPreferredAuthenticationMethods) -join ';')
        DefaultMfaMethod                             = $entry.defaultMfaMethod
        MethodsRegistered                            = (@($entry.methodsRegistered) -join ';')
        LastUpdatedDateTime                          = ConvertTo-UtcDateTime -Value $entry.lastUpdatedDateTime
    })
}
Write-Progress -Activity 'Shaping registration details' -Completed

# Posture numbers are calculated before -OnlyNotRegistered narrows the output.
$total = $report.Count
$mfaRegisteredCount = @($report | Where-Object { $_.IsMfaRegistered }).Count
$passwordlessCount = @($report | Where-Object { $_.IsPasswordlessCapable }).Count
$adminsWithoutMfa = @($report | Where-Object { $_.IsAdmin -and -not $_.IsMfaRegistered })
$mfaPercent = 0
$passwordlessPercent = 0
if ($total -gt 0) {
    $mfaPercent = [math]::Round(($mfaRegisteredCount / $total) * 100, 1)
    $passwordlessPercent = [math]::Round(($passwordlessCount / $total) * 100, 1)
}

$output = @($report)
if ($OnlyNotRegistered) {
    $output = @($report | Where-Object { -not $_.IsMfaRegistered })
}

if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No users matched the selected filters; no CSV was written.'
}

$adminColour = 'Green'
if ($adminsWithoutMfa.Count -gt 0) { $adminColour = 'Red' }
Write-Host ''
Write-Host 'MFA registration summary' -ForegroundColor Cyan
Write-Host ('  Users evaluated      : {0}' -f $total)
Write-Host ('  MFA registered       : {0} ({1}%)' -f $mfaRegisteredCount, $mfaPercent) -ForegroundColor Green
Write-Host ('  Passwordless capable : {0} ({1}%)' -f $passwordlessCount, $passwordlessPercent) -ForegroundColor Green
Write-Host ('  Admins without MFA   : {0}' -f $adminsWithoutMfa.Count) -ForegroundColor $adminColour
Write-Host ('  Rows exported        : {0} -> {1}' -f $output.Count, $OutputPath)

if ($adminsWithoutMfa.Count -gt 0) {
    $adminList = ($adminsWithoutMfa | Select-Object -ExpandProperty UserPrincipalName) -join ', '
    Write-Warning ('{0} administrator account(s) are not registered for MFA: {1}' -f $adminsWithoutMfa.Count, $adminList)
}

if ($PassThru) {
    $output
}
#endregion Main
