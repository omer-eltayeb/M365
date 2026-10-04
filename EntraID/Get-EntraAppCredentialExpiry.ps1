<#
.SYNOPSIS
    Reports app registration client secrets and certificates that are expired or expiring soon.
.DESCRIPTION
    Lists every app registration (GET /applications with $select=passwordCredentials,keyCredentials) through
    Microsoft Graph and returns one row per credential with its type, name, key id, validity window, remaining
    days and a status of Expired, ExpiringSoon (within -DaysUntilExpiry) or Valid. With -IncludeOwners the owners
    of each affected app are added (GET /applications/{id}/owners) so the report can be routed to the right team.
    By default only Expired and ExpiringSoon credentials are exported; -IncludeValid adds the healthy ones.
.PARAMETER DaysUntilExpiry
    Credentials expiring within this many days are reported as ExpiringSoon. Default 30.
.PARAMETER IncludeValid
    Also exports credentials that are valid for longer than -DaysUntilExpiry.
.PARAMETER IncludeOwners
    Adds an Owners column (UPN or display name, joined with ';'). One extra Graph call per reported application and
    the additional User.Read.All scope.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraAppCredentialExpiry_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraAppCredentialExpiry.ps1
    Exports all secrets and certificates that are expired or expire within 30 days.
.EXAMPLE
    PS> .\Get-EntraAppCredentialExpiry.ps1 -DaysUntilExpiry 60 -IncludeOwners -OutputPath C:\Temp\AppCredentials.csv -Verbose
    Uses a 60-day window, adds the owners of each application and saves the report to the given CSV.
.EXAMPLE
    PS> .\Get-EntraAppCredentialExpiry.ps1 -IncludeValid -PassThru | Sort-Object -Property DaysRemaining | Select-Object -First 10
    Includes healthy credentials and shows the ten that expire next.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Application.Read.All (delegated); User.Read.All is added with -IncludeOwners so owner names can be
                  read. Any user with the Application Administrator, Cloud Application Administrator, Global Reader
                  or Security Reader role can run it.
    Category    : Applications & consent
    Changes     : No
    Notes       : Only app registrations (application objects) are covered; credentials stored on enterprise apps
                  (service principals) are not included. Secret values are never returned by Graph, only metadata.
                  Owners can be users or service principals; service principals are listed by display name.
.LINK
    https://learn.microsoft.com/graph/api/application-list
.LINK
    https://learn.microsoft.com/graph/api/application-list-owners
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysUntilExpiry = 30,

    [Parameter()]
    [switch]$IncludeValid,

    [Parameter()]
    [switch]$IncludeOwners,

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

function Get-ApplicationOwners {
    <# Returns the owners of an application as 'upn;upn' (display name for non-user owners); empty when there are none. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApplicationObjectId
    )
    $uri = 'https://graph.microsoft.com/v1.0/applications/{0}/owners?$select=id,displayName,userPrincipalName' -f $ApplicationObjectId
    $names = @()
    foreach ($owner in (Invoke-GraphPaged -Uri $uri)) {
        if (-not [string]::IsNullOrEmpty($owner.userPrincipalName)) { $names += $owner.userPrincipalName }
        elseif (-not [string]::IsNullOrEmpty($owner.displayName)) { $names += $owner.displayName }
    }
    Start-Sleep -Milliseconds 200
    return ($names -join ';')
}
#endregion Helpers

#region Main
$requiredScopes = @('Application.Read.All')
# Without a user-read scope Graph returns owner objects with only their id (limited information for inaccessible objects).
if ($IncludeOwners) { $requiredScopes += 'User.Read.All' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraAppCredentialExpiry_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

$uri = 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials,signInAudience&$top=999'
Write-Verbose 'Retrieving app registrations with their credentials.'
try {
    $applications = Invoke-GraphPaged -Uri $uri
}
catch {
    throw "Failed to list app registrations: $($_.Exception.Message)"
}
Write-Verbose "Evaluating credentials of $($applications.Count) app registrations."

$now = [datetime]::UtcNow
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$appsWithoutCredentials = 0
$processed = 0
foreach ($application in $applications) {
    $processed++
    if ($processed % 50 -eq 0) {
        Write-Progress -Activity 'Evaluating application credentials' -Status "$processed of $($applications.Count)" -PercentComplete (($processed / $applications.Count) * 100)
    }
    $credentials = @()
    foreach ($secret in @($application.passwordCredentials)) {
        if ($null -ne $secret) { $credentials += [PSCustomObject]@{ Type = 'Secret'; Source = $secret } }
    }
    foreach ($certificate in @($application.keyCredentials)) {
        if ($null -ne $certificate) { $credentials += [PSCustomObject]@{ Type = 'Certificate'; Source = $certificate } }
    }
    if ($credentials.Count -eq 0) {
        $appsWithoutCredentials++
        continue
    }

    foreach ($credential in $credentials) {
        $source = $credential.Source
        $start = ConvertTo-UtcDateTime -Value $source.startDateTime
        $end = ConvertTo-UtcDateTime -Value $source.endDateTime
        $daysRemaining = $null
        $status = 'Valid'
        if ($null -ne $end) {
            # Floor keeps "expires later today" at 0 days and anything already past as a negative number.
            $daysRemaining = [int][math]::Floor(($end - $now).TotalDays)
            if ($daysRemaining -lt 0) { $status = 'Expired' }
            elseif ($daysRemaining -le $DaysUntilExpiry) { $status = 'ExpiringSoon' }
        }
        if ($status -eq 'Valid' -and -not $IncludeValid) { continue }

        $credentialName = $source.displayName
        if ([string]::IsNullOrEmpty($credentialName) -and -not [string]::IsNullOrEmpty($source.hint)) { $credentialName = 'hint: {0}...' -f $source.hint }

        $rows.Add([PSCustomObject]@{
            AppDisplayName     = $application.displayName
            AppId              = $application.appId
            ObjectId           = $application.id
            SignInAudience     = $application.signInAudience
            CredentialType     = $credential.Type
            CredentialName     = $credentialName
            KeyId              = $source.keyId
            StartDateTime      = $start
            EndDateTime        = $end
            DaysRemaining      = $daysRemaining
            Status             = $status
            Owners             = $null
            AppCreatedDateTime = ConvertTo-UtcDateTime -Value $application.createdDateTime
        })
    }
}
Write-Progress -Activity 'Evaluating application credentials' -Completed

$appsWithoutOwners = @()
if ($IncludeOwners -and $rows.Count -gt 0) {
    # Owners are looked up once per application and copied to every credential row of that app.
    $ownerCache = @{}
    $appIds = @($rows | Select-Object -ExpandProperty ObjectId -Unique)
    $processed = 0
    foreach ($objectId in $appIds) {
        $processed++
        Write-Progress -Activity 'Resolving application owners' -Status "$processed of $($appIds.Count)" -PercentComplete (($processed / $appIds.Count) * 100)
        try {
            $ownerCache[$objectId] = Get-ApplicationOwners -ApplicationObjectId $objectId
        }
        catch {
            $ownerCache[$objectId] = $null
            Write-Warning ('Owners of application {0} could not be read: {1}' -f $objectId, $_.Exception.Message)
        }
    }
    Write-Progress -Activity 'Resolving application owners' -Completed
    foreach ($row in $rows) {
        $row.Owners = $ownerCache[$row.ObjectId]
        if ([string]::IsNullOrEmpty($row.Owners) -and $appsWithoutOwners -notcontains $row.AppDisplayName) { $appsWithoutOwners += $row.AppDisplayName }
    }
}

$sortedRows = @($rows | Sort-Object -Property DaysRemaining, AppDisplayName)
if ($sortedRows.Count -gt 0) {
    $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning ('No credentials are expired or expiring within {0} days; no CSV was written.' -f $DaysUntilExpiry)
}

$expiredCount = @($sortedRows | Where-Object { $_.Status -eq 'Expired' }).Count
$expiringCount = @($sortedRows | Where-Object { $_.Status -eq 'ExpiringSoon' }).Count
$validCount = @($sortedRows | Where-Object { $_.Status -eq 'Valid' }).Count
Write-Host ''
Write-Host 'App credential expiry summary' -ForegroundColor Cyan
Write-Host ('  App registrations scanned : {0} ({1} without any credential)' -f $applications.Count, $appsWithoutCredentials)
Write-Host ('  Expired                   : {0}' -f $expiredCount) -ForegroundColor Red
Write-Host ('  Expiring within {0,3} days  : {1}' -f $DaysUntilExpiry, $expiringCount) -ForegroundColor Yellow
if ($IncludeValid) { Write-Host ('  Valid                     : {0}' -f $validCount) -ForegroundColor Green }
Write-Host ('  Rows exported             : {0} -> {1}' -f $sortedRows.Count, $OutputPath)

if ($appsWithoutOwners.Count -gt 0) {
    Write-Warning ('{0} application(s) in the report have no owner, so nobody will be notified about the renewal: {1}' -f $appsWithoutOwners.Count, ($appsWithoutOwners -join ', '))
}

if ($PassThru) {
    $sortedRows
}
#endregion Main
