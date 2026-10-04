<#
.SYNOPSIS
    Groups Microsoft Entra sign-ins per user, country, city and IP address and flags unexpected countries and atypical travel.
.DESCRIPTION
    Reads successful interactive sign-ins (GET /auditLogs/signIns, $top=1000, capped by -MaxRecords; failures too with
    -IncludeFailures) and aggregates them per user + country + city + IP with counts, first/last seen and applications used.
    Countries outside -ExpectedCountries are flagged. Consecutive successful sign-ins of one user from different countries
    within -HoursWindow hours are listed as atypical travel in <base>_AtypicalTravel.csv.
.PARAMETER DaysBack
    Days of history to read (1-30). Default 7. Microsoft Entra ID P1/P2 keeps 30 days of sign-in logs, the Free tier 7 days.
.PARAMETER ExpectedCountries
    ISO 3166-1 alpha-2 codes of the countries your users normally sign in from, for example 'GB','IE','DE'. Anything else is flagged.
.PARAMETER IncludeFailures
    Also aggregate failed sign-ins (adds FailureCount per location). The travel check always uses successful sign-ins only.
.PARAMETER HoursWindow
    Maximum hours between two consecutive sign-ins from different countries to be reported as atypical travel. Default 2.
.PARAMETER MaxRecords
    Maximum number of events to download. Default 10000; a warning is written when the cap is reached.
.PARAMETER OutputPath
    Path of the location CSV. Defaults to .\Reports\EntraSignInsByLocation_yyyyMMdd-HHmm.csv; travel findings get the _AtypicalTravel suffix.
.PARAMETER PassThru
    Also emits the location objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraSignInsByLocation.ps1 -ExpectedCountries 'GB','IE'
    Exports last week's sign-in locations, flags every country other than GB and IE and lists atypical travel within 2 hours.
.EXAMPLE
    PS> .\Get-EntraSignInsByLocation.ps1 -DaysBack 30 -IncludeFailures -HoursWindow 4 -MaxRecords 100000 -PassThru
    Aggregates a full month including failures and widens the travel window to 4 hours.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AuditLog.Read.All (delegated).
    Category    : Sign-ins, audit & risk
    Changes     : No
    Notes       : Retention is 30 days with Microsoft Entra ID P1/P2 and 7 days on the Free tier. Locations come from IP geolocation, so
                  VPNs, cloud proxies and mobile carriers cause false positives. Unexpected is empty without -ExpectedCountries.
.LINK
    https://learn.microsoft.com/graph/api/signin-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$DaysBack = 7,

    [Parameter()]
    [string[]]$ExpectedCountries,

    [Parameter()]
    [switch]$IncludeFailures,

    [Parameter()]
    [ValidateRange(1, 72)]
    [int]$HoursWindow = 2,

    [Parameter()]
    [ValidateRange(1, 1000000)]
    [int]$MaxRecords = 10000,

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

function Invoke-GraphPagedCapped {
    <# Like Invoke-GraphPaged but stops after MaxRecords items and warns when the cap truncated the result. #>
    param([string]$Uri, [int]$MaxRecords)
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    $received = 0
    while (-not [string]::IsNullOrEmpty($nextLink) -and $results.Count -lt $MaxRecords) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject -ErrorAction Stop
        foreach ($item in $response.value) { $received++; if ($results.Count -lt $MaxRecords) { $results.Add($item) } }
        $nextLink = $response.'@odata.nextLink'
        Write-Progress -Activity 'Downloading sign-in events' -Status ('{0} events retrieved' -f $results.Count)
    }
    Write-Progress -Activity 'Downloading sign-in events' -Completed
    if ($received -gt $results.Count -or -not [string]::IsNullOrEmpty($nextLink)) {
        Write-Warning ('MaxRecords ({0}) reached; older events were not downloaded. Narrow the filter or raise -MaxRecords.' -f $MaxRecords)
    }
    return $results
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraSignInsByLocation_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$travelPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_AtypicalTravel.csv')
$expected = @($ExpectedCountries | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToUpperInvariant() })
try { Connect-GraphIfNeeded -Scopes @('AuditLog.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$uri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1000&$filter=createdDateTime ge {0}' -f $since
if (-not $IncludeFailures) { $uri += ' and status/errorCode eq 0' }
try { $signIns = Invoke-GraphPagedCapped -Uri $uri -MaxRecords $MaxRecords }
catch { throw "Failed to read sign-in logs: $($_.Exception.Message)" }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($group in ($signIns | Group-Object -Property { '{0}|{1}|{2}|{3}' -f $_.userPrincipalName, $_.location.countryOrRegion, $_.location.city, $_.ipAddress })) {
    $events = @($group.Group | Sort-Object -Property createdDateTime)
    $first = $events[0]
    $country = $first.location.countryOrRegion
    if ($expected.Count -gt 0 -and -not [string]::IsNullOrEmpty($country)) { $unexpected = $expected -notcontains $country.ToUpperInvariant() } else { $unexpected = $null }
    $rows.Add([PSCustomObject]@{
        UserPrincipalName = $first.userPrincipalName
        UserDisplayName   = $first.userDisplayName
        Country           = $country
        City              = $first.location.city
        IPAddress         = $first.ipAddress
        SignInCount       = $events.Count
        FailureCount      = @($events | Where-Object { $_.status.errorCode -ne 0 }).Count
        FirstSeen         = ([datetime]$first.createdDateTime).ToUniversalTime()
        LastSeen          = ([datetime]$events[-1].createdDateTime).ToUniversalTime()
        Unexpected        = $unexpected
        Applications      = (@($events | Select-Object -ExpandProperty appDisplayName -Unique | Sort-Object) -join '; ')
    })
}

# Atypical travel (lite): consecutive successful sign-ins of one user from two different countries within the window.
$travel = New-Object -TypeName System.Collections.Generic.List[object]
$successes = @($signIns | Where-Object { $_.status.errorCode -eq 0 -and -not [string]::IsNullOrEmpty($_.location.countryOrRegion) })
foreach ($userGroup in ($successes | Group-Object -Property userPrincipalName)) {
    $ordered = @($userGroup.Group | Sort-Object -Property createdDateTime)
    for ($i = 1; $i -lt $ordered.Count; $i++) {
        $previous = $ordered[$i - 1]; $current = $ordered[$i]
        $hours = (([datetime]$current.createdDateTime) - ([datetime]$previous.createdDateTime)).TotalHours
        if ($previous.location.countryOrRegion -eq $current.location.countryOrRegion -or $hours -gt $HoursWindow) { continue }
        $travel.Add([PSCustomObject]@{
            UserPrincipalName = $userGroup.Name
            FirstSignIn       = ([datetime]$previous.createdDateTime).ToUniversalTime()
            FirstCountry      = $previous.location.countryOrRegion
            FirstCity         = $previous.location.city
            FirstIPAddress    = $previous.ipAddress
            FirstApp          = $previous.appDisplayName
            SecondSignIn      = ([datetime]$current.createdDateTime).ToUniversalTime()
            SecondCountry     = $current.location.countryOrRegion
            SecondCity        = $current.location.city
            SecondIPAddress   = $current.ipAddress
            SecondApp         = $current.appDisplayName
            HoursBetween      = [math]::Round($hours, 2)
        })
    }
}
$sortedRows = @($rows | Sort-Object -Property UserPrincipalName, @{ Expression = 'SignInCount'; Descending = $true })
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No sign-ins were found in the selected period; no CSV was written.' }
if ($travel.Count -gt 0) { $travel | Export-Csv -Path $travelPath -NoTypeInformation -Encoding UTF8 }
$unexpectedRows = @($sortedRows | Where-Object { $_.Unexpected -eq $true })
Write-Host ('Sign-in locations (last {0} days): {1} events, {2} user/location rows -> {3}' -f $DaysBack, $signIns.Count, $sortedRows.Count, $OutputPath) -ForegroundColor Cyan
if ($unexpectedRows.Count -gt 0) {
    Write-Host ('  Unexpected countries: {0} rows ({1})' -f $unexpectedRows.Count, (@($unexpectedRows | Select-Object -ExpandProperty Country -Unique) -join ', ')) -ForegroundColor Yellow
}
if ($travel.Count -gt 0) { Write-Host ('  Atypical travel: {0} sign-in pairs within {1} h -> {2}' -f $travel.Count, $HoursWindow, $travelPath) -ForegroundColor Yellow }
if ($PassThru) { $sortedRows }
#endregion Main
