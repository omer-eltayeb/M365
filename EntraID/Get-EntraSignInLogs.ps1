<#
.SYNOPSIS
    Exports Microsoft Entra interactive (and optionally non-interactive) sign-in events with Conditional Access and device details.
.DESCRIPTION
    Queries GET /auditLogs/signIns with a server-side $filter built from the parameters (date range, user, application,
    success or failure, IP address), pages through the results ($top=1000) and stops at -MaxRecords. Every event becomes one
    row: user, app, client, IP, location, device, result code, Conditional Access outcome, applied policies (name:result) and risk.
.PARAMETER DaysBack
    Days of history to read (1-30). Default 7. Microsoft Entra ID P1/P2 keeps 30 days of sign-in logs, the Free tier 7 days.
.PARAMETER UserPrincipalName
    Only sign-ins of this user (exact UPN).
.PARAMETER AppDisplayName
    Only sign-ins to the application with this exact display name, for example 'Microsoft Teams'.
.PARAMETER OnlyFailures
    Only failed sign-ins (status/errorCode ne 0). Cannot be combined with -OnlySuccess.
.PARAMETER OnlySuccess
    Only successful sign-ins (status/errorCode eq 0). Cannot be combined with -OnlyFailures.
.PARAMETER IpAddress
    Only sign-ins from this exact IP address.
.PARAMETER IncludeNonInteractive
    Also return non-interactive user sign-ins (token refreshes, background sign-ins). Switches the query to the beta endpoint.
.PARAMETER MaxRecords
    Maximum number of events to download. Default 10000; a warning is written when the cap is reached.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraSignInLogs_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraSignInLogs.ps1 -DaysBack 1 -OnlyFailures
    Exports every failed interactive sign-in of the last 24 hours.
.EXAMPLE
    PS> .\Get-EntraSignInLogs.ps1 -UserPrincipalName jane.doe@contoso.com -IncludeNonInteractive -MaxRecords 50000 -PassThru
    Exports and lists the interactive and non-interactive sign-ins of one user for the last 7 days.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AuditLog.Read.All, Directory.Read.All (delegated).
    Category    : Sign-ins, audit & risk
    Changes     : No
    Notes       : Retention is 30 days with Microsoft Entra ID P1/P2 and 7 days on the Free tier; risk columns show 'hidden' without
                  P2. -IncludeNonInteractive uses the beta endpoint (subject to change, very large volumes); only beta returns MfaMethod.
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
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$AppDisplayName,

    [Parameter()]
    [switch]$OnlyFailures,

    [Parameter()]
    [switch]$OnlySuccess,

    [Parameter()]
    [string]$IpAddress,

    [Parameter()]
    [switch]$IncludeNonInteractive,

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
if ($OnlyFailures -and $OnlySuccess) { throw 'Use either -OnlyFailures or -OnlySuccess, not both.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraSignInLogs_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('AuditLog.Read.All', 'Directory.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# Sign-in UPNs are stored lower-case; the other string filters are exact matches with single quotes doubled.
$clauses = @("createdDateTime ge $([datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ'))")
if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) { $clauses += "userPrincipalName eq '{0}'" -f ($UserPrincipalName.ToLowerInvariant() -replace "'", "''") }
if (-not [string]::IsNullOrWhiteSpace($AppDisplayName)) { $clauses += "appDisplayName eq '{0}'" -f ($AppDisplayName -replace "'", "''") }
if (-not [string]::IsNullOrWhiteSpace($IpAddress)) { $clauses += "ipAddress eq '$IpAddress'" }
if ($OnlyFailures) { $clauses += 'status/errorCode ne 0' } elseif ($OnlySuccess) { $clauses += 'status/errorCode eq 0' }
# beta: v1.0 only returns interactive user sign-ins; the signInEventTypes filter exists on beta only.
$version = 'v1.0'
if ($IncludeNonInteractive) { $version = 'beta'; $clauses += "(signInEventTypes/any(t: t eq 'interactiveUser') or signInEventTypes/any(t: t eq 'nonInteractiveUser'))" }
$uri = 'https://graph.microsoft.com/{0}/auditLogs/signIns?$top=1000&$filter={1}' -f $version, ($clauses -join ' and ')
Write-Verbose "Query: $uri"
try { $signIns = Invoke-GraphPagedCapped -Uri $uri -MaxRecords $MaxRecords }
catch { throw "Failed to read sign-in logs: $($_.Exception.Message)" }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($signIn in $signIns) {
    $policies = @($signIn.appliedConditionalAccessPolicies | Where-Object { $null -ne $_ } | ForEach-Object { '{0}:{1}' -f $_.displayName, $_.result })
    $rows.Add([PSCustomObject]@{
        CreatedDateTime         = ([datetime]$signIn.createdDateTime).ToUniversalTime()
        UserPrincipalName       = $signIn.userPrincipalName
        UserDisplayName         = $signIn.userDisplayName
        AppDisplayName          = $signIn.appDisplayName
        ClientAppUsed           = $signIn.clientAppUsed
        IsInteractive           = $signIn.isInteractive
        IPAddress               = $signIn.ipAddress
        City                    = $signIn.location.city
        Country                 = $signIn.location.countryOrRegion
        DeviceOS                = $signIn.deviceDetail.operatingSystem
        Browser                 = $signIn.deviceDetail.browser
        IsCompliant             = $signIn.deviceDetail.isCompliant
        IsManaged               = $signIn.deviceDetail.isManaged
        TrustType               = $signIn.deviceDetail.trustType
        ErrorCode               = $signIn.status.errorCode
        FailureReason           = $signIn.status.failureReason
        ConditionalAccessStatus = $signIn.conditionalAccessStatus
        AppliedPolicies         = $policies -join '; '
        MfaMethod               = $signIn.mfaDetail.authMethod
        RiskLevelDuringSignIn   = $signIn.riskLevelDuringSignIn
        RiskState               = $signIn.riskState
        ResourceDisplayName     = $signIn.resourceDisplayName
        CorrelationId           = $signIn.correlationId
    })
}

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No sign-in events matched the filter; no CSV was written.' }
$failedCount = @($rows | Where-Object { $_.ErrorCode -ne 0 }).Count
$userCount = @($rows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
Write-Host ('Sign-in export (last {0} days): {1} events, {2} failed, {3} distinct users -> {4}' -f $DaysBack, $rows.Count, $failedCount, $userCount, $OutputPath) -ForegroundColor Cyan
if ($PassThru) { $rows }
#endregion Main
