<#
.SYNOPSIS
    Summarises failed Microsoft Entra sign-ins by error code, user, application, country and IP, with a password-spray indicator.
.DESCRIPTION
    Downloads failed interactive sign-ins (GET /auditLogs/signIns?$filter=createdDateTime ge ... and status/errorCode ne 0,
    $top=1000, capped by -MaxRecords), translates common AADSTS error codes into plain language and writes one CSV with every
    failure plus <base>_Summary.csv with the top 20 error codes, users, applications, countries and IPs. Source IPs that failed
    against at least -SprayUserThreshold distinct users are flagged as a password-spray indicator in both files.
.PARAMETER DaysBack
    Days of history to read (1-30). Default 7. Microsoft Entra ID P1/P2 keeps 30 days of sign-in logs, the Free tier 7 days.
.PARAMETER SprayUserThreshold
    Minimum number of distinct users a single IP must fail against to be flagged as a password-spray source. Default 10.
.PARAMETER MaxRecords
    Maximum number of failure events to download. Default 10000; a warning is written when the cap is reached.
.PARAMETER OutputPath
    Path of the per-failure CSV. Defaults to .\Reports\EntraFailedSignIns_yyyyMMdd-HHmm.csv; the summary gets the _Summary suffix.
.PARAMETER PassThru
    Also emits the per-failure objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraFailedSignInSummary.ps1
    Exports last week's failed sign-ins and a summary CSV, then prints the top error codes and any spray-suspect IPs.
.EXAMPLE
    PS> .\Get-EntraFailedSignInSummary.ps1 -DaysBack 1 -SprayUserThreshold 5 -MaxRecords 50000 -Verbose
    Analyses the last 24 hours with a lower spray threshold and a higher download cap.
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
    Notes       : Retention is 30 days with Microsoft Entra ID P1/P2 and 7 days on the Free tier. Interrupt codes (50074, 50076, 50140,
                  50058, 50173) are logged as failures even though the user usually completes the sign-in. Interactive sign-ins only.
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
    [ValidateRange(2, 10000)]
    [int]$SprayUserThreshold = 10,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraFailedSignIns_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$summaryPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_Summary.csv')
# Plain-language meaning of the most common AADSTS codes; unknown codes keep an empty ErrorMeaning (FailureReason still explains them).
$errorMeanings = @{
    '50126' = 'Invalid username or password';               '50053' = 'Account locked or IP blocked (too many failed attempts)'
    '50057' = 'User account disabled';                      '50074' = 'Strong authentication required'
    '50076' = 'MFA required';                               '50079' = 'MFA registration required'
    '50105' = 'User not assigned to the application';       '50140' = 'Keep-me-signed-in interrupt'
    '53000' = 'Device not compliant (Conditional Access)';  '53001' = 'Device not joined (Conditional Access)'
    '53003' = 'Blocked by Conditional Access';              '530032' = 'Blocked by security policy'
    '65001' = 'Consent required';                           '70044' = 'Session expired or revoked'
    '500121' = 'MFA authentication failed';                 '50058' = 'Silent sign-in failed (interaction required)'
    '51006' = 'Token expired';                              '50173' = 'Fresh token required'
    '50097' = 'Device authentication required';             '50133' = 'Session invalid because the password changed'
}
try { Connect-GraphIfNeeded -Scopes @('AuditLog.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$uri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1000&$filter=createdDateTime ge {0} and status/errorCode ne 0' -f $since
try { $signIns = Invoke-GraphPagedCapped -Uri $uri -MaxRecords $MaxRecords }
catch { throw "Failed to read sign-in logs: $($_.Exception.Message)" }
# Password-spray indicator: one source IP failing against many distinct accounts.
$sprayIps = @($signIns | Where-Object { -not [string]::IsNullOrEmpty($_.ipAddress) } | Group-Object -Property ipAddress |
    Where-Object { @($_.Group | Select-Object -ExpandProperty userPrincipalName -Unique).Count -ge $SprayUserThreshold } | Select-Object -ExpandProperty Name)
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($signIn in $signIns) {
    $rows.Add([PSCustomObject]@{
        CreatedDateTime         = ([datetime]$signIn.createdDateTime).ToUniversalTime()
        UserPrincipalName       = $signIn.userPrincipalName
        UserDisplayName         = $signIn.userDisplayName
        AppDisplayName          = $signIn.appDisplayName
        ClientAppUsed           = $signIn.clientAppUsed
        IPAddress               = $signIn.ipAddress
        City                    = $signIn.location.city
        Country                 = $signIn.location.countryOrRegion
        DeviceOS                = $signIn.deviceDetail.operatingSystem
        IsCompliant             = $signIn.deviceDetail.isCompliant
        IsManaged               = $signIn.deviceDetail.isManaged
        ErrorCode               = $signIn.status.errorCode
        ErrorMeaning            = $errorMeanings[[string]$signIn.status.errorCode]
        FailureReason           = $signIn.status.failureReason
        ConditionalAccessStatus = $signIn.conditionalAccessStatus
        RiskLevelDuringSignIn   = $signIn.riskLevelDuringSignIn
        RiskState               = $signIn.riskState
        PasswordSprayIp         = ($sprayIps -contains $signIn.ipAddress)
        ResourceDisplayName     = $signIn.resourceDisplayName
        CorrelationId           = $signIn.correlationId
    })
}

$summary = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($dimension in @('ErrorCode', 'UserPrincipalName', 'AppDisplayName', 'Country', 'IPAddress')) {
    foreach ($group in ($rows | Group-Object -Property $dimension | Sort-Object -Property Count -Descending | Select-Object -First 20)) {
        $detail = $null
        if ($dimension -eq 'ErrorCode') { $detail = $errorMeanings[[string]$group.Name] }
        $summary.Add([PSCustomObject]@{ Dimension = $dimension; Value = $group.Name; Count = $group.Count; Detail = $detail })
    }
}
foreach ($ip in $sprayIps) {
    $ipRows = @($rows | Where-Object { $_.IPAddress -eq $ip })
    $distinctUsers = @($ipRows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    $detail = '{0} failures against {1} distinct users from {2}' -f $ipRows.Count, $distinctUsers, (@($ipRows | Select-Object -ExpandProperty Country -Unique) -join ',')
    $summary.Add([PSCustomObject]@{ Dimension = 'PasswordSprayIndicator'; Value = $ip; Count = $distinctUsers; Detail = $detail })
}
if ($rows.Count -gt 0) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    $summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
}
else { Write-Warning 'No failed sign-ins were found in the selected period; no CSV was written.' }

$userCount = @($rows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
Write-Host ('Failed sign-ins (last {0} days): {1} failures, {2} users -> {3} (+ _Summary.csv)' -f $DaysBack, $rows.Count, $userCount, $OutputPath) -ForegroundColor Cyan
foreach ($item in ($summary | Where-Object { $_.Dimension -eq 'ErrorCode' } | Select-Object -First 10)) {
    Write-Host ('  {0,-8} {1,7}  {2}' -f $item.Value, $item.Count, $item.Detail)
}
if ($sprayIps.Count -gt 0) { Write-Host ('  Password-spray indicator ({0}+ users per IP): {1}' -f $SprayUserThreshold, ($sprayIps -join ', ')) -ForegroundColor Yellow }
if ($PassThru) { $rows }
#endregion Main
