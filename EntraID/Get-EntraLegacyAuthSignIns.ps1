<#
.SYNOPSIS
    Finds sign-ins that used legacy authentication protocols (POP3, IMAP4, SMTP, ActiveSync, EWS, MAPI, ...) and whether they succeeded.
.DESCRIPTION
    Reads interactive sign-ins (GET /auditLogs/signIns, $top=1000, capped by -MaxRecords) whose clientAppUsed is one of the legacy
    protocols, using a server-side $filter with or-clauses; if the service rejects the long filter the script downloads the period
    and filters locally. Every event is classified as Success (token issued), Blocked (Conditional Access or security policy) or
    Failed, exported to CSV, and summarised per protocol, user and application in <base>_Summary.csv and on the console.
.PARAMETER DaysBack
    Days of history to read (1-30). Default 7. Microsoft Entra ID P1/P2 keeps 30 days of sign-in logs, the Free tier 7 days.
.PARAMETER MaxRecords
    Maximum number of events to download. Default 10000; a warning is written when the cap is reached.
.PARAMETER OutputPath
    Path of the per-event CSV. Defaults to .\Reports\EntraLegacyAuthSignIns_yyyyMMdd-HHmm.csv; the summary gets the _Summary suffix.
.PARAMETER PassThru
    Also emits the per-event objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraLegacyAuthSignIns.ps1
    Exports last week's legacy authentication sign-ins and prints how many succeeded, were blocked or failed per protocol.
.EXAMPLE
    PS> .\Get-EntraLegacyAuthSignIns.ps1 -DaysBack 30 -MaxRecords 100000 -PassThru | Where-Object { $_.Outcome -eq 'Success' }
    Lists every successful legacy sign-in of the last 30 days - the users that a "block legacy authentication" policy would affect.
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
    Notes       : Retention is 30 days with Microsoft Entra ID P1/P2 and 7 days on the Free tier. 'Success' means Entra ID issued a
                  token; Exchange Online may still reject basic authentication, so use the list to scope a Conditional Access block.
                  'Other clients' and 'Unknown' are included because Microsoft treats them as legacy in the Conditional Access
                  client-app condition.
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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraLegacyAuthSignIns_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$summaryPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_Summary.csv')

$legacyProtocols = @('Exchange ActiveSync', 'Exchange Online PowerShell', 'Exchange Web Services', 'IMAP4', 'POP3', 'SMTP', 'Authenticated SMTP',
    'MAPI Over HTTP', 'Outlook Anywhere (RPC over HTTP)', 'AutoDiscover', 'Offline Address Book', 'Reporting Web Services', 'Other clients', 'Unknown')

try { Connect-GraphIfNeeded -Scopes @('AuditLog.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$baseUri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1000&$filter=createdDateTime ge {0}' -f $since
$protocolFilter = '(' + (@($legacyProtocols | ForEach-Object { "clientAppUsed eq '$_'" }) -join ' or ') + ')'
try { $signIns = Invoke-GraphPagedCapped -Uri ($baseUri + ' and ' + $protocolFilter) -MaxRecords $MaxRecords }
catch {
    # Long or-chains on clientAppUsed are occasionally rejected (HTTP 400); fall back to the date filter and select locally.
    Write-Warning "The server-side protocol filter was rejected ($($_.Exception.Message)). Downloading all sign-ins of the period and filtering locally."
    try { $signIns = @(Invoke-GraphPagedCapped -Uri $baseUri -MaxRecords $MaxRecords | Where-Object { $legacyProtocols -contains $_.clientAppUsed }) }
    catch { throw "Failed to read sign-in logs: $($_.Exception.Message)" }
}
Write-Verbose "Loaded $($signIns.Count) legacy authentication sign-ins since $since."

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($signIn in $signIns) {
    # Success = Entra ID issued a token. Blocked = Conditional Access or a tenant security policy stopped it. Anything else = Failed.
    $outcome = 'Failed'
    if ($signIn.status.errorCode -eq 0) { $outcome = 'Success' }
    elseif ($signIn.conditionalAccessStatus -eq 'failure' -or $signIn.status.errorCode -in 53003, 530032) { $outcome = 'Blocked' }
    $policies = @($signIn.appliedConditionalAccessPolicies | Where-Object { $null -ne $_ } | ForEach-Object { '{0}:{1}' -f $_.displayName, $_.result })
    $rows.Add([PSCustomObject]@{
        CreatedDateTime         = ([datetime]$signIn.createdDateTime).ToUniversalTime()
        UserPrincipalName       = $signIn.userPrincipalName
        UserDisplayName         = $signIn.userDisplayName
        ClientAppUsed           = $signIn.clientAppUsed
        Outcome                 = $outcome
        AppDisplayName          = $signIn.appDisplayName
        ResourceDisplayName     = $signIn.resourceDisplayName
        IPAddress               = $signIn.ipAddress
        City                    = $signIn.location.city
        Country                 = $signIn.location.countryOrRegion
        DeviceOS                = $signIn.deviceDetail.operatingSystem
        Browser                 = $signIn.deviceDetail.browser
        ErrorCode               = $signIn.status.errorCode
        FailureReason           = $signIn.status.failureReason
        ConditionalAccessStatus = $signIn.conditionalAccessStatus
        AppliedPolicies         = $policies -join '; '
        CorrelationId           = $signIn.correlationId
    })
}

$summary = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($dimension in @('ClientAppUsed', 'UserPrincipalName', 'AppDisplayName')) {
    foreach ($group in ($rows | Group-Object -Property $dimension | Sort-Object -Property Count -Descending)) {
        $summary.Add([PSCustomObject]@{
            Dimension = $dimension
            Value     = $group.Name
            Total     = $group.Count
            Success   = @($group.Group | Where-Object { $_.Outcome -eq 'Success' }).Count
            Blocked   = @($group.Group | Where-Object { $_.Outcome -eq 'Blocked' }).Count
            Failed    = @($group.Group | Where-Object { $_.Outcome -eq 'Failed' }).Count
        })
    }
}

if ($rows.Count -gt 0) {
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    $summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
}
else { Write-Warning 'No legacy authentication sign-ins were found in the selected period; no CSV was written.' }

$successCount = @($rows | Where-Object { $_.Outcome -eq 'Success' }).Count
$blockedCount = @($rows | Where-Object { $_.Outcome -eq 'Blocked' }).Count
Write-Host ('Legacy auth (last {0} days): {1} sign-ins, {2} succeeded, {3} blocked -> {4} (+ _Summary.csv)' -f $DaysBack, $rows.Count, $successCount, $blockedCount, $OutputPath) -ForegroundColor Cyan
foreach ($item in ($summary | Where-Object { $_.Dimension -eq 'ClientAppUsed' })) {
    Write-Host ('  {0,-34} total {1,6}  success {2,6}  blocked {3,6}  failed {4,6}' -f $item.Value, $item.Total, $item.Success, $item.Blocked, $item.Failed)
}
$successUsers = @($rows | Where-Object { $_.Outcome -eq 'Success' } | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
if ($successUsers -gt 0) {
    Write-Host ('  {0} user(s) still sign in successfully with legacy protocols; review them before enforcing a Conditional Access block.' -f $successUsers) -ForegroundColor Yellow
}
if ($PassThru) { $rows }
#endregion Main
