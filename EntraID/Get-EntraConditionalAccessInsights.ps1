<#
.SYNOPSIS
    Aggregates how every Conditional Access policy was evaluated in recent sign-ins, including report-only impact and uncovered sign-ins.
.DESCRIPTION
    Downloads interactive sign-ins (GET /auditLogs/signIns, $top=1000, capped by -MaxRecords) for the last -DaysBack days and counts
    per policy the appliedConditionalAccessPolicies results (Success, Failure, NotApplied, NotEnabled, ReportOnlySuccess,
    ReportOnlyFailure, ReportOnlyNotApplied, ReportOnlyInterrupted), joined with the state from GET /identity/conditionalAccess/policies.
    Also writes <base>_ReportOnlyImpact.csv (user/app pairs a report-only policy would have blocked or interrupted) and
    <base>_Uncovered.csv (sign-ins where no policy applied, grouped by application and user).
.PARAMETER DaysBack
    Days of history to analyse (1-30). Default 7. Microsoft Entra ID P1/P2 keeps 30 days of sign-in logs, the Free tier 7 days.
.PARAMETER MaxRecords
    Maximum number of sign-in events to download. Default 10000; a warning is written when the cap is reached.
.PARAMETER OutputPath
    Path of the per-policy CSV. Defaults to .\Reports\EntraConditionalAccessInsights_yyyyMMdd-HHmm.csv; companion files get a suffix.
.PARAMETER PassThru
    Also emits the per-policy objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraConditionalAccessInsights.ps1
    Analyses the last 7 days and prints a per-policy table with success, failure and report-only counts.
.EXAMPLE
    PS> .\Get-EntraConditionalAccessInsights.ps1 -DaysBack 30 -MaxRecords 200000 -PassThru | Where-Object { $_.ReportOnlyFailure -gt 0 }
    Shows which report-only policies would have blocked users over the last month before switching them on.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AuditLog.Read.All, Policy.Read.All (delegated).
    Category    : Sign-ins, audit & risk
    Changes     : No
    Notes       : Requires Microsoft Entra ID P1. Retention is 30 days with P1/P2 and 7 days on the Free tier. Interactive sign-ins only;
                  counts are per event, so one user retrying five times counts five times. Deleted policies show State 'deleted'.
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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraConditionalAccessInsights_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$basePath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath))
$impactPath = $basePath + '_ReportOnlyImpact.csv'
$uncoveredPath = $basePath + '_Uncovered.csv'
try { Connect-GraphIfNeeded -Scopes @('AuditLog.Read.All', 'Policy.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $policies = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=id,displayName,state' }
catch { throw "Failed to read Conditional Access policies: $($_.Exception.Message)" }
$policyLookup = @{}
foreach ($policy in $policies) { $policyLookup[[string]$policy.id] = $policy }
$since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$uri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1000&$filter=createdDateTime ge {0}' -f $since
try { $signIns = Invoke-GraphPagedCapped -Uri $uri -MaxRecords $MaxRecords }
catch { throw "Failed to read sign-in logs: $($_.Exception.Message)" }
$resultNames = @('success', 'failure', 'notApplied', 'notEnabled', 'reportOnlySuccess', 'reportOnlyFailure', 'reportOnlyNotApplied', 'reportOnlyInterrupted', 'unknown')
$stats = @{}; $impact = @{}; $uncovered = @{}
foreach ($signIn in $signIns) {
    $created = ([datetime]$signIn.createdDateTime).ToUniversalTime()
    if ($signIn.conditionalAccessStatus -eq 'notApplied') {
        $key = '{0}|{1}' -f $signIn.appDisplayName, $signIn.userPrincipalName
        if (-not $uncovered.ContainsKey($key)) {
            $uncovered[$key] = [PSCustomObject]@{ AppDisplayName = $signIn.appDisplayName; UserPrincipalName = $signIn.userPrincipalName; SignInCount = 0; LastSeen = $created }
        }
        $uncovered[$key].SignInCount++
        if ($created -gt $uncovered[$key].LastSeen) { $uncovered[$key].LastSeen = $created }
    }
    foreach ($applied in @($signIn.appliedConditionalAccessPolicies | Where-Object { $null -ne $_ })) {
        $policyId = [string]$applied.id
        if (-not $stats.ContainsKey($policyId)) {
            $stats[$policyId] = @{ Name = $applied.displayName }
            foreach ($name in $resultNames) { $stats[$policyId][$name] = 0 }
        }
        $result = [string]$applied.result
        if ($resultNames -notcontains $result) { $result = 'unknown' }
        $stats[$policyId][$result]++
        # Report-only failure/interrupt = the user would have been blocked or challenged had the policy been enforced.
        if ($result -in 'reportOnlyFailure', 'reportOnlyInterrupted') {
            $key = '{0}|{1}|{2}|{3}' -f $policyId, $signIn.userPrincipalName, $signIn.appDisplayName, $result
            if (-not $impact.ContainsKey($key)) {
                $impact[$key] = [PSCustomObject]@{
                    PolicyName = $applied.displayName; UserPrincipalName = $signIn.userPrincipalName; AppDisplayName = $signIn.appDisplayName
                    Result = $result; GrantControls = (@($applied.enforcedGrantControls) -join ', '); SignInCount = 0; LastSeen = $created
                }
            }
            $impact[$key].SignInCount++
            if ($created -gt $impact[$key].LastSeen) { $impact[$key].LastSeen = $created }
        }
    }
}

# One row per current policy (zero counts reveal policies that never matched) plus policies seen in the logs but since deleted.
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$allIds = @($policyLookup.Keys) + @($stats.Keys | Where-Object { -not $policyLookup.ContainsKey($_) })
foreach ($id in $allIds) {
    $policy = $policyLookup[$id]; $stat = $stats[$id]
    $row = [ordered]@{ PolicyName = $null; PolicyId = $id; State = 'deleted'; Evaluations = 0 }
    if ($null -ne $policy) { $row.PolicyName = $policy.displayName; $row.State = $policy.state }
    elseif ($null -ne $stat) { $row.PolicyName = $stat.Name }
    foreach ($name in $resultNames) {
        $value = 0
        if ($null -ne $stat) { $value = $stat[$name] }
        $row[$name.Substring(0, 1).ToUpperInvariant() + $name.Substring(1)] = $value
        $row.Evaluations += $value
    }
    $rows.Add([PSCustomObject]$row)
}
$sortedRows = @($rows | Sort-Object -Property Evaluations -Descending)
$impactRows = @($impact.Values | Sort-Object -Property SignInCount -Descending)
$uncoveredRows = @($uncovered.Values | Sort-Object -Property SignInCount -Descending)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No Conditional Access policies or sign-ins were found; no CSV was written.' }
if ($impactRows.Count -gt 0) { $impactRows | Export-Csv -Path $impactPath -NoTypeInformation -Encoding UTF8 }
if ($uncoveredRows.Count -gt 0) { $uncoveredRows | Export-Csv -Path $uncoveredPath -NoTypeInformation -Encoding UTF8 }
$caFailures = @($signIns | Where-Object { $_.conditionalAccessStatus -eq 'failure' }).Count
Write-Host ('CA insights (last {0} days): {1} sign-ins, {2} blocked by CA, {3} policies -> {4}' -f $DaysBack, $signIns.Count, $caFailures, $sortedRows.Count, $OutputPath) -ForegroundColor Cyan
foreach ($row in ($sortedRows | Select-Object -First 15)) {
    $name = [string]$row.PolicyName; if ($name.Length -gt 55) { $name = $name.Substring(0, 52) + '...' }
    Write-Host ('  {0,-55} {1,-34} success {2,6}  failure {3,6}  report-only failure {4,6}' -f $name, $row.State, $row.Success, $row.Failure, $row.ReportOnlyFailure)
}
if ($impactRows.Count -gt 0) { Write-Host ('  Report-only impact: {0} user/app pairs would be blocked or interrupted -> {1}' -f $impactRows.Count, $impactPath) -ForegroundColor Yellow }
if ($uncoveredRows.Count -gt 0) { Write-Host ('  Uncovered: {0} app/user pairs signed in with no policy applied -> {1}' -f $uncoveredRows.Count, $uncoveredPath) -ForegroundColor Yellow }
if ($PassThru) { $sortedRows }
#endregion Main
