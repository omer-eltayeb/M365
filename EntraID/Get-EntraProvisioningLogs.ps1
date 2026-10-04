<#
.SYNOPSIS
    Exports Microsoft Entra provisioning logs (SCIM / HR-driven user provisioning to SaaS apps) with status, errors and changed attributes.
.DESCRIPTION
    Queries GET /auditLogs/provisioning?$filter=activityDateTime ge <ISO> for the last -DaysBack days, pages through the results and
    stops at -MaxRecords. Every provisioning event becomes one row: application (service principal), action, status, error code and
    reason, source and target identity and system, modified properties (truncated to 300 characters), job and cycle id.
    -OnlyFailures and -AppName narrow the result client-side. Exports to CSV and prints counts per application/status and the top error reasons.
.PARAMETER DaysBack
    Days of history to read (1-30). Default 7. Provisioning logs are kept for 30 days.
.PARAMETER OnlyFailures
    Only events with status 'failure'.
.PARAMETER AppName
    Only events of applications whose display name matches this wildcard pattern, for example 'Workday*' or '*Salesforce*'.
.PARAMETER MaxRecords
    Maximum number of events to download. Default 10000; a warning is written when the cap is reached.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraProvisioningLogs_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraProvisioningLogs.ps1 -OnlyFailures
    Exports every failed provisioning event of the last 7 days and prints the most common error reasons.
.EXAMPLE
    PS> .\Get-EntraProvisioningLogs.ps1 -AppName 'Workday*' -DaysBack 30 -MaxRecords 50000 -PassThru
    Lists a month of Workday provisioning events (creates, updates, disables, skips) in the console and the CSV.
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
    Notes       : Provisioning logs only exist for applications with automatic provisioning configured and are retained for 30 days.
                  'skipped' events are normal (users out of scope or unchanged). Modified property values are the raw strings sent to the
                  target application. Filtering by application runs after the download, so -MaxRecords counts all events of the period.
.LINK
    https://learn.microsoft.com/graph/api/provisioningobjectsummary-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$DaysBack = 7,

    [Parameter()]
    [switch]$OnlyFailures,

    [Parameter()]
    [string]$AppName,

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
        Write-Progress -Activity 'Downloading provisioning events' -Status ('{0} events retrieved' -f $results.Count)
    }
    Write-Progress -Activity 'Downloading provisioning events' -Completed
    if ($received -gt $results.Count -or -not [string]::IsNullOrEmpty($nextLink)) {
        Write-Warning ('MaxRecords ({0}) reached; older events were not downloaded. Narrow the filter or raise -MaxRecords.' -f $MaxRecords)
    }
    return $results
}

function Get-IdentityLabel {
    <# Returns the most readable identifier of a provisioning identity (display name, then id). #>
    param([object]$Identity)
    if ($null -eq $Identity) { return $null }
    return @($Identity.displayName, $Identity.id) | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 1
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraProvisioningLogs_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('AuditLog.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$uri = 'https://graph.microsoft.com/v1.0/auditLogs/provisioning?$filter=activityDateTime ge {0}' -f $since
try { $events = Invoke-GraphPagedCapped -Uri $uri -MaxRecords $MaxRecords }
catch { throw "Failed to read provisioning logs: $($_.Exception.Message)" }
Write-Verbose "Loaded $($events.Count) provisioning events since $since."

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($provisioningEvent in $events) {
    $status = [string]$provisioningEvent.provisioningStatusInfo.status
    $appDisplayName = [string]$provisioningEvent.servicePrincipal.displayName
    if ($OnlyFailures -and $status -ne 'failure') { continue }
    if (-not [string]::IsNullOrWhiteSpace($AppName) -and $appDisplayName -notlike $AppName) { continue }
    $errorInfo = $provisioningEvent.provisioningStatusInfo.errorInformation
    $modified = @($provisioningEvent.modifiedProperties | Where-Object { $null -ne $_ -and -not [string]::IsNullOrEmpty($_.displayName) } |
        ForEach-Object { '{0}: {1} -> {2}' -f $_.displayName, $_.oldValue, $_.newValue }) -join '; '
    if ($modified.Length -gt 300) { $modified = $modified.Substring(0, 297) + '...' }
    $rows.Add([PSCustomObject]@{
        ActivityDateTime   = ([datetime]$provisioningEvent.activityDateTime).ToUniversalTime()
        ServicePrincipal   = $appDisplayName
        Action             = $provisioningEvent.provisioningAction
        Status             = $status
        ErrorCode          = $errorInfo.errorCode
        ErrorReason        = $errorInfo.reason
        RecommendedAction  = $errorInfo.recommendedAction
        SourceIdentity     = Get-IdentityLabel -Identity $provisioningEvent.sourceIdentity
        SourceIdentityType = $provisioningEvent.sourceIdentity.identityType
        TargetIdentity     = Get-IdentityLabel -Identity $provisioningEvent.targetIdentity
        TargetIdentityType = $provisioningEvent.targetIdentity.identityType
        SourceSystem       = $provisioningEvent.sourceSystem.displayName
        TargetSystem       = $provisioningEvent.targetSystem.displayName
        ModifiedProperties = $modified
        DurationMs         = $provisioningEvent.durationInMilliseconds
        JobId              = $provisioningEvent.jobId
        CycleId            = $provisioningEvent.cycleId
    })
}

$sortedRows = @($rows | Sort-Object -Property ActivityDateTime -Descending)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No provisioning events matched the selected filters; no CSV was written.' }

$failureCount = @($sortedRows | Where-Object { $_.Status -eq 'failure' }).Count
Write-Host ('Provisioning (last {0} days): {1} events downloaded, {2} matched, {3} failures -> {4}' -f $DaysBack, $events.Count, $sortedRows.Count, $failureCount, $OutputPath) -ForegroundColor Cyan
Write-Host '  Events per application and status:'
foreach ($group in ($sortedRows | Group-Object -Property ServicePrincipal, Status | Sort-Object -Property Count -Descending | Select-Object -First 15)) {
    Write-Host ('    {0,-70} {1,7}' -f $group.Name, $group.Count)
}
$topErrors = @($sortedRows | Where-Object { -not [string]::IsNullOrEmpty($_.ErrorReason) } | Group-Object -Property ErrorReason | Sort-Object -Property Count -Descending | Select-Object -First 10)
if ($topErrors.Count -gt 0) {
    Write-Host '  Top error reasons:' -ForegroundColor Yellow
    foreach ($group in $topErrors) {
        $reason = $group.Name
        if ($reason.Length -gt 110) { $reason = $reason.Substring(0, 107) + '...' }
        Write-Host ('    {0,5}  {1}' -f $group.Count, $reason) -ForegroundColor Yellow
    }
}
if ($PassThru) { $sortedRows }
#endregion Main
