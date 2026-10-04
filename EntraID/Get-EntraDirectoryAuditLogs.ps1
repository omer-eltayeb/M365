<#
.SYNOPSIS
    Exports Microsoft Entra directory audit events (who changed what, when) with initiator, targets and modified properties.
.DESCRIPTION
    Queries GET /auditLogs/directoryAudits?$filter=activityDateTime ge <ISO> (plus category and result eq 'failure' when requested),
    pages through the results and stops at -MaxRecords; activity, initiator and target wildcards are applied client-side. Each event
    becomes one row with the initiator (user or application), the targets and their types, and the modified properties as
    "name: old -> new" (truncated to 500 characters). Exports to CSV and prints the top activities and initiators.
.PARAMETER DaysBack
    Days of history to read (1-30). Default 7. Microsoft Entra ID P1/P2 keeps 30 days of audit logs, the Free tier 7 days.
.PARAMETER Category
    Only events of this audit category (server-side), for example UserManagement, GroupManagement, RoleManagement or Policy.
.PARAMETER ActivityDisplayName
    Only events whose activity matches this wildcard pattern, for example 'Add member to role' or '*password*'.
.PARAMETER InitiatedBy
    Only events initiated by a user UPN or application name matching this wildcard pattern, for example 'admin*' or 'Microsoft Intune*'.
.PARAMETER TargetName
    Only events where a target display name or UPN matches this wildcard pattern, for example '*Global Administrator*'.
.PARAMETER OnlyFailures
    Only events with result 'failure' (server-side).
.PARAMETER MaxRecords
    Maximum number of events to download. Default 10000; a warning is written when the cap is reached.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraDirectoryAuditLogs_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraDirectoryAuditLogs.ps1 -Category RoleManagement -DaysBack 30
    Exports every role management change of the last 30 days (role assignments, PIM activations, eligibility changes).
.EXAMPLE
    PS> .\Get-EntraDirectoryAuditLogs.ps1 -ActivityDisplayName '*Conditional Access*' -InitiatedBy '*@contoso.com' -PassThru
    Lists last week's Conditional Access policy changes made by users (not by applications) in the console and the CSV.
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
    Notes       : Retention is 30 days with Microsoft Entra ID P1/P2 and 7 days on the Free tier. Old/new values are the raw JSON fragments
                  stored by Entra ID. Wildcards run after the download, so -MaxRecords counts all events of the period; narrow with -Category.
.LINK
    https://learn.microsoft.com/graph/api/directoryaudit-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$DaysBack = 7,

    [Parameter()]
    [string]$Category,

    [Parameter()]
    [string]$ActivityDisplayName,

    [Parameter()]
    [string]$InitiatedBy,

    [Parameter()]
    [string]$TargetName,

    [Parameter()]
    [switch]$OnlyFailures,

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
        Write-Progress -Activity 'Downloading audit events' -Status ('{0} events retrieved' -f $results.Count)
    }
    Write-Progress -Activity 'Downloading audit events' -Completed
    if ($received -gt $results.Count -or -not [string]::IsNullOrEmpty($nextLink)) {
        Write-Warning ('MaxRecords ({0}) reached; older events were not downloaded. Narrow the filter or raise -MaxRecords.' -f $MaxRecords)
    }
    return $results
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraDirectoryAuditLogs_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('AuditLog.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$clauses = @("activityDateTime ge $([datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ'))")
if (-not [string]::IsNullOrWhiteSpace($Category)) { $clauses += "category eq '{0}'" -f ($Category -replace "'", "''") }
if ($OnlyFailures) { $clauses += "result eq 'failure'" }
$uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=999&$filter=' + ($clauses -join ' and ')
try { $events = Invoke-GraphPagedCapped -Uri $uri -MaxRecords $MaxRecords }
catch { throw "Failed to read directory audit logs: $($_.Exception.Message)" }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($auditEvent in $events) {
    if (-not [string]::IsNullOrWhiteSpace($ActivityDisplayName) -and ([string]$auditEvent.activityDisplayName) -notlike $ActivityDisplayName) { continue }
    # Audit events are initiated either by a signed-in user or by an application / service principal (never both).
    $initiator = $null; $initiatorType = 'Unknown'
    if ($null -ne $auditEvent.initiatedBy.user -and -not [string]::IsNullOrEmpty($auditEvent.initiatedBy.user.id + $auditEvent.initiatedBy.user.userPrincipalName)) {
        $initiatorType = 'User'
        $initiator = @($auditEvent.initiatedBy.user.userPrincipalName, $auditEvent.initiatedBy.user.displayName, $auditEvent.initiatedBy.user.id) | Where-Object { $_ } | Select-Object -First 1
    }
    elseif ($null -ne $auditEvent.initiatedBy.app) {
        $initiatorType = 'Application'
        $initiator = @($auditEvent.initiatedBy.app.displayName, $auditEvent.initiatedBy.app.servicePrincipalName, $auditEvent.initiatedBy.app.appId) | Where-Object { $_ } | Select-Object -First 1
    }
    if (-not [string]::IsNullOrWhiteSpace($InitiatedBy) -and ([string]$initiator) -notlike $InitiatedBy) { continue }
    $targets = @($auditEvent.targetResources | Where-Object { $null -ne $_ })
    $targetNames = @($targets | ForEach-Object { @($_.displayName, $_.userPrincipalName, $_.id) | Where-Object { $_ } | Select-Object -First 1 })
    if (-not [string]::IsNullOrWhiteSpace($TargetName) -and @($targetNames | Where-Object { $_ -like $TargetName }).Count -eq 0) { continue }
    $modified = @($targets | ForEach-Object { $_.modifiedProperties } | Where-Object { $null -ne $_ -and -not [string]::IsNullOrEmpty($_.displayName) } |
        ForEach-Object { '{0}: {1} -> {2}' -f $_.displayName, $_.oldValue, $_.newValue }) -join '; '
    if ($modified.Length -gt 500) { $modified = $modified.Substring(0, 497) + '...' }
    $rows.Add([PSCustomObject]@{
        ActivityDateTime    = ([datetime]$auditEvent.activityDateTime).ToUniversalTime()
        ActivityDisplayName = $auditEvent.activityDisplayName
        Category            = $auditEvent.category
        Result              = $auditEvent.result
        ResultReason        = $auditEvent.resultReason
        InitiatedBy         = $initiator
        InitiatedByType     = $initiatorType
        InitiatedByIp       = $auditEvent.initiatedBy.user.ipAddress
        Targets             = $targetNames -join '; '
        TargetTypes         = (@($targets | Select-Object -ExpandProperty type -Unique) -join '; ')
        ModifiedProperties  = $modified
        LoggedByService     = $auditEvent.loggedByService
        CorrelationId       = $auditEvent.correlationId
    })
}

$sortedRows = @($rows | Sort-Object -Property ActivityDateTime -Descending)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No audit events matched the selected filters; no CSV was written.' }
$failureCount = @($sortedRows | Where-Object { $_.Result -eq 'failure' }).Count
Write-Host ('Directory audit (last {0} days): {1} events downloaded, {2} matched, {3} failures -> {4}' -f $DaysBack, $events.Count, $sortedRows.Count, $failureCount, $OutputPath) -ForegroundColor Cyan
foreach ($property in @('ActivityDisplayName', 'InitiatedBy')) {
    Write-Host ('  Top 10 by {0}:' -f $property)
    foreach ($group in ($sortedRows | Group-Object -Property $property | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
        Write-Host ('    {0,-70} {1,7}' -f $group.Name, $group.Count)
    }
}
if ($PassThru) { $sortedRows }
#endregion Main
