<#
.SYNOPSIS
    Exports the Intune audit log (who changed what, when) for the last N days with optional actor, category and activity filters.
.DESCRIPTION
    Reads audit events from Microsoft Graph v1.0 (/deviceManagement/auditEvents filtered server-side on activityDateTime) and
    flattens each event into one row: actor (user or application), actor type, activity, operation type, result, category,
    component, affected resource and the modified properties as "name: old -> new". Wildcard filters on actor and activity type
    and an exact category filter are applied client-side. Exports to CSV, optionally to the pipeline, and prints the busiest
    actors and the operation type distribution.
.PARAMETER DaysBack
    Number of days of audit history to read (1-30). Default 7.
.PARAMETER Actor
    Wildcard pattern matched against the actor's user principal name or application display name (for example 'admin*' or '*Intune portal*').
.PARAMETER Category
    Exact audit category, for example Device, DeviceConfiguration, Compliance, Application, Enrollment, Role or SoftwareUpdates.
.PARAMETER ActivityType
    Wildcard pattern matched against the activity type (for example '*Delete*' or 'Patch DeviceConfiguration*').
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneAuditEvents_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the event objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneAuditEvents.ps1
    Exports the last 7 days of Intune audit events to .\Reports and shows the most active actors.
.EXAMPLE
    PS> .\Get-IntuneAuditEvents.ps1 -DaysBack 30 -ActivityType '*Delete*' -Category DeviceConfiguration -PassThru | Format-Table ActivityDateTime, Actor, Resource
    Lists every configuration profile deletion in the last 30 days with the admin who performed it.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role with the Audit data > Read permission
    Category    : Reporting & platform insights
    Changes     : No
    Notes       : Intune retains audit events for one year; -DaysBack is capped at 30 to keep result sets manageable (busy tenants
                  generate thousands of events a day). Actions performed through the admin center show the Microsoft Intune
                  portal extension as application with the signed-in admin as actor. ModifiedProperties is truncated to 500
                  characters. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-auditing-auditevent-list
.LINK
    https://learn.microsoft.com/intune/governance/monitor-audit-logs
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$DaysBack = 7,

    [Parameter()]
    [string]$Actor,

    [Parameter()]
    [string]$Category,

    [Parameter()]
    [string]$ActivityType,

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
    <# Converts a Graph date value (string or DateTime) to a UTC [datetime]; $null for empty values or the 0001-01-01 placeholder. #>
    param([object]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { $parsed = ([datetime]$Value).ToUniversalTime() } catch { return $null }
    if ($parsed.Year -le 1) { return $null }
    return $parsed
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneAuditEvents_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementConfiguration.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$since = (Get-Date).ToUniversalTime().AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$uri = 'https://graph.microsoft.com/v1.0/deviceManagement/auditEvents?$filter=activityDateTime ge {0}' -f $since
Write-Verbose ('Reading audit events since {0} (UTC).' -f $since)
try { $events = @(Invoke-GraphPaged -Uri $uri) } catch { throw "Failed to retrieve audit events from Microsoft Graph: $($_.Exception.Message)" }
Write-Verbose ('{0} audit events retrieved.' -f $events.Count)

$report = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($auditEvent in $events) {
    $index++
    if ($index % 200 -eq 0) { Write-Progress -Activity 'Processing audit events' -Status ('{0} of {1}' -f $index, $events.Count) -PercentComplete ([int](($index / $events.Count) * 100)) }
    $actorName = [string]$auditEvent.actor.userPrincipalName
    if ([string]::IsNullOrWhiteSpace($actorName)) { $actorName = [string]$auditEvent.actor.applicationDisplayName }
    if (-not [string]::IsNullOrWhiteSpace($Actor) -and $actorName -notlike $Actor -and [string]$auditEvent.actor.applicationDisplayName -notlike $Actor) { continue }
    if (-not [string]::IsNullOrWhiteSpace($Category) -and $auditEvent.category -ne $Category) { continue }
    if (-not [string]::IsNullOrWhiteSpace($ActivityType) -and [string]$auditEvent.activityType -notlike $ActivityType) { continue }

    # Only the first resource carries the changed properties for almost every event type; keep the row flat and readable.
    $resource = $null
    if ($null -ne $auditEvent.resources -and @($auditEvent.resources).Count -gt 0) { $resource = @($auditEvent.resources)[0] }
    $changes = @()
    if ($null -ne $resource -and $null -ne $resource.modifiedProperties) {
        $changes = @($resource.modifiedProperties | ForEach-Object { '{0}: {1} -> {2}' -f $_.displayName, $_.oldValue, $_.newValue })
    }
    $modified = ($changes -join '; ') -replace '[\r\n]+', ' '
    if ($modified.Length -gt 500) { $modified = $modified.Substring(0, 500) + '...' }

    $report.Add([PSCustomObject]@{
            ActivityDateTime      = ConvertTo-UtcDateTime -Value $auditEvent.activityDateTime
            Actor                 = $actorName
            ActorType             = $auditEvent.actor.auditActorType
            Application           = $auditEvent.actor.applicationDisplayName
            ActivityType          = $auditEvent.activityType
            ActivityOperationType = $auditEvent.activityOperationType
            ActivityResult        = $auditEvent.activityResult
            Category              = $auditEvent.category
            ComponentName         = $auditEvent.componentName
            Resource              = $resource.displayName
            ResourceType          = $resource.type
            ModifiedProperties    = $modified
            CorrelationId         = $auditEvent.correlationId
            EventId               = $auditEvent.id
        })
}
Write-Progress -Activity 'Processing audit events' -Completed
$report = @($report | Sort-Object -Property ActivityDateTime -Descending)

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else { Write-Warning 'No audit events matched the selection; no CSV file was written.' }

Write-Host ''
Write-Host ('Audit events (last {0} days) : {1} retrieved, {2} after filters' -f $DaysBack, $events.Count, $report.Count) -ForegroundColor Cyan
Write-Host 'Top actors:' -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property Actor | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('  {0,-60} {1,6}' -f $group.Name, $group.Count)
}
Write-Host 'Operation types:' -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property ActivityOperationType | Sort-Object -Property Count -Descending)) {
    $colour = 'Gray'; if ($group.Name -eq 'Delete') { $colour = 'Yellow' }
    Write-Host ('  {0,-20} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
$failures = @($report | Where-Object { $_.ActivityResult -ne 'Success' }).Count
if ($failures -gt 0) { Write-Host ('Events with a non-success result: {0}' -f $failures) -ForegroundColor Red }

if ($PassThru) { $report }
#endregion Main
