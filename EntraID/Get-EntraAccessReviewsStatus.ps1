<#
.SYNOPSIS
    Reports the status of Microsoft Entra access reviews: definitions, their instances, pending decisions and overdue reviews.
.DESCRIPTION
    Reads every access review schedule definition (GET /identityGovernance/accessReviews/definitions) with its scope, reviewers
    and recurrence, then every instance (GET /identityGovernance/accessReviews/definitions/{id}/instances). For instances that
    are in progress the number of decisions still marked NotReviewed is counted
    (GET .../instances/{id}/decisions?$filter=decision eq 'NotReviewed'&$count=true) and instances whose end date has passed
    are flagged as overdue. One CSV row per instance (or per definition without instances) with a summary per status.
.PARAMETER ReviewName
    Only definitions whose display name matches this wildcard pattern, for example 'Guest*'.
.PARAMETER ActiveOnly
    Skips instances that are already Completed or Applied.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraAccessReviewsStatus_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraAccessReviewsStatus.ps1
    Exports every access review instance and prints the counts per status, the overdue reviews and the pending decisions.
.EXAMPLE
    PS> .\Get-EntraAccessReviewsStatus.ps1 -ActiveOnly -ReviewName 'Guest*' -PassThru
    Lists only the running guest access reviews in the console.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AccessReview.Read.All (delegated); Global Reader, Security Reader or Identity Governance Administrator.
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : Requires Microsoft Entra ID P2 or Microsoft Entra ID Governance. Pending decisions are only counted for
                  instances in progress (one extra request each). Reviews created in PIM or Entitlement Management are included.
.LINK
    https://learn.microsoft.com/graph/api/accessreviewset-list-definitions
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ReviewName,

    [Parameter()]
    [switch]$ActiveOnly,

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
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    return ([datetime]$Value).ToUniversalTime()
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraAccessReviewsStatus_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('AccessReview.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$baseUri = 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions'
try { $definitions = @(Invoke-GraphPaged -Uri ($baseUri + '?$select=id,displayName,status,scope,reviewers,settings,createdDateTime,lastModifiedDateTime,createdBy')) }
catch { throw "Failed to read access review definitions (requires Microsoft Entra ID P2 or Governance): $($_.Exception.Message)" }
Write-Verbose "Loaded $($definitions.Count) access review definitions."

$now = [datetime]::UtcNow
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($definition in $definitions) {
    $processed++
    if (-not [string]::IsNullOrWhiteSpace($ReviewName) -and $definition.displayName -notlike $ReviewName) { continue }
    Write-Progress -Activity 'Reading access reviews' -Status $definition.displayName -PercentComplete (($processed / $definitions.Count) * 100)

    # Query scopes carry a single query; principal/resource membership scopes carry a list of resource scopes instead.
    $scope = $definition.scope
    $scopeQuery = $scope.query
    if ([string]::IsNullOrEmpty($scopeQuery)) { $scopeQuery = (@($scope.resourceScopes | ForEach-Object { $_.query }) -join '; ') }
    $pattern = $definition.settings.recurrence.pattern
    $recurrence = 'oneTime'
    if ($null -ne $pattern) { $recurrence = '{0} (interval {1})' -f $pattern.type, $pattern.interval }
    $range = $definition.settings.recurrence.range
    $rangeText = $null
    if ($null -ne $range) { $rangeText = ('{0} {1} - {2}' -f $range.type, $range.startDate, $range.endDate).Trim(' -') }
    $createdBy = @($definition.createdBy.userPrincipalName, $definition.createdBy.displayName) | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 1

    $instances = @()
    try { $instances = @(Invoke-GraphPaged -Uri ('{0}/{1}/instances' -f $baseUri, $definition.id)) }
    catch { Write-Warning ('Instances of review "{0}" could not be read: {1}' -f $definition.displayName, $_.Exception.Message) }
    if ($instances.Count -eq 0) { $instances = @($null) }

    foreach ($instance in $instances) {
        if ($ActiveOnly -and $instance.status -in @('Completed', 'Applied')) { continue }
        $pending = $null
        if ($instance.status -eq 'InProgress') {
            try {
                $decisionsUri = '{0}/{1}/instances/{2}/decisions?$filter=decision eq ''NotReviewed''' -f $baseUri, $definition.id, $instance.id
                $response = Invoke-MgGraphRequest -Method GET -Uri ($decisionsUri + '&$count=true&$top=1') -Headers @{ ConsistencyLevel = 'eventual' } -OutputType PSObject -ErrorAction Stop
                $pending = $response.'@odata.count'
                if ($null -eq $pending) { $pending = @(Invoke-GraphPaged -Uri ($decisionsUri + '&$select=id')).Count }
                Start-Sleep -Milliseconds 200
            }
            catch { Write-Warning ('Pending decisions of review "{0}" could not be counted: {1}' -f $definition.displayName, $_.Exception.Message) }
        }
        $endDate = ConvertTo-UtcDateTime -Value $instance.endDateTime
        $daysRemaining = $null
        if ($null -ne $endDate -and $instance.status -notin @('Completed', 'Applied')) { $daysRemaining = [math]::Round(($endDate - $now).TotalDays, 1) }

        $rows.Add([PSCustomObject]@{
            ReviewName           = $definition.displayName
            DefinitionStatus     = $definition.status
            ScopeType            = ([string]$scope.'@odata.type') -replace '^#microsoft\.graph\.', ''
            ScopeQuery           = $scopeQuery
            Reviewers            = (@($definition.reviewers | ForEach-Object { $_.query }) -join '; ')
            Recurrence           = $recurrence
            RecurrenceRange      = $rangeText
            InstanceStatus       = $instance.status
            StartDateTime        = ConvertTo-UtcDateTime -Value $instance.startDateTime
            EndDateTime          = $endDate
            DaysRemaining        = $daysRemaining
            PendingDecisions     = $pending
            Overdue              = ($instance.status -eq 'InProgress' -and $null -ne $endDate -and $endDate -lt $now)
            CreatedBy            = $createdBy
            CreatedDateTime      = ConvertTo-UtcDateTime -Value $definition.createdDateTime
            LastModifiedDateTime = ConvertTo-UtcDateTime -Value $definition.lastModifiedDateTime
            DefinitionId         = $definition.id
            InstanceId           = $instance.id
        })
    }
}
Write-Progress -Activity 'Reading access reviews' -Completed

$sortedRows = @($rows | Sort-Object -Property ReviewName, StartDateTime)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No access reviews matched the selected filters; no CSV was written.' }

Write-Host ''
Write-Host 'Access review summary' -ForegroundColor Cyan
foreach ($group in ($sortedRows | Where-Object { $null -ne $_.InstanceStatus } | Group-Object -Property InstanceStatus | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-14}: {1}' -f $group.Name, $group.Count)
}
$overdue = @($sortedRows | Where-Object { $_.Overdue })
$pendingTotal = ($sortedRows | Where-Object { $null -ne $_.PendingDecisions } | Measure-Object -Property PendingDecisions -Sum).Sum
Write-Host ('  Definitions / instances : {0} / {1} -> {2}' -f @($sortedRows | Select-Object -ExpandProperty DefinitionId -Unique).Count, $sortedRows.Count, $OutputPath)
Write-Host ('  Pending decisions       : {0}' -f [int]$pendingTotal)
if ($overdue.Count -gt 0) {
    Write-Host ('  Overdue reviews         : {0}' -f $overdue.Count) -ForegroundColor Yellow
    foreach ($row in $overdue) { Write-Host ('    {0,-50} ended {1:yyyy-MM-dd}, {2} pending' -f $row.ReviewName, $row.EndDateTime, $row.PendingDecisions) -ForegroundColor Yellow }
}

if ($PassThru) { $sortedRows }
#endregion Main
