<#
.SYNOPSIS
    Runs a Microsoft Purview audit log search through the Microsoft Graph Audit Search API and exports the records.
.DESCRIPTION
    Creates an asynchronous audit log query (POST /security/auditLog/queries) with the given date range and filters, polls
    its status every 10 seconds until it succeeds, fails or times out, then pages /security/auditLog/queries/{id}/records.
    Each record becomes one row with the common properties plus ResultStatus, Workload, UserAgent, Subject, SourceFileName
    and SiteUrl flattened from auditData. Exports a CSV and prints counts by service and operation. No Exchange session needed.
.PARAMETER DaysBack
    Number of days to search back from now (default 7, maximum 365; Audit (Standard) keeps 180 days).
.PARAMETER RecordTypes
    Record types in Graph enum form, for example exchangeItem, sharePointFileOperation, azureActiveDirectoryStsLogon.
.PARAMETER Operations
    Operations to filter on, for example FileDownloaded, UserLoggedIn, MailItemsAccessed.
.PARAMETER UserPrincipalNames
    User principal names of the actors to filter on.
.PARAMETER IpAddresses
    Client IP addresses to filter on.
.PARAMETER Keyword
    Free-text keyword searched across non-indexed properties of the records.
.PARAMETER ServiceFilters
    Workloads to filter on, for example Exchange, SharePoint, OneDrive, AzureActiveDirectory, MicrosoftTeams.
.PARAMETER QueryName
    Display name of the saved query as shown in the Purview portal. Defaults to AuditQuery_yyyyMMdd-HHmm.
.PARAMETER TimeoutMinutes
    Maximum time to wait for the query to complete (default 30). Large queries can take considerably longer than searches.
.PARAMETER IncludeRawJson
    Add the full auditData JSON as the last CSV column.
.PARAMETER ApiVersion
    Graph API version: v1.0 (default, generally available) or beta for clouds where the API is still in preview.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewAuditLogViaGraph_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the flattened records to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewAuditLogViaGraph.ps1 -DaysBack 3 -RecordTypes sharePointFileOperation -Operations FileDownloaded
    Exports three days of file downloads through Graph and prints the service and operation summary.
.EXAMPLE
    PS> .\Get-PurviewAuditLogViaGraph.ps1 -DaysBack 30 -UserPrincipalNames alex@contoso.com -IncludeRawJson -TimeoutMinutes 60 -Verbose
    Collects everything one user did in the last 30 days, keeping the raw JSON and waiting up to an hour for the query.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AuditLogsQuery.Read.All (delegated; a workload-specific AuditLogsQuery-*.Read.All scope also works) plus the Audit Logs or View-Only Audit Logs role in Purview
    Category    : Audit log scenarios
    Changes     : No
    Notes       : The Audit Search API is asynchronous: the query is queued on the service and usually needs minutes (sometimes much
                  longer) before records can be read, and tenants have daily and concurrent-query limits. Queries appear under Audit >
                  Search in the Purview portal. The API moved from beta to v1.0 in 2025. Timestamps are UTC; retention applies.
.LINK
    https://learn.microsoft.com/graph/api/security-auditcoreroot-post-auditlogqueries
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 7,

    [Parameter()]
    [string[]]$RecordTypes,

    [Parameter()]
    [string[]]$Operations,

    [Parameter()]
    [string[]]$UserPrincipalNames,

    [Parameter()]
    [string[]]$IpAddresses,

    [Parameter()]
    [string]$Keyword,

    [Parameter()]
    [string[]]$ServiceFilters,

    [Parameter()]
    [string]$QueryName,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$TimeoutMinutes = 30,

    [Parameter()]
    [switch]$IncludeRawJson,

    [Parameter()]
    [ValidateSet('v1.0', 'beta')]
    [string]$ApiVersion = 'v1.0',

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewAuditLogViaGraph_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($QueryName)) { $QueryName = 'AuditQuery_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm') }
$endTime = (Get-Date).ToUniversalTime()
$startTime = $endTime.AddDays(-$DaysBack)
try { Connect-GraphIfNeeded -Scopes 'AuditLogsQuery.Read.All' } catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$queriesUri = "https://graph.microsoft.com/$ApiVersion/security/auditLog/queries"
$body = @{ displayName = $QueryName; filterStartDateTime = $startTime.ToString('o'); filterEndDateTime = $endTime.ToString('o') }
if ($RecordTypes) { $body['recordTypeFilters'] = @($RecordTypes) }
if ($Operations) { $body['operationFilters'] = @($Operations) }
if ($UserPrincipalNames) { $body['userPrincipalNameFilters'] = @($UserPrincipalNames) }
if ($IpAddresses) { $body['ipAddressFilters'] = @($IpAddresses) }
if ($ServiceFilters) { $body['serviceFilters'] = @($ServiceFilters) }
if (-not [string]::IsNullOrWhiteSpace($Keyword)) { $body['keywordFilter'] = $Keyword }
try { $query = Invoke-MgGraphRequest -Method POST -Uri $queriesUri -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop }
catch { throw "Failed to create the audit log query: $($_.Exception.Message)" }
Write-Verbose "Created audit log query $($query.id) ('$QueryName') with status $($query.status)."
# The query runs server-side; poll until it leaves notStarted/running or the timeout expires.
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$status = [string]$query.status
$started = Get-Date
while (('notStarted', 'running' -contains $status) -and (Get-Date) -lt $deadline) {
    Write-Progress -Activity 'Waiting for the audit log query' -Status ('Status {0}, {1:mm\:ss} elapsed (timeout {2} min)' -f $status, ((Get-Date) - $started), $TimeoutMinutes)
    Start-Sleep -Seconds 10
    try { $query = Invoke-MgGraphRequest -Method GET -Uri "$queriesUri/$($query.id)" -OutputType PSObject -ErrorAction Stop }
    catch { Write-Warning "Polling the query status failed, retrying: $($_.Exception.Message)" }
    $status = [string]$query.status
}
Write-Progress -Activity 'Waiting for the audit log query' -Completed
if ($status -ne 'succeeded') { throw "Audit log query $($query.id) ended with status '$status' after $TimeoutMinutes minute(s); increase -TimeoutMinutes or check Audit > Search in Purview." }
if ($query.isRecordCountLimitExceeded -eq $true) { Write-Warning ('The query exceeded the record-count limit ({0}); narrow the filters or the date range.' -f $query.recordCountLimit) }
$records = @(Invoke-GraphPaged -Uri "$queriesUri/$($query.id)/records")
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    $audit = $record.auditData
    $row = [ordered]@{ CreatedDateTime = [datetime]$record.createdDateTime; UserPrincipalName = [string]$record.userPrincipalName; UserType = [string]$record.userType }
    foreach ($field in 'operation', 'service', 'clientIp', 'objectId', 'auditLogRecordType', 'id') { $row[$field.Substring(0, 1).ToUpperInvariant() + $field.Substring(1)] = [string]$record.$field }
    $row['AdministrativeUnits'] = (@($record.administrativeUnits) -join '; ')
    foreach ($field in 'ResultStatus', 'Workload', 'Subject', 'SourceFileName', 'SiteUrl') { $row[$field] = [string]$audit.$field }
    $row['UserAgent'] = [string]$(if ($audit.UserAgent) { $audit.UserAgent } else { $audit.ClientInfoString })
    if ($IncludeRawJson) { $row['AuditData'] = $(if ($null -ne $audit) { $audit | ConvertTo-Json -Depth 10 -Compress } else { '' }) }
    $results.Add([PSCustomObject]$row)
}
$results = @($results | Sort-Object -Property CreatedDateTime)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'The query returned no records for the given window and filters.' }
Write-Host 'Graph audit log query summary' -ForegroundColor Cyan
Write-Host ('  Query   : {0} ({1}) status {2}, approx. {3} record(s) on the service' -f $QueryName, $query.id, $status, $query.approximateReturnedRecordCount)
Write-Host ('  Window  : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} UTC, {2} record(s) downloaded' -f $startTime, $endTime, $results.Count)
foreach ($section in @(@('By service', 'Service', 20), @('Top operations', 'Operation', 10))) {
    Write-Host ('  {0}:' -f $section[0])
    $groups = $results | Group-Object -Property $section[1] | Sort-Object -Property Count -Descending | Select-Object -First $section[2]
    foreach ($group in $groups) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
}
Write-Host ('  Report  : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
