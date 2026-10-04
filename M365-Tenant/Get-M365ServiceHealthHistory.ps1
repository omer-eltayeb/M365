<#
.SYNOPSIS
    Exports the Microsoft 365 service health history (resolved and open issues) with per-service incident counts and mean time to resolve.
.DESCRIPTION
    Reads every incident and advisory modified in the last -DaysBack days from /admin/serviceAnnouncement/issues
    (Microsoft Graph v1.0, server-side $filter on lastModifiedDateTime) including resolved ones, and exports one row per
    issue with classification, status, start/end time, duration in hours, number of Microsoft posts and the impact
    description. A second CSV, <OutputPath base>_ByService.csv, aggregates issues, incidents, advisories, open items and
    the mean/maximum hours to resolve per service. -IncludeOverview adds <OutputPath base>_Overview.csv with the current
    health status of every subscribed service from /admin/serviceAnnouncement/healthOverviews.
.PARAMETER DaysBack
    Keep issues whose lastModifiedDateTime is within the last N days. Default 30, maximum 365.
.PARAMETER Service
    Wildcard filter on the service name, for example 'Microsoft Intune' or '*Exchange*'. A value without wildcards is matched as *value*.
.PARAMETER Classification
    Keep only 'incident' or 'advisory' issues.
.PARAMETER IncludeOverview
    Also export the current status per service to <OutputPath base>_Overview.csv.
.PARAMETER OutputPath
    Path of the issues CSV. Defaults to .\Reports\M365ServiceHealthHistory_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the issue objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365ServiceHealthHistory.ps1
    Exports all issues updated in the last 30 days and prints incidents per service with the mean time to resolve.
.EXAMPLE
    PS> .\Get-M365ServiceHealthHistory.ps1 -DaysBack 90 -Classification incident -Service 'Microsoft Intune' -IncludeOverview -OutputPath C:\Temp\Health.csv
    Exports 90 days of Intune incidents plus C:\Temp\Health_ByService.csv and C:\Temp\Health_Overview.csv.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : ServiceHealth.Read.All (delegated). The signed-in user needs a role that can see service health, for
                  example Service Support Administrator, Global Reader or any service-specific administrator role.
    Category    : Tenant configuration & health
    Changes     : No
    Notes       : All date/time values are UTC. Only services the tenant is subscribed to are returned and Microsoft keeps
                  roughly the last 12 months of history. DurationHours runs from startDateTime to endDateTime for resolved
                  issues and to now for open ones; MeanHoursToResolve averages resolved incidents only. For open issues
                  only, use Get-M365ServiceHealthReport.ps1 from this folder.
.LINK
    https://learn.microsoft.com/graph/api/serviceannouncement-list-issues
.LINK
    https://learn.microsoft.com/graph/api/serviceannouncement-list-healthoverviews
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [Parameter()]
    [string]$Service,

    [Parameter()]
    [ValidateSet('advisory', 'incident')]
    [string]$Classification,

    [Parameter()]
    [switch]$IncludeOverview,

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
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; $null when empty. #>
    param([Parameter()][AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}

function ConvertFrom-Html {
    <# Turns an HTML fragment into single-line plain text (tags stripped, entities decoded) and truncates it. #>
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$Html, [Parameter()][int]$MaxLength = 0)
    if ([string]::IsNullOrWhiteSpace($Html)) { return $null }
    $text = $Html -replace '(?i)<br\s*/?>|</p>|</li>|</div>|</tr>|</h[1-6]>', ' '
    $text = [System.Net.WebUtility]::HtmlDecode(($text -replace '<[^>]+>', ''))
    $text = ($text -replace '\s+', ' ').Trim()
    if ($MaxLength -gt 3 -and $text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength - 3) + '...' }
    return $text
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365ServiceHealthHistory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
$byServicePath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_ByService.csv' -f $baseName))
$overviewPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_Overview.csv' -f $baseName))

try {
    Connect-GraphIfNeeded -Scopes @('ServiceHealth.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$nowUtc = [datetime]::UtcNow
$since = $nowUtc.AddDays(-$DaysBack)
$servicePattern = $null
if (-not [string]::IsNullOrWhiteSpace($Service)) {
    $servicePattern = $Service
    if ($servicePattern -notmatch '[\*\?]') { $servicePattern = "*$servicePattern*" }
}
$issuesUri = 'https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/issues'
Write-Verbose "Reading service health issues modified since $($since.ToString('u'))."
try {
    $issues = @(Invoke-GraphPaged -Uri ('{0}?$filter=lastModifiedDateTime ge {1:yyyy-MM-ddTHH:mm:ssZ}' -f $issuesUri, $since))
}
catch {
    # Fall back to the unfiltered list (a few hundred rows) if the service rejects the $filter; the window is re-applied below.
    Write-Warning "Server-side filter failed ($($_.Exception.Message)); reading the full issue list instead."
    try { $issues = @(Invoke-GraphPaged -Uri $issuesUri) } catch { throw "Failed to read service health issues: $($_.Exception.Message)" }
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($issue in $issues) {
    $lastModified = ConvertTo-UtcDateTime -Value $issue.lastModifiedDateTime
    if ($null -ne $lastModified -and $lastModified -lt $since) { continue }
    if ($null -ne $servicePattern -and [string]$issue.service -notlike $servicePattern) { continue }
    if (-not [string]::IsNullOrWhiteSpace($Classification) -and [string]$issue.classification -ne $Classification) { continue }
    $isResolved = [bool]$issue.isResolved
    $start = ConvertTo-UtcDateTime -Value $issue.startDateTime
    $end = ConvertTo-UtcDateTime -Value $issue.endDateTime
    $durationHours = $null
    if ($null -ne $start) {
        $until = $nowUtc
        if ($isResolved -and $null -ne $end) { $until = $end }
        $durationHours = [math]::Round(($until - $start).TotalHours, 1)
    }
    $rows.Add([PSCustomObject]@{
            Id                   = $issue.id
            Title                = $issue.title
            Service              = $issue.service
            Feature              = $issue.feature
            Classification       = $issue.classification
            Status               = $issue.status
            Origin               = $issue.origin
            IsResolved           = $isResolved
            StartDateTime        = $start
            EndDateTime          = $end
            LastModifiedDateTime = $lastModified
            DurationHours        = $durationHours
            PostsCount           = @($issue.posts).Count
            ImpactDescription    = ConvertFrom-Html -Html ([string]$issue.impactDescription) -MaxLength 200
        })
}
$output = @($rows | Sort-Object -Property @{ Expression = 'StartDateTime'; Descending = $true })
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No issues matched the filters; no issues CSV was written.' }

$byService = foreach ($group in ($output | Group-Object -Property Service | Sort-Object -Property Name)) {
    $resolvedIncidents = @($group.Group | Where-Object { $_.IsResolved -and $_.Classification -eq 'incident' -and $null -ne $_.DurationHours })
    $meanHours = $null
    $maxHours = $null
    if ($resolvedIncidents.Count -gt 0) {
        $meanHours = [math]::Round(($resolvedIncidents | Measure-Object -Property DurationHours -Average).Average, 1)
        $maxHours = ($resolvedIncidents | Measure-Object -Property DurationHours -Maximum).Maximum
    }
    [PSCustomObject]@{
        Service            = $group.Name
        Issues             = $group.Count
        Incidents          = @($group.Group | Where-Object { $_.Classification -eq 'incident' }).Count
        Advisories         = @($group.Group | Where-Object { $_.Classification -eq 'advisory' }).Count
        Open               = @($group.Group | Where-Object { -not $_.IsResolved }).Count
        ResolvedIncidents  = $resolvedIncidents.Count
        MeanHoursToResolve = $meanHours
        MaxHoursToResolve  = $maxHours
    }
}
$byService = @($byService)
if ($byService.Count -gt 0) { $byService | Export-Csv -Path $byServicePath -NoTypeInformation -Encoding UTF8 }

$overview = @()
if ($IncludeOverview) {
    try {
        $overview = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/healthOverviews?$expand=issues' | ForEach-Object {
                $openIssues = @($_.issues | Where-Object { -not $_.isResolved })
                [PSCustomObject]@{
                    Service       = $_.service
                    Status        = $_.status
                    OpenIssues    = $openIssues.Count
                    OpenIncidents = @($openIssues | Where-Object { $_.classification -eq 'incident' }).Count
                }
            } | Sort-Object -Property Service)
        if ($overview.Count -gt 0) { $overview | Export-Csv -Path $overviewPath -NoTypeInformation -Encoding UTF8 }
    }
    catch {
        Write-Warning "Could not read the service health overview: $($_.Exception.Message)"
    }
}

$openItems = @($output | Where-Object { -not $_.IsResolved })
$incidents = @($output | Where-Object { $_.Classification -eq 'incident' })
$openColor = 'Green'
if ($openItems.Count -gt 0) { $openColor = 'Yellow' }
Write-Host ''
Write-Host 'Service health history summary' -ForegroundColor Cyan
$serviceLabel = 'all'
if ($null -ne $servicePattern) { $serviceLabel = $servicePattern }
$classificationLabel = 'all'
if (-not [string]::IsNullOrWhiteSpace($Classification)) { $classificationLabel = $Classification }
Write-Host ('  Window / filters      : last {0} days / service {1} / classification {2}' -f $DaysBack, $serviceLabel, $classificationLabel)
Write-Host ('  Issues exported       : {0} ({1} incidents, {2} advisories) -> {3}' -f $output.Count, $incidents.Count, ($output.Count - $incidents.Count), $OutputPath)
Write-Host ('  Open items            : {0}' -f $openItems.Count) -ForegroundColor $openColor
Write-Host '  Incidents per service (resolved mean hours):'
foreach ($entry in ($byService | Where-Object { $_.Incidents -gt 0 } | Sort-Object -Property Incidents -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,-40} {1,3} incidents  mean {2,6} h  max {3,6} h' -f $entry.Service, $entry.Incidents, $entry.MeanHoursToResolve, $entry.MaxHoursToResolve)
}
Write-Host '  Longest incidents:'
foreach ($longest in ($incidents | Sort-Object -Property DurationHours -Descending | Select-Object -First 5)) {
    Write-Host ('    {0,-10} {1,7} h  {2} - {3}' -f $longest.Id, $longest.DurationHours, $longest.Service, $longest.Title)
}
Write-Host ('  Per-service summary   : {0}' -f $byServicePath)
if ($IncludeOverview) {
    $degraded = @($overview | Where-Object { $_.Status -ne 'serviceOperational' })
    Write-Host ('  Current overview      : {0} services, {1} not operational -> {2}' -f $overview.Count, $degraded.Count, $overviewPath)
}

if ($PassThru) { $output }
#endregion Main
