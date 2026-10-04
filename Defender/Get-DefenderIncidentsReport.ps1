<#
.SYNOPSIS
    Reports Microsoft Defender XDR incidents for triage, including how long each one has been open.
.DESCRIPTION
    Queries the incidents endpoint (GET /security/incidents) through Microsoft Graph with a server-side $filter on
    createdDateTime and, optionally, status and severity. Every incident becomes one row with its severity and
    priority score, classification, assignment, tags, portal link and DaysOpen (time since creation for incidents
    that are not resolved or redirected). With -IncludeAlerts the alerts are expanded ($expand=alerts) and the alert count plus the first
    five alert titles are added. The result is exported to CSV and the console summarises the open incidents by
    severity, the oldest open incident and the mean age of open high-severity incidents.
.PARAMETER DaysBack
    Number of days to look back based on createdDateTime. Default 30, maximum 365.
.PARAMETER Status
    Only incidents with this status: active, inProgress, resolved or redirected.
.PARAMETER Severity
    Only incidents with this severity: informational, low, medium or high.
.PARAMETER IncludeAlerts
    Expands the alerts of each incident and adds the AlertCount and AlertTitles columns (slower on large tenants).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderIncidents_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderIncidentsReport.ps1
    Exports every incident created in the last 30 days and prints the open-incident summary.
.EXAMPLE
    PS> .\Get-DefenderIncidentsReport.ps1 -DaysBack 90 -Status active -Severity high -IncludeAlerts -OutputPath C:\Temp\OpenHigh.csv -Verbose
    Exports the active high-severity incidents of the last 90 days with their alert titles to the given CSV.
.EXAMPLE
    PS> .\Get-DefenderIncidentsReport.ps1 -Status active -PassThru | Sort-Object -Property DaysOpen -Descending | Select-Object -First 5
    Shows the five active incidents that have been open the longest.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityIncident.Read.All (delegated); the signed-in user needs Security Reader, Security Operator
                  or Security Administrator in Microsoft Defender XDR.
    Category    : Defender XDR alerts & incidents
    Changes     : No
    Notes       : Incidents are only created for Defender services that are licensed and onboarded in the tenant.
                  Graph incident severity tops out at 'high' (there is no 'critical' level). Redirected incidents
                  were merged into another incident and are treated as closed.
.LINK
    https://learn.microsoft.com/graph/api/security-list-incidents
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [Parameter()]
    [ValidateSet('active', 'inProgress', 'resolved', 'redirected')]
    [string]$Status,

    [Parameter()]
    [ValidateSet('informational', 'low', 'medium', 'high')]
    [string]$Severity,

    [Parameter()]
    [switch]$IncludeAlerts,

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
    param(
        [Parameter()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}
#endregion Helpers

#region Main
$requiredScopes = @('SecurityIncident.Read.All')
$closedStatuses = @('resolved', 'redirected')

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderIncidents_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
}
catch {
    throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)"
}

# InvariantCulture keeps ':' as the time separator regardless of the local culture, so the OData literal stays valid.
$since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
$filterParts = @("createdDateTime ge $since")
if (-not [string]::IsNullOrEmpty($Status)) { $filterParts += "status eq '$Status'" }
if (-not [string]::IsNullOrEmpty($Severity)) { $filterParts += "severity eq '$Severity'" }
$uri = 'https://graph.microsoft.com/v1.0/security/incidents?$filter=' + ($filterParts -join ' and ')
if ($IncludeAlerts) { $uri += '&$expand=alerts' }

Write-Verbose "Requesting $uri"
try {
    $incidents = Invoke-GraphPaged -Uri $uri
}
catch {
    throw "Failed to read incidents from Microsoft Defender XDR: $($_.Exception.Message)"
}
Write-Verbose "Retrieved $($incidents.Count) incidents."

$now = [datetime]::UtcNow
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($incident in $incidents) {
    $processed++
    if ($processed % 100 -eq 0) {
        Write-Progress -Activity 'Shaping incidents' -Status "$processed of $($incidents.Count)" -PercentComplete (($processed / $incidents.Count) * 100)
    }
    $created = ConvertTo-UtcDateTime -Value $incident.createdDateTime
    $daysOpen = $null
    if ($null -ne $created -and $closedStatuses -notcontains [string]$incident.status) {
        $daysOpen = [math]::Round(($now - $created).TotalDays, 1)
    }

    $row = [PSCustomObject]@{
        Id                 = $incident.id
        DisplayName        = $incident.displayName
        Severity           = $incident.severity
        PriorityScore      = $incident.priorityScore
        Status             = $incident.status
        Classification     = $incident.classification
        Determination      = $incident.determination
        AssignedTo         = $incident.assignedTo
        CreatedDateTime    = $created
        LastUpdateDateTime = ConvertTo-UtcDateTime -Value $incident.lastUpdateDateTime
        DaysOpen           = $daysOpen
        SystemTags         = (@($incident.systemTags) -join ';')
        CustomTags         = (@($incident.customTags) -join ';')
        IncidentWebUrl     = $incident.incidentWebUrl
    }
    if ($IncludeAlerts) {
        $incidentAlerts = @($incident.alerts | Where-Object { $null -ne $_ })
        $titles = @($incidentAlerts | ForEach-Object { $_.title } | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique -First 5)
        $row | Add-Member -NotePropertyName 'AlertCount' -NotePropertyValue $incidentAlerts.Count
        $row | Add-Member -NotePropertyName 'AlertTitles' -NotePropertyValue ($titles -join ';')
    }
    $rows.Add($row)
}
Write-Progress -Activity 'Shaping incidents' -Completed

$sortedRows = @($rows | Sort-Object -Property CreatedDateTime -Descending)
if ($sortedRows.Count -gt 0) {
    $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning ('No incidents matched the filter in the last {0} days; no CSV was written.' -f $DaysBack)
}

$openRows = @($sortedRows | Where-Object { $closedStatuses -notcontains [string]$_.Status })
Write-Host ''
Write-Host ('Defender XDR incidents summary (last {0} days)' -f $DaysBack) -ForegroundColor Cyan
Write-Host ('  Incidents exported : {0} ({1} open, {2} closed) -> {3}' -f $sortedRows.Count, $openRows.Count, ($sortedRows.Count - $openRows.Count), $OutputPath)
Write-Host '  Open incidents by severity:' -ForegroundColor Yellow
foreach ($level in @('high', 'medium', 'low', 'informational')) {
    $levelCount = @($openRows | Where-Object { $_.Severity -eq $level }).Count
    if ($levelCount -gt 0) { Write-Host ('    {0,-14}: {1}' -f $level, $levelCount) }
}
if ($openRows.Count -gt 0) {
    $oldest = $openRows | Sort-Object -Property CreatedDateTime | Select-Object -First 1
    Write-Host ('  Oldest open incident : {0} - "{1}" ({2} days, {3})' -f $oldest.Id, $oldest.DisplayName, $oldest.DaysOpen, $oldest.Severity)
    # Severity 'high' is the top level in Graph; it covers what the portal shows as high and critical incidents.
    $openHigh = @($openRows | Where-Object { $_.Severity -eq 'high' -and $null -ne $_.DaysOpen })
    if ($openHigh.Count -gt 0) {
        $meanDaysOpen = [math]::Round(($openHigh | Measure-Object -Property DaysOpen -Average).Average, 1)
        Write-Host ('  Mean age of open high-severity incidents : {0} days ({1} incidents)' -f $meanDaysOpen, $openHigh.Count) -ForegroundColor Yellow
    }
}

if ($PassThru) {
    $sortedRows
}
#endregion Main
