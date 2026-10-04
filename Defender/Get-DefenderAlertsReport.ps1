<#
.SYNOPSIS
    Reports alerts from Microsoft Defender XDR (unified alerts API) for the last N days.
.DESCRIPTION
    Queries the unified alerts endpoint (GET /security/alerts_v2) through Microsoft Graph with a server-side
    $filter on createdDateTime and, optionally, severity, status and service source. Every alert becomes one row
    with its classification, the incident it belongs to, the affected devices and users extracted from the
    evidence collection, MITRE ATT&CK techniques, a trimmed recommended-actions text and the portal link.
    The result is exported to CSV and the console shows counts by severity and service plus the ten devices
    with the most alerts.
.PARAMETER DaysBack
    Number of days to look back based on createdDateTime. Default 7, maximum 365.
.PARAMETER Severity
    Only alerts with this severity: informational, low, medium or high.
.PARAMETER Status
    Only alerts with this status: new, inProgress or resolved.
.PARAMETER ServiceSource
    Only alerts raised by this service, for example microsoftDefenderForEndpoint or microsoftDefenderForOffice365.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderAlerts_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderAlertsReport.ps1
    Exports every alert created in the last 7 days and prints the severity, service and top-device summary.
.EXAMPLE
    PS> .\Get-DefenderAlertsReport.ps1 -DaysBack 30 -Severity high -Status new -OutputPath C:\Temp\HighAlerts.csv -Verbose
    Exports unhandled high-severity alerts from the last 30 days to the given CSV.
.EXAMPLE
    PS> .\Get-DefenderAlertsReport.ps1 -ServiceSource microsoftDefenderForEndpoint -PassThru | Group-Object -Property Category
    Shows the Defender for Endpoint alerts of the last week grouped by category.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityAlert.Read.All (delegated); the signed-in user needs Security Reader, Security Operator
                  or Security Administrator in Microsoft Defender XDR.
    Category    : Defender XDR alerts & incidents
    Changes     : No
    Notes       : Alerts are only returned for Defender services that are licensed and onboarded in the tenant.
                  Microsoft Sentinel alerts appear when the workspace is connected to Defender XDR. Large tenants
                  with thousands of alerts take a while to page; narrow the query with -DaysBack or the filters.
.LINK
    https://learn.microsoft.com/graph/api/security-list-alerts_v2
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 7,

    [Parameter()]
    [ValidateSet('informational', 'low', 'medium', 'high')]
    [string]$Severity,

    [Parameter()]
    [ValidateSet('new', 'inProgress', 'resolved')]
    [string]$Status,

    [Parameter()]
    [ValidateSet('microsoftDefenderForEndpoint', 'microsoftDefenderForOffice365', 'microsoftDefenderForIdentity',
        'microsoftDefenderForCloudApps', 'microsoftSentinel', 'azureAdIdentityProtection', 'microsoftAppGovernance',
        'dataLossPrevention', 'microsoftDefenderForCloud', 'microsoft365Defender')]
    [string]$ServiceSource,

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
$requiredScopes = @('SecurityAlert.Read.All')

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderAlerts_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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
if (-not [string]::IsNullOrEmpty($Severity)) { $filterParts += "severity eq '$Severity'" }
if (-not [string]::IsNullOrEmpty($Status)) { $filterParts += "status eq '$Status'" }
if (-not [string]::IsNullOrEmpty($ServiceSource)) { $filterParts += "serviceSource eq '$ServiceSource'" }
$uri = 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=100&$filter=' + ($filterParts -join ' and ')

Write-Verbose "Requesting $uri"
try {
    $alerts = Invoke-GraphPaged -Uri $uri
}
catch {
    throw "Failed to read alerts from Microsoft Defender XDR: $($_.Exception.Message)"
}
Write-Verbose "Retrieved $($alerts.Count) alerts."

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($alert in $alerts) {
    $processed++
    if ($processed % 100 -eq 0) {
        Write-Progress -Activity 'Shaping alerts' -Status "$processed of $($alerts.Count)" -PercentComplete (($processed / $alerts.Count) * 100)
    }
    $devices = @()
    $users = @()
    foreach ($evidence in @($alert.evidence)) {
        if ($null -eq $evidence) { continue }
        switch ([string]$evidence.'@odata.type') {
            '#microsoft.graph.security.deviceEvidence' {
                if (-not [string]::IsNullOrEmpty($evidence.deviceDnsName)) { $devices += $evidence.deviceDnsName }
            }
            '#microsoft.graph.security.userEvidence' {
                $account = $evidence.userAccount
                if ($null -ne $account) {
                    if (-not [string]::IsNullOrEmpty($account.userPrincipalName)) { $users += $account.userPrincipalName }
                    elseif (-not [string]::IsNullOrEmpty($account.accountName)) { $users += $account.accountName }
                }
            }
        }
    }
    # Recommended actions can be several paragraphs; keep a single-line preview for the CSV.
    $recommended = ([string]$alert.recommendedActions) -replace '\s*[\r\n]+\s*', ' '
    if ($recommended.Length -gt 300) { $recommended = $recommended.Substring(0, 297) + '...' }
    # 'categories' replaces the deprecated single-value 'category'; older alerts may only carry the latter.
    $category = (@($alert.categories | Where-Object { $_ }) -join ';')
    if ([string]::IsNullOrEmpty($category)) { $category = $alert.category }

    $rows.Add([PSCustomObject]@{
        Id                    = $alert.id
        Title                 = $alert.title
        Severity              = $alert.severity
        Status                = $alert.status
        ServiceSource         = $alert.serviceSource
        DetectionSource       = $alert.detectionSource
        Category              = $category
        CreatedDateTime       = ConvertTo-UtcDateTime -Value $alert.createdDateTime
        FirstActivityDateTime = ConvertTo-UtcDateTime -Value $alert.firstActivityDateTime
        LastUpdateDateTime    = ConvertTo-UtcDateTime -Value $alert.lastUpdateDateTime
        AssignedTo            = $alert.assignedTo
        Classification        = $alert.classification
        Determination         = $alert.determination
        IncidentId            = $alert.incidentId
        Devices               = (@($devices | Select-Object -Unique) -join ';')
        Users                 = (@($users | Select-Object -Unique) -join ';')
        MitreTechniques       = (@($alert.mitreTechniques) -join ';')
        RecommendedActions    = $recommended
        AlertWebUrl           = $alert.alertWebUrl
    })
}
Write-Progress -Activity 'Shaping alerts' -Completed

$sortedRows = @($rows | Sort-Object -Property CreatedDateTime -Descending)
if ($sortedRows.Count -gt 0) {
    $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning ('No alerts matched the filter in the last {0} days; no CSV was written.' -f $DaysBack)
}

Write-Host ''
Write-Host ('Defender XDR alerts summary (last {0} days)' -f $DaysBack) -ForegroundColor Cyan
Write-Host ('  Alerts exported : {0} -> {1}' -f $sortedRows.Count, $OutputPath)
Write-Host '  By severity:' -ForegroundColor Yellow
foreach ($level in @('high', 'medium', 'low', 'informational')) {
    $levelCount = @($sortedRows | Where-Object { $_.Severity -eq $level }).Count
    if ($levelCount -gt 0) { Write-Host ('    {0,-14}: {1}' -f $level, $levelCount) }
}
Write-Host '  By service source:' -ForegroundColor Yellow
foreach ($group in ($sortedRows | Group-Object -Property ServiceSource | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-32}: {1}' -f $group.Name, $group.Count)
}
$topDevices = @($sortedRows | Where-Object { -not [string]::IsNullOrEmpty($_.Devices) } | ForEach-Object { $_.Devices.Split(';') } |
    Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 10)
if ($topDevices.Count -gt 0) {
    Write-Host '  Top devices by alert count:' -ForegroundColor Yellow
    foreach ($device in $topDevices) {
        Write-Host ('    {0,-40}: {1}' -f $device.Name, $device.Count)
    }
}

if ($PassThru) {
    $sortedRows
}
#endregion Main
