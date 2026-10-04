<#
.SYNOPSIS
    Reports Microsoft Defender for Identity health issues (sensor and global) with severity, affected domains and fixes.
.DESCRIPTION
    Reads the Defender for Identity health issues through Microsoft Graph (GET /security/identities/healthIssues with a
    server-side $filter on status, severity and type) and returns one row per issue: type (sensor or global), issue type id,
    severity, status, affected domains and sensors, age in days, description, recommendations, the PowerShell commands
    Microsoft suggests to fix it and the additional information list. Exports the CSV and prints counts by severity and
    type, the most frequent issue titles and the sensors with the most open issues.
.PARAMETER Status
    Issue status to return: open (default), closed, suppressed or all.
.PARAMETER Severity
    Only issues with this severity: low, medium or high.
.PARAMETER HealthIssueType
    Only issues of this type: sensor (one specific sensor) or global (Defender for Identity configuration).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderIdentityHealthIssues_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderIdentityHealthIssues.ps1
    Exports every open health issue and prints the summary.
.EXAMPLE
    PS> .\Get-DefenderIdentityHealthIssues.ps1 -Severity high -HealthIssueType sensor -OutputPath C:\Temp\MdiSensorIssues.csv -Verbose
    Exports only the high-severity sensor issues, for example sensors that stopped communicating or are missing a prerequisite.
.EXAMPLE
    PS> .\Get-DefenderIdentityHealthIssues.ps1 -Status all -PassThru | Group-Object -Property DisplayName | Sort-Object -Property Count -Descending
    Shows which issue types recur most often, including the ones already closed.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityIdentitiesHealth.Read.All (delegated); Security Reader, Security Operator or Security Administrator.
    Category    : Defender for Identity
    Changes     : No
    Notes       : Requires a Microsoft Defender for Identity licence (standalone, EMS E5 or Microsoft 365 E5) and an MDI workspace;
                  tenants without one get an error or an empty result. The /security/identities endpoints are generally available
                  on v1.0. Closing or suppressing issues is done in the Defender portal (or with the ReadWrite scope).
.LINK
    https://learn.microsoft.com/graph/api/security-identitycontainer-list-healthissues
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('open', 'closed', 'suppressed', 'all')]
    [string]$Status = 'open',

    [Parameter()]
    [ValidateSet('low', 'medium', 'high')]
    [string]$Severity,

    [Parameter()]
    [ValidateSet('sensor', 'global')]
    [string]$HealthIssueType,

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
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderIdentityHealthIssues_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('SecurityIdentitiesHealth.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$filterParts = @()
if ($Status -ne 'all') { $filterParts += "status eq '$Status'" }
if (-not [string]::IsNullOrEmpty($Severity)) { $filterParts += "severity eq '$Severity'" }
if (-not [string]::IsNullOrEmpty($HealthIssueType)) { $filterParts += "healthIssueType eq '$HealthIssueType'" }
$uri = 'https://graph.microsoft.com/v1.0/security/identities/healthIssues'
if ($filterParts.Count -gt 0) { $uri += '?$filter=' + ($filterParts -join ' and ') }
Write-Verbose "Requesting $uri"
try { $issues = @(Invoke-GraphPaged -Uri $uri) }
catch { throw "Failed to read Defender for Identity health issues (is MDI licensed and the workspace created?): $($_.Exception.Message)" }
Write-Verbose "Retrieved $($issues.Count) health issues."

$now = [datetime]::UtcNow
$severityRank = @{ high = 3; medium = 2; low = 1 }
$rows = foreach ($issue in $issues) {
    $created = ConvertTo-UtcDateTime -Value $issue.createdDateTime
    $additional = (@($issue.additionalInformation | Where-Object { $_ }) -join ' | ') -replace '^(.{500}).+$', '$1...'
    [PSCustomObject]@{
        Id                        = $issue.id
        DisplayName               = $issue.displayName
        HealthIssueType           = $issue.healthIssueType
        IssueTypeId               = $issue.issueTypeId
        Severity                  = $issue.severity
        Status                    = $issue.status
        DomainNames               = (@($issue.domainNames | Where-Object { $_ }) -join ';')
        SensorDnsNames            = (@($issue.sensorDNSNames | Where-Object { $_ }) -join ';')
        AgeDays                   = $(if ($null -ne $created) { [math]::Round(($now - $created).TotalDays, 1) } else { $null })
        CreatedDateTime           = $created
        LastModifiedDateTime      = ConvertTo-UtcDateTime -Value $issue.lastModifiedDateTime
        Description               = ([string]$issue.description) -replace '\s*[\r\n]+\s*', ' '
        Recommendations           = (@($issue.recommendations | Where-Object { $_ }) -join ' | ') -replace '\s*[\r\n]+\s*', ' '
        RecommendedActionCommands = (@($issue.recommendedActionCommands | Where-Object { $_ }) -join ' ; ')
        AdditionalInformation     = $additional
    }
}
$sortedRows = @($rows | Sort-Object -Property @{ Expression = { [int]$severityRank[[string]$_.Severity] }; Descending = $true }, CreatedDateTime)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No health issues matched the filter; no CSV was written.' }

Write-Host ''
Write-Host ('Defender for Identity health issues (status: {0})' -f $Status) -ForegroundColor Cyan
Write-Host ('  Issues exported : {0} -> {1}' -f $sortedRows.Count, $OutputPath)
Write-Host '  By severity / type:' -ForegroundColor Yellow
foreach ($level in @('high', 'medium', 'low')) {
    $levelRows = @($sortedRows | Where-Object { $_.Severity -eq $level })
    if ($levelRows.Count -eq 0) { continue }
    $sensorCount = @($levelRows | Where-Object { $_.HealthIssueType -eq 'sensor' }).Count
    Write-Host ('    {0,-8}: {1,4} ({2} sensor, {3} global)' -f $level, $levelRows.Count, $sensorCount, ($levelRows.Count - $sensorCount))
}
$topIssues = @($sortedRows | Group-Object -Property DisplayName | Sort-Object -Property Count -Descending | Select-Object -First 8)
if ($topIssues.Count -gt 0) {
    Write-Host '  Most frequent issues:' -ForegroundColor Yellow
    foreach ($group in $topIssues) { Write-Host ('    {0,4} x {1} ({2})' -f $group.Count, $group.Name, $group.Group[0].Severity) }
}
$topSensors = @($sortedRows | Where-Object { -not [string]::IsNullOrEmpty($_.SensorDnsNames) } | ForEach-Object { $_.SensorDnsNames.Split(';') } |
    Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 8)
if ($topSensors.Count -gt 0) {
    Write-Host '  Sensors with the most issues:' -ForegroundColor Yellow
    foreach ($group in $topSensors) { Write-Host ('    {0,4} x {1}' -f $group.Count, $group.Name) }
}
$oldest = $sortedRows | Where-Object { $_.Status -eq 'open' -and $null -ne $_.AgeDays } | Sort-Object -Property AgeDays -Descending | Select-Object -First 1
if ($null -ne $oldest) { Write-Host ('  Oldest open issue : "{0}" open for {1} days ({2})' -f $oldest.DisplayName, $oldest.AgeDays, $oldest.Severity) }

if ($PassThru) { $sortedRows }
#endregion Main
