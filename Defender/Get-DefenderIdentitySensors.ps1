<#
.SYNOPSIS
    Inventories Microsoft Defender for Identity sensors and flags unhealthy, outdated or misconfigured ones.
.DESCRIPTION
    Lists the Defender for Identity sensors through Microsoft Graph (GET /security/identities/sensors): type (domain
    controller, standalone, AD FS, AD CS, Entra Connect), domain, deployment status, health status, service status, version,
    open issue count, delayed-update setting and the domain controllers a standalone sensor monitors. The open sensor health
    issues (GET /security/identities/healthIssues) are matched to each sensor by DNS name so the row shows what is wrong.
    Every sensor gets a Flags column (NotHealthy, Deployment:<status>, Service:<status>, VersionBehind compared with the most
    common version in the tenant). Exports the CSV and prints counts by type, health, deployment status and version.
.PARAMETER OnlyFlagged
    Exports only the sensors that have at least one flag.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderIdentitySensors_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderIdentitySensors.ps1
    Exports every sensor with its health and version information and prints the fleet summary.
.EXAMPLE
    PS> .\Get-DefenderIdentitySensors.ps1 -OnlyFlagged -OutputPath C:\Temp\MdiSensorsToFix.csv -Verbose
    Exports only the sensors that need attention, with the open issues that explain why.
.EXAMPLE
    PS> .\Get-DefenderIdentitySensors.ps1 -PassThru | Where-Object { $_.Flags -like '*VersionBehind*' } | Select-Object DisplayName, Version, IsDelayedDeploymentEnabled
    Lists the sensors running an older version than the rest of the fleet together with their delayed-update setting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityIdentitiesSensors.Read.All and SecurityIdentitiesHealth.Read.All (delegated); Security Reader, Security
                  Operator or Security Administrator.
    Category    : Defender for Identity
    Changes     : No
    Notes       : Requires a Microsoft Defender for Identity licence and workspace. Sensors with delayed deployment enabled update
                  about 72 hours after the others, so a one-version lag on those sensors is expected. deploymentStatus
                  'unreachable' means the domain controller was removed from Active Directory without uninstalling the sensor.
.LINK
    https://learn.microsoft.com/graph/api/security-identitycontainer-list-sensors
.LINK
    https://learn.microsoft.com/graph/api/security-identitycontainer-list-healthissues
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$OnlyFlagged,

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

function Test-SensorNameMatch {
    <# True when one of an issue's sensor DNS names equals a sensor name or is that name with a DNS suffix appended. #>
    param([string[]]$IssueNames, [string[]]$SensorNames)
    foreach ($name in @($IssueNames | Where-Object { $_ })) {
        $lower = $name.ToLowerInvariant()
        foreach ($candidate in $SensorNames) { if ($lower -eq $candidate -or $lower -like "$candidate.*") { return $true } }
    }
    return $false
}

function ConvertTo-VersionOrNull {
    <# Parses a sensor version string such as 2.239.18124.58593 into [version]; returns $null when it does not parse. #>
    param([string]$Text)
    $parsed = $null
    if ([version]::TryParse([string]$Text, [ref]$parsed)) { return $parsed }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderIdentitySensors_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('SecurityIdentitiesSensors.Read.All', 'SecurityIdentitiesHealth.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$identitiesUri = 'https://graph.microsoft.com/v1.0/security/identities'
try { $sensors = @(Invoke-GraphPaged -Uri "$identitiesUri/sensors") }
catch { throw "Failed to list Defender for Identity sensors (is MDI licensed and the workspace created?): $($_.Exception.Message)" }
if ($sensors.Count -eq 0) { Write-Warning 'No Defender for Identity sensors were returned.'; return }
# Open sensor issues are fetched once and matched by DNS name; the per-sensor /healthIssues navigation would cost one call per sensor.
$openIssues = @()
try { $openIssues = @(Invoke-GraphPaged -Uri "$identitiesUri/healthIssues?`$filter=status eq 'open' and healthIssueType eq 'sensor'") }
catch { Write-Warning "Open health issues could not be read; the OpenIssues column stays empty: $($_.Exception.Message)" }

# The most common version is the fleet baseline; sensors below it are flagged (delayed-deployment sensors lag by design).
$versionGroups = @($sensors | Where-Object { -not [string]::IsNullOrEmpty($_.version) } | Group-Object -Property version | Sort-Object -Property Count, Name -Descending)
$baselineVersion = $null
if ($versionGroups.Count -gt 0) { $baselineVersion = ConvertTo-VersionOrNull -Text $versionGroups[0].Name }
$problemDeployment = @('outdated', 'updateFailed', 'notConfigured', 'unreachable', 'disconnected', 'startFailure')

$rows = foreach ($sensor in $sensors) {
    $dnsNames = @(@($sensor.displayName) + @($sensor.settings.domainControllerDnsNames) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $sensorIssues = @($openIssues | Where-Object { Test-SensorNameMatch -IssueNames $_.sensorDNSNames -SensorNames $dnsNames })
    $version = ConvertTo-VersionOrNull -Text $sensor.version
    $flags = @()
    if ([string]$sensor.healthStatus -ne 'healthy') { $flags += 'NotHealthy' }
    if ($problemDeployment -contains [string]$sensor.deploymentStatus) { $flags += ('Deployment:{0}' -f $sensor.deploymentStatus) }
    if (-not [string]::IsNullOrEmpty($sensor.serviceStatus) -and [string]$sensor.serviceStatus -ne 'running') { $flags += ('Service:{0}' -f $sensor.serviceStatus) }
    if ($null -ne $version -and $null -ne $baselineVersion -and $version -lt $baselineVersion) { $flags += 'VersionBehind' }
    [PSCustomObject]@{
        Id                         = $sensor.id
        DisplayName                = $sensor.displayName
        SensorType                 = $sensor.sensorType
        DomainName                 = $sensor.domainName
        DeploymentStatus           = $sensor.deploymentStatus
        HealthStatus               = $sensor.healthStatus
        ServiceStatus              = $sensor.serviceStatus
        OpenHealthIssuesCount      = $sensor.openHealthIssuesCount
        Version                    = $sensor.version
        BaselineVersion            = [string]$baselineVersion
        IsDelayedDeploymentEnabled = $sensor.settings.isDelayedDeploymentEnabled
        DomainControllerDnsNames   = (@($sensor.settings.domainControllerDnsNames | Where-Object { $_ }) -join ';')
        Description                = $sensor.settings.description
        CreatedDateTime            = ConvertTo-UtcDateTime -Value $sensor.createdDateTime
        Flags                      = ($flags -join ';')
        OpenIssues                 = (@($sensorIssues | ForEach-Object { '{0} ({1})' -f $_.displayName, $_.severity } | Select-Object -Unique) -join ';')
    }
}
$allRows = @($rows | Sort-Object -Property @{ Expression = { $_.Flags.Length -gt 0 }; Descending = $true }, DomainName, DisplayName)
$flaggedRows = @($allRows | Where-Object { -not [string]::IsNullOrEmpty($_.Flags) })
$exportRows = @($(if ($OnlyFlagged) { $flaggedRows } else { $allRows }))
if ($exportRows.Count -gt 0) { $exportRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No sensors matched the selection; no CSV was written.' }

Write-Host ''
Write-Host ('Defender for Identity sensors: {0} total, {1} flagged, {2} exported -> {3}' -f $allRows.Count, $flaggedRows.Count, $exportRows.Count, $OutputPath) -ForegroundColor Cyan
foreach ($dimension in @('SensorType', 'HealthStatus', 'DeploymentStatus')) {
    $parts = @($allRows | Group-Object -Property $dimension | Sort-Object -Property Count -Descending | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count })
    Write-Host ('  {0,-17}: {1}' -f $dimension, ($parts -join ', '))
}
Write-Host ('  {0,-17}: {1} (baseline {2})' -f 'Versions', (@($versionGroups | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '), $baselineVersion)
if ($flaggedRows.Count -gt 0) {
    Write-Host '  Sensors needing attention (sensor | flags | open issues):' -ForegroundColor Yellow
    foreach ($row in ($flaggedRows | Select-Object -First 15)) { Write-Host ('    {0,-28} | {1,-36} | {2}' -f $row.DisplayName, $row.Flags, $row.OpenIssues) }
}

if ($PassThru) { $exportRows }
#endregion Main
