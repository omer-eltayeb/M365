<#
.SYNOPSIS
    Exports the Microsoft Defender for Endpoint device inventory with sensor health, risk and exposure details.
.DESCRIPTION
    Acquires an app-only token for the Defender for Endpoint API and lists devices with GET /machines, building an optional
    server-side $filter from -HealthStatus, -RiskScore, -ExposureLevel, -OsPlatform and -LastSeenOlderThanDays. Exports every
    device (identity, OS build, sensor health, onboarding state, risk, exposure, Entra join state, tags, device group, IP addresses,
    device value, management channel, Defender Antivirus status) to CSV and prints a health / risk / exposure summary.
.PARAMETER TenantId
    Directory (tenant) ID or verified domain of the tenant that hosts the app registration.
.PARAMETER AppCredential
    PSCredential whose user name is the application (client) ID and whose password is the client secret.
.PARAMETER HealthStatus
    Sensor health to filter on: Active, Inactive, ImpairedCommunication, NoSensorData or NoSensorDataImpairedCommunication.
.PARAMETER RiskScore
    Risk score to filter on: None, Informational, Low, Medium or High.
.PARAMETER ExposureLevel
    Exposure level to filter on: None, Low, Medium or High.
.PARAMETER OsPlatform
    OS platform to filter on, for example Windows11, Windows10, WindowsServer2022, macOS, Linux, iOS or Android.
.PARAMETER LastSeenOlderThanDays
    Only return devices whose sensor last reported more than this many days ago (stale devices).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\MDEMachines_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the device objects to the pipeline.
.EXAMPLE
    PS> $cred = Get-Credential -UserName '<application-id>' -Message 'Client secret'
    PS> .\Get-MDEMachines.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred
    Exports every device known to Defender for Endpoint and prints the health, risk and exposure summary.
.EXAMPLE
    PS> .\Get-MDEMachines.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -HealthStatus Inactive -LastSeenOlderThanDays 30 -PassThru | Format-Table ComputerDnsName, LastSeen, OsPlatform
    Lists devices whose sensor is inactive and has been silent for more than 30 days, candidates for offboarding or clean-up.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x (REST calls only, no modules)
    Permissions : Application permission Machine.Read.All (WindowsDefenderATP API) granted with admin consent to an app registration.
    Category    : Defender for Endpoint API
    Changes     : No
    Notes       : Pages of up to 10,000 devices are followed automatically; only devices seen within the tenant's data retention period are returned. Dates are UTC.
.LINK
    https://learn.microsoft.com/defender-endpoint/api/get-machines
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [pscredential]$AppCredential,

    [Parameter()]
    [ValidateSet('Active', 'Inactive', 'ImpairedCommunication', 'NoSensorData', 'NoSensorDataImpairedCommunication')]
    [string]$HealthStatus,

    [Parameter()]
    [ValidateSet('None', 'Informational', 'Low', 'Medium', 'High')]
    [string]$RiskScore,

    [Parameter()]
    [ValidateSet('None', 'Low', 'Medium', 'High')]
    [string]$ExposureLevel,

    [Parameter()]
    [string]$OsPlatform,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$LastSeenOlderThanDays,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$baseUri = 'https://api.securitycenter.microsoft.com/api'

#region Helpers
function Get-MdeAccessToken {
    <# Acquires an app-only token for the Defender for Endpoint API with the client-credentials flow. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [pscredential]$AppCredential
    )
    $body = @{
        client_id     = $AppCredential.UserName
        client_secret = $AppCredential.GetNetworkCredential().Password
        scope         = 'https://api.securitycenter.microsoft.com/.default'
        grant_type    = 'client_credentials'
    }
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $response = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    return $response.access_token
}

function Invoke-MdeRequest {
    <# Calls the Defender for Endpoint API; GET requests follow @odata.nextLink. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [object]$Body
    )
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    if ($Method -ne 'GET') {
        $json = $null
        if ($null -ne $Body) { $json = $Body | ConvertTo-Json -Depth 10 }
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json -ErrorAction Stop
    }
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $response = Invoke-RestMethod -Method GET -Uri $nextLink -Headers $headers -ErrorAction Stop
        if ($null -ne $response.PSObject.Properties['value']) { foreach ($item in $response.value) { $results.Add($item) } }
        else { $results.Add($response) }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}

function ConvertTo-UtcDateTime {
    <# Normalises an API date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('MDEMachines_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { $token = Get-MdeAccessToken -TenantId $TenantId -AppCredential $AppCredential }
catch { throw "Unable to acquire a Defender for Endpoint API token: $($_.Exception.Message)" }

$filterParts = @()
if (-not [string]::IsNullOrEmpty($HealthStatus)) { $filterParts += "healthStatus eq '$HealthStatus'" }
if (-not [string]::IsNullOrEmpty($RiskScore)) { $filterParts += "riskScore eq '$RiskScore'" }
if (-not [string]::IsNullOrEmpty($ExposureLevel)) { $filterParts += "exposureLevel eq '$ExposureLevel'" }
if (-not [string]::IsNullOrWhiteSpace($OsPlatform)) { $filterParts += "osPlatform eq '$($OsPlatform.Trim())'" }
if ($LastSeenOlderThanDays -gt 0) {
    # InvariantCulture keeps ':' as the time separator regardless of the local culture, so the OData literal stays valid.
    $cutoff = [datetime]::UtcNow.AddDays(-$LastSeenOlderThanDays).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $filterParts += "lastSeen lt $cutoff"
}
$uri = "$baseUri/machines"
if ($filterParts.Count -gt 0) { $uri = '{0}?$filter={1}' -f $uri, ($filterParts -join ' and ') }
Write-Verbose "Querying $uri"
try { $machines = @(Invoke-MdeRequest -Token $token -Uri $uri) }
catch {
    # The service answers 404 instead of an empty collection when no device matches.
    if ($null -ne $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { $machines = @() } else { throw "Failed to list devices: $($_.Exception.Message)" }
}

$rows = @(foreach ($machine in ($machines | Sort-Object -Property computerDnsName)) {
        [PSCustomObject]@{
            Id                    = $machine.id
            ComputerDnsName       = $machine.computerDnsName
            OsPlatform            = $machine.osPlatform
            OsVersion             = $machine.osVersion
            OsBuild               = $machine.osBuild
            Version               = $machine.version
            LastSeen              = ConvertTo-UtcDateTime -Value $machine.lastSeen
            FirstSeen             = ConvertTo-UtcDateTime -Value $machine.firstSeen
            HealthStatus          = $machine.healthStatus
            OnboardingStatus      = $machine.onboardingStatus
            RiskScore             = $machine.riskScore
            ExposureLevel         = $machine.exposureLevel
            IsAadJoined           = $machine.isAadJoined
            AadDeviceId           = $machine.aadDeviceId
            MachineTags           = (@($machine.machineTags) -join ';')
            RbacGroupName         = $machine.rbacGroupName
            LastIpAddress         = $machine.lastIpAddress
            LastExternalIpAddress = $machine.lastExternalIpAddress
            DeviceValue           = $machine.deviceValue
            ManagedBy             = $machine.managedBy
            DefenderAvStatus      = $machine.defenderAvStatus
        }
    })
if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 } else { Write-Warning 'No device matched the given filter; nothing was exported.' }

Write-Host ('Defender for Endpoint devices: {0} (report: {1})' -f $rows.Count, $OutputPath) -ForegroundColor Cyan
foreach ($dimension in @('HealthStatus', 'RiskScore', 'ExposureLevel')) {
    $groups = @($rows | Group-Object -Property $dimension | Sort-Object -Property Count -Descending |
            ForEach-Object { '{0}={1}' -f $(if ([string]::IsNullOrEmpty($_.Name)) { 'Unknown' } else { $_.Name }), $_.Count })
    Write-Host ('  {0,-14} {1}' -f $dimension, ($groups -join ', ')) -ForegroundColor Green
}

if ($PassThru) { $rows }
#endregion Main
