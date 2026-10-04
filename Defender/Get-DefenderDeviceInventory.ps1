<#
.SYNOPSIS
    Exports the Defender for Endpoint device inventory (latest DeviceInfo record per device) with sensor health and onboarding status.
.DESCRIPTION
    Runs an Advanced Hunting query through Microsoft Graph (POST v1.0 /security/runHuntingQuery) that takes the most recent
    DeviceInfo heartbeat per DeviceId within the last -Days days and projects OS, build, onboarding status, sensor health,
    device group, join type, exposure level, public IP, logged-on users and hardware model. Optional filters narrow the list to
    one OS family or to devices whose sensor is not healthy. Writes a CSV and prints a summary by OS platform, sensor health,
    onboarding status and exposure level.
.PARAMETER Days
    Timespan of the query in days (1-30, default 7). Devices that did not report within the window are not listed.
.PARAMETER OnlyUnhealthy
    Returns only devices whose SensorHealthState is not Active or whose OnboardingStatus is not Onboarded.
.PARAMETER OsPlatform
    Prefix match on OSPlatform, for example Windows, Windows11, WindowsServer, macOS, Linux, Android or iOS.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderDeviceInventory_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the device rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderDeviceInventory.ps1
    Exports every device seen in the last 7 days and prints the OS, sensor health, onboarding and exposure breakdown.
.EXAMPLE
    PS> .\Get-DefenderDeviceInventory.ps1 -Days 30 -OnlyUnhealthy -OsPlatform WindowsServer -OutputPath C:\Temp\UnhealthyServers.csv -Verbose
    Lists Windows Server devices with an inactive, impaired or misconfigured sensor over the full 30-day window.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access.
    Category    : Advanced hunting (Graph)
    Changes     : No
    Notes       : Advanced hunting caps results per query (10,000 rows in the portal, 100,000 through the API); -Days maps to the
                  Timespan property (P<n>D). Devices that are discovered but not onboarded only appear when device discovery is on.
                  LoggedOnUsers is flattened to DOMAIN\user pairs separated by '; '.
.LINK
    https://learn.microsoft.com/graph/api/security-security-runhuntingquery
.LINK
    https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceinfo-table
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$Days = 7,

    [Parameter()]
    [switch]$OnlyUnhealthy,

    [Parameter()]
    [string]$OsPlatform,

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

function Invoke-HuntingQuery {
    <# Runs an Advanced Hunting KQL query through Microsoft Graph and returns the result rows. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$Days = 7
    )
    $body = @{ Query = $Query; Timespan = ('P{0}D' -f $Days) }
    $response = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
    if ($null -eq $response.results) { return @() }
    return @($response.results)
}

function ConvertTo-ReportRow {
    <# Copies one hunting result row into a PSCustomObject in projection order: dynamic arrays joined with '; ', ISO timestamps as UTC [datetime]. #>
    param([Parameter(Mandatory = $true)][object]$Row)
    $shaped = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [array]) { $value = @($value | ForEach-Object { if ($_ -is [string] -or $_ -is [ValueType]) { [string]$_ } else { $_ | ConvertTo-Json -Compress } }) -join '; ' }
        elseif ($value -is [string] -and $value -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') { $value = [datetime]::Parse($value, [cultureinfo]::InvariantCulture, 'AdjustToUniversal') }
        $shaped[$property.Name] = $value
    }
    return [PSCustomObject]$shaped
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderDeviceInventory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('ThreatHunting.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# Filters run after arg_max so the latest record decides health, not an older heartbeat that happened to match.
# Backslash and single quote are escaped so the user value is a safe KQL string literal.
$filters = @()
if (-not [string]::IsNullOrWhiteSpace($OsPlatform)) { $filters += "| where OSPlatform startswith '{0}'" -f $OsPlatform.Replace('\', '\\').Replace("'", "\'") }
if ($OnlyUnhealthy) { $filters += "| where SensorHealthState != 'Active' or OnboardingStatus != 'Onboarded'" }
$query = @"
DeviceInfo
| where isnotempty(OSPlatform)
| summarize arg_max(Timestamp, *) by DeviceId
$($filters -join "`n")
| project Timestamp, DeviceName, DeviceId, OSPlatform, OSVersion, OSBuild, OnboardingStatus, SensorHealthState, MachineGroup, DeviceType, JoinType,
    IsAzureADJoined, AadDeviceId, ExposureLevel, PublicIP, LoggedOnUsers, ClientVersion, DeviceCategory, Model, Vendor
| order by DeviceName asc
"@
Write-Verbose "Running query:`n$query"
try { $rows = @(Invoke-HuntingQuery -Query $query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }
if ($rows.Count -eq 0) { Write-Warning ('No devices matched in the last {0} day(s); nothing exported.' -f $Days); return }

$report = foreach ($row in $rows) {
    $shaped = ConvertTo-ReportRow -Row $row
    # LoggedOnUsers is a JSON array of {UserName, DomainName, Sid}; DOMAIN\user reads better in Excel than raw JSON.
    $users = foreach ($user in @($row.LoggedOnUsers)) {
        if ($null -eq $user) { continue }
        if ($user -is [string]) { $user } elseif ([string]::IsNullOrWhiteSpace($user.DomainName)) { [string]$user.UserName } else { '{0}\{1}' -f $user.DomainName, $user.UserName }
    }
    $shaped.LoggedOnUsers = (@($users) -join '; ')
    $shaped
}
$report = @($report)
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$unhealthy = @($report | Where-Object { $_.SensorHealthState -ne 'Active' -or $_.OnboardingStatus -ne 'Onboarded' }).Count
Write-Host ('Defender device inventory (last {0} days): {1} device(s), {2} with an unhealthy or not onboarded sensor' -f $Days, $report.Count, $unhealthy) -ForegroundColor Cyan
foreach ($dimension in @('OSPlatform', 'SensorHealthState', 'OnboardingStatus', 'ExposureLevel')) {
    $parts = foreach ($group in ($report | Group-Object -Property $dimension | Sort-Object -Property Count -Descending)) {
        $label = $group.Name
        if ([string]::IsNullOrWhiteSpace($label)) { $label = '(blank)' }
        '{0} {1}' -f $group.Count, $label
    }
    Write-Host ('  {0,-18}: {1}' -f $dimension, (@($parts) -join ' | ')) -ForegroundColor Yellow
}
Write-Host ('  Report -> {0}' -f $OutputPath)

if ($PassThru) { $report }
#endregion Main
