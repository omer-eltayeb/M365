<#
.SYNOPSIS
    Reports the encryption state of Intune managed devices and, optionally, whether Windows devices have a BitLocker recovery key escrowed in Entra ID.
.DESCRIPTION
    Reads every managed device from Microsoft Graph v1.0 (/deviceManagement/managedDevices) with its isEncrypted flag and
    hardware details. With -CheckRecoveryKeys the tenant's BitLocker recovery key list is read once from
    /informationProtection/bitlocker/recoveryKeys, grouped by Entra device ID and joined to every Windows device as HasRecoveryKey,
    KeyCount and LatestKeyDate, which exposes encrypted devices that have no recoverable key. Exports to CSV, optionally to the pipeline.
.PARAMETER OperatingSystem
    Restrict the report to one platform: Windows, iOS, Android, macOS or Linux (server-side $filter).
.PARAMETER OnlyUnencrypted
    Report only devices whose isEncrypted flag is false or has not been reported.
.PARAMETER CheckRecoveryKeys
    Also check for escrowed BitLocker recovery keys (Windows devices only); requires BitLockerKey.ReadBasic.All.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneEncryptionReport_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneEncryptionReport.ps1 -OnlyUnencrypted
    Lists every managed device that is not reporting encryption and writes the CSV to .\Reports.
.EXAMPLE
    PS> .\Get-IntuneEncryptionReport.ps1 -OperatingSystem Windows -CheckRecoveryKeys -PassThru | Where-Object { $_.IsEncrypted -and -not $_.HasRecoveryKey }
    Finds encrypted Windows devices that have no BitLocker recovery key escrowed in Entra ID.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All; BitLockerKey.ReadBasic.All only with -CheckRecoveryKeys (delegated).
    Category    : Devices & remote actions
    Changes     : No
    Notes       : isEncrypted is what the device reported at its last check-in (BitLocker OS volume on Windows, FileVault on
                  macOS, device encryption on iOS/Android) and can lag behind the admin center Encryption report. Listing
                  recovery keys never returns key material; with delegated permissions the signed-in user needs a role such
                  as Helpdesk Administrator, Security Reader or Intune Administrator to see keys for devices they do not own.
                  The three key columns stay empty for non-Windows devices and without -CheckRecoveryKeys. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list
.LINK
    https://learn.microsoft.com/graph/api/bitlocker-list-recoverykeys
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'Linux')]
    [string]$OperatingSystem,

    [Parameter()]
    [switch]$OnlyUnencrypted,

    [Parameter()]
    [switch]$CheckRecoveryKeys,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneEncryptionReport_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$scopes = @('DeviceManagementManagedDevices.Read.All')
if ($CheckRecoveryKeys) { $scopes += 'BitLockerKey.ReadBasic.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$uri = $graphV1 + '/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,isEncrypted,' +
    'complianceState,manufacturer,model,serialNumber,lastSyncDateTime,azureADDeviceId'
if (-not [string]::IsNullOrWhiteSpace($OperatingSystem)) { $uri += "&`$filter=operatingSystem eq '$OperatingSystem'" }
try { $devices = @(Invoke-GraphPaged -Uri $uri) } catch { throw "Failed to retrieve managed devices from Microsoft Graph: $($_.Exception.Message)" }
Write-Verbose ('{0} managed devices retrieved.' -f $devices.Count)
if ($OnlyUnencrypted) { $devices = @($devices | Where-Object { $_.isEncrypted -ne $true }) }

# One paged read of the tenant key list is far cheaper than one filtered call per device; keys are grouped by Entra device ID.
$keysByDevice = @{}
if ($CheckRecoveryKeys) {
    $keysUri = $graphV1 + '/informationProtection/bitlocker/recoveryKeys?$select=id,createdDateTime,deviceId,volumeType'
    try { $keys = @(Invoke-GraphPaged -Uri $keysUri) } catch { throw "Failed to list BitLocker recovery keys: $($_.Exception.Message)" }
    foreach ($key in $keys) {
        $keyDeviceId = [string]$key.deviceId
        if (-not $keysByDevice.ContainsKey($keyDeviceId)) { $keysByDevice[$keyDeviceId] = New-Object -TypeName System.Collections.Generic.List[object] }
        $keysByDevice[$keyDeviceId].Add((ConvertTo-UtcDateTime -Value $key.createdDateTime))
    }
    Write-Verbose ('{0} recovery keys found for {1} distinct devices.' -f $keys.Count, $keysByDevice.Count)
}

$report = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($device in $devices) {
    $hasKey = $null; $keyCount = $null; $latestKey = $null
    if ($CheckRecoveryKeys -and $device.operatingSystem -eq 'Windows') {
        $hasKey = $false
        $keyCount = 0
        $entraDeviceId = [string]$device.azureADDeviceId
        if (-not [string]::IsNullOrEmpty($entraDeviceId) -and $keysByDevice.ContainsKey($entraDeviceId)) {
            $hasKey = $true
            $keyCount = $keysByDevice[$entraDeviceId].Count
            $latestKey = $keysByDevice[$entraDeviceId] | Sort-Object -Descending | Select-Object -First 1
        }
    }
    $report.Add([PSCustomObject]@{
            DeviceName        = $device.deviceName
            UserPrincipalName = $device.userPrincipalName
            OperatingSystem   = $device.operatingSystem
            OSVersion         = $device.osVersion
            IsEncrypted       = $device.isEncrypted
            ComplianceState   = $device.complianceState
            Manufacturer      = $device.manufacturer
            Model             = $device.model
            SerialNumber      = $device.serialNumber
            LastSyncDateTime  = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime
            HasRecoveryKey    = $hasKey
            KeyCount          = $keyCount
            LatestKeyDate     = $latestKey
            AzureADDeviceId   = $device.azureADDeviceId
            ManagedDeviceId   = $device.id
        })
}

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No devices matched the selection; no CSV file was written.'
}

$encrypted = @($report | Where-Object { $_.IsEncrypted -eq $true }).Count
Write-Host ''
Write-Host ('Devices reported : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host ('Encrypted / not encrypted : {0} / {1}' -f $encrypted, ($report.Count - $encrypted)) -ForegroundColor Yellow
if ($CheckRecoveryKeys) {
    $missingKey = @($report | Where-Object { $_.OperatingSystem -eq 'Windows' -and $_.IsEncrypted -eq $true -and -not $_.HasRecoveryKey }).Count
    Write-Host ('Encrypted Windows devices without an escrowed recovery key: {0}' -f $missingKey) -ForegroundColor Red
}

if ($PassThru) {
    $report
}
#endregion Main
