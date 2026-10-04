<#
.SYNOPSIS
    Inventories the BitLocker recovery keys escrowed in Entra ID, joined to the owning device, optionally including the key material for selected devices.
.DESCRIPTION
    Lists bitlockerRecoveryKey objects from Microsoft Graph v1.0 (/informationProtection/bitlocker/recoveryKeys) and joins
    each key to its Entra device (/devices) for the display name, platform and join type. Without -DeviceName every key in
    the tenant is listed; with -DeviceName the matching devices are resolved first and their keys are read with the deviceId
    filter. -IncludeKey adds the recovery password (GET .../recoveryKeys/{id}?$select=key). Exports to CSV, optionally to the pipeline.
.PARAMETER DeviceName
    One or more wildcard patterns matched against the Entra device display name, for example 'LT-FIN-*', 'DT-0042'.
.PARAMETER IncludeKey
    Also retrieve the 48-digit recovery password of every listed key. Requires -DeviceName and BitLockerKey.Read.All; every read is audited.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneBitLockerRecoveryKeys_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneBitLockerRecoveryKeys.ps1
    Lists every escrowed key with device name, volume type, creation date and whether it is the newest key of its device.
.EXAMPLE
    PS> .\Get-IntuneBitLockerRecoveryKeys.ps1 -DeviceName 'LT-0042' -IncludeKey -PassThru | Format-Table DeviceName, VolumeType, CreatedDateTime, RecoveryKey
    Retrieves the recovery passwords of one device for a support call; the read is logged in the Entra ID audit log.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : BitLockerKey.ReadBasic.All and Device.Read.All; BitLockerKey.Read.All only with -IncludeKey (delegated).
    Category    : Devices & remote actions
    Changes     : No
    Notes       : With delegated permissions the signed-in user must own the device or hold a role such as Helpdesk Administrator,
                  Security Reader, Cloud Device Administrator or Intune Administrator. Reading key material is written to the
                  Entra ID audit log (KeyManagement > "Read BitLocker key") and the CSV then holds clear-text recovery passwords:
                  protect and delete it after use. Old keys stay escrowed after a rotation; IsNewestForDevice marks the current one. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/bitlocker-list-recoverykeys
.LINK
    https://learn.microsoft.com/graph/api/bitlockerrecoverykey-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$DeviceName,

    [Parameter()]
    [switch]$IncludeKey,

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
$hasDeviceName = ($null -ne $DeviceName -and @($DeviceName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0)
if ($IncludeKey -and -not $hasDeviceName) {
    throw '-IncludeKey requires -DeviceName so that recovery passwords are only retrieved for specific devices.'
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneBitLockerRecoveryKeys_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$scopes = @('BitLockerKey.ReadBasic.All', 'Device.Read.All')
if ($IncludeKey) { $scopes += 'BitLockerKey.Read.All' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
# Keys only carry the Entra deviceId, so the directory device list is read once and indexed instead of one lookup per key.
try { $directoryDevices = @(Invoke-GraphPaged -Uri ($graphV1 + '/devices?$select=deviceId,displayName,operatingSystem,trustType')) }
catch { throw "Failed to read the Entra ID device list: $($_.Exception.Message)" }
$deviceIndex = @{}
$targetIds = @{}
foreach ($directoryDevice in $directoryDevices) {
    $deviceIndex[[string]$directoryDevice.deviceId] = $directoryDevice
    if ($hasDeviceName) {
        foreach ($pattern in $DeviceName) {
            if ($directoryDevice.displayName -like $pattern) { $targetIds[[string]$directoryDevice.deviceId] = $true; break }
        }
    }
}
Write-Verbose ('{0} directory devices indexed.' -f $deviceIndex.Count)
if ($hasDeviceName -and $targetIds.Count -eq 0) { Write-Warning 'No Entra ID device matched -DeviceName; nothing to report.'; return }

$keysUri = $graphV1 + '/informationProtection/bitlocker/recoveryKeys?$select=id,createdDateTime,deviceId,volumeType'
$keys = @()
if ($hasDeviceName -and $targetIds.Count -le 50) {
    # A handful of targets: use the documented deviceId filter instead of walking the whole tenant key list.
    foreach ($targetId in @($targetIds.Keys)) {
        try { $keys += @(Invoke-GraphPaged -Uri ("{0}&`$filter=deviceId eq '{1}'" -f $keysUri, $targetId)) }
        catch { Write-Warning ('Failed to list keys for device {0} ({1}): {2}' -f $deviceIndex[$targetId].displayName, $targetId, $_.Exception.Message) }
        Start-Sleep -Milliseconds 200
    }
}
else {
    try { $keys = @(Invoke-GraphPaged -Uri $keysUri) } catch { throw "Failed to list BitLocker recovery keys: $($_.Exception.Message)" }
    if ($hasDeviceName) { $keys = @($keys | Where-Object { $targetIds.ContainsKey([string]$_.deviceId) }) }
}
Write-Verbose ('{0} recovery keys retrieved.' -f $keys.Count)

$newestKeyByDevice = @{}
foreach ($group in ($keys | Group-Object -Property deviceId)) {
    $newest = $group.Group | Sort-Object -Property { ConvertTo-UtcDateTime -Value $_.createdDateTime } -Descending | Select-Object -First 1
    $newestKeyByDevice[[string]$group.Name] = [string]$newest.id
}
if ($IncludeKey -and $keys.Count -gt 0) {
    Write-Warning ('Reading the recovery password of {0} key(s); each read is recorded in the Entra ID audit log and the output holds clear-text keys.' -f $keys.Count)
}

$report = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($key in $keys) {
    $index++
    $keyDeviceId = [string]$key.deviceId; $device = $deviceIndex[$keyDeviceId]; $recoveryKey = $null
    if ($IncludeKey) {
        Write-Progress -Activity 'Reading BitLocker recovery passwords' -Status ('{0} of {1}' -f $index, $keys.Count) -PercentComplete ([int](($index / $keys.Count) * 100))
        $keyUri = '{0}/informationProtection/bitlocker/recoveryKeys/{1}?$select=key' -f $graphV1, $key.id
        try { $recoveryKey = (Invoke-MgGraphRequest -Method GET -Uri $keyUri -OutputType PSObject -ErrorAction Stop).key }
        catch { Write-Warning ('Failed to read key {0} for device {1}: {2}' -f $key.id, $device.displayName, $_.Exception.Message) }
        Start-Sleep -Milliseconds 200
    }
    $report.Add([PSCustomObject]@{
            DeviceName        = $device.displayName
            OperatingSystem   = $device.operatingSystem
            TrustType         = $device.trustType
            DeviceId          = $keyDeviceId
            KeyId             = $key.id
            VolumeType        = $key.volumeType
            CreatedDateTime   = ConvertTo-UtcDateTime -Value $key.createdDateTime
            IsNewestForDevice = ($newestKeyByDevice[$keyDeviceId] -eq [string]$key.id)
            RecoveryKey       = $recoveryKey
        })
}
Write-Progress -Activity 'Reading BitLocker recovery passwords' -Completed

if ($report.Count -eq 0) { Write-Warning 'No BitLocker recovery keys were found; no CSV file was written.' }
else {
    $report | Sort-Object -Property DeviceName, CreatedDateTime | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}

Write-Host ''
Write-Host ('Recovery keys listed : {0} (across {1} devices)' -f $report.Count, $newestKeyByDevice.Count) -ForegroundColor Cyan
Write-Host ('Keys of unknown device: {0}' -f @($report | Where-Object { [string]::IsNullOrEmpty($_.DeviceName) }).Count) -ForegroundColor Yellow

if ($PassThru) { $report }
#endregion Main
