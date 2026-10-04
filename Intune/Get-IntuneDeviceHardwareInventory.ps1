<#
.SYNOPSIS
    Builds a per-device hardware inventory (storage, memory, TPM, BIOS, battery, network) for Intune managed devices.
.DESCRIPTION
    Lists managed devices from Microsoft Graph v1.0 (/deviceManagement/managedDevices) with optional platform and
    wildcard name filters, then reads each device's hardwareInformation from the beta endpoint, because Intune only
    returns TPM, BIOS, battery and IP details on a single-device GET with an explicit $select.
    Storage and memory are converted to GB, the free-space percentage is calculated and devices below
    -LowDiskThresholdGB are flagged. The inventory is exported to CSV and summarised on the console.
.PARAMETER OperatingSystem
    Restrict the inventory to one platform: Windows, iOS, Android, macOS or Linux (server-side $filter).
.PARAMETER DeviceName
    One or more wildcard patterns matched against the device name, for example 'LT-*', 'DT-00?2'.
.PARAMETER LowDiskThresholdGB
    Devices with less free storage than this value (GB) are flagged LowDiskSpace = True. Default 20.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneHardwareInventory_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the inventory objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneDeviceHardwareInventory.ps1
    Inventories every managed device and writes the CSV to .\Reports.
.EXAMPLE
    PS> .\Get-IntuneDeviceHardwareInventory.ps1 -OperatingSystem Windows -LowDiskThresholdGB 30 -PassThru | Where-Object { $_.LowDiskSpace }
    Lists the Windows devices with less than 30 GB free so they can be targeted for clean-up.
.EXAMPLE
    PS> .\Get-IntuneDeviceHardwareInventory.ps1 -DeviceName 'LT-FIN-*' -OutputPath C:\Temp\finance-hardware.csv -Verbose
    Inventories the finance laptops only and saves the report to a custom path.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All (delegated); Intune Read Only Operator or higher.
    Category    : Devices & remote actions
    Changes     : No
    Notes       : Hardware details are read from the beta endpoint, which Microsoft may change without notice. One Graph
                  call is made per device with a 200 ms pause, so a 5,000-device tenant takes roughly 20 minutes. TPM,
                  BIOS, battery, licensing and wired IP fields are only reported by Windows devices; other platforms
                  return blanks for them. Storage values are rounded to two decimals.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-get?view=graph-rest-beta
.LINK
    https://learn.microsoft.com/graph/api/resources/intune-devices-hardwareinformation?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'Linux')]
    [string]$OperatingSystem,

    [Parameter()]
    [string[]]$DeviceName,

    [Parameter()]
    [ValidateRange(1, 10000)]
    [int]$LowDiskThresholdGB = 20,

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

function ConvertTo-Gigabytes {
    <# Converts a byte count to GB with two decimals; returns $null when the value is missing or zero. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$Bytes
    )
    if ($null -eq $Bytes -or [double]$Bytes -le 0) { return $null }
    return [math]::Round([double]$Bytes / 1GB, 2)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneHardwareInventory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('DeviceManagementManagedDevices.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$listUri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,model,manufacturer,serialNumber'
if (-not [string]::IsNullOrWhiteSpace($OperatingSystem)) { $listUri += "&`$filter=operatingSystem eq '$OperatingSystem'" }
try {
    $devices = @(Invoke-GraphPaged -Uri $listUri)
}
catch {
    throw "Failed to retrieve managed devices from Microsoft Graph: $($_.Exception.Message)"
}
if ($null -ne $DeviceName -and $DeviceName.Count -gt 0) {
    $devices = @($devices | Where-Object { $name = [string]$_.deviceName; @($DeviceName | Where-Object { $name -like $_ }).Count -gt 0 })
}
Write-Verbose ('{0} devices selected for hardware inventory.' -f $devices.Count)

# beta: hardwareInformation, physicalMemoryInBytes and the MAC addresses are only returned by a single-device GET on the beta endpoint.
$detailUri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices/{0}?$select=id,deviceName,hardwareInformation,physicalMemoryInBytes,processorArchitecture,ethernetMacAddress,wiFiMacAddress,totalStorageSpaceInBytes,freeStorageSpaceInBytes'
$report = New-Object -TypeName System.Collections.Generic.List[object]
$detailFailures = 0
$index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Collecting hardware inventory' -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    $detail = $null
    try {
        $detail = Invoke-MgGraphRequest -Method GET -Uri ($detailUri -f $device.id) -OutputType PSObject -ErrorAction Stop
    }
    catch {
        $detailFailures++
        Write-Warning ('Hardware details could not be read for {0}: {1}' -f $device.deviceName, $_.Exception.Message)
    }
    Start-Sleep -Milliseconds 200

    # When the detail call failed every property below resolves to $null and the row still carries the v1.0 basics.
    $hardware = $detail.hardwareInformation
    $totalGB = ConvertTo-Gigabytes -Bytes $detail.totalStorageSpaceInBytes
    $freeGB = ConvertTo-Gigabytes -Bytes $detail.freeStorageSpaceInBytes
    $freePercent = $null
    if ($null -ne $totalGB -and $null -ne $freeGB) { $freePercent = [math]::Round(($freeGB / $totalGB) * 100, 1) }

    $report.Add([PSCustomObject]@{
            DeviceName            = $device.deviceName
            UserPrincipalName     = $device.userPrincipalName
            OperatingSystem       = $device.operatingSystem
            OSVersion             = $device.osVersion
            Model                 = $device.model
            Manufacturer          = $device.manufacturer
            SerialNumber          = $device.serialNumber
            TotalStorageGB        = $totalGB
            FreeStorageGB         = $freeGB
            FreeStoragePercent    = $freePercent
            LowDiskSpace          = ($null -ne $freeGB -and $freeGB -lt $LowDiskThresholdGB)
            MemoryGB              = ConvertTo-Gigabytes -Bytes $detail.physicalMemoryInBytes
            ProcessorArchitecture = $detail.processorArchitecture
            TpmVersion            = $hardware.tpmSpecificationVersion
            TpmManufacturer       = $hardware.tpmManufacturer
            BiosVersion           = $hardware.systemManagementBIOSVersion
            BatteryHealthPercent  = $hardware.batteryHealthPercentage
            BatteryChargeCycles   = $hardware.batteryChargeCycles
            IPv4                  = $hardware.ipAddressV4
            WiredIPv4             = (@($hardware.wiredIPv4Addresses) -join ', ')
            WifiMac               = $detail.wiFiMacAddress
            EthernetMac           = $detail.ethernetMacAddress
            OsBuild               = $hardware.osBuildNumber
            DeviceLicensingStatus = $hardware.deviceLicensingStatus
            ManagedDeviceId       = $device.id
        })
}
Write-Progress -Activity 'Collecting hardware inventory' -Completed

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No managed devices matched the selection; no CSV file was written.'
}

$lowDiskCount = @($report | Where-Object { $_.LowDiskSpace }).Count
Write-Host ''
Write-Host ('Devices inventoried        : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host ('Hardware detail failures   : {0}' -f $detailFailures) -ForegroundColor Yellow
Write-Host ('Below {0,4} GB free storage : {1}' -f $LowDiskThresholdGB, $lowDiskCount) -ForegroundColor Yellow
foreach ($group in ($report | Group-Object -Property OperatingSystem | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-20} {1,6}' -f $group.Name, $group.Count)
}

if ($PassThru) {
    $report
}
#endregion Main
