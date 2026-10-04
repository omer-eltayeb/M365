<#
.SYNOPSIS
    Microsoft Defender Antivirus health report for Intune-managed Windows devices.
.DESCRIPTION
    Lists Windows devices from Microsoft Graph (v1.0 /deviceManagement/managedDevices) and reads the
    beta /windowsProtectionState of each device: real-time and malware protection, tamper protection,
    signature/engine versions, overdue signatures and scans, pending reboot and last report time.
    Each device is classified as Healthy, AttentionNeeded, Critical or NoDataReported (HealthStatus)
    with the individual findings in an Issues column. Exports to CSV and prints counts per status.
.PARAMETER DeviceName
    Wildcard pattern applied to the Intune device name, for example 'LT-*'.
.PARAMETER OnlyProblems
    Return only devices whose HealthStatus is not Healthy (including NoDataReported).
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneDefenderAVStatus_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneDefenderAVStatus.ps1
    Exports the Defender Antivirus state of every Windows device and prints counts per HealthStatus.
.EXAMPLE
    PS> .\Get-IntuneDefenderAVStatus.ps1 -OnlyProblems -PassThru | Where-Object { $_.HealthStatus -eq 'Critical' } | Format-Table DeviceName, UserPrincipalName, Issues
    Lists the devices on which malware or real-time protection is disabled.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Reporting & platform insights
    Changes     : No
    Notes       : windowsProtectionState exists only on the beta endpoint and may change without notice. The script
                  makes one Graph call per Windows device with a 200 ms pause, so expect roughly 4-5 devices per second
                  (about 4 minutes per 1,000 devices); the SDK retries HTTP 429 automatically. Devices that have not yet
                  reported Defender state return HTTP 404 and are listed as NoDataReported. Protection state is refreshed
                  at device check-in; a Critical finding should be confirmed on the device before acting on it.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-windowsprotectionstate-get?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DeviceName,

    [Parameter()]
    [switch]$OnlyProblems,

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
    <# Normalises a Graph date value (string or DateTime) to a UTC [datetime]; returns $null for empty or 0001-01-01 placeholders. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { $parsed = [datetime]$Value } catch { return $null }
    if ($parsed.Year -le 1) { return $null }
    return $parsed.ToUniversalTime()
}

function Test-GraphNotFoundError {
    <# Returns $true when an Invoke-MgGraphRequest error represents HTTP 404 (resource missing or not yet reported). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    $text = '{0} {1}' -f $ErrorRecord.Exception.Message, $ErrorRecord.ErrorDetails.Message
    return ($text -match 'NotFound|\b404\b|does not exist')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneDefenderAVStatus_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

$graphV1 = 'https://graph.microsoft.com/v1.0'
$graphBeta = 'https://graph.microsoft.com/beta'   # beta: windowsProtectionState is not exposed on the v1.0 managedDevice
$deviceUri = $graphV1 + '/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,osVersion,lastSyncDateTime,complianceState&$filter=operatingSystem eq ''Windows'''
try {
    $devices = @(Invoke-GraphPaged -Uri $deviceUri)
}
catch {
    throw "Failed to retrieve Windows managed devices from Microsoft Graph: $($_.Exception.Message)"
}
if (-not [string]::IsNullOrWhiteSpace($DeviceName)) {
    $devices = @($devices | Where-Object { $_.deviceName -like $DeviceName })
}
Write-Verbose ('{0} Windows devices selected.' -f $devices.Count)
if ($devices.Count -eq 0) {
    Write-Warning 'No Windows managed devices matched the specified criteria; nothing to report.'
    return
}

$report = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Reading Defender Antivirus state' -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))

    $state = $null
    $errorMessage = $null
    try {
        $state = Invoke-MgGraphRequest -Method GET -Uri ('{0}/deviceManagement/managedDevices/{1}/windowsProtectionState' -f $graphBeta, $device.id) -OutputType PSObject -ErrorAction Stop
    }
    catch {
        if (Test-GraphNotFoundError -ErrorRecord $_) {
            Write-Verbose ('{0}: no Windows protection state has been reported yet.' -f $device.deviceName)
        }
        else {
            $errorMessage = $_.Exception.Message
            Write-Warning ('{0}: could not read protection state: {1}' -f $device.deviceName, $errorMessage)
        }
    }

    $lastReported = $null
    if ($null -ne $state) { $lastReported = ConvertTo-UtcDateTime -Value $state.lastReportedDateTime }
    $issues = @()
    $healthStatus = 'NoDataReported'
    if ($null -ne $lastReported) {
        # Disabled protection is critical; everything else is hygiene that needs attention.
        if ($state.malwareProtectionEnabled -eq $false) { $issues += 'Malware protection disabled' }
        if ($state.realTimeProtectionEnabled -eq $false) { $issues += 'Real-time protection disabled' }
        $criticalCount = $issues.Count
        if ($state.tamperProtectionEnabled -eq $false) { $issues += 'Tamper protection off' }
        if ($state.signatureUpdateOverdue -eq $true) { $issues += 'Signature update overdue' }
        if ($state.fullScanOverdue -eq $true) { $issues += 'Full scan overdue' }
        if ($state.quickScanOverdue -eq $true) { $issues += 'Quick scan overdue' }
        if ($state.rebootRequired -eq $true) { $issues += 'Reboot required' }
        if ($criticalCount -gt 0) { $healthStatus = 'Critical' }
        elseif ($issues.Count -gt 0) { $healthStatus = 'AttentionNeeded' }
        else { $healthStatus = 'Healthy' }
    }

    $report.Add([PSCustomObject]@{
            DeviceName                     = $device.deviceName
            UserPrincipalName              = $device.userPrincipalName
            OSVersion                      = $device.osVersion
            ComplianceState                = $device.complianceState
            LastSyncDateTime               = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime
            HealthStatus                   = $healthStatus
            Issues                         = ($issues -join '; ')
            RealTimeProtectionEnabled      = $state.realTimeProtectionEnabled
            MalwareProtectionEnabled       = $state.malwareProtectionEnabled
            NetworkInspectionSystemEnabled = $state.networkInspectionSystemEnabled
            TamperProtectionEnabled        = $state.tamperProtectionEnabled
            IsVirtualMachine               = $state.isVirtualMachine
            DeviceState                    = $state.deviceState
            ProductStatus                  = $state.productStatus
            AntiMalwareVersion             = $state.antiMalwareVersion
            EngineVersion                  = $state.engineVersion
            SignatureVersion               = $state.signatureVersion
            SignatureUpdateOverdue         = $state.signatureUpdateOverdue
            FullScanOverdue                = $state.fullScanOverdue
            QuickScanOverdue               = $state.quickScanOverdue
            RebootRequired                 = $state.rebootRequired
            LastQuickScanDateTime          = ConvertTo-UtcDateTime -Value $state.lastQuickScanDateTime
            LastFullScanDateTime           = ConvertTo-UtcDateTime -Value $state.lastFullScanDateTime
            LastReportedDateTime           = $lastReported
            ManagedDeviceId                = $device.id
            Error                          = $errorMessage
        })
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading Defender Antivirus state' -Completed

$output = $report
if ($OnlyProblems) {
    $output = @($report | Where-Object { $_.HealthStatus -ne 'Healthy' })
}

if ($output.Count -gt 0) {
    $output | Sort-Object -Property HealthStatus, DeviceName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No devices matched the specified criteria; no CSV file was written.'
}

$statusColours = @{ Healthy = 'Green'; AttentionNeeded = 'Yellow'; Critical = 'Red'; NoDataReported = 'Gray' }
Write-Host ''
Write-Host ('Windows devices checked : {0}' -f $report.Count) -ForegroundColor Cyan
foreach ($status in @('Healthy', 'AttentionNeeded', 'Critical', 'NoDataReported')) {
    $count = @($report | Where-Object { $_.HealthStatus -eq $status }).Count
    Write-Host ('  {0,-16} {1,6}' -f $status, $count) -ForegroundColor $statusColours[$status]
}

if ($PassThru) {
    $output
}
#endregion Main
