<#
.SYNOPSIS
    Reports the setting-level reasons why Intune managed devices are non-compliant.
.DESCRIPTION
    Lists every non-compliant managed device (v1.0 /deviceManagement/managedDevices with a server-side
    complianceState filter) and then reads the per-policy compliance state of each device from beta
    /deviceManagement/managedDevices/{id}/deviceCompliancePolicyStates, including the settingStates
    collection. One row is produced per device, policy and setting; by default only settings in the
    nonCompliant, error or conflict state are kept so the report answers "which setting fails on which
    device". The CSV is exported and a console summary of the most common failing settings is printed.
.PARAMETER DeviceName
    Wildcard pattern (for example 'LT-FIN-*') applied to the device name after the devices are retrieved.
.PARAMETER OperatingSystem
    Restrict the report to one platform: Windows, iOS, Android, macOS or Linux (server-side $filter).
.PARAMETER IncludeAllSettings
    Keep every evaluated setting (compliant, notApplicable, ...) instead of only the failing ones.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneNoncompliantDeviceDetails_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report rows to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneNoncompliantDeviceDetails.ps1
    Exports the failing compliance settings of every non-compliant device and prints the top failing settings.
.EXAMPLE
    PS> .\Get-IntuneNoncompliantDeviceDetails.ps1 -OperatingSystem Windows -DeviceName 'LT-*' -IncludeAllSettings -PassThru | Out-GridView
    Shows every evaluated compliance setting (not only the failing ones) for the non-compliant laptops.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : The per-device policy states are read from the beta endpoint because the v1.0 response regularly
                  returns an empty settingStates collection; beta may change without notice. The built-in "Default
                  Device Compliance Policy" (no compliance policy assigned, device not in contact, no enrolled user)
                  is included because it is a frequent cause of non-compliance. One Graph call is made per device
                  with a 200 ms pause between devices. All date/time values are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-devicecompliancepolicystate-list?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DeviceName,

    [Parameter()]
    [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'Linux')]
    [string]$OperatingSystem,

    [Parameter()]
    [switch]$IncludeAllSettings,

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneNoncompliantDeviceDetails_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

$filter = "complianceState eq 'noncompliant'"
if (-not [string]::IsNullOrWhiteSpace($OperatingSystem)) { $filter += " and operatingSystem eq '$OperatingSystem'" }
$deviceUri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,lastSyncDateTime&$filter=' + $filter
Write-Verbose "Requesting non-compliant devices: $deviceUri"
try {
    $devices = @(Invoke-GraphPaged -Uri $deviceUri)
}
catch {
    throw "Failed to retrieve managed devices from Microsoft Graph: $($_.Exception.Message)"
}
if (-not [string]::IsNullOrWhiteSpace($DeviceName)) {
    $devices = @($devices | Where-Object { $_.deviceName -like $DeviceName })
}
Write-Verbose ('{0} non-compliant devices to inspect.' -f $devices.Count)

$failingStates = @('nonCompliant', 'error', 'conflict')
$report = New-Object -TypeName System.Collections.Generic.List[object]
$failedDevices = 0
$index = 0
foreach ($device in $devices) {
    $index++
    Write-Progress -Activity 'Reading compliance policy states' -Status ('{0} of {1}: {2}' -f $index, $devices.Count, $device.deviceName) -PercentComplete ([int](($index / $devices.Count) * 100))
    try {
        # beta: v1.0 frequently returns the policy states without their settingStates detail.
        $policyStates = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/beta/deviceManagement/managedDevices/{0}/deviceCompliancePolicyStates' -f $device.id))
    }
    catch {
        $failedDevices++
        Write-Warning ("Could not read policy states for device '{0}' ({1}): {2}" -f $device.deviceName, $device.id, $_.Exception.Message)
        continue
    }

    foreach ($policyState in $policyStates) {
        $settings = @()
        if ($null -ne $policyState.settingStates) { $settings = @($policyState.settingStates) }
        if (-not $IncludeAllSettings) {
            $settings = @($settings | Where-Object { $failingStates -contains $_.state })
            # Keep a failing policy visible even when Graph returns no setting detail for it.
            if ($settings.Count -eq 0 -and $failingStates -contains $policyState.state) {
                $settings = @([PSCustomObject]@{ setting = $null; settingName = '(no setting detail returned)'; state = $policyState.state; currentValue = $null; errorCode = $null; errorDescription = $null })
            }
        }
        foreach ($setting in $settings) {
            $settingName = $setting.settingName
            if ([string]::IsNullOrWhiteSpace($settingName)) { $settingName = $setting.setting }
            $report.Add([PSCustomObject]@{
                    DeviceName        = $device.deviceName
                    UserPrincipalName = $device.userPrincipalName
                    OperatingSystem   = $device.operatingSystem
                    OSVersion         = $device.osVersion
                    LastSyncDateTime  = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime
                    PolicyName        = $policyState.displayName
                    PolicyState       = $policyState.state
                    SettingName       = $settingName
                    Setting           = $setting.setting
                    SettingState      = $setting.state
                    CurrentValue      = $setting.currentValue
                    ErrorCode         = $setting.errorCode
                    ErrorDescription  = $setting.errorDescription
                    ManagedDeviceId   = $device.id
                })
        }
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading compliance policy states' -Completed

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No non-compliant devices (or no failing settings) matched the criteria; no CSV file was written.'
}

Write-Host ''
$failureColour = 'Cyan'
if ($failedDevices -gt 0) { $failureColour = 'Yellow' }
Write-Host ('Non-compliant devices inspected : {0}' -f $devices.Count) -ForegroundColor Cyan
Write-Host ('Devices that could not be read  : {0}' -f $failedDevices) -ForegroundColor $failureColour
Write-Host ('Setting rows in report          : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host 'Top failing settings:' -ForegroundColor Cyan
$failingRows = @($report | Where-Object { $failingStates -contains $_.SettingState })
foreach ($group in ($failingRows | Group-Object -Property SettingName | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('  {0,-70} {1,6}' -f $group.Name, $group.Count) -ForegroundColor Yellow
}

if ($PassThru) {
    $report
}
#endregion Main
