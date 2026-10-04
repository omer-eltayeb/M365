<#
.SYNOPSIS
    Reports every Intune managed Android device with its management mode, OS version and security patch level, flagging outdated, rooted and legacy devices.
.DESCRIPTION
    Reads Android devices from the Microsoft Graph beta endpoint (/deviceManagement/managedDevices filtered to operatingSystem
    eq 'Android'; beta is needed for androidSecurityPatchLevel) and derives the management mode (Dedicated, Fully managed,
    Corporate-owned or Personally-owned work profile, AOSP, legacy device administrator) from deviceEnrollmentType and
    managementAgent. Flags patches older than -MaxPatchAgeDays, OS below -MinimumAndroidVersion and rooted devices. Exports to CSV.
.PARAMETER MaxPatchAgeDays
    Security patches older than this many days flag the device as PatchOutdated. Default 90.
.PARAMETER MinimumAndroidVersion
    Lowest acceptable Android major version; older devices are flagged BelowMinimumOs. Default 10.
.PARAMETER OnlyFlagged
    Report only devices with at least one flag (outdated patch, old OS, rooted or device administrator).
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneAndroidDeviceReport_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneAndroidDeviceReport.ps1
    Reports all Android devices and prints the distribution by management mode and OS version.
.EXAMPLE
    PS> .\Get-IntuneAndroidDeviceReport.ps1 -MaxPatchAgeDays 60 -MinimumAndroidVersion 12 -OnlyFlagged -PassThru | Format-Table DeviceName, ManagementMode, OSVersion, SecurityPatchLevel
    Lists devices whose patch level is older than 60 days, that run Android 11 or lower, are rooted or still use device administrator.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementManagedDevices.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Reporting & platform insights
    Changes     : No
    Notes       : androidSecurityPatchLevel is only returned by the beta endpoint, which Microsoft may change without notice; it
                  reflects the device's last check-in. Device administrator management is deprecated and no longer supported by
                  Intune, so those devices should be re-enrolled with Android Enterprise. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list?view=graph-rest-beta
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$MaxPatchAgeDays = 90,

    [Parameter()]
    [ValidateRange(1, 99)]
    [int]$MinimumAndroidVersion = 10,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneAndroidDeviceReport_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementManagedDevices.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

# beta: androidSecurityPatchLevel is not exposed on the v1.0 managedDevice resource.
$uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$filter=operatingSystem eq ''Android''' +
    '&$select=id,deviceName,userPrincipalName,deviceEnrollmentType,managementAgent,osVersion,androidSecurityPatchLevel,model,manufacturer,' +
    'jailBroken,isSupervised,lastSyncDateTime,complianceState,ownerType,enrolledDateTime'
try { $devices = @(Invoke-GraphPaged -Uri $uri) } catch { throw "Failed to retrieve Android devices from Microsoft Graph: $($_.Exception.Message)" }
Write-Verbose ('{0} Android devices retrieved.' -f $devices.Count)

$modeByEnrollment = @{
    androidEnterpriseDedicatedDevice = 'Dedicated'; androidEnterpriseFullyManaged = 'Fully managed'; androidEnterpriseCorporateWorkProfile = 'Corporate-owned work profile'
    androidAOSPUserOwnedDeviceEnrollment = 'AOSP user-associated'; androidAOSPUserlessDeviceEnrollment = 'AOSP userless'
}
$today = (Get-Date).ToUniversalTime().Date
$report = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($device in $devices) {
    $enrollmentType = [string]$device.deviceEnrollmentType
    $agent = [string]$device.managementAgent
    $isDeviceAdmin = $false
    if ($modeByEnrollment.ContainsKey($enrollmentType)) { $mode = $modeByEnrollment[$enrollmentType] }
    elseif ($agent -like '*googleCloudDevicePolicyController*') { $mode = 'Personally-owned work profile' }
    elseif ($agent -eq 'mdm') { $mode = 'Device administrator'; $isDeviceAdmin = $true }   # legacy Android device administrator enrolment
    else { $mode = 'Unknown ({0} / {1})' -f $enrollmentType, $agent }

    $patchDate = $null; $patchAge = $null
    # Patch levels arrive as 'yyyy-MM-dd' (occasionally 'yyyy-MM'); anything unparsable stays blank rather than failing the row.
    if ([datetime]::TryParse([string]$device.androidSecurityPatchLevel, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$patchDate)) {
        $patchAge = [int]($today - $patchDate.ToUniversalTime().Date).TotalDays
    }
    $osMajor = $null
    if (([string]$device.osVersion -split '\.')[0] -match '^\d+$') { $osMajor = [int]$Matches[0] }

    $patchOutdated = ($null -ne $patchAge -and $patchAge -gt $MaxPatchAgeDays)
    $belowMinimumOs = ($null -ne $osMajor -and $osMajor -lt $MinimumAndroidVersion)
    $isRooted = ([string]$device.jailBroken -eq 'True')
    if ($OnlyFlagged -and -not ($patchOutdated -or $belowMinimumOs -or $isRooted -or $isDeviceAdmin)) { continue }

    $report.Add([PSCustomObject]@{
            DeviceName            = $device.deviceName
            UserPrincipalName     = $device.userPrincipalName
            ManagementMode        = $mode
            IsDeviceAdministrator = $isDeviceAdmin
            OwnerType             = $device.ownerType
            OSVersion             = $device.osVersion
            OSMajor               = $osMajor
            SecurityPatchLevel    = $device.androidSecurityPatchLevel
            SecurityPatchAgeDays  = $patchAge
            PatchOutdated         = $patchOutdated
            BelowMinimumOs        = $belowMinimumOs
            IsRooted              = $isRooted
            Manufacturer          = $device.manufacturer
            Model                 = $device.model
            ComplianceState       = $device.complianceState
            LastSyncDateTime      = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime
            EnrolledDateTime      = ConvertTo-UtcDateTime -Value $device.enrolledDateTime
            EnrollmentType        = $enrollmentType
            ManagementAgent       = $agent
            ManagedDeviceId       = $device.id
        })
}

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else { Write-Warning 'No Android devices matched the selection; no CSV file was written.' }

Write-Host ('Android devices reported : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host 'By management mode:' -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property ManagementMode | Sort-Object -Property Count -Descending)) {
    $colour = 'Gray'; if ($group.Name -eq 'Device administrator') { $colour = 'Yellow' }
    Write-Host ('  {0,-34} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
Write-Host 'By Android version:' -ForegroundColor Cyan
foreach ($group in ($report | Where-Object { $null -ne $_.OSMajor } | Group-Object -Property OSMajor | Sort-Object -Property { [int]$_.Name } -Descending)) {
    $colour = 'Gray'; if ([int]$group.Name -lt $MinimumAndroidVersion) { $colour = 'Yellow' }
    Write-Host ('  Android {0,-26} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
$belowOs = @($report | Where-Object { $_.BelowMinimumOs }).Count; $rooted = @($report | Where-Object { $_.IsRooted }).Count
Write-Host ('Patch older than {0} days : {1}' -f $MaxPatchAgeDays, @($report | Where-Object { $_.PatchOutdated }).Count) -ForegroundColor Yellow
Write-Host ('Below Android {0} / rooted  : {1} / {2}' -f $MinimumAndroidVersion, $belowOs, $rooted) -ForegroundColor Red

if ($PassThru) { $report }
#endregion Main
