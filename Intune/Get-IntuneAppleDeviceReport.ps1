<#
.SYNOPSIS
    Reports every Intune managed iOS, iPadOS and macOS device with its enrollment method, supervision state, MDM certificate expiry and OS version flags.
.DESCRIPTION
    Reads Apple devices from Microsoft Graph v1.0 (/deviceManagement/managedDevices filtered to iOS, iPadOS and macOS; falls back
    to one query per platform when the combined filter is rejected), derives the enrollment method from deviceEnrollmentType
    (Automated Device Enrollment, Apple User Enrollment, user enrollment, device enrollment manager) and flags corporate iOS/iPadOS
    devices that are not supervised, MDM certificates expiring within -CertWarnDays and devices below -MinimumOsVersion. Exports to CSV.
.PARAMETER CertWarnDays
    Devices whose managementCertificateExpirationDate is within this many days are flagged MdmCertExpiring. Default 30.
.PARAMETER MinimumOsVersion
    Hashtable of platform -> minimum version, for example @{ iOS = '17.0'; iPadOS = '17.0'; macOS = '14.0' }. Older devices are flagged BelowMinimumOs.
.PARAMETER OnlyFlagged
    Report only devices with at least one flag (not supervised, certificate expiring or OS below minimum).
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneAppleDeviceReport_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneAppleDeviceReport.ps1
    Reports all Apple devices and prints the distribution by platform, enrollment method and OS major version.
.EXAMPLE
    PS> .\Get-IntuneAppleDeviceReport.ps1 -MinimumOsVersion @{ iOS = '17.0'; macOS = '14.0' } -CertWarnDays 60 -OnlyFlagged -PassThru | Format-Table DeviceName, Platform, OSVersion, MdmCertDaysLeft
    Lists unsupervised corporate iPhones/iPads, devices on iOS 16 or macOS 13 and older, and devices whose MDM certificate expires within 60 days.
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
    Notes       : The MDM management certificate renews automatically while a device checks in, so an expiring certificate usually
                  means a device that stopped syncing; once expired it must be re-enrolled. Supervision requires Automated Device
                  Enrollment or Apple Configurator. Intune may report iPads as iOS instead of iPadOS. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-devices-manageddevice-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$CertWarnDays = 30,

    [Parameter()]
    [hashtable]$MinimumOsVersion,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneAppleDeviceReport_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementManagedDevices.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$platforms = @('iOS', 'iPadOS', 'macOS')
$baseUri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,isSupervised,' +
    'deviceEnrollmentType,managementCertificateExpirationDate,model,serialNumber,lastSyncDateTime,complianceState,ownerType,enrolledDateTime,exchangeAccessState'
try { $devices = @(Invoke-GraphPaged -Uri ($baseUri + '&$filter=' + (($platforms | ForEach-Object { "operatingSystem eq '$_'" }) -join ' or '))) }
catch {
    # Some tenants reject 'or' filters on managedDevices; fall back to one call per platform.
    Write-Verbose ('Combined platform filter rejected ({0}); querying each platform separately.' -f $_.Exception.Message)
    $devices = @()
    foreach ($platform in $platforms) {
        try { $devices += @(Invoke-GraphPaged -Uri ($baseUri + "&`$filter=operatingSystem eq '$platform'")) } catch { throw "Failed to retrieve $platform devices: $($_.Exception.Message)" }
    }
}
Write-Verbose ('{0} Apple devices retrieved.' -f $devices.Count)
$methodByType = @{
    appleBulkWithUser = 'Automated Device Enrollment'; appleBulkWithoutUser = 'Automated Device Enrollment'; deviceEnrollmentManager = 'Device enrollment manager'
    userEnrollment = 'User enrollment'; appleUserEnrollment = 'Apple User Enrollment'; appleUserEnrollmentWithServiceAccount = 'Apple User Enrollment'
    appleAccountDrivenUserEnrollment = 'Apple User Enrollment' }
$minimumByPlatform = @{}
if ($null -ne $MinimumOsVersion) { foreach ($key in @($MinimumOsVersion.Keys)) { $minimumByPlatform[[string]$key] = [version]([string]$MinimumOsVersion[$key]) } }
$now = (Get-Date).ToUniversalTime(); $report = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($device in $devices) {
    $platform = [string]$device.operatingSystem
    $method = 'Device enrollment'
    if ($methodByType.ContainsKey([string]$device.deviceEnrollmentType)) { $method = $methodByType[[string]$device.deviceEnrollmentType] }
    $osVersion = $null; $osMajor = $null
    if ([version]::TryParse([string]$device.osVersion, [ref]$osVersion)) { $osMajor = $osVersion.Major }
    $certExpiry = ConvertTo-UtcDateTime -Value $device.managementCertificateExpirationDate; $certDaysLeft = $null
    if ($null -ne $certExpiry) { $certDaysLeft = [int][Math]::Floor(($certExpiry - $now).TotalDays) }

    $notSupervised = ($platform -ne 'macOS' -and [string]$device.ownerType -eq 'company' -and $device.isSupervised -ne $true)
    $certExpiring = ($null -ne $certDaysLeft -and $certDaysLeft -le $CertWarnDays)
    $belowMinimum = $null
    if ($minimumByPlatform.ContainsKey($platform) -and $null -ne $osVersion) { $belowMinimum = $osVersion -lt $minimumByPlatform[$platform] }
    if ($OnlyFlagged -and -not ($notSupervised -or $certExpiring -or $belowMinimum -eq $true)) { continue }

    $report.Add([PSCustomObject]@{
            DeviceName          = $device.deviceName
            UserPrincipalName   = $device.userPrincipalName
            Platform            = $platform
            OSVersion           = $device.osVersion
            OSMajor             = $osMajor
            EnrollmentMethod    = $method
            EnrollmentType      = $device.deviceEnrollmentType
            OwnerType           = $device.ownerType
            IsSupervised        = $device.isSupervised
            NotSupervised       = $notSupervised
            MdmCertExpiration   = $certExpiry
            MdmCertDaysLeft     = $certDaysLeft
            MdmCertExpiring     = $certExpiring
            BelowMinimumOs      = $belowMinimum
            Model               = $device.model
            SerialNumber        = $device.serialNumber
            ComplianceState     = $device.complianceState
            ExchangeAccessState = $device.exchangeAccessState
            LastSyncDateTime    = ConvertTo-UtcDateTime -Value $device.lastSyncDateTime
            EnrolledDateTime    = ConvertTo-UtcDateTime -Value $device.enrolledDateTime
            ManagedDeviceId     = $device.id
        })
}

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else { Write-Warning 'No Apple devices matched the selection; no CSV file was written.' }

Write-Host ('Apple devices reported : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host 'By platform / enrollment method:' -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property Platform, EnrollmentMethod | Sort-Object -Property Name)) {
    Write-Host ('  {0,-50} {1,6}' -f $group.Name, $group.Count)
}
Write-Host 'By platform / OS major version:' -ForegroundColor Cyan
foreach ($group in ($report | Where-Object { $null -ne $_.OSMajor } | Group-Object -Property Platform, OSMajor | Sort-Object -Property Name)) {
    $colour = 'Gray'; if (@($group.Group | Where-Object { $_.BelowMinimumOs -eq $true }).Count -gt 0) { $colour = 'Yellow' }
    Write-Host ('  {0,-50} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
Write-Host ('Corporate iOS/iPadOS not supervised : {0}' -f @($report | Where-Object { $_.NotSupervised }).Count) -ForegroundColor Yellow
Write-Host ('MDM certificate expiring <= {0} days : {1}' -f $CertWarnDays, @($report | Where-Object { $_.MdmCertExpiring }).Count) -ForegroundColor Red
if ($minimumByPlatform.Count -gt 0) { Write-Host ('Below minimum OS version : {0}' -f @($report | Where-Object { $_.BelowMinimumOs -eq $true }).Count) -ForegroundColor Yellow }

if ($PassThru) { $report }
#endregion Main
