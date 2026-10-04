<#
.SYNOPSIS
    Windows Autopilot registration health report: profile assignment status, enrollment state and last contact per device.
.DESCRIPTION
    Lists every Windows Autopilot device identity from Microsoft Graph (v1.0
    /deviceManagement/windowsAutopilotDeviceIdentities) with hardware, group tag, deployment profile
    assignment and enrollment details. With -IncludeManagedDeviceDetails the identities are joined to
    the Intune managed device record (managedDeviceId) to add the enrolled device name, compliance
    state and last sync. A ProblemReason column flags devices without a profile, with a failed
    assignment or enrollment, or that have not contacted the service for -NotContactedDays days.
.PARAMETER GroupTag
    Wildcard pattern applied to the Autopilot group tag, for example 'Kiosk*'.
.PARAMETER OnlyProblems
    Return only devices with a non-empty ProblemReason.
.PARAMETER IncludeManagedDeviceDetails
    Join the Intune managed device record to populate EnrolledDeviceName, ComplianceState, LastSyncDateTime
    and EnrolledDateTime. Requests DeviceManagementManagedDevices.Read.All in addition.
.PARAMETER NotContactedDays
    Days without contact after which a device in enrollment state notContacted or unknown is flagged. Default 30.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\AutopilotDevices_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-AutopilotDeviceReport.ps1
    Exports all Autopilot registrations and prints a summary by profile assignment status and enrollment state.
.EXAMPLE
    PS> .\Get-AutopilotDeviceReport.ps1 -OnlyProblems -IncludeManagedDeviceDetails -PassThru | Format-Table SerialNumber, GroupTag, ProfileAssignmentStatus, EnrollmentState, ProblemReason
    Shows only registrations that need attention, enriched with the Intune device record where one exists.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementServiceConfig.Read.All; DeviceManagementManagedDevices.Read.All only with
                  -IncludeManagedDeviceDetails (delegated). Intune RBAC: Read Only Operator or any role with
                  "Enrollment programs" read permission.
    Category    : Enrollment & Autopilot
    Changes     : No
    Notes       : v1.0 endpoints only. Autopilot requires Windows Autopilot licensing (Intune Plan 1 or an equivalent
                  bundle). lastContactedDateTime is the last Autopilot service contact, not the Intune sync time.
                  All date/time values are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-enrollment-windowsautopilotdeviceidentity-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$GroupTag,

    [Parameter()]
    [switch]$OnlyProblems,

    [Parameter()]
    [switch]$IncludeManagedDeviceDetails,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$NotContactedDays = 30,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('AutopilotDevices_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$scopes = @('DeviceManagementServiceConfig.Read.All')
if ($IncludeManagedDeviceDetails) { $scopes += 'DeviceManagementManagedDevices.Read.All' }
try {
    Connect-GraphIfNeeded -Scopes $scopes
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0'
$selectProperties = @(
    'id', 'serialNumber', 'model', 'manufacturer', 'groupTag', 'purchaseOrderIdentifier', 'enrollmentState',
    'lastContactedDateTime', 'deploymentProfileAssignmentStatus', 'deploymentProfileAssignmentDetailedStatus',
    'deploymentProfileAssignedDateTime', 'azureActiveDirectoryDeviceId', 'managedDeviceId', 'addressableUserName',
    'userPrincipalName', 'displayName'
) -join ','
try {
    $identities = @(Invoke-GraphPaged -Uri ('{0}/deviceManagement/windowsAutopilotDeviceIdentities?$select={1}' -f $graphV1, $selectProperties))
}
catch {
    throw "Failed to retrieve Windows Autopilot device identities: $($_.Exception.Message)"
}
if (-not [string]::IsNullOrWhiteSpace($GroupTag)) {
    $identities = @($identities | Where-Object { $_.groupTag -like $GroupTag })
}
Write-Verbose ('{0} Autopilot device identities selected.' -f $identities.Count)

# Index Windows managed devices by id so each Autopilot identity can be joined without extra Graph calls.
$managedDevices = @{}
if ($IncludeManagedDeviceDetails) {
    try {
        $managedUri = $graphV1 + '/deviceManagement/managedDevices?$select=id,deviceName,complianceState,lastSyncDateTime,enrolledDateTime&$filter=operatingSystem eq ''Windows'''
        foreach ($managedDevice in @(Invoke-GraphPaged -Uri $managedUri)) {
            $managedDevices[[string]$managedDevice.id] = $managedDevice
        }
    }
    catch {
        throw "Failed to retrieve managed devices for the join: $($_.Exception.Message)"
    }
    Write-Verbose ('{0} Windows managed devices available for the join.' -f $managedDevices.Count)
}

$cutoff = [datetime]::UtcNow.AddDays(-$NotContactedDays)
$emptyGuid = '00000000-0000-0000-0000-000000000000'
$report = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($identity in $identities) {
    $index++
    if ($index % 250 -eq 0) {
        Write-Progress -Activity 'Building Autopilot report' -Status ('{0} of {1}' -f $index, $identities.Count) -PercentComplete ([int](($index / $identities.Count) * 100))
    }

    $profileStatus = [string]$identity.deploymentProfileAssignmentStatus
    $enrollmentState = [string]$identity.enrollmentState
    $lastContacted = ConvertTo-UtcDateTime -Value $identity.lastContactedDateTime
    $profileAssigned = ConvertTo-UtcDateTime -Value $identity.deploymentProfileAssignedDateTime

    $reasons = @()
    if ($profileStatus -in @('notAssigned', 'failed')) { $reasons += ('Deployment profile {0}' -f $profileStatus) }
    if ($enrollmentState -eq 'failed') { $reasons += 'Enrollment failed' }
    if ($enrollmentState -in @('notContacted', 'unknown')) {
        # A device that never contacted the service has no lastContactedDateTime; fall back to the profile assignment date.
        $referenceDate = $lastContacted
        if ($null -eq $referenceDate) { $referenceDate = $profileAssigned }
        if ($null -eq $referenceDate -or $referenceDate -lt $cutoff) {
            $reasons += ('Enrollment state {0} for more than {1} days' -f $enrollmentState, $NotContactedDays)
        }
    }

    $managedDeviceId = [string]$identity.managedDeviceId
    if ($managedDeviceId -eq $emptyGuid) { $managedDeviceId = $null }
    $managed = $null
    if (-not [string]::IsNullOrEmpty($managedDeviceId) -and $managedDevices.ContainsKey($managedDeviceId)) {
        $managed = $managedDevices[$managedDeviceId]
    }

    $report.Add([PSCustomObject]@{
            SerialNumber                    = $identity.serialNumber
            DisplayName                     = $identity.displayName
            Manufacturer                    = $identity.manufacturer
            Model                           = $identity.model
            GroupTag                        = $identity.groupTag
            PurchaseOrder                   = $identity.purchaseOrderIdentifier
            EnrollmentState                 = $enrollmentState
            LastContactedDateTime           = $lastContacted
            ProfileAssignmentStatus         = $profileStatus
            ProfileAssignmentDetailedStatus = $identity.deploymentProfileAssignmentDetailedStatus
            ProfileAssignedDateTime         = $profileAssigned
            UserPrincipalName               = $identity.userPrincipalName
            AddressableUserName             = $identity.addressableUserName
            EntraDeviceId                   = $identity.azureActiveDirectoryDeviceId
            ManagedDeviceId                 = $managedDeviceId
            EnrolledDeviceName              = $managed.deviceName
            ComplianceState                 = $managed.complianceState
            LastSyncDateTime                = ConvertTo-UtcDateTime -Value $managed.lastSyncDateTime
            EnrolledDateTime                = ConvertTo-UtcDateTime -Value $managed.enrolledDateTime
            ProblemReason                   = ($reasons -join '; ')
            AutopilotDeviceId               = $identity.id
        })
}
Write-Progress -Activity 'Building Autopilot report' -Completed

$output = $report
if ($OnlyProblems) {
    $output = @($report | Where-Object { -not [string]::IsNullOrEmpty($_.ProblemReason) })
}

if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No Autopilot devices matched the specified criteria; no CSV file was written.'
}

$problemCount = @($report | Where-Object { -not [string]::IsNullOrEmpty($_.ProblemReason) }).Count
$problemColour = 'Green'
if ($problemCount -gt 0) { $problemColour = 'Yellow' }
Write-Host ''
Write-Host ('Autopilot devices        : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host ('Devices needing attention: {0}' -f $problemCount) -ForegroundColor $problemColour
Write-Host 'By deployment profile assignment status:' -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property ProfileAssignmentStatus | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-28} {1,6}' -f $group.Name, $group.Count)
}
Write-Host 'By enrollment state:' -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property EnrollmentState | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-28} {1,6}' -f $group.Name, $group.Count)
}

if ($PassThru) {
    $output
}
#endregion Main
