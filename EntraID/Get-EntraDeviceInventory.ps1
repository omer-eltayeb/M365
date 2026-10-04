<#
.SYNOPSIS
    Exports an inventory of the device objects in Microsoft Entra ID with join type, management, compliance and owner details.
.DESCRIPTION
    Reads /devices through Microsoft Graph with the registered owners expanded and shapes each device into one row: the
    join type derived from trustType (Microsoft Entra joined / hybrid joined / registered), the Autopilot flag derived from
    physicalIds ([ZTDId]), the MDM name derived from mdmAppId, plus compliance, management, operating system, hardware,
    owner and sign-in details. -JoinType and -OperatingSystem are applied server-side; -OnlyUnmanaged and
    -OnlyNonCompliant are applied client-side so devices that were never enrolled (empty flags) are included.
    Output: CSV plus a console summary by join type and operating system.
.PARAMETER JoinType
    EntraJoined (trustType AzureAd), HybridJoined (ServerAd) or Registered (Workplace).
.PARAMETER OperatingSystem
    Operating system prefix as stored in Entra ID, for example Windows, iOS, Android, MacMDM or Linux.
.PARAMETER OnlyUnmanaged
    Returns only devices whose isManaged flag is not true (not enrolled in Intune or another MDM).
.PARAMETER OnlyNonCompliant
    Returns only devices whose isCompliant flag is not true.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraDeviceInventory_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the device objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraDeviceInventory.ps1
    Exports every device in the tenant and prints the join type and operating system summary.
.EXAMPLE
    PS> .\Get-EntraDeviceInventory.ps1 -JoinType Registered -OperatingSystem Windows -OnlyUnmanaged -PassThru | Sort-Object -Property LastSignInDateTime
    Lists Windows devices that are only registered (typically BYOD) and not MDM-managed, oldest sign-in first.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Device.Read.All (delegated)
    Category    : Devices
    Changes     : No
    Notes       : isCompliant and isManaged are written by the MDM and stay empty for devices that were never enrolled.
                  approximateLastSignInDateTime is updated at most once a day and only when the device authenticates, so
                  it can lag real usage. Expanding registeredOwners returns at most 20 owners per device.
.LINK
    https://learn.microsoft.com/graph/api/device-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('EntraJoined', 'HybridJoined', 'Registered')]
    [string]$JoinType,

    [Parameter()]
    [string]$OperatingSystem,

    [Parameter()]
    [switch]$OnlyUnmanaged,

    [Parameter()]
    [switch]$OnlyNonCompliant,

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraDeviceInventory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('Device.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$trustTypes = @{ EntraJoined = 'AzureAd'; HybridJoined = 'ServerAd'; Registered = 'Workplace' }
$joinNames = @{ AzureAd = 'Microsoft Entra joined'; ServerAd = 'Microsoft Entra hybrid joined'; Workplace = 'Microsoft Entra registered' }
$mdmNames = @{ '0000000a-0000-0000-c000-000000000000' = 'Microsoft Intune' }
$filters = @()
if (-not [string]::IsNullOrWhiteSpace($JoinType)) { $filters += "trustType eq '{0}'" -f $trustTypes[$JoinType] }
if (-not [string]::IsNullOrWhiteSpace($OperatingSystem)) { $filters += "startswith(operatingSystem,'{0}')" -f $OperatingSystem.Replace("'", "''") }
$select = 'id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,managementType,approximateLastSignInDateTime,' +
    'registrationDateTime,accountEnabled,profileType,deviceOwnership,enrollmentType,manufacturer,model,mdmAppId,isRooted,physicalIds'
$uri = '{0}/devices?$select={1}&$expand=registeredOwners($select=userPrincipalName)&$top=999' -f $graphV1, $select
if ($filters.Count -gt 0) { $uri += '&$filter=' + ($filters -join ' and ') }
try { $devices = @(Invoke-GraphPaged -Uri $uri) }
catch { throw "Failed to read devices from Microsoft Graph: $($_.Exception.Message)" }
Write-Verbose "Read $($devices.Count) device object(s) from Microsoft Graph."

$now = Get-Date
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($device in $devices) {
    # isManaged / isCompliant are null for devices that were never enrolled, so 'not true' is the correct test.
    if ($OnlyUnmanaged -and $device.isManaged -eq $true) { continue }
    if ($OnlyNonCompliant -and $device.isCompliant -eq $true) { continue }
    $joinType = $joinNames[[string]$device.trustType]
    if ([string]::IsNullOrEmpty($joinType)) { $joinType = [string]$device.trustType }
    $mdmName = $null
    if (-not [string]::IsNullOrEmpty($device.mdmAppId)) { $mdmName = $mdmNames[$device.mdmAppId]; if ($null -eq $mdmName) { $mdmName = $device.mdmAppId } }
    $lastSignIn = $null
    $daysSinceSignIn = $null
    if ($null -ne $device.approximateLastSignInDateTime) {
        $lastSignIn = [datetime]$device.approximateLastSignInDateTime
        $daysSinceSignIn = [int][math]::Floor(($now - $lastSignIn).TotalDays)
    }
    $registered = $null
    if ($null -ne $device.registrationDateTime) { $registered = [datetime]$device.registrationDateTime }
    $results.Add([PSCustomObject]@{
        DisplayName          = $device.displayName
        ObjectId             = $device.id
        DeviceId             = $device.deviceId
        JoinType             = $joinType
        OperatingSystem      = $device.operatingSystem
        OSVersion            = $device.operatingSystemVersion
        AccountEnabled       = $device.accountEnabled
        IsManaged            = $device.isManaged
        IsCompliant          = $device.isCompliant
        ManagementType       = $device.managementType
        MdmName              = $mdmName
        IsAutopilot          = (@(@($device.physicalIds) -match '^\[ZTDId\]').Count -gt 0)
        Owners               = (@(@($device.registeredOwners) | ForEach-Object { $_.userPrincipalName }) -join '; ')
        ProfileType          = $device.profileType
        DeviceOwnership      = $device.deviceOwnership
        EnrollmentType       = $device.enrollmentType
        Manufacturer         = $device.manufacturer
        Model                = $device.model
        IsRooted             = $device.isRooted
        RegistrationDateTime = $registered
        LastSignInDateTime   = $lastSignIn
        DaysSinceLastSignIn  = $daysSinceSignIn
    })
}

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No devices matched the selected filters; no CSV was written.' }

Write-Host ('Device inventory: {0} device(s)' -f $results.Count) -ForegroundColor Cyan
Write-Host '  By join type:'
foreach ($bucket in ($results | Group-Object -Property JoinType | Sort-Object -Property Count -Descending)) { Write-Host ('    {0,-30}: {1}' -f $bucket.Name, $bucket.Count) }
Write-Host '  By operating system:'
foreach ($bucket in ($results | Group-Object -Property OperatingSystem | Sort-Object -Property Count -Descending)) { Write-Host ('    {0,-30}: {1}' -f $bucket.Name, $bucket.Count) }
Write-Host ('  Autopilot registered  : {0}' -f @($results | Where-Object { $_.IsAutopilot }).Count)
Write-Host ('  Not MDM-managed       : {0}' -f @($results | Where-Object { $_.IsManaged -ne $true }).Count) -ForegroundColor Yellow
Write-Host ('  Non-compliant (false) : {0}' -f @($results | Where-Object { $_.IsCompliant -eq $false }).Count) -ForegroundColor Yellow
Write-Host ('  Report                : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
