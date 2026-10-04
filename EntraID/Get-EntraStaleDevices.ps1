<#
.SYNOPSIS
    Finds Microsoft Entra ID devices that have not signed in for a number of days and can disable or remove them.
.DESCRIPTION
    Queries /devices with $filter=approximateLastSignInDateTime le <cutoff> (advanced query with ConsistencyLevel=eventual
    and $count=true) through Microsoft Graph, excludes Windows Autopilot registered devices unless -IncludeAutopilot and
    reports one row per stale device with join type, OS, management and compliance state, last sign-in and days inactive.
    By default the script only reports. -DisableDevices (PATCH /devices/{id}, accountEnabled=false) and -RemoveDevices
    (DELETE /devices/{id}) are mutually exclusive, wrapped in ShouldProcess and skip hybrid joined devices.
.PARAMETER DaysInactive
    Devices whose last sign-in is older than this many days are considered stale (1-3650, default 90).
.PARAMETER IncludeAutopilot
    Also reports (and acts on) devices that carry a Windows Autopilot [ZTDId] physical ID; excluded by default because
    Autopilot devices are expected to sit idle before deployment.
.PARAMETER DisableDevices
    Disables the stale devices that are still enabled. Cannot be combined with -RemoveDevices.
.PARAMETER RemoveDevices
    Deletes the stale devices from Microsoft Entra ID. Cannot be combined with -DisableDevices.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraStaleDevices_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the device objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraStaleDevices.ps1 -DaysInactive 120
    Reports devices without a sign-in in the last 120 days; nothing is changed.
.EXAMPLE
    PS> .\Get-EntraStaleDevices.ps1 -DaysInactive 180 -DisableDevices -WhatIf
    Shows which devices would be disabled. Run again without -WhatIf to disable them (each device is confirmed).
.EXAMPLE
    PS> .\Get-EntraStaleDevices.ps1 -DaysInactive 365 -RemoveDevices -Confirm:$false -PassThru | Where-Object { $_.Action -eq 'Failed' }
    Deletes devices inactive for a year without prompting and lists the ones that failed.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Device.Read.All; Device.ReadWrite.All with -DisableDevices / -RemoveDevices (delegated)
    Category    : Devices
    Changes     : Optional (-DisableDevices / -RemoveDevices)
    Notes       : Hybrid joined devices (trustType ServerAd) are recreated by Microsoft Entra Connect Sync, so they are reported
                  but skipped by both actions; clean them up in on-premises AD. Intune-managed devices are better retired through
                  Intune device clean-up rules. Deleting devices needs the Cloud Device Administrator or Intune Administrator role.
                  Disabling blocks sign-in on the device, so disable first and delete after a grace period. Devices that never
                  signed in are not returned by this filter.
.LINK
    https://learn.microsoft.com/graph/api/device-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [switch]$IncludeAutopilot,

    [Parameter()]
    [switch]$DisableDevices,

    [Parameter()]
    [switch]$RemoveDevices,

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
if ($DisableDevices -and $RemoveDevices) { throw '-DisableDevices and -RemoveDevices cannot be combined; disable first, remove later.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraStaleDevices_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('Device.Read.All')
if ($DisableDevices -or $RemoveDevices) { $scopes += 'Device.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$joinNames = @{ AzureAd = 'Microsoft Entra joined'; ServerAd = 'Microsoft Entra hybrid joined'; Workplace = 'Microsoft Entra registered' }
$cutoff = (Get-Date).ToUniversalTime().AddDays(-$DaysInactive).ToString('yyyy-MM-ddTHH:mm:ssZ')
$select = 'id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,accountEnabled,approximateLastSignInDateTime,registrationDateTime,physicalIds'
# Filtering on approximateLastSignInDateTime is an advanced query: it needs ConsistencyLevel=eventual together with $count=true.
$uri = '{0}/devices?$filter=approximateLastSignInDateTime le {1}&$count=true&$select={2}&$top=999' -f $graphV1, $cutoff, $select
try { $devices = @(Invoke-GraphPaged -Uri $uri -Headers @{ ConsistencyLevel = 'eventual' }) }
catch { throw "Failed to query stale devices: $($_.Exception.Message)" }
Write-Verbose "Graph returned $($devices.Count) device(s) with a last sign-in before $cutoff."
$results = New-Object -TypeName System.Collections.Generic.List[object]
$autopilotSkipped = 0
foreach ($device in $devices) {
    $isAutopilot = (@(@($device.physicalIds) -match '^\[ZTDId\]').Count -gt 0)
    if ($isAutopilot -and -not $IncludeAutopilot) { $autopilotSkipped++; continue }
    $joinType = $joinNames[[string]$device.trustType]
    if ([string]::IsNullOrEmpty($joinType)) { $joinType = [string]$device.trustType }
    $lastSignIn = [datetime]$device.approximateLastSignInDateTime
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
        IsAutopilot          = $isAutopilot
        LastSignInDateTime   = $lastSignIn
        DaysInactive         = [int][math]::Floor(((Get-Date).ToUniversalTime() - $lastSignIn.ToUniversalTime()).TotalDays)
        RegistrationDateTime = $registered
        Action               = 'None'
    })
}

if ($DisableDevices -or $RemoveDevices) {
    $verb = 'Disable'
    if ($RemoveDevices) { $verb = 'Remove' }
    $processed = 0
    foreach ($row in $results) {
        $processed++
        Write-Progress -Activity "$verb stale devices" -Status "$processed of $($results.Count): $($row.DisplayName)" -PercentComplete (($processed / $results.Count) * 100)
        if ($row.JoinType -eq $joinNames['ServerAd']) { $row.Action = 'Skipped (hybrid joined)'; continue }
        if ($DisableDevices -and $row.AccountEnabled -eq $false) { $row.Action = 'Skipped (already disabled)'; continue }
        $target = '{0} ({1}, last sign-in {2:yyyy-MM-dd})' -f $row.DisplayName, $row.OperatingSystem, $row.LastSignInDateTime
        if (-not $PSCmdlet.ShouldProcess($target, "$verb device")) { $row.Action = 'WhatIf'; continue }
        $deviceUri = '{0}/devices/{1}' -f $graphV1, $row.ObjectId
        try {
            if ($RemoveDevices) {
                Invoke-MgGraphRequest -Method DELETE -Uri $deviceUri -ErrorAction Stop | Out-Null
                $row.Action = 'Removed'
            }
            else {
                Invoke-MgGraphRequest -Method PATCH -Uri $deviceUri -Body @{ accountEnabled = $false } -ContentType 'application/json' -ErrorAction Stop | Out-Null
                $row.Action = 'Disabled'
                $row.AccountEnabled = $false
            }
        }
        catch { $row.Action = 'Failed'; Write-Warning "Could not $($verb.ToLower()) '$($row.DisplayName)': $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 200
    }
    Write-Progress -Activity "$verb stale devices" -Completed
}

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning "No stale devices found for $DaysInactive day(s); no CSV was written." }

Write-Host ('Stale devices (no sign-in for {0}+ days): {1}' -f $DaysInactive, $results.Count) -ForegroundColor Cyan
foreach ($bucket in ($results | Group-Object -Property JoinType | Sort-Object -Property Count -Descending)) { Write-Host ('  {0,-30}: {1}' -f $bucket.Name, $bucket.Count) }
Write-Host ('  Already disabled              : {0}' -f @($results | Where-Object { $_.AccountEnabled -eq $false }).Count)
if ($autopilotSkipped -gt 0) { Write-Host ('  Autopilot devices excluded    : {0} (use -IncludeAutopilot)' -f $autopilotSkipped) }
foreach ($bucket in ($results | Where-Object { $_.Action -ne 'None' } | Group-Object -Property Action)) { Write-Host ('  {0,-30}: {1}' -f $bucket.Name, $bucket.Count) -ForegroundColor Yellow }
Write-Host ('  Report                        : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
