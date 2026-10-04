<#
.SYNOPSIS
    Imports Windows Autopilot hardware hashes from a Get-WindowsAutopilotInfo CSV, optionally waits for the import result and triggers a sync.
.DESCRIPTION
    Reads the CSV produced by Get-WindowsAutopilotInfo (columns "Device Serial Number", "Windows Product ID", "Hardware Hash" and the
    optional "Group Tag" and "Assigned User") and posts one importedWindowsAutopilotDeviceIdentity per row to Microsoft Graph v1.0
    /deviceManagement/importedWindowsAutopilotDeviceIdentities. With -Wait the script polls each import every 30 seconds until the
    service reports complete, partial or error (or -TimeoutMinutes elapses) and surfaces deviceErrorCode/deviceErrorName. -Sync then
    asks the Autopilot service to synchronise. Every import is wrapped in ShouldProcess; one result object per device is emitted.
.PARAMETER InputCsv
    Path to the Get-WindowsAutopilotInfo CSV. Rows without a serial number or hardware hash are skipped with a warning.
.PARAMETER GroupTag
    Group tag applied to every imported device, overriding any "Group Tag" column value.
.PARAMETER Wait
    Poll the import status until every device has finished processing or the timeout is reached.
.PARAMETER TimeoutMinutes
    Maximum time to wait for the import results when -Wait is used. Default 20.
.PARAMETER Sync
    Trigger an Autopilot service sync (beta /deviceManagement/windowsAutopilotSettings/sync) after a successful import.
.EXAMPLE
    PS> .\Import-AutopilotDevices.ps1 -InputCsv .\AutopilotHWID.csv -WhatIf
    Validates the CSV and shows which serial numbers would be imported without contacting the service.
.EXAMPLE
    PS> .\Import-AutopilotDevices.ps1 -InputCsv .\AutopilotHWID.csv -GroupTag 'Kiosk' -Wait -Sync -Confirm:$false
    Imports every device with the Kiosk group tag, waits for the registration result and starts an Autopilot sync.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementServiceConfig.ReadWrite.All (delegated). Intune RBAC: Intune Administrator or a role with
                  "Enrollment programs / Create device" permission.
    Category    : Enrollment & Autopilot
    Changes     : Yes
    Notes       : Only the sync action uses beta (v1.0 has no equivalent). Imports are processed asynchronously and usually take
                  5-15 minutes; error 806 (ZtdDeviceAlreadyAssigned) means the device is already registered in this tenant and 808
                  that it belongs to another tenant. The service refuses a sync more often than every 10 minutes.
.LINK
    https://learn.microsoft.com/graph/api/intune-enrollment-importedwindowsautopilotdeviceidentity-create?view=graph-rest-1.0
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [string]$GroupTag,

    [Parameter()]
    [switch]$Wait,

    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$TimeoutMinutes = 20,

    [Parameter()]
    [switch]$Sync
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

function Get-CsvValue {
    <# Returns a trimmed CSV cell or $null when the column is missing or empty, so optional columns never throw. #>
    param([object]$Row, [string]$Column)
    $property = $Row.PSObject.Properties[$Column]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) { return $null }
    return ([string]$property.Value).Trim()
}
#endregion Helpers

#region Main
$rows = @(Import-Csv -Path $InputCsv)
if ($rows.Count -eq 0) { throw "'$InputCsv' contains no rows." }
foreach ($required in @('Device Serial Number', 'Hardware Hash')) {
    if ($null -eq $rows[0].PSObject.Properties[$required]) { throw "'$InputCsv' must contain the column '$required' (as written by Get-WindowsAutopilotInfo)." }
}

try { Connect-GraphIfNeeded -Scopes @('DeviceManagementServiceConfig.ReadWrite.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$importUri = 'https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities'
$results = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($row in $rows) {
    $index++
    $serial = Get-CsvValue -Row $row -Column 'Device Serial Number'
    $hash = Get-CsvValue -Row $row -Column 'Hardware Hash'
    $tag = $GroupTag
    if ([string]::IsNullOrWhiteSpace($tag)) { $tag = Get-CsvValue -Row $row -Column 'Group Tag' }
    $assignedUser = Get-CsvValue -Row $row -Column 'Assigned User'
    $result = [PSCustomObject]@{ SerialNumber = $serial; GroupTag = $tag; AssignedUser = $assignedUser; Result = 'Skipped'; ImportStatus = $null
        ErrorCode = $null; ErrorName = $null; ImportId = $null; Error = $null }
    $results.Add($result)
    if ([string]::IsNullOrWhiteSpace($serial) -or [string]::IsNullOrWhiteSpace($hash)) {
        $result.Error = 'Missing serial number or hardware hash'
        Write-Warning ('Row {0}: missing serial number or hardware hash; skipped.' -f $index)
        continue
    }
    Write-Progress -Activity 'Importing Autopilot devices' -Status ('{0} of {1}: {2}' -f $index, $rows.Count, $serial) -PercentComplete ([int](($index / $rows.Count) * 100))
    # The CSV hash is already base64 (what Graph expects for the binary property); the state object is required on create.
    $body = @{
        '@odata.type'             = '#microsoft.graph.importedWindowsAutopilotDeviceIdentity'
        serialNumber              = $serial
        productKey                = [string](Get-CsvValue -Row $row -Column 'Windows Product ID')
        hardwareIdentifier        = $hash
        groupTag                  = [string]$tag
        assignedUserPrincipalName = [string]$assignedUser
        state                     = @{ '@odata.type' = 'microsoft.graph.importedWindowsAutopilotDeviceIdentityState'; deviceImportStatus = 'pending'
            deviceRegistrationId = ''; deviceErrorCode = 0; deviceErrorName = '' }
    }
    $target = 'Serial {0} (group tag: {1}, user: {2})' -f $serial, $tag, $assignedUser
    if ($PSCmdlet.ShouldProcess($target, 'Import Autopilot device identity')) {
        try {
            $imported = Invoke-MgGraphRequest -Method POST -Uri $importUri -Body $body -OutputType PSObject -ErrorAction Stop
            $result.Result = 'Imported'; $result.ImportId = $imported.id; $result.ImportStatus = $imported.state.deviceImportStatus
        }
        catch { $result.Result = 'Failed'; $result.Error = $_.Exception.Message; Write-Warning ('Import of {0} failed: {1}' -f $serial, $result.Error) }
        Start-Sleep -Milliseconds 200
    }
}
Write-Progress -Activity 'Importing Autopilot devices' -Completed

$pending = @($results | Where-Object { $_.Result -eq 'Imported' })
if ($Wait -and $pending.Count -gt 0) {
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while ($pending.Count -gt 0 -and (Get-Date) -lt $deadline) {
        Write-Host ('Waiting for {0} import(s) to finish; next check in 30 s (timeout {1:HH:mm:ss}).' -f $pending.Count, $deadline) -ForegroundColor Cyan
        Start-Sleep -Seconds 30
        foreach ($item in $pending) {
            try { $state = (Invoke-MgGraphRequest -Method GET -Uri ('{0}/{1}' -f $importUri, $item.ImportId) -OutputType PSObject -ErrorAction Stop).state }
            catch { Write-Warning ('Status check for {0} failed: {1}' -f $item.SerialNumber, $_.Exception.Message); continue }
            $item.ImportStatus = $state.deviceImportStatus
            if ($state.deviceImportStatus -in @('complete', 'partial', 'error')) {
                $item.ErrorCode = $state.deviceErrorCode; $item.ErrorName = $state.deviceErrorName
                if ($state.deviceImportStatus -eq 'error' -or [int]$state.deviceErrorCode -ne 0) { $item.Result = 'ImportError' }
                else { $item.Result = 'Registered' }
            }
        }
        $pending = @($results | Where-Object { $_.Result -eq 'Imported' })
    }
    if ($pending.Count -gt 0) { Write-Warning ('{0} import(s) were still pending after {1} minutes; re-check them in the Intune admin center.' -f $pending.Count, $TimeoutMinutes) }
}

$imported = @($results | Where-Object { $_.Result -in @('Imported', 'Registered') }).Count
if ($Sync -and $imported -gt 0 -and $PSCmdlet.ShouldProcess('Windows Autopilot service', 'Trigger device sync')) {
    # beta: the sync action has no v1.0 equivalent.
    try {
        Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotSettings/sync' -ErrorAction Stop | Out-Null
        Write-Host 'Autopilot sync requested.' -ForegroundColor Green
    }
    catch { Write-Warning ('Autopilot sync request failed (the service allows one sync every 10 minutes): {0}' -f $_.Exception.Message) }
}

Write-Host ("`nRows in CSV : {0}" -f $rows.Count) -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = @{ Failed = 'Red'; ImportError = 'Red'; Imported = 'Green'; Registered = 'Green' }[$group.Name]; if (-not $colour) { $colour = 'Yellow' }
    Write-Host ('  {0,-12} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
foreach ($item in ($results | Where-Object { $_.Result -eq 'ImportError' })) {
    Write-Host ('  {0}: error {1} {2}' -f $item.SerialNumber, $item.ErrorCode, $item.ErrorName) -ForegroundColor Red
}

$results
#endregion Main
