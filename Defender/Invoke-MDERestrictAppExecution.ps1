<#
.SYNOPSIS
    Restricts app execution on devices with Microsoft Defender for Endpoint (only Microsoft-signed code runs), or lifts the restriction.
.DESCRIPTION
    Resolves the target devices by machine id, device name or CSV, then submits POST /machines/{id}/restrictCodeExecution or, with
    -Remove, POST /machines/{id}/unrestrictCodeExecution through the Defender for Endpoint API. Every request goes through
    ShouldProcess (ConfirmImpact High); -Wait polls the machine actions until they finish. Outputs one result object per device.
.PARAMETER TenantId
    Directory (tenant) ID or verified domain of the tenant that hosts the app registration.
.PARAMETER AppCredential
    PSCredential whose user name is the application (client) ID and whose password is the client secret.
.PARAMETER MachineId
    One or more Defender for Endpoint machine ids.
.PARAMETER DeviceName
    One or more device names; matched on computerDnsName exactly first, then as a prefix (so a short host name works).
.PARAMETER InputCsv
    CSV file with a DeviceName column, resolved like -DeviceName.
.PARAMETER Comment
    Comment recorded with the action in the Action center (ticket number, reason).
.PARAMETER Remove
    Removes the app execution restriction (unrestrictCodeExecution) instead of applying it.
.PARAMETER Wait
    Polls the machine actions every 20 seconds until they complete or -TimeoutMinutes elapses.
.PARAMETER TimeoutMinutes
    Maximum time to wait for the actions when -Wait is used. Default 10.
.EXAMPLE
    PS> $cred = Get-Credential -UserName '<application-id>' -Message 'Client secret'
    PS> .\Invoke-MDERestrictAppExecution.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -DeviceName 'LAPTOP-0042' -Comment 'INC0042 unknown binaries executing' -Wait
    Asks for confirmation, applies the code integrity policy on LAPTOP-0042 and waits until Defender reports the action as Succeeded.
.EXAMPLE
    PS> .\Invoke-MDERestrictAppExecution.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -InputCsv .\restricted.csv -Remove -Comment 'INC0042 closed' -Confirm:$false
    Lifts the restriction on every device listed in the CSV without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x (REST calls only, no modules)
    Permissions : Application permissions Machine.RestrictExecution and Machine.Read.All (device lookup) granted with admin consent to an app registration.
    Category    : Defender for Endpoint API
    Changes     : Yes
    Notes       : The restriction applies a Windows Defender Application Control policy that only allows Microsoft-signed binaries; it is
                  supported on Windows 10 1709+ / Windows 11 and Windows Server 2019+. Offline devices stay Pending until they connect.
.LINK
    https://learn.microsoft.com/defender-endpoint/api/restrict-code-execution
#>
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [pscredential]$AppCredential,

    [Parameter()]
    [string[]]$MachineId,

    [Parameter()]
    [string[]]$DeviceName,

    [Parameter()]
    [string]$InputCsv,

    [Parameter(Mandatory = $true)]
    [string]$Comment,

    [Parameter()]
    [switch]$Remove,

    [Parameter()]
    [switch]$Wait,

    [Parameter()]
    [ValidateRange(1, 120)]
    [int]$TimeoutMinutes = 10
)

$ErrorActionPreference = 'Stop'
$baseUri = 'https://api.securitycenter.microsoft.com/api'

#region Helpers
function Get-MdeAccessToken {
    <# Acquires an app-only token for the Defender for Endpoint API with the client-credentials flow. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [pscredential]$AppCredential
    )
    $body = @{
        client_id     = $AppCredential.UserName
        client_secret = $AppCredential.GetNetworkCredential().Password
        scope         = 'https://api.securitycenter.microsoft.com/.default'
        grant_type    = 'client_credentials'
    }
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $response = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    return $response.access_token
}

function Invoke-MdeRequest {
    <# Calls the Defender for Endpoint API; GET requests follow @odata.nextLink. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [object]$Body
    )
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    if ($Method -ne 'GET') {
        $json = $null
        if ($null -ne $Body) { $json = $Body | ConvertTo-Json -Depth 10 }
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json -ErrorAction Stop
    }
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $response = Invoke-RestMethod -Method GET -Uri $nextLink -Headers $headers -ErrorAction Stop
        if ($null -ne $response.PSObject.Properties['value']) { foreach ($item in $response.value) { $results.Add($item) } }
        else { $results.Add($response) }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}

function Resolve-MdeMachine {
    <# Resolves -MachineId, -DeviceName and -InputCsv (DeviceName column) to unique machine objects; names match exactly first, then as a prefix. #>
    param([string]$Token, [string[]]$MachineId, [string[]]$DeviceName, [string]$InputCsv)
    $names = @($DeviceName)
    if (-not [string]::IsNullOrWhiteSpace($InputCsv)) { $names += @(Import-Csv -Path $InputCsv | ForEach-Object { $_.DeviceName }) }
    $found = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($id in @($MachineId | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        try { $found.Add(@(Invoke-MdeRequest -Token $Token -Uri "$baseUri/machines/$($id.Trim())")[0]) }
        catch { Write-Warning "Machine id '$id' was not found: $($_.Exception.Message)" }
    }
    foreach ($name in @($names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Select-Object -Unique)) {
        $hits = @()
        foreach ($filter in @("computerDnsName eq '$name'", "startswith(computerDnsName,'$name')")) {
            try { $hits = @(Invoke-MdeRequest -Token $Token -Uri ('{0}/machines?$filter={1}' -f $baseUri, $filter)) }
            catch { Write-Warning "Device lookup '$filter' failed: $($_.Exception.Message)" }
            if ($hits.Count -gt 0) { break }
        }
        if ($hits.Count -eq 0) { Write-Warning "No device matches '$name'."; continue }
        if ($hits.Count -gt 1) { Write-Warning "'$name' matches $($hits.Count) devices: $(@($hits | ForEach-Object { $_.computerDnsName }) -join ', ')" }
        foreach ($machine in $hits) { $found.Add($machine) }
    }
    return @($found | Sort-Object -Property id -Unique)
}

function Wait-MdeMachineAction {
    <# Polls GET /machineactions/{id} every 20 seconds and refreshes the rows until no action is Pending/InProgress or the timeout elapses. #>
    param([string]$Token, [object[]]$Rows, [int]$TimeoutMinutes)
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $running = @($Rows | Where-Object { $_.Status -in @('Pending', 'InProgress') })
    while ($running.Count -gt 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 20
        foreach ($row in $running) {
            try { $row.Status = @(Invoke-MdeRequest -Token $Token -Uri "$baseUri/machineactions/$($row.ActionId)")[0].status }
            catch { Write-Warning "Could not refresh action $($row.ActionId): $($_.Exception.Message)" }
        }
        $running = @($running | Where-Object { $_.Status -in @('Pending', 'InProgress') })
    }
    foreach ($row in $running) { $row.Message = "Still $($row.Status) after $TimeoutMinutes minute(s); follow up in the Action center." }
}
#endregion Helpers

#region Main
if (@($MachineId).Count -eq 0 -and @($DeviceName).Count -eq 0 -and [string]::IsNullOrWhiteSpace($InputCsv)) { throw 'Select the devices with -MachineId, -DeviceName or -InputCsv.' }
try { $token = Get-MdeAccessToken -TenantId $TenantId -AppCredential $AppCredential }
catch { throw "Unable to acquire a Defender for Endpoint API token: $($_.Exception.Message)" }
$machines = @(Resolve-MdeMachine -Token $token -MachineId $MachineId -DeviceName $DeviceName -InputCsv $InputCsv)
if ($machines.Count -eq 0) { Write-Warning 'No device could be resolved; nothing to do.'; return }

$actionName = $(if ($Remove) { 'unrestrictCodeExecution' } else { 'restrictCodeExecution' })
$operation = $(if ($Remove) { 'Remove the app execution restriction' } else { 'Restrict app execution to Microsoft-signed code' })
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($machine in $machines) {
    $row = [PSCustomObject]@{ DeviceName = $machine.computerDnsName; MachineId = $machine.id; Action = $actionName; ActionId = $null; Status = 'Skipped'; Message = $null }
    $rows.Add($row)
    $target = '{0} ({1}, {2}, last seen {3})' -f $machine.computerDnsName, $machine.id, $machine.osPlatform, $machine.lastSeen
    if (-not $PSCmdlet.ShouldProcess($target, $operation)) { $row.Message = 'Not confirmed (or -WhatIf)'; continue }
    try {
        $action = Invoke-MdeRequest -Token $token -Uri ('{0}/machines/{1}/{2}' -f $baseUri, $machine.id, $actionName) -Method POST -Body @{ Comment = $Comment }
        $row.ActionId = $action.id; $row.Status = $action.status
    }
    catch {
        # The API explains rejections (unsupported OS, action already running) in the response body, which ErrorDetails carries.
        $row.Status = 'Failed'; $row.Message = $(if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message })
        Write-Warning "$actionName failed for $($machine.computerDnsName): $($row.Message)"
    }
    Start-Sleep -Milliseconds 200
}
if ($Wait) { Wait-MdeMachineAction -Token $token -Rows $rows -TimeoutMinutes $TimeoutMinutes }

Write-Host ('Defender for Endpoint {0}: {1} device(s)' -f $actionName, $rows.Count) -ForegroundColor Cyan
foreach ($group in ($rows | Group-Object -Property Status | Sort-Object -Property Name)) {
    $colour = switch ($group.Name) { 'Succeeded' { 'Green' } 'Failed' { 'Red' } 'Skipped' { 'Gray' } default { 'Yellow' } }
    Write-Host ('  {0,-12} {1,5}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
$rows
#endregion Main
