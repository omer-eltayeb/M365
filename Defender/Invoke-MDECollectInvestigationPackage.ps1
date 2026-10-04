<#
.SYNOPSIS
    Collects Microsoft Defender for Endpoint investigation packages from devices and optionally downloads the ZIP files.
.DESCRIPTION
    Resolves the target devices by machine id, device name or CSV and submits POST /machines/{id}/collectInvestigationPackage
    for each one (ShouldProcess). The script waits for the actions to finish, then calls GET /machineactions/{id}/getPackageUri
    for the short-lived SAS link; with -Download each package is saved as <DeviceName>_<yyyyMMdd-HHmm>.zip in -DownloadFolder.
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
.PARAMETER TimeoutMinutes
    Maximum time to wait for the collections to finish (polled every 20 seconds). Default 10; 0 submits the requests without waiting.
.PARAMETER Download
    Downloads every finished package to -DownloadFolder with Invoke-WebRequest.
.PARAMETER DownloadFolder
    Folder for the downloaded ZIP files, created when missing. Default .\InvestigationPackages.
.EXAMPLE
    PS> .\Invoke-MDECollectInvestigationPackage.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -DeviceName 'LAPTOP-0042' -Comment 'INC0042 forensics' -Download
    Collects the package from LAPTOP-0042, waits for completion and saves LAPTOP-0042_<timestamp>.zip under .\InvestigationPackages.
.EXAMPLE
    PS> .\Invoke-MDECollectInvestigationPackage.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -InputCsv .\affected.csv -Comment 'INC0042' -TimeoutMinutes 0 -Confirm:$false
    Queues the collection on every device in the CSV without prompting or waiting; the packages can be downloaded later from the Action center.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x (REST calls only, no modules)
    Permissions : Application permissions Machine.CollectForensics and Machine.Read.All (device lookup), admin consent required; the API
                  reference also lists Machine.ReadWrite.All for getPackageUri, grant it as well if the link request is denied.
    Category    : Defender for Endpoint API
    Changes     : Yes
    Notes       : getPackageUri allows 2 calls per minute, so the script pauses 30 seconds between packages and uses each SAS link at once.
.LINK
    https://learn.microsoft.com/defender-endpoint/api/collect-investigation-package
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
    [ValidateRange(0, 120)]
    [int]$TimeoutMinutes = 10,

    [Parameter()]
    [switch]$Download,

    [Parameter()]
    [string]$DownloadFolder = (Join-Path -Path (Get-Location).Path -ChildPath 'InvestigationPackages')
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
}
#endregion Helpers

#region Main
if (@($MachineId).Count -eq 0 -and @($DeviceName).Count -eq 0 -and [string]::IsNullOrWhiteSpace($InputCsv)) { throw 'Select the devices with -MachineId, -DeviceName or -InputCsv.' }
if ($Download) { if ($TimeoutMinutes -eq 0) { throw '-Download needs the collections to finish; use -TimeoutMinutes above 0.' }; New-Item -Path $DownloadFolder -ItemType Directory -Force | Out-Null }
try { $token = Get-MdeAccessToken -TenantId $TenantId -AppCredential $AppCredential }
catch { throw "Unable to acquire a Defender for Endpoint API token: $($_.Exception.Message)" }
$machines = @(Resolve-MdeMachine -Token $token -MachineId $MachineId -DeviceName $DeviceName -InputCsv $InputCsv)
if ($machines.Count -eq 0) { Write-Warning 'No device could be resolved; nothing to do.'; return }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($machine in $machines) {
    $row = [PSCustomObject]@{ DeviceName = $machine.computerDnsName; MachineId = $machine.id; ActionId = $null; Status = 'Skipped'; PackageUri = $null; FilePath = $null; Message = $null }
    $rows.Add($row)
    $target = '{0} ({1}, {2}, last seen {3})' -f $machine.computerDnsName, $machine.id, $machine.osPlatform, $machine.lastSeen
    if (-not $PSCmdlet.ShouldProcess($target, 'Collect investigation package')) { $row.Message = 'Not confirmed (or -WhatIf)'; continue }
    try {
        $action = Invoke-MdeRequest -Token $token -Uri ('{0}/machines/{1}/collectInvestigationPackage' -f $baseUri, $machine.id) -Method POST -Body @{ Comment = $Comment }
        $row.ActionId = $action.id; $row.Status = $action.status
    }
    catch { $row.Status = 'Failed'; $row.Message = $(if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message }); Write-Warning "$($machine.computerDnsName): $($row.Message)" }
}
Wait-MdeMachineAction -Token $token -Rows $rows -TimeoutMinutes $TimeoutMinutes

$completed = @($rows | Where-Object { $_.Status -eq 'Succeeded' })
for ($i = 0; $i -lt $completed.Count; $i++) {
    # getPackageUri allows 2 calls per minute and its SAS link expires quickly, so packages are fetched and downloaded one at a time.
    if ($i -gt 0) { Start-Sleep -Seconds 30 }
    $row = $completed[$i]
    try {
        $row.PackageUri = ([string]@(Invoke-MdeRequest -Token $token -Uri ('{0}/machineactions/{1}/getPackageUri' -f $baseUri, $row.ActionId))[0]).Trim('"')
        if (-not $Download) { continue }
        $filePath = Join-Path -Path $DownloadFolder -ChildPath ('{0}_{1}.zip' -f ($row.DeviceName -replace '[\\/:*?"<>|]', '_'), (Get-Date -Format 'yyyyMMdd-HHmm'))
        Invoke-WebRequest -Uri $row.PackageUri -OutFile $filePath -UseBasicParsing -ErrorAction Stop
        $row.FilePath = $filePath; $row.Message = 'Downloaded {0:N1} MB' -f ((Get-Item -Path $filePath).Length / 1MB)
    }
    catch { $row.Message = "Package retrieval failed: $($_.Exception.Message)"; Write-Warning "$($row.DeviceName): $($row.Message)" }
}

$summary = @($rows | Group-Object -Property Status | Sort-Object -Property Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '
Write-Host ('Investigation package collection: {0} device(s) - {1}; {2} package(s) downloaded' -f $rows.Count, $summary, @($rows | Where-Object { $null -ne $_.FilePath }).Count) -ForegroundColor Cyan
$rows
#endregion Main
