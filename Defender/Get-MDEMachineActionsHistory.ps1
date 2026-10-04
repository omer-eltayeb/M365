<#
.SYNOPSIS
    Reports the Microsoft Defender for Endpoint response actions (isolation, scans, packages...) submitted in the last N days.
.DESCRIPTION
    Lists machine actions with GET /machineactions filtered server-side on creationDateTimeUtc (-DaysBack) and optionally on
    -Type and -Status, then exports who requested what, on which device, with which outcome, scope and error details. With
    -CancelPending every action still Pending is cancelled (POST /machineactions/{id}/cancel) after confirmation, which is how
    stuck actions for offline devices are cleared from the Action center.
.PARAMETER TenantId
    Directory (tenant) ID or verified domain of the tenant that hosts the app registration.
.PARAMETER AppCredential
    PSCredential whose user name is the application (client) ID and whose password is the client secret.
.PARAMETER DaysBack
    How many days of history to include (1-180). Default 30.
.PARAMETER Type
    Only return actions of this type, for example Isolate, Unisolate, RunAntiVirusScan or CollectInvestigationPackage.
.PARAMETER Status
    Only return actions in this state: Pending, InProgress, Succeeded, Failed, TimeOut or Cancelled.
.PARAMETER CancelPending
    Cancels the Pending actions found by the query. Each cancellation goes through ShouldProcess (-WhatIf / -Confirm).
.PARAMETER Comment
    Comment recorded with each cancellation. Mandatory together with -CancelPending.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\MDEMachineActions_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the action objects to the pipeline.
.EXAMPLE
    PS> $cred = Get-Credential -UserName '<application-id>' -Message 'Client secret'
    PS> .\Get-MDEMachineActionsHistory.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -DaysBack 90
    Exports every response action of the last 90 days and prints the counts by type and status.
.EXAMPLE
    PS> .\Get-MDEMachineActionsHistory.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -Type Isolate -Status Pending -CancelPending -Comment 'INC0042 closed' -WhatIf
    Shows which pending isolation requests would be cancelled without cancelling anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x (REST calls only, no modules)
    Permissions : Application permission Machine.Read.All to report; cancelling also needs the permission of the action type (Machine.Isolate,
                  Machine.Scan, Machine.CollectForensics, Machine.RestrictExecution, Machine.LiveResponse...), granted with admin consent.
    Category    : Defender for Endpoint API
    Changes     : Optional (-CancelPending)
    Notes       : Only Pending actions can be cancelled; InProgress actions finish on their own. Dates are UTC.
.LINK
    https://learn.microsoft.com/defender-endpoint/api/get-machineactions-collection
#>
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [pscredential]$AppCredential,

    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 30,

    [Parameter()]
    [ValidateSet('RunAntiVirusScan', 'Offboard', 'LiveResponse', 'CollectInvestigationPackage', 'Isolate', 'Unisolate', 'StopAndQuarantineFile', 'RestrictCodeExecution', 'UnrestrictCodeExecution')]
    [string]$Type,

    [Parameter()]
    [ValidateSet('Pending', 'InProgress', 'Succeeded', 'Failed', 'TimeOut', 'Cancelled')]
    [string]$Status,

    [Parameter()]
    [switch]$CancelPending,

    [Parameter()]
    [string]$Comment,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
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

function ConvertTo-UtcDateTime {
    <# Normalises an API date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
}
#endregion Helpers

#region Main
if ($CancelPending -and [string]::IsNullOrWhiteSpace($Comment)) { throw 'Specify -Comment when using -CancelPending; the comment is recorded with every cancellation.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('MDEMachineActions_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { $token = Get-MdeAccessToken -TenantId $TenantId -AppCredential $AppCredential }
catch { throw "Unable to acquire a Defender for Endpoint API token: $($_.Exception.Message)" }

# InvariantCulture keeps ':' as the time separator regardless of the local culture, so the OData literal stays valid.
$since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
$filterParts = @("creationDateTimeUtc ge $since")
if (-not [string]::IsNullOrEmpty($Type)) { $filterParts += "type eq '$Type'" }
if (-not [string]::IsNullOrEmpty($Status)) { $filterParts += "status eq '$Status'" }
$uri = '{0}/machineactions?$filter={1}' -f $baseUri, ($filterParts -join ' and ')
Write-Verbose "Querying $uri"
try { $actions = @(Invoke-MdeRequest -Token $token -Uri $uri) }
catch { throw "Failed to list machine actions: $($_.Exception.Message)" }

$rows = @(foreach ($action in ($actions | Sort-Object -Property creationDateTimeUtc -Descending)) {
        [PSCustomObject]@{
            Id                    = $action.id
            Type                  = $action.type
            Status                = $action.status
            Requestor             = $action.requestor
            RequestorComment      = $action.requestorComment
            CreationDateTimeUtc   = ConvertTo-UtcDateTime -Value $action.creationDateTimeUtc
            LastUpdateDateTimeUtc = ConvertTo-UtcDateTime -Value $action.lastUpdateDateTimeUtc
            ComputerDnsName       = $action.computerDnsName
            MachineId             = $action.machineId
            Scope                 = $action.scope
            Errors                = (@($action.errorHResult, $action.troubleshootInfo) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) -and [string]$_ -ne '0' }) -join ' | '
            CancelResult          = $null
        }
    })

$cancelled = 0
if ($CancelPending) {
    $pending = @($rows | Where-Object { $_.Status -eq 'Pending' })
    if ($pending.Count -eq 0) { Write-Warning 'No action is in the Pending state; nothing to cancel.' }
    foreach ($row in $pending) {
        $target = '{0} on {1} (requested {2:u} by {3})' -f $row.Type, $row.ComputerDnsName, $row.CreationDateTimeUtc, $row.Requestor
        if (-not $PSCmdlet.ShouldProcess($target, 'Cancel machine action')) { $row.CancelResult = 'Skipped'; continue }
        try {
            $result = Invoke-MdeRequest -Token $token -Uri ('{0}/machineactions/{1}/cancel' -f $baseUri, $row.Id) -Method POST -Body @{ Comment = $Comment }
            $row.Status = $result.status; $row.CancelResult = 'Cancelled'; $cancelled++
        }
        catch { $row.CancelResult = "Failed: $($_.Exception.Message)"; Write-Warning "Could not cancel action $($row.Id) ($target): $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 200
    }
}

if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 } else { Write-Warning "No machine action matched in the last $DaysBack days; nothing was exported." }

Write-Host ('Defender for Endpoint machine actions, last {0} days: {1} (report: {2})' -f $DaysBack, $rows.Count, $OutputPath) -ForegroundColor Cyan
foreach ($dimension in @('Type', 'Status')) {
    $groups = @($rows | Group-Object -Property $dimension | Sort-Object -Property Count -Descending | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count })
    Write-Host ('  {0,-8} {1}' -f $dimension, ($groups -join ', ')) -ForegroundColor Green
}
if ($CancelPending) { Write-Host ('  Cancelled now: {0}' -f $cancelled) -ForegroundColor Green }

if ($PassThru) { $rows }
#endregion Main
