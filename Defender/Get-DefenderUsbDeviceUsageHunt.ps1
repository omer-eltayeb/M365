<#
.SYNOPSIS
    Hunts USB drive mounts and removable device connections across onboarded devices, with product, manufacturer and serial number.
.DESCRIPTION
    Runs an Advanced Hunting query through Microsoft Graph (POST v1.0 /security/runHuntingQuery) over DeviceEvents for the
    UsbDriveMounted, UsbDriveUnmounted and PnpDeviceConnected actions, parses AdditionalFields into DriveLetter, ProductName,
    SerialNumber, Manufacturer, Volume, ClassName and DeviceDescription, and keeps PnP connections only for the USB, DiskDrive and WPD
    classes. Returns one row per event (newest first) or, with -Summary, one row per device, serial number and product with the number
    of mounts and the first and last time the drive was seen. Writes a CSV and prints the most active devices.
.PARAMETER Days
    Timespan of the query in days (1-30, default 7).
.PARAMETER DeviceName
    Prefix match on DeviceName, so the short name works against the FQDN stored by Defender.
.PARAMETER AccountName
    Exact (case-insensitive) match on the account that was signed in when the device was connected (InitiatingProcessAccountName).
.PARAMETER Summary
    Summarises UsbDriveMounted/Unmounted events per DeviceName, SerialNumber and ProductName (Mounts, Events, FirstSeen, LastSeen, Accounts).
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderUsbDeviceUsageHunt_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderUsbDeviceUsageHunt.ps1 -Days 30 -Summary
    Shows which removable drives (by serial number) were mounted on which devices over the last 30 days and how often.
.EXAMPLE
    PS> .\Get-DefenderUsbDeviceUsageHunt.ps1 -DeviceName FIN-LT -AccountName jdoe -OutputPath C:\Temp\UsbEvents.csv -PassThru | Select-Object -First 20
    Lists every USB event for one user on the finance laptops and shows the 20 most recent ones in the console.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access.
    Category    : Advanced hunting (Graph)
    Changes     : No
    Notes       : Advanced hunting caps results per query (10,000 rows in the portal, 100,000 through the API); -Days maps to the Timespan
                  property (P<n>D). PnpDeviceConnected rows carry ClassName and DeviceDescription but no drive letter or serial number, which
                  is why -Summary only counts UsbDriveMounted/Unmounted events. Pair this hunt with a device control policy for enforcement.
.LINK
    https://learn.microsoft.com/graph/api/security-security-runhuntingquery
.LINK
    https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceevents-table
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$Days = 7,

    [Parameter()]
    [string]$DeviceName,

    [Parameter()]
    [string]$AccountName,

    [Parameter()]
    [switch]$Summary,

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

function Invoke-HuntingQuery {
    <# Runs an Advanced Hunting KQL query through Microsoft Graph and returns the result rows. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$Days = 7
    )
    $body = @{ Query = $Query; Timespan = ('P{0}D' -f $Days) }
    $response = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
    if ($null -eq $response.results) { return @() }
    return @($response.results)
}

function ConvertTo-ReportRow {
    <# Copies one hunting result row into a PSCustomObject in projection order: dynamic arrays joined with '; ', ISO timestamps as UTC [datetime]. #>
    param([Parameter(Mandatory = $true)][object]$Row)
    $shaped = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [array]) { $value = @($value | ForEach-Object { if ($_ -is [string] -or $_ -is [ValueType]) { [string]$_ } else { $_ | ConvertTo-Json -Compress } }) -join '; ' }
        elseif ($value -is [string] -and $value -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') { $value = [datetime]::Parse($value, [cultureinfo]::InvariantCulture, 'AdjustToUniversal') }
        $shaped[$property.Name] = $value
    }
    return [PSCustomObject]$shaped
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderUsbDeviceUsageHunt_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('ThreatHunting.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# Backslash and single quote are escaped so user values are safe KQL string literals.
$filters = @()
if (-not [string]::IsNullOrWhiteSpace($DeviceName)) { $filters += "| where DeviceName startswith '{0}'" -f $DeviceName.Replace('\', '\\').Replace("'", "\'") }
if (-not [string]::IsNullOrWhiteSpace($AccountName)) { $filters += "| where InitiatingProcessAccountName =~ '{0}'" -f $AccountName.Replace('\', '\\').Replace("'", "\'") }
$shape = @"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, ActionType, DriveLetter, ProductName, Manufacturer, SerialNumber, Volume, ClassName, DeviceDescription
| order by Timestamp desc
"@
if ($Summary) {
    $shape = @"
| where ActionType startswith 'UsbDrive'
| summarize Mounts=countif(ActionType == 'UsbDriveMounted'), Events=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    Accounts=make_set(InitiatingProcessAccountName, 10) by DeviceName, SerialNumber, ProductName
| order by Mounts desc
"@
}
$query = @"
DeviceEvents
| where ActionType in ('UsbDriveMounted','UsbDriveUnmounted','PnpDeviceConnected')
$($filters -join "`n")
| extend Parsed = parse_json(AdditionalFields)
| extend DriveLetter = tostring(Parsed.DriveLetter), ProductName = tostring(Parsed.ProductName), SerialNumber = tostring(Parsed.SerialNumber),
    Manufacturer = tostring(Parsed.Manufacturer), Volume = tostring(Parsed.Volume), ClassName = tostring(Parsed.ClassName), DeviceDescription = tostring(Parsed.DeviceDescription)
| where ActionType != 'PnpDeviceConnected' or ClassName in~ ('USB','DiskDrive','WPD')
$shape
"@
Write-Verbose "Running query:`n$query"
try { $rows = @(Invoke-HuntingQuery -Query $query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }
if ($rows.Count -eq 0) { Write-Warning ('No USB or removable device events matched in the last {0} day(s); nothing exported.' -f $Days); return }
$report = @(foreach ($row in $rows) { ConvertTo-ReportRow -Row $row })
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$deviceCount = @($report | Select-Object -ExpandProperty DeviceName -Unique).Count
$serialCount = @($report | Where-Object { -not [string]::IsNullOrWhiteSpace($_.SerialNumber) } | Select-Object -ExpandProperty SerialNumber -Unique).Count
if ($Summary) {
    Write-Host ('USB drive usage (last {0} days): {1} device/drive pair(s), {2} device(s), {3} distinct serial number(s)' -f $Days, $report.Count, $deviceCount, $serialCount) -ForegroundColor Cyan
    Write-Host '  Most mounted drives:' -ForegroundColor Yellow
    foreach ($row in ($report | Select-Object -First 10)) {
        Write-Host ('    {0,5} mount(s)  {1}  {2} [{3}]  last {4:yyyy-MM-dd HH:mm}' -f $row.Mounts, $row.DeviceName, $row.ProductName, $row.SerialNumber, $row.LastSeen)
    }
}
else {
    $mounts = @($report | Where-Object { $_.ActionType -eq 'UsbDriveMounted' }).Count
    Write-Host ('USB and removable device events (last {0} days): {1} event(s), {2} mount(s), {3} device(s), {4} distinct serial number(s)' -f $Days,
        $report.Count, $mounts, $deviceCount, $serialCount) -ForegroundColor Cyan
    Write-Host '  Devices with the most events:' -ForegroundColor Yellow
    foreach ($group in ($report | Group-Object -Property DeviceName | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
        Write-Host ('    {0,5} event(s)  {1}' -f $group.Count, $group.Name)
    }
}
Write-Host ('  Report -> {0}' -f $OutputPath)
if ($PassThru) { $report }
#endregion Main
