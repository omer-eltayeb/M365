<#
.SYNOPSIS
    Hunts remote (RDP and network) logon attempts per device and source IP to surface brute-force patterns and external access.
.DESCRIPTION
    Runs an Advanced Hunting query through Microsoft Graph (POST v1.0 /security/runHuntingQuery) over DeviceLogonEvents and summarises
    RemoteInteractive and Network logons per DeviceName, RemoteIP, RemoteDeviceName and LogonType: attempts, failures, successes, first and
    last seen, up to 10 account names and whether the source IP is public; rows are ordered by failures and limited to sources with at
    least -MinimumFailures failed attempts. -ShowAdminLogons runs a different hunt: interactive logons by local administrators per account.
.PARAMETER Days
    Timespan of the query in days (1-30, default 7).
.PARAMETER LogonType
    Restricts the default hunt to RemoteInteractive (RDP) or Network logons. Default: both.
.PARAMETER OnlyExternal
    Keeps only sources whose RemoteIP is a public IPv4 address (not(ipv4_is_private(RemoteIP))).
.PARAMETER MinimumFailures
    Minimum number of failed attempts per device and source (default 5). Use 0 to include sources that only succeeded.
.PARAMETER DeviceName
    Prefix match on DeviceName, so the short name works against the FQDN stored by Defender.
.PARAMETER ShowAdminLogons
    Reports interactive logons by local administrators (IsLocalAdmin == true) per AccountName and AccountDomain instead.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderRemoteLogonsHunt_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderRemoteLogonsHunt.ps1 -OnlyExternal -MinimumFailures 0 -Days 30
    Lists every public IP that attempted RDP or network logons in the last 30 days, including the ones that succeeded without failures.
.EXAMPLE
    PS> .\Get-DefenderRemoteLogonsHunt.ps1 -ShowAdminLogons -DeviceName SRV- -OutputPath C:\Temp\AdminLogons.csv -PassThru | Sort-Object -Property Logons -Descending
    Shows which local administrator accounts signed in interactively on servers whose name starts with SRV-.
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
                  property (P<n>D). IsExternalIP is empty for IPv6 sources (ipv4_is_private only evaluates IPv4). Network logons include
                  normal file-share and management traffic, so tune -MinimumFailures before raising alarms.
.LINK
    https://learn.microsoft.com/graph/api/security-security-runhuntingquery
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$Days = 7,

    [Parameter()]
    [ValidateSet('RemoteInteractive', 'Network')]
    [string]$LogonType,

    [Parameter()]
    [switch]$OnlyExternal,

    [Parameter()]
    [int]$MinimumFailures = 5,

    [Parameter()]
    [string]$DeviceName,

    [Parameter()]
    [switch]$ShowAdminLogons,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderRemoteLogonsHunt_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('ThreatHunting.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
# Backslash and single quote are escaped so the user value is a safe KQL string literal.
$deviceFilter = ''
if (-not [string]::IsNullOrWhiteSpace($DeviceName)) { $deviceFilter = "| where DeviceName startswith '{0}'" -f $DeviceName.Replace('\', '\\').Replace("'", "\'") }
$query = @"
DeviceLogonEvents
| where LogonType in ('RemoteInteractive','Network') and ActionType in ('LogonSuccess','LogonFailed')
| where isnotempty(RemoteIP)
| extend IsExternalIP = not(ipv4_is_private(RemoteIP))
$deviceFilter
$(if (-not [string]::IsNullOrWhiteSpace($LogonType)) { "| where LogonType == '$LogonType'" })
$(if ($OnlyExternal) { '| where IsExternalIP == true' })
| summarize Attempts=count(), Failures=countif(ActionType=='LogonFailed'), Successes=countif(ActionType=='LogonSuccess'), FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp), Accounts=make_set(AccountName, 10) by DeviceName, RemoteIP, RemoteDeviceName, LogonType, IsExternalIP
| where Failures >= $MinimumFailures
| order by Failures desc
"@
if ($ShowAdminLogons) {
    $query = @"
DeviceLogonEvents
| where IsLocalAdmin == true and LogonType == 'Interactive'
$deviceFilter
| summarize Logons=count(), Devices=make_set(DeviceName, 20) by AccountName, AccountDomain
| order by Logons desc
"@
}
Write-Verbose "Running query:`n$query"
try { $rows = @(Invoke-HuntingQuery -Query $query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }
if ($rows.Count -eq 0) { Write-Warning ('No logon events matched the filters in the last {0} day(s); nothing exported.' -f $Days); return }
$report = @(foreach ($row in $rows) { ConvertTo-ReportRow -Row $row })
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($ShowAdminLogons) {
    Write-Host ('Local administrator interactive logons (last {0} days): {1} account(s)' -f $Days, $report.Count) -ForegroundColor Cyan
    foreach ($row in ($report | Select-Object -First 10)) { Write-Host ('    {0,6} logon(s)  {1}\{2}  on {3}' -f $row.Logons, $row.AccountDomain, $row.AccountName, $row.Devices) }
}
else {
    $bruteForce = @($report | Where-Object { $_.Failures -ge 20 })
    $breached = @($bruteForce | Where-Object { $_.Successes -gt 0 }).Count
    $external = @($report | Where-Object { $_.IsExternalIP -eq $true }).Count
    Write-Host ('Remote logon sources (last {0} days): {1} device/source pair(s), {2} from public IPs' -f $Days, $report.Count, $external) -ForegroundColor Cyan
    Write-Host ('  Brute-force pattern (20+ failures): {0} pair(s), {1} followed by a success' -f $bruteForce.Count, $breached) -ForegroundColor $(if ($breached -gt 0) { 'Red' } else { 'Yellow' })
    foreach ($row in ($report | Select-Object -First 10)) {
        Write-Host ('    {0,6} failed / {1,5} ok  {2,-16} -> {3}  ({4}, external: {5})' -f $row.Failures, $row.Successes, $row.RemoteIP, $row.DeviceName, $row.LogonType, $row.IsExternalIP)
    }
}
Write-Host ('  Report -> {0}' -f $OutputPath)
if ($PassThru) { $report }
#endregion Main
