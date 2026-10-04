<#
.SYNOPSIS
    Hunts Defender for Identity logon telemetry for password spray sources, NTLM usage and interactive logons by service accounts.
.DESCRIPTION
    Runs one of three Advanced Hunting queries over IdentityLogonEvents through Microsoft Graph (POST v1.0 /security/runHuntingQuery):
    Spray (default) summarises failed logons per source IP, location, device and application with the distinct accounts targeted, protocols
    and failure reasons, keeping sources with at least -MinimumFailures failures; Ntlm counts NTLM authentications per account, source device,
    destination device and application; ServiceAccountInteractive lists interactive logons by -ServiceAccountPrefix accounts and their devices.
.PARAMETER Days
    Timespan of the query in days (1-30, default 7).
.PARAMETER Mode
    Spray (default), Ntlm or ServiceAccountInteractive.
.PARAMETER MinimumFailures
    Spray mode only: minimum failed logons per source (default 20).
.PARAMETER ServiceAccountPrefix
    ServiceAccountInteractive mode only: AccountName prefix that identifies service accounts (default svc).
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderIdentityLogonHunt_<Mode>_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderIdentityLogonHunt.ps1 -Days 3 -MinimumFailures 50
    Lists the sources that produced 50 or more failed logons in the last 3 days, with the accounts they tried.
.EXAMPLE
    PS> .\Get-DefenderIdentityLogonHunt.ps1 -Mode ServiceAccountInteractive -ServiceAccountPrefix 'sa_' -OutputPath C:\Temp\ServiceAccountLogons.csv -PassThru
    Shows which sa_ accounts are used for interactive sign-ins, which usually violates service-account hygiene.
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
                  property (P<n>D). IdentityLogonEvents needs Defender for Identity sensors on the domain controllers (plus Defender for Cloud
                  Apps for cloud logons); without them the table is empty. A distributed spray shows as many low-volume sources - check Targets.
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
    [ValidateSet('Spray', 'Ntlm', 'ServiceAccountInteractive')]
    [string]$Mode = 'Spray',

    [Parameter()]
    [ValidateRange(1, 1000000)]
    [int]$MinimumFailures = 20,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceAccountPrefix = 'svc',

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderIdentityLogonHunt_{0}_{1}.csv' -f $Mode, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('ThreatHunting.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# Backslash and single quote are escaped so the user value is a safe KQL string literal.
$prefix = $ServiceAccountPrefix.Replace('\', '\\').Replace("'", "\'")
$query = @"
IdentityLogonEvents
| where ActionType == 'LogonFailed'
| summarize Failures=count(), Targets=dcount(AccountUpn), Accounts=make_set(AccountUpn, 20), Protocols=make_set(Protocol), FailureReasons=make_set(FailureReason),
    FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by IPAddress, Location, DeviceName, Application
| where Failures >= $MinimumFailures
| order by Failures desc
"@
if ($Mode -eq 'Ntlm') {
    $query = @"
IdentityLogonEvents
| where Protocol == 'Ntlm'
| summarize Logons=count() by AccountUpn, DeviceName, DestinationDeviceName, Application
| order by Logons desc
"@
}
elseif ($Mode -eq 'ServiceAccountInteractive') {
    $query = @"
IdentityLogonEvents
| where LogonType == 'Interactive' and AccountName startswith '$prefix'
| summarize Logons=count(), Devices=make_set(DeviceName, 20) by AccountUpn, AccountName
| order by Logons desc
"@
}
Write-Verbose "Running query:`n$query"
try { $rows = @(Invoke-HuntingQuery -Query $query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }
if ($rows.Count -eq 0) { Write-Warning ('No identity logon events matched the {0} hunt in the last {1} day(s); nothing exported.' -f $Mode, $Days); return }
$report = @(foreach ($row in $rows) { ConvertTo-ReportRow -Row $row })
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$countColumn = if ($Mode -eq 'Spray') { 'Failures' } else { 'Logons' }
$total = ($report | Measure-Object -Property $countColumn -Sum).Sum
Write-Host ('Identity logon hunt - {0} (last {1} days): {2} row(s), {3} {4}' -f $Mode, $Days, $report.Count, $total, $countColumn.ToLower()) -ForegroundColor Cyan
if ($Mode -eq 'Spray') {
    $sprays = @($report | Where-Object { $_.Targets -ge 5 }).Count
    Write-Host ('  Sources that hit 5 or more accounts (spray pattern): {0}' -f $sprays) -ForegroundColor $(if ($sprays -gt 0) { 'Red' } else { 'Yellow' })
}
Write-Host '  Top rows:' -ForegroundColor Yellow
foreach ($row in ($report | Select-Object -First 10)) {
    $line = switch ($Mode) {
        'Ntlm' { '{0,6} logon(s)  {1}  {2} -> {3}  via {4}' -f $row.Logons, $row.AccountUpn, $row.DeviceName, $row.DestinationDeviceName, $row.Application }
        'ServiceAccountInteractive' { '{0,6} logon(s)  {1}  on {2}' -f $row.Logons, $row.AccountName, $row.Devices }
        default { '{0,6} failure(s) / {1,4} account(s)  {2,-16} {3}  via {4}  [{5}]' -f $row.Failures, $row.Targets, $row.IPAddress, $row.Location, $row.Application, $row.FailureReasons }
    }
    Write-Host ('    ' + $line)
}
Write-Host ('  Report -> {0}' -f $OutputPath)
if ($PassThru) { $report }
#endregion Main
