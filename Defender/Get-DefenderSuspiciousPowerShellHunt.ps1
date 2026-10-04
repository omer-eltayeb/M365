<#
.SYNOPSIS
    Hunts suspicious PowerShell executions (encoded, hidden, download-cradle and Defender-tampering command lines) across onboarded devices.
.DESCRIPTION
    Runs an Advanced Hunting query through Microsoft Graph (POST v1.0 /security/runHuntingQuery) over DeviceProcessEvents for powershell.exe,
    pwsh.exe and powershell_ise.exe whose command line contains classic attacker tokens (-enc, FromBase64String, DownloadString, IEX, -w hidden,
    bypass, Invoke-Mimikatz, Set-MpPreference and so on), excluding known management parents such as the Intune Management Extension. Returns
    one row per event with parent process and SHA256, or with -Summary one row per device, account and parent; -DecodeEncoded decodes -enc payloads.
.PARAMETER Days
    Timespan of the query in days (1-30, default 7).
.PARAMETER DeviceName
    Prefix match on DeviceName, so the short name works against the FQDN stored by Defender.
.PARAMETER AccountName
    Exact (case-insensitive) match on AccountName, for example jdoe or SYSTEM.
.PARAMETER ExcludeInitiatingProcess
    Parent process file names to ignore. Default: IntuneManagementExtension.exe and ccmexec.exe. Pass an empty array to keep everything.
.PARAMETER Summary
    Summarises events per DeviceName, AccountName and InitiatingProcessFileName (Events, FirstSeen, LastSeen, SampleCommandLine).
.PARAMETER DecodeEncoded
    Adds a DecodedCommand column: the Base64 after -e, -ec, -enc or -EncodedCommand decoded as UTF-16LE and truncated to 300 characters.
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderSuspiciousPowerShellHunt_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderSuspiciousPowerShellHunt.ps1 -DecodeEncoded
    Exports every suspicious PowerShell launch of the last 7 days with the decoded encoded commands.
.EXAMPLE
    PS> .\Get-DefenderSuspiciousPowerShellHunt.ps1 -Days 30 -Summary -ExcludeInitiatingProcess IntuneManagementExtension.exe, ccmexec.exe, monitoringhost.exe
    Shows which devices, accounts and parent processes launch flagged PowerShell most often, ignoring three management agents.
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
                  property (P<n>D). The token list is deliberately broad, so expect legitimate admin scripts in the output and tune it with
                  -Summary and -ExcludeInitiatingProcess. DecodedCommand shows '(invalid base64)' when the recorded command line was truncated.
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
    [string]$DeviceName,

    [Parameter()]
    [string]$AccountName,

    [Parameter()]
    [string[]]$ExcludeInitiatingProcess = @('IntuneManagementExtension.exe', 'ccmexec.exe'),

    [Parameter()]
    [switch]$Summary,

    [Parameter()]
    [switch]$DecodeEncoded,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderSuspiciousPowerShellHunt_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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
if (-not [string]::IsNullOrWhiteSpace($AccountName)) { $filters += "| where AccountName =~ '{0}'" -f $AccountName.Replace('\', '\\').Replace("'", "\'") }
$excluded = @($ExcludeInitiatingProcess | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { "'{0}'" -f $_.Replace('\', '\\').Replace("'", "\'") })
if ($excluded.Count -gt 0) { $filters += '| where InitiatingProcessFileName !in~ ({0})' -f ($excluded -join ', ') }
$shape = '| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256, ReportId'
$shape += "`n| order by Timestamp desc"
if ($Summary) {
    $shape = '| summarize Events=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), SampleCommandLine=any(ProcessCommandLine) by DeviceName, AccountName, InitiatingProcessFileName'
    $shape += "`n| order by Events desc"
}
$query = @"
DeviceProcessEvents
| where FileName in~ ('powershell.exe','pwsh.exe','powershell_ise.exe')
| where ProcessCommandLine has_any ('-enc','-EncodedCommand','FromBase64String','DownloadString','DownloadFile','IEX','Invoke-Expression','Invoke-WebRequest',
    'Net.WebClient','-nop','-w hidden','-WindowStyle Hidden','bypass','Invoke-Mimikatz','Add-MpPreference','Set-MpPreference')
$($filters -join "`n")
$shape
"@
Write-Verbose "Running query:`n$query"
try { $rows = @(Invoke-HuntingQuery -Query $query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }
if ($rows.Count -eq 0) { Write-Warning ('No suspicious PowerShell events matched in the last {0} day(s); nothing exported.' -f $Days); return }
$report = @(foreach ($row in $rows) { ConvertTo-ReportRow -Row $row })
if ($DecodeEncoded -and -not $Summary) {
    foreach ($row in $report) {
        $decoded = ''
        if ($row.ProcessCommandLine -match '(?i)\s-e(?:c|nc|ncodedcommand)?\s+["'']?([A-Za-z0-9+/=]{16,})') {
            try { $decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1])) } catch { $decoded = '(invalid base64)' }
            if ($decoded.Length -gt 300) { $decoded = $decoded.Substring(0, 300) + '...' }
        }
        $row | Add-Member -NotePropertyName DecodedCommand -NotePropertyValue $decoded
    }
}
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$deviceCount = @($report | Select-Object -ExpandProperty DeviceName -Unique).Count
Write-Host ('Suspicious PowerShell, last {0} days: {1} {2} on {3} device(s)' -f $Days, $report.Count, $(if ($Summary) { 'combination(s)' } else { 'event(s)' }), $deviceCount) -ForegroundColor Cyan
$parents = $report | Group-Object -Property InitiatingProcessFileName | Sort-Object -Property Count -Descending | Select-Object -First 5
Write-Host ('  Top initiating processes: {0}' -f (@($parents | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }) -join ' | ')) -ForegroundColor Yellow
foreach ($row in ($report | Select-Object -First 5)) {
    $commandLine = if ($Summary) { '{0} event(s), e.g. {1}' -f $row.Events, $row.SampleCommandLine } else { [string]$row.ProcessCommandLine }
    if ($commandLine.Length -gt 120) { $commandLine = $commandLine.Substring(0, 120) + '...' }
    Write-Host ('    {0} / {1} / parent {2}: {3}' -f $row.DeviceName, $row.AccountName, $row.InitiatingProcessFileName, $commandLine)
}
Write-Host ('  Report -> {0}' -f $OutputPath)
if ($PassThru) { $report }
#endregion Main
