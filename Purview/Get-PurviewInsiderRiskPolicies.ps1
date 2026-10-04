<#
.SYNOPSIS
    Documents Microsoft Purview Insider Risk Management policies (scenario, mode, scope, time spans, indicators).
.DESCRIPTION
    Connects to Security & Compliance PowerShell and reads every policy with Get-InsiderRiskPolicy. Each policy becomes
    one row with its scenario, enabled state / mode, priority, Exchange, SharePoint, OneDrive and Teams scope, historic and
    in-scope time spans, the indicators found in the policy Settings (when present), created / changed dates and
    distribution status. Policies that are disabled or have no locations are flagged. Writes a CSV plus a raw JSON export
    of everything the cmdlet returned and prints a short summary.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewInsiderRiskPolicies_yyyyMMdd-HHmm.csv; the raw JSON is written next to it with a .json extension.
.PARAMETER PassThru
    Also emit the policy rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewInsiderRiskPolicies.ps1
    Exports all insider risk policies to .\Reports and prints counts by scenario with the disabled / unscoped flags.
.EXAMPLE
    PS> .\Get-PurviewInsiderRiskPolicies.ps1 -OutputPath C:\Baselines\IRM\Policies.csv -PassThru | Where-Object { $_.Flag }
    Keeps a baseline copy and shows only the policies that need attention.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Insider Risk Management or Insider Risk Management Admins role group in Microsoft Purview (Security & Compliance PowerShell)
    Category    : Risk, compliance & roles
    Changes     : No
    Notes       : Insider Risk Management needs Microsoft 365 E5, E5 Compliance or the E5 Insider Risk Management add-on. The
                  Get-InsiderRiskPolicy cmdlet is only imported into the session when the account holds an IRM role group, and
                  the properties it returns vary between tenants and module versions, so the script reads them defensively and
                  stops with a clear message when the cmdlet is missing. Indicators are parsed from the Settings JSON when present.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-insiderriskpolicy
.LINK
    https://learn.microsoft.com/purview/insider-risk-management-policies
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-ExchangeIfNeeded {
    <# Connects to Exchange Online (or Security & Compliance PowerShell) only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Compliance
    )
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($Compliance) {
        $active = @($connections | Where-Object { $_.ConnectionUri -like '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Security & Compliance PowerShell.'
            Connect-IPPSSession -ErrorAction Stop
        }
    }
    else {
        $active = @($connections | Where-Object { $_.ConnectionUri -notlike '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewInsiderRiskPolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$jsonPath = [System.IO.Path]::ChangeExtension($OutputPath, '.json')

try {
    Connect-ExchangeIfNeeded -Compliance
}
catch {
    throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)"
}
if ($null -eq (Get-Command -Name Get-InsiderRiskPolicy -ErrorAction SilentlyContinue)) {
    throw ('Get-InsiderRiskPolicy is not available in this session. It requires Microsoft 365 E5 / E5 Compliance (or the IRM add-on) ' +
        'and membership in the Insider Risk Management or Insider Risk Management Admins role group.')
}
try {
    $policies = @(Get-InsiderRiskPolicy -ErrorAction Stop)
}
catch {
    throw "Get-InsiderRiskPolicy failed: $($_.Exception.Message)"
}

$locationNames = 'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'TeamsLocation'
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($policy in $policies) {
    $index++
    Write-Progress -Activity 'Reading insider risk policies' -Status $policy.Name -PercentComplete (100 * $index / $policies.Count)
    # Enabled is not present on every version of the cmdlet output; Mode carries the same information then.
    $isEnabled = $(if ($null -ne $policy.PSObject.Properties['Enabled']) { $policy.Enabled -eq $true } else { [string]$policy.Mode -eq 'Enable' })
    $locationCount = 0
    $row = [ordered]@{
        Name                = [string]$policy.Name
        Guid                = [string]$policy.Guid
        Enabled             = $isEnabled
        Mode                = [string]$policy.Mode
        InsiderRiskScenario = [string]$policy.InsiderRiskScenario
        Priority            = $policy.Priority
    }
    foreach ($name in $locationNames) {
        $values = @($policy.$name | Where-Object { $null -ne $_ })
        $locationCount += $values.Count
        $row[$name] = ($values -join '; ')
    }
    # Settings is a JSON document on current builds; the indicator names live in its Indicators collection.
    $indicators = ''
    $settings = $policy.Settings
    if ($settings -is [string] -and $settings.TrimStart().StartsWith('{')) {
        try { $settings = $settings | ConvertFrom-Json -ErrorAction Stop } catch { Write-Verbose "Settings of '$($policy.Name)' is not valid JSON." }
    }
    if ($null -ne $settings -and $null -ne $settings.PSObject.Properties['Indicators']) {
        $indicators = @($settings.Indicators | ForEach-Object { if ($_ -is [string]) { $_ } else { [string]$_.Name } }) -join '; '
    }
    $row['HistoricTimeSpan'] = [string]$policy.HistoricTimeSpan
    $row['InScopeTimeSpan'] = [string]$policy.InScopeTimeSpan
    $row['Indicators'] = $indicators
    $row['WhenCreated'] = $policy.WhenCreated
    $row['WhenChanged'] = $policy.WhenChanged
    $row['DistributionStatus'] = [string]$policy.DistributionStatus
    $flags = @()
    if (-not $isEnabled) { $flags += 'Disabled' }
    if ($locationCount -eq 0) { $flags += 'NoLocations' }
    $row['Flag'] = ($flags -join '; ')
    $results.Add([PSCustomObject]$row)
}
Write-Progress -Activity 'Reading insider risk policies' -Completed

if ($results.Count -gt 0) {
    $results | Sort-Object -Property Priority, Name | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    $policies | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
}
else {
    Write-Warning 'No insider risk policies were returned. Either none exist or the account lacks an Insider Risk Management role group.'
}

Write-Host ''
Write-Host 'Insider risk policy summary' -ForegroundColor Cyan
Write-Host ('  Policies     : {0}  (enabled {1}, disabled {2})' -f $results.Count, @($results | Where-Object { $_.Enabled }).Count, @($results | Where-Object { -not $_.Enabled }).Count)
Write-Host ('  No locations : {0}' -f @($results | Where-Object { $_.Flag -like '*NoLocations*' }).Count) -ForegroundColor Yellow
Write-Host '  By scenario  :'
foreach ($group in ($results | Group-Object -Property InsiderRiskScenario | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,5}  {1}' -f $group.Count, $(if ($group.Name) { $group.Name } else { '(not reported)' }))
}
foreach ($flagged in ($results | Where-Object { $_.Flag })) { Write-Host ('  Review       : {0} -> {1}' -f $flagged.Name, $flagged.Flag) -ForegroundColor Yellow }
if ($results.Count -gt 0) {
    Write-Host ('  Report       : {0}' -f $OutputPath)
    Write-Host ('  Raw JSON     : {0}' -f $jsonPath)
}

if ($PassThru) {
    $results
}
#endregion Main
