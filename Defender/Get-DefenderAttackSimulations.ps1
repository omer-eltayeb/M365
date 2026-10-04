<#
.SYNOPSIS
    Reports Attack simulation training campaigns with their click, compromise and report rates.
.DESCRIPTION
    Lists the phishing simulations of the tenant (GET /security/attackSimulation/simulations, optional server-side $filter on
    status) and reads the report overview of every launched simulation (GET .../simulations/{id}/report/overview) to add the
    resolved target count, the event counters (delivered, link clicked, credentials supplied, attachment opened, reported) and
    the training numbers. One row per simulation with technique, delivery platform, launch and completion dates, compromise
    rate and report rate. With -IncludeAutomations the simulation automations and their runs go to <base>_Automations.csv.
.PARAMETER Status
    Only simulations with this status: draft, running, scheduled, succeeded, failed, canceled or excluded.
.PARAMETER IncludeAutomations
    Also exports the simulation automations (GET /security/attackSimulation/simulationAutomations and /runs).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderAttackSimulations_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the simulation rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderAttackSimulations.ps1
    Exports every simulation with its results and prints the campaigns with the highest compromise rate.
.EXAMPLE
    PS> .\Get-DefenderAttackSimulations.ps1 -Status succeeded -IncludeAutomations -OutputPath C:\Temp\Simulations.csv -Verbose
    Exports the completed campaigns plus the automation schedules and run history.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AttackSimulation.Read.All (delegated); Attack Simulation Administrator, Security Reader or Security Administrator.
    Category    : Attack simulation training
    Changes     : No
    Notes       : Requires Microsoft Defender for Office 365 Plan 2 (or Microsoft 365 E5). Draft and scheduled simulations have no
                  report yet, so their result columns stay empty. Compromised = credentials supplied + attachment opened;
                  CompromiseRatePercent is the rate computed by the service.
.LINK
    https://learn.microsoft.com/graph/api/attacksimulationroot-list-simulations
.LINK
    https://learn.microsoft.com/graph/api/simulationreportoverview-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('draft', 'running', 'scheduled', 'succeeded', 'failed', 'canceled', 'excluded')]
    [string]$Status,

    [Parameter()]
    [switch]$IncludeAutomations,

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

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Get-Rate {
    <# Percentage of $Part in $Whole rounded to one decimal; $null when the denominator is missing or zero. #>
    param([object]$Part, [object]$Whole)
    if ($null -eq $Whole -or [double]$Whole -le 0 -or $null -eq $Part) { return $null }
    return [math]::Round(([double]$Part / [double]$Whole) * 100, 1)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderAttackSimulations_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
$automationsPath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($OutputPath), $baseName + '_Automations.csv')

try { Connect-GraphIfNeeded -Scopes @('AttackSimulation.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$baseUri = 'https://graph.microsoft.com/v1.0/security/attackSimulation'
$uri = "$baseUri/simulations" + $(if ([string]::IsNullOrEmpty($Status)) { '' } else { "?`$filter=status eq '$Status'" })
try { $simulations = @(Invoke-GraphPaged -Uri $uri) }
catch { throw "Failed to list attack simulations (is Defender for Office 365 Plan 2 licensed?): $($_.Exception.Message)" }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($simulation in $simulations) {
    $index++
    Write-Progress -Activity 'Reading simulation reports' -Status ('{0} of {1}' -f $index, $simulations.Count) -PercentComplete ([int](($index / $simulations.Count) * 100))
    $events = @{}; $overview = $null
    # Reports exist only once a simulation has started; draft and scheduled campaigns return an error here.
    if (@('draft', 'scheduled') -notcontains [string]$simulation.status) {
        try { $overview = Invoke-MgGraphRequest -Method GET -Uri ('{0}/simulations/{1}/report/overview' -f $baseUri, $simulation.id) -OutputType PSObject -ErrorAction Stop }
        catch { Write-Warning ('Report overview not available for "{0}" ({1}): {2}' -f $simulation.displayName, $simulation.status, $_.Exception.Message) }
        Start-Sleep -Milliseconds 200
    }
    foreach ($simulationEvent in @($overview.simulationEventsContent.events)) {
        if ($null -ne $simulationEvent -and -not [string]::IsNullOrEmpty($simulationEvent.eventName)) { $events[[string]$simulationEvent.eventName] = [int]$simulationEvent.count }
    }
    $targets = $overview.resolvedTargetsCount
    $delivered = ($events.Keys | Where-Object { $_ -like 'SuccessfullyDelivered*' } | ForEach-Object { $events[$_] } | Measure-Object -Sum).Sum
    $compromised = [int]$events['CredSupplied'] + [int]$events['AttachmentOpened']
    $compromiseRate = $overview.simulationEventsContent.compromisedRate
    if ($null -ne $compromiseRate) { $compromiseRate = [math]::Round([double]$compromiseRate, 1) } elseif ($null -ne $overview) { $compromiseRate = Get-Rate -Part $compromised -Whole $targets }
    $trainingInfos = @($overview.trainingEventsContent.assignedTrainingsInfos | Where-Object { $null -ne $_ })
    $trainingsCompleted = $null; if ($trainingInfos.Count -gt 0) { $trainingsCompleted = ($trainingInfos | Measure-Object -Property completedUserCount -Sum).Sum }
    $hasReport = ($null -ne $overview)
    $rows.Add([PSCustomObject]@{
            Id = $simulation.id; Simulation = $simulation.displayName; Status = $simulation.status; AttackType = $simulation.attackType; Technique = $simulation.attackTechnique
            Platform = $simulation.payloadDeliveryPlatform; IsAutomated = $simulation.isAutomated; CreatedBy = $simulation.createdBy.displayName; TargetType = $simulation.includedAccountTarget.type
            LaunchDateTime = ConvertTo-UtcDateTime -Value $simulation.launchDateTime; CompletionDateTime = ConvertTo-UtcDateTime -Value $simulation.completionDateTime
            DurationInDays = $simulation.durationInDays; Targets = $targets
            Delivered = $(if ($hasReport) { [int]$delivered } else { $null }); Clicked = $(if ($hasReport) { [int]$events['EmailLinkClicked'] } else { $null })
            Compromised = $(if ($hasReport) { $compromised } else { $null }); Reported = $(if ($hasReport) { [int]$events['ReportedEmail'] } else { $null })
            CompromiseRatePercent = $compromiseRate; ReportRatePercent = Get-Rate -Part $events['ReportedEmail'] -Whole $targets
            TrainingsAssignedUsers = $overview.trainingEventsContent.trainingsAssignedUserCount; TrainingsCompletedUsers = $trainingsCompleted
            Events = (@($events.Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, $events[$_] }) -join ';')
        })
}
Write-Progress -Activity 'Reading simulation reports' -Completed
$sortedRows = @($rows | Sort-Object -Property LaunchDateTime -Descending)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 } else { Write-Warning 'No simulations matched the filter; no CSV was written.' }
$automationRows = @()
if ($IncludeAutomations) {
    try { $automations = @(Invoke-GraphPaged -Uri "$baseUri/simulationAutomations") }
    catch { throw "Failed to list simulation automations: $($_.Exception.Message)" }
    $automationRows = @(foreach ($automation in $automations) {
            $runs = @()
            try { $runs = @(Invoke-GraphPaged -Uri ('{0}/simulationAutomations/{1}/runs' -f $baseUri, $automation.id)) }
            catch { Write-Warning ('Runs not available for automation "{0}": {1}' -f $automation.displayName, $_.Exception.Message) }
            $lastRun = $runs | Sort-Object -Property { ConvertTo-UtcDateTime -Value $_.startDateTime } -Descending | Select-Object -First 1
            [PSCustomObject]@{
                Id = $automation.id; DisplayName = $automation.displayName; Status = $automation.status; CreatedBy = $automation.createdBy.displayName; Runs = $runs.Count
                LastRunStatus = $lastRun.status; LastRunDateTime = ConvertTo-UtcDateTime -Value $automation.lastRunDateTime; NextRunDateTime = ConvertTo-UtcDateTime -Value $automation.nextRunDateTime
            }
            Start-Sleep -Milliseconds 200
        })
    if ($automationRows.Count -gt 0) { $automationRows | Export-Csv -Path $automationsPath -NoTypeInformation -Encoding UTF8 }
}

$completed = @($sortedRows | Where-Object { $_.Status -eq 'succeeded' -and $null -ne $_.CompromiseRatePercent })
$byStatus = @($sortedRows | Group-Object -Property Status | Sort-Object -Property Count -Descending | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '
Write-Host 'Attack simulation training summary' -ForegroundColor Cyan
Write-Host ('  Simulations exported : {0} ({1}) -> {2}' -f $sortedRows.Count, $byStatus, $OutputPath)
if ($completed.Count -gt 0) {
    $meanCompromise = [math]::Round(($completed | Measure-Object -Property CompromiseRatePercent -Average).Average, 1)
    $meanReport = [math]::Round(($completed | Where-Object { $null -ne $_.ReportRatePercent } | Measure-Object -Property ReportRatePercent -Average).Average, 1)
    Write-Host ('  Completed campaigns  : {0} | mean compromise rate {1}% | mean report rate {2}%' -f $completed.Count, $meanCompromise, $meanReport)
    Write-Host '  Highest compromise rate (rate | technique | launched | simulation):' -ForegroundColor Yellow
    foreach ($row in ($completed | Sort-Object -Property CompromiseRatePercent -Descending | Select-Object -First 5)) {
        Write-Host ('    {0,5}% | {1,-20} | {2:yyyy-MM-dd} | {3}' -f $row.CompromiseRatePercent, $row.Technique, $row.LaunchDateTime, $row.Simulation)
    }
}
if ($IncludeAutomations) { Write-Host ('  Automations exported : {0} -> {1}' -f $automationRows.Count, $automationsPath) }

if ($PassThru) { $sortedRows }
#endregion Main
