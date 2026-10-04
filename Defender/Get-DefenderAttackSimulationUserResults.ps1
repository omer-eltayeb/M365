<#
.SYNOPSIS
    Reports per-user results of Attack simulation training campaigns and finds repeat offenders across simulations.
.DESCRIPTION
    Resolves simulations by id or wildcard name (GET /security/attackSimulation/simulations) and reads the user report of each
    one (GET .../simulations/{id}/report/simulationUsers): compromised and when, reported, click details (time, IP, OS, browser),
    training counters and the raw event list. One row per user and simulation goes to the main CSV; users compromised in at least
    -RepeatThreshold different simulations go to <base>_RepeatOffenders.csv. -IncludeDepartment adds the department from /users.
.PARAMETER SimulationId
    One or more simulation ids.
.PARAMETER SimulationName
    One or more wildcard patterns matched against the simulation display name, for example 'Q3*' or '*Payroll*'. Default set.
.PARAMETER RepeatThreshold
    Minimum number of different simulations a user must have been compromised in to appear as a repeat offender. Default 2.
.PARAMETER IncludeDepartment
    Resolves the department of every user through GET /users/{email}?$select=department (one call per unique user).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderAttackSimulationUsers_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the per-user rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderAttackSimulationUserResults.ps1 -SimulationName '*2026*' -IncludeDepartment
    Exports every user result of the 2026 campaigns with departments and prints the repeat offenders and department rates.
.EXAMPLE
    PS> .\Get-DefenderAttackSimulationUserResults.ps1 -SimulationId 'f1b13829-3829-f1b1-2938-b1f12938b1a' -PassThru | Where-Object { $_.IsCompromised } | Select-Object Email, ClickIpAddress
    Lists the compromised users of one campaign with the time and source IP of the click.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AttackSimulation.Read.All (+ User.Read.All with -IncludeDepartment); Attack Simulation Administrator or Security Reader.
    Category    : Attack simulation training
    Changes     : No
    Notes       : Requires Microsoft Defender for Office 365 Plan 2 (or Microsoft 365 E5). Draft and scheduled simulations have
                  no user report and are skipped. Repeat offenders are computed over the selected simulations only (-SimulationName '*' for all).
.LINK
    https://learn.microsoft.com/graph/api/resources/usersimulationdetails
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
    [string[]]$SimulationId,

    [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
    [string[]]$SimulationName,

    [Parameter()]
    [ValidateRange(1, 50)]
    [int]$RepeatThreshold = 2,

    [Parameter()]
    [switch]$IncludeDepartment,

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
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderAttackSimulationUsers_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$offendersPath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($OutputPath), [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_RepeatOffenders.csv')
$requiredScopes = @('AttackSimulation.Read.All') + @(if ($IncludeDepartment) { 'User.Read.All' })
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$graphV1 = 'https://graph.microsoft.com/v1.0'
$simulationsUri = "$graphV1/security/attackSimulation/simulations"
try {
    if ($PSCmdlet.ParameterSetName -eq 'ById') {
        $simulations = @(foreach ($id in ($SimulationId | Select-Object -Unique)) { Invoke-MgGraphRequest -Method GET -Uri "$simulationsUri/$id" -OutputType PSObject -ErrorAction Stop })
    }
    else { $simulations = @(Invoke-GraphPaged -Uri $simulationsUri | Where-Object { $candidate = $_; @($SimulationName | Where-Object { $candidate.displayName -like $_ }).Count -gt 0 }) }
}
catch { throw "Failed to resolve the simulations: $($_.Exception.Message)" }
foreach ($item in @($simulations | Where-Object { @('draft', 'scheduled') -contains [string]$_.status })) {
    Write-Warning ('Simulation "{0}" is {1} and has no user report yet; skipped.' -f $item.displayName, $item.status)
}
$simulations = @($simulations | Where-Object { @('draft', 'scheduled') -notcontains [string]$_.status })
if ($simulations.Count -eq 0) { Write-Warning 'No launched simulation matched the selection.'; return }
$rows = New-Object -TypeName System.Collections.Generic.List[object]; $index = 0
foreach ($simulation in $simulations) {
    $index++
    Write-Progress -Activity 'Reading simulation user reports' -Status ('{0} of {1}' -f $index, $simulations.Count) -PercentComplete ([int](($index / $simulations.Count) * 100))
    try { $users = @(Invoke-GraphPaged -Uri ('{0}/{1}/report/simulationUsers' -f $simulationsUri, $simulation.id)) }
    catch { Write-Warning ('User report not available for "{0}": {1}' -f $simulation.displayName, $_.Exception.Message); continue }
    foreach ($user in $users) {
        $events = @($user.simulationEvents | Where-Object { $null -ne $_ })
        $click = $events | Where-Object { $_.eventName -eq 'EmailLinkClicked' } | Sort-Object -Property { ConvertTo-UtcDateTime -Value $_.eventDateTime } | Select-Object -First 1
        $rows.Add([PSCustomObject]@{
                SimulationId = $simulation.id; Simulation = $simulation.displayName; Technique = $simulation.attackTechnique; LaunchDateTime = ConvertTo-UtcDateTime -Value $simulation.launchDateTime
                UserDisplayName = $user.simulationUser.displayName; Email = ([string]$user.simulationUser.email).ToLowerInvariant(); Department = $null; IsCompromised = [bool]$user.isCompromised
                CompromisedDateTime = ConvertTo-UtcDateTime -Value $user.compromisedDateTime; ReportedPhishDateTime = ConvertTo-UtcDateTime -Value $user.reportedPhishDateTime
                Clicked = ($null -ne $click); FirstClickDateTime = ConvertTo-UtcDateTime -Value $click.eventDateTime; ClickIpAddress = $click.ipAddress
                OsPlatform = $click.osPlatform; Browser = $click.browser; AssignedTrainings = $user.assignedTrainingsCount; CompletedTrainings = $user.completedTrainingsCount
                InProgressTrainings = $user.inProgressTrainingsCount; Events = (@($events | ForEach-Object { '{0}@{1:u}' -f $_.eventName, (ConvertTo-UtcDateTime -Value $_.eventDateTime) }) -join ';')
            })
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading simulation user reports' -Completed
if ($rows.Count -eq 0) { Write-Warning 'The selected simulations returned no user results.'; return }
if ($IncludeDepartment) {
    $departments = @{}
    $emails = @($rows | ForEach-Object { $_.Email } | Where-Object { $_ } | Select-Object -Unique)
    $index = 0
    foreach ($email in $emails) {
        $index++
        Write-Progress -Activity 'Resolving departments' -Status ('{0} of {1}' -f $index, $emails.Count) -PercentComplete ([int](($index / $emails.Count) * 100))
        $userUri = '{0}/users/{1}?$select=department' -f $graphV1, [uri]::EscapeDataString($email)
        try { $departments[$email] = (Invoke-MgGraphRequest -Method GET -Uri $userUri -OutputType PSObject -ErrorAction Stop).department }
        catch { Write-Warning ('Department lookup failed for {0}: {1}' -f $email, $_.Exception.Message) }
        Start-Sleep -Milliseconds 200
    }
    Write-Progress -Activity 'Resolving departments' -Completed
    foreach ($row in $rows) { if ($departments.ContainsKey($row.Email)) { $row.Department = $departments[$row.Email] } }
}
$compromisedRows = @($rows | Where-Object { $_.IsCompromised })
$offenders = @(foreach ($group in ($compromisedRows | Where-Object { $_.Email } | Group-Object -Property Email)) {
        $simulationIds = @($group.Group | ForEach-Object { $_.SimulationId } | Select-Object -Unique)
        if ($simulationIds.Count -lt $RepeatThreshold) { continue }
        [PSCustomObject]@{
            Email = $group.Name; UserDisplayName = $group.Group[0].UserDisplayName; Department = $group.Group[0].Department; CompromisedCount = $simulationIds.Count
            LastCompromisedDateTime = ($group.Group | Sort-Object -Property CompromisedDateTime -Descending | Select-Object -First 1).CompromisedDateTime
            Simulations = (@($group.Group | Sort-Object -Property LaunchDateTime | ForEach-Object { $_.Simulation } | Select-Object -Unique) -join ';')
        }
    } | Sort-Object -Property CompromisedCount, LastCompromisedDateTime -Descending)
$output = @($rows | Sort-Object -Property LaunchDateTime, Simulation, Email)
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($offenders.Count -gt 0) { $offenders | Export-Csv -Path $offendersPath -NoTypeInformation -Encoding UTF8 }
$uniqueUsers = @($rows | ForEach-Object { $_.Email } | Select-Object -Unique).Count; $reportedCount = @($rows | Where-Object { $null -ne $_.ReportedPhishDateTime }).Count
Write-Host ('Attack simulation user results ({0} simulations, {1} user rows, {2} unique users)' -f $simulations.Count, $rows.Count, $uniqueUsers) -ForegroundColor Cyan
Write-Host ('  Compromised {0} ({1}%) | Reported {2} ({3}%) | Clicked {4}' -f $compromisedRows.Count, [math]::Round(($compromisedRows.Count / $rows.Count) * 100, 1), $reportedCount,
    [math]::Round(($reportedCount / $rows.Count) * 100, 1), @($rows | Where-Object { $_.Clicked }).Count)
Write-Host ('  Repeat offenders (compromised in >= {0} simulations): {1}' -f $RepeatThreshold, $offenders.Count) -ForegroundColor $(if ($offenders.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($offender in ($offenders | Select-Object -First 10)) { Write-Host ('    {0,-45} {1}x, last {2:yyyy-MM-dd}' -f $offender.Email, $offender.CompromisedCount, $offender.LastCompromisedDateTime) }
if ($IncludeDepartment) {
    Write-Host '  Compromise rate by department (compromised / users):' -ForegroundColor Yellow
    foreach ($group in ($rows | Group-Object -Property Department | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
        $hit = @($group.Group | Where-Object { $_.IsCompromised }).Count; $name = $(if ($group.Name) { $group.Name } else { '(unknown)' })
        Write-Host ('    {0,-30} {1,5} / {2,-5} {3,5}%' -f $name, $hit, $group.Count, [math]::Round(($hit / $group.Count) * 100, 1))
    }
}
Write-Host ('  Rows exported : {0} -> {1}' -f $output.Count, $OutputPath)
if ($offenders.Count -gt 0) { Write-Host ('  Repeat offenders -> {0}' -f $offendersPath) }
if ($PassThru) { $output }
#endregion Main
