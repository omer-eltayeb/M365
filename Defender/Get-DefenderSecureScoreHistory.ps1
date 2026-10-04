<#
.SYNOPSIS
    Trends Microsoft Secure Score over the retained daily snapshots and explains score drops at control level.
.DESCRIPTION
    Reads the Secure Score snapshots (GET /security/secureScores, newest -Days entries) and builds one row per day with
    the score, maximum, percentage, Microsoft's comparative averages (all tenants, similar seat size), licensed and active
    user counts and the delta from the previous day. For every day whose score moved by at least -DropThreshold points
    (down or up) the controlScores of that day are compared with the previous day and each changed control is written to
    <base>_ControlChanges.csv, so a drop can be traced to the setting or signal that changed. The console shows first versus
    last score, the best and worst day and the drop days with their top control changes.
.PARAMETER Days
    Number of most recent daily snapshots to analyse. Default 90 (the service keeps roughly 90 days).
.PARAMETER DropThreshold
    Minimum day-over-day change in points that counts as a drop or gain worth explaining. Default 2.
.PARAMETER OutputPath
    Path of the history CSV. Defaults to .\Reports\DefenderSecureScoreHistory_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the daily rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderSecureScoreHistory.ps1
    Exports the last 90 days, lists the days that lost two or more points and the controls that moved on those days.
.EXAMPLE
    PS> .\Get-DefenderSecureScoreHistory.ps1 -Days 30 -DropThreshold 0.5 -OutputPath C:\Temp\SecureScore30d.csv -Verbose
    Looks at the last month with a fine-grained threshold, useful right after a configuration change.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityEvents.Read.All (delegated); Security Reader, Security Administrator or Global Reader.
    Category    : Secure Score
    Changes     : No
    Notes       : Snapshots are generated once a day and retained for about 90 days, so -Days above the retention simply
                  returns what exists. A new or retired improvement action changes the maximum score as well; compare the
                  Percent column, not only the points, when the maximum moves. Comparative averages are percentages.
.LINK
    https://learn.microsoft.com/graph/api/security-list-securescores
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(2, 365)]
    [int]$Days = 90,

    [Parameter()]
    [ValidateRange(0.1, 1000)]
    [double]$DropThreshold = 2,

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

function Get-ComparativeAverage {
    <# Returns the averageScore of the comparison with the given basis (AllTenants, TotalSeats, IndustryTypes) or $null. #>
    param([object]$Snapshot, [string]$Basis)
    $match = @($Snapshot.averageComparativeScores | Where-Object { $null -ne $_ -and [string]$_.basis -eq $Basis })
    if ($match.Count -eq 0 -or $null -eq $match[0].averageScore) { return $null }
    return [math]::Round([double]$match[0].averageScore, 1)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderSecureScoreHistory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$changesPath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($OutputPath), [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_ControlChanges.csv')

try { Connect-GraphIfNeeded -Scopes @('SecurityEvents.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# The collection is newest-first; paging through it and keeping the newest -Days entries honours the parameter even
# when the service returns more items per page than requested.
try { $snapshots = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/security/secureScores?$top={0}' -f $Days)) }
catch { throw "Failed to read Secure Score snapshots: $($_.Exception.Message)" }
$snapshots = @($snapshots | Sort-Object -Property { ConvertTo-UtcDateTime -Value $_.createdDateTime } -Descending | Select-Object -First $Days)
if ($snapshots.Count -eq 0) { throw 'The tenant returned no Secure Score snapshot.' }
[array]::Reverse($snapshots)
Write-Verbose ('Analysing {0} snapshots from {1} to {2}.' -f $snapshots.Count, $snapshots[0].createdDateTime, $snapshots[-1].createdDateTime)

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$changes = New-Object -TypeName System.Collections.Generic.List[object]
$previous = $null
foreach ($snapshot in $snapshots) {
    $score = [math]::Round([double]$snapshot.currentScore, 2)
    $maxScore = [math]::Round([double]$snapshot.maxScore, 2)
    $day = (ConvertTo-UtcDateTime -Value $snapshot.createdDateTime).Date
    $delta = $null
    if ($null -ne $previous) { $delta = [math]::Round($score - [double]$previous.currentScore, 2) }
    $rows.Add([PSCustomObject]@{
            Date = $day; Score = $score; MaxScore = $maxScore
            Percent = $(if ($maxScore -gt 0) { [math]::Round(($score / $maxScore) * 100, 1) } else { $null }); DeltaFromPrevious = $delta
            AvgAllTenants = Get-ComparativeAverage -Snapshot $snapshot -Basis 'AllTenants'; AvgSimilarSeats = Get-ComparativeAverage -Snapshot $snapshot -Basis 'TotalSeats'
            LicensedUserCount = $snapshot.licensedUserCount; ActiveUserCount = $snapshot.activeUserCount; EnabledServices = (@($snapshot.enabledServices) -join ';')
        })
    # Only days that moved by the threshold are diffed; comparing every control of every day would bury the signal.
    if ($null -ne $delta -and [math]::Abs($delta) -ge $DropThreshold) {
        $before = @{}
        foreach ($control in @($previous.controlScores | Where-Object { $null -ne $_ })) { $before[[string]$control.controlName] = $control }
        $after = @{}
        foreach ($control in @($snapshot.controlScores | Where-Object { $null -ne $_ })) { $after[[string]$control.controlName] = $control }
        foreach ($name in @(@($before.Keys) + @($after.Keys) | Select-Object -Unique)) {
            $oldScore = $(if ($before.ContainsKey($name)) { [math]::Round([double]$before[$name].score, 2) } else { $null })
            $newScore = $(if ($after.ContainsKey($name)) { [math]::Round([double]$after[$name].score, 2) } else { $null })
            if ([double]$oldScore -eq [double]$newScore) { continue }
            $control = $(if ($after.ContainsKey($name)) { $after[$name] } else { $before[$name] })
            $changes.Add([PSCustomObject]@{
                    Date = $day; DayDelta = $delta; ControlName = $name; Category = $control.controlCategory; PreviousScore = $oldScore; NewScore = $newScore
                    Delta = [math]::Round([double]$newScore - [double]$oldScore, 2); ImplementationStatus = $control.implementationStatus
                    Note = $(if ($null -eq $oldScore) { 'Control added' } elseif ($null -eq $newScore) { 'Control removed' } else { $null })
                })
        }
    }
    $previous = $snapshot
}
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$sortedChanges = @($changes | Sort-Object -Property Date, Delta)
if ($sortedChanges.Count -gt 0) { $sortedChanges | Export-Csv -Path $changesPath -NoTypeInformation -Encoding UTF8 }

$first = $rows[0]; $last = $rows[$rows.Count - 1]
$best = $rows | Sort-Object -Property Score -Descending | Select-Object -First 1
$worst = $rows | Sort-Object -Property Score | Select-Object -First 1
$drops = @($rows | Where-Object { $null -ne $_.DeltaFromPrevious -and $_.DeltaFromPrevious -le -$DropThreshold })
Write-Host ''
Write-Host ('Microsoft Secure Score history ({0} days)' -f $rows.Count) -ForegroundColor Cyan
Write-Host ('  {0:yyyy-MM-dd}: {1:N2} / {2:N0} ({3}%)  ->  {4:yyyy-MM-dd}: {5:N2} / {6:N0} ({7}%)  change {8:+0.00;-0.00;0.00} points' -f $first.Date, $first.Score, $first.MaxScore, $first.Percent,
    $last.Date, $last.Score, $last.MaxScore, $last.Percent, ($last.Score - $first.Score)) -ForegroundColor Green
Write-Host ('  Best day  : {0:yyyy-MM-dd} ({1:N2}) | Worst day : {2:yyyy-MM-dd} ({3:N2})' -f $best.Date, $best.Score, $worst.Date, $worst.Score)
if ($null -ne $last.AvgAllTenants) { Write-Host ('  Comparison: all tenants {0}% | similar seat size {1}% | you {2}%' -f $last.AvgAllTenants, $last.AvgSimilarSeats, $last.Percent) }
Write-Host ('  Days with a drop of {0}+ points: {1}' -f $DropThreshold, $drops.Count) -ForegroundColor $(if ($drops.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($drop in $drops) {
    Write-Host ('    {0:yyyy-MM-dd} {1,7:+0.00;-0.00} points' -f $drop.Date, $drop.DeltaFromPrevious)
    foreach ($change in ($sortedChanges | Where-Object { $_.Date -eq $drop.Date -and $_.Delta -lt 0 } | Select-Object -First 3)) {
        Write-Host ('      {0,7:+0.00;-0.00}  {1} ({2})' -f $change.Delta, $change.ControlName, $change.Category)
    }
}
Write-Host ('  History -> {0}' -f $OutputPath)
if ($sortedChanges.Count -gt 0) { Write-Host ('  Control changes ({0}) -> {1}' -f $sortedChanges.Count, $changesPath) }

if ($PassThru) { $rows }
#endregion Main
