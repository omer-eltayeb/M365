<#
.SYNOPSIS
    Shows the current Microsoft Secure Score and the improvement actions with the largest remaining point gap.
.DESCRIPTION
    Reads the latest Secure Score snapshot (GET /security/secureScores?$top=1) and the control profiles
    (GET /security/secureScoreControlProfiles) through Microsoft Graph, joins them by control name and returns one
    row per improvement action with achieved points, maximum points, remaining gap, implementation cost, user impact,
    the state your team set (Default, Planned, Resolved, Ignored, ThirdParty, RiskAccepted ...) and the portal link.
    The console shows the score as points and percentage together with Microsoft's comparative averages; the CSV
    contains the top -TopGaps opportunities (controls that still have points to gain) sorted by remaining points.
.PARAMETER TopGaps
    Number of improvement actions to export, largest remaining gap first. Default 20; use 0 for all open actions.
.PARAMETER Service
    Only controls whose service name contains this text, for example 'AzureAD', 'MDO', 'MDATP', 'Exchange', 'Intune' or 'Teams'.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderSecureScore_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderSecureScore.ps1
    Prints the current score and exports the 20 improvement actions with the most points to gain.
.EXAMPLE
    PS> .\Get-DefenderSecureScore.ps1 -Service AzureAD -TopGaps 0 -OutputPath C:\Temp\IdentityScore.csv -Verbose
    Exports every open identity improvement action to the given CSV.
.EXAMPLE
    PS> .\Get-DefenderSecureScore.ps1 -PassThru | Where-Object { $_.ImplementationCost -eq 'Low' -and $_.UserImpact -eq 'Low' }
    Shows the quick wins: open actions that are cheap to implement and invisible to users.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityEvents.Read.All (delegated); the signed-in user needs Security Reader, Security Administrator
                  or Global Reader.
    Category    : Secure Score
    Changes     : No
    Notes       : Secure Score snapshots are generated once a day, so changes made today appear tomorrow. The
                  comparative averages (AllTenants, TotalSeats) are percentages published by Microsoft and are not
                  returned by every tenant. Controls for services the tenant is not licensed for are not scored.
.LINK
    https://learn.microsoft.com/graph/api/security-list-securescores
.LINK
    https://learn.microsoft.com/graph/api/security-list-securescorecontrolprofiles
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(0, 1000)]
    [int]$TopGaps = 20,

    [Parameter()]
    [string]$Service,

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
#endregion Helpers

#region Main
$requiredScopes = @('SecurityEvents.Read.All')

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderSecureScore_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
}
catch {
    throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)"
}

try {
    # The scores collection holds up to 90 daily snapshots; the first item of a $top=1 request is the newest one,
    # so this call is made directly instead of through the paging helper.
    $scoreResponse = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/security/secureScores?$top=1' -OutputType PSObject -ErrorAction Stop
    $latest = @($scoreResponse.value)[0]
    if ($null -eq $latest) { throw 'The tenant returned no Secure Score snapshot.' }
    $profiles = Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles'
}
catch {
    throw "Failed to read Secure Score data: $($_.Exception.Message)"
}

$profileLookup = @{}
foreach ($controlProfile in $profiles) { $profileLookup[[string]$controlProfile.id] = $controlProfile }
Write-Verbose "Loaded $($profiles.Count) control profiles and the snapshot created $($latest.createdDateTime)."

$controls = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($control in @($latest.controlScores)) {
    if ($null -eq $control) { continue }
    $controlName = [string]$control.controlName
    $controlProfile = $profileLookup[$controlName]
    if ($null -eq $controlProfile) {
        # Brand-new actions can be scored before their profile is published; fall back to the score data.
        $controlProfile = [PSCustomObject]@{ title = $controlName; service = $null; controlCategory = $control.controlCategory; maxScore = $null; implementationCost = $null; userImpact = $null; actionType = $null; actionUrl = $null; controlStateUpdates = $null }
    }
    if (-not [string]::IsNullOrWhiteSpace($Service) -and ([string]$controlProfile.service) -notlike "*$Service*") { continue }

    $maxScore = 0.0
    if ($null -ne $controlProfile.maxScore) { $maxScore = [double]$controlProfile.maxScore }
    $achieved = 0.0
    if ($null -ne $control.score) { $achieved = [double]$control.score }
    $gap = [math]::Round([math]::Max($maxScore - $achieved, 0), 2)
    $percentComplete = $null
    if ($maxScore -gt 0) { $percentComplete = [math]::Round(($achieved / $maxScore) * 100, 1) }

    # controlStateUpdates is the history of manual state changes; the newest entry is the current state.
    $state = 'Default'
    if ($null -ne $controlProfile.controlStateUpdates) {
        $latestUpdate = @($controlProfile.controlStateUpdates | Sort-Object -Property updatedDateTime -Descending)[0]
        if ($null -ne $latestUpdate -and -not [string]::IsNullOrEmpty($latestUpdate.state)) { $state = $latestUpdate.state }
    }

    $controls.Add([PSCustomObject]@{
        ControlName          = $controlName
        Title                = $controlProfile.title
        Service              = $controlProfile.service
        Category             = $controlProfile.controlCategory
        ScoreAchieved        = [math]::Round($achieved, 2)
        MaxScore             = $maxScore
        ScoreGap             = $gap
        PercentComplete      = $percentComplete
        ImplementationCost   = $controlProfile.implementationCost
        UserImpact           = $controlProfile.userImpact
        ActionType           = $controlProfile.actionType
        State                = $state
        ImplementationStatus = $control.implementationStatus
        ActionUrl            = $controlProfile.actionUrl
    })
}

$opportunities = @($controls | Where-Object { $_.ScoreGap -gt 0 } | Sort-Object -Property ScoreGap, MaxScore -Descending)
if ($TopGaps -gt 0 -and $opportunities.Count -gt $TopGaps) {
    $opportunities = @($opportunities | Select-Object -First $TopGaps)
}

if ($opportunities.Count -gt 0) {
    $opportunities | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No improvement actions with remaining points matched the filter; no CSV was written.'
}

$currentScore = [double]$latest.currentScore
$maxTotal = [double]$latest.maxScore
$scorePercent = 0
if ($maxTotal -gt 0) { $scorePercent = [math]::Round(($currentScore / $maxTotal) * 100, 1) }
$completeCount = @($controls | Where-Object { $_.ScoreGap -eq 0 }).Count

Write-Host ''
Write-Host 'Microsoft Secure Score summary' -ForegroundColor Cyan
Write-Host ('  Current score         : {0:N2} / {1:N0} ({2}%) as of {3}' -f $currentScore, $maxTotal, $scorePercent, $latest.createdDateTime) -ForegroundColor Green
foreach ($comparison in @($latest.averageComparativeScores)) {
    if ($null -eq $comparison) { continue }
    $label = [string]$comparison.basis
    if ($label -eq 'TotalSeats' -and $null -ne $comparison.seatSizeRangeLowerValue) {
        $label = 'TotalSeats {0}-{1}' -f $comparison.seatSizeRangeLowerValue, $comparison.seatSizeRangeUpperValue
    }
    Write-Host ('  Average ({0,-20}) : {1}%' -f $label, [math]::Round([double]$comparison.averageScore, 1))
}
Write-Host ('  Controls scored       : {0} ({1} complete, {2} with points remaining)' -f $controls.Count, $completeCount, ($controls.Count - $completeCount))
Write-Host ('  Rows exported         : {0} -> {1}' -f $opportunities.Count, $OutputPath)
Write-Host '  Largest gaps (points remaining | service | action):' -ForegroundColor Yellow
foreach ($item in ($opportunities | Select-Object -First 10)) {
    Write-Host ('    {0,6:N2} | {1,-10} | {2}' -f $item.ScoreGap, $item.Service, $item.Title)
}

if ($PassThru) {
    $opportunities
}
#endregion Main
