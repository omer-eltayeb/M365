<#
.SYNOPSIS
    Reports Microsoft Entra ID Protection risky users, risk detections and (optionally) risky service principals; can confirm or dismiss a user.
.DESCRIPTION
    Reads GET /identityProtection/riskyUsers filtered on risk state (atRisk by default) and level, GET /identityProtection/riskDetections
    for the last -DaysBack days (written to <base>_Detections.csv) and, with -IncludeServicePrincipals, /identityProtection/riskyServicePrincipals.
    By default the script only reports. With -UserPrincipalName plus -ConfirmCompromised or -Dismiss it posts to /identityProtection/
    riskyUsers/confirmCompromised or /dismiss for that single user, guarded by ShouldProcess (-WhatIf / -Confirm).
.PARAMETER RiskLevel
    Only principals with one of these risk levels: low, medium, high, hidden, none. Default: all levels.
.PARAMETER RiskState
    Risk states to report; default atRisk. Pass several to include remediated or dismissed users: -RiskState atRisk, remediated, dismissed.
.PARAMETER DaysBack
    Days of risk detections to export (1-90). Default 30.
.PARAMETER IncludeServicePrincipals
    Also read risky service principals (requires Workload Identities Premium and IdentityRiskyServicePrincipal.Read.All).
.PARAMETER UserPrincipalName
    Report only this user regardless of risk state; also the target of -ConfirmCompromised / -Dismiss.
.PARAMETER ConfirmCompromised
    Mark the user given in -UserPrincipalName as confirmed compromised (risk level becomes high). Prompts for confirmation.
.PARAMETER Dismiss
    Dismiss the risk of the user given in -UserPrincipalName (risk state becomes dismissed). Prompts for confirmation.
.PARAMETER OutputPath
    Path of the risky principals CSV. Defaults to .\Reports\EntraRiskyUsers_yyyyMMdd-HHmm.csv; detections get the _Detections suffix.
.PARAMETER PassThru
    Also emits the risky principal objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraRiskyUsersAndDetections.ps1 -RiskLevel high, medium
    Exports users currently at medium or high risk plus every risk detection of the last 30 days.
.EXAMPLE
    PS> .\Get-EntraRiskyUsersAndDetections.ps1 -UserPrincipalName jane.doe@contoso.com -Dismiss -WhatIf
    Shows the user's risk record and what the dismiss call would do without performing it.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All (delegated); IdentityRiskyUser.ReadWrite.All with -ConfirmCompromised/-Dismiss;
                  IdentityRiskyServicePrincipal.Read.All with -IncludeServicePrincipals.
    Category    : Sign-ins, audit & risk
    Changes     : Optional (-ConfirmCompromised / -Dismiss)
    Notes       : Requires Microsoft Entra ID P2 (risk level shows 'hidden' without it). Confirming a user as compromised raises the risk
                  to high and triggers risk-based Conditional Access policies; dismissing clears it. Both actions are audited by Entra ID.
.LINK
    https://learn.microsoft.com/graph/api/riskyuser-list
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateSet('low', 'medium', 'high', 'hidden', 'none')]
    [string[]]$RiskLevel,

    [Parameter()]
    [ValidateSet('atRisk', 'confirmedCompromised', 'remediated', 'dismissed', 'confirmedSafe', 'none')]
    [string[]]$RiskState = @('atRisk'),

    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$DaysBack = 30,

    [Parameter()]
    [switch]$IncludeServicePrincipals,

    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [switch]$ConfirmCompromised,

    [Parameter()]
    [switch]$Dismiss,

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
if ($ConfirmCompromised -and $Dismiss) { throw 'Use either -ConfirmCompromised or -Dismiss, not both.' }
if (($ConfirmCompromised -or $Dismiss) -and [string]::IsNullOrWhiteSpace($UserPrincipalName)) { throw '-ConfirmCompromised and -Dismiss require -UserPrincipalName.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraRiskyUsers_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$detectionsPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_Detections.csv')
$scopes = @('IdentityRiskEvent.Read.All', 'IdentityRiskyUser.Read.All')
if ($ConfirmCompromised -or $Dismiss) { $scopes[1] = 'IdentityRiskyUser.ReadWrite.All' }
if ($IncludeServicePrincipals) { $scopes += 'IdentityRiskyServicePrincipal.Read.All' }
try { Connect-GraphIfNeeded -Scopes $scopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$v1 = 'https://graph.microsoft.com/v1.0/identityProtection'
$stateClause = '(' + (@($RiskState | Select-Object -Unique | ForEach-Object { "riskState eq '$_'" }) -join ' or ') + ')'
$clauses = @($stateClause)
if ($PSBoundParameters.ContainsKey('RiskLevel')) { $clauses += '(' + (@($RiskLevel | ForEach-Object { "riskLevel eq '$_'" }) -join ' or ') + ')' }
# A named user is always shown, whatever its current state, so that the action below can target it.
if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) { $clauses = @("userPrincipalName eq '{0}'" -f ($UserPrincipalName -replace "'", "''")) }
try { $principals = @(Invoke-GraphPaged -Uri ('{0}/riskyUsers?$filter={1}' -f $v1, ($clauses -join ' and '))) }
catch { throw "Failed to read risky users (requires Microsoft Entra ID P2 and the listed scopes): $($_.Exception.Message)" }
if ($IncludeServicePrincipals) {
    try { $principals += @(Invoke-GraphPaged -Uri ('{0}/riskyServicePrincipals?$filter={1}' -f $v1, $stateClause)) }
    catch { Write-Warning "Failed to read risky service principals (requires Workload Identities Premium): $($_.Exception.Message)" }
}
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($principal in $principals) {
    # Risky users expose userPrincipalName/userDisplayName; risky service principals expose displayName/appId.
    $principalType = 'ServicePrincipal'; if ($null -ne $principal.PSObject.Properties['userPrincipalName']) { $principalType = 'User' }
    $rows.Add([PSCustomObject]@{
        PrincipalType     = $principalType
        DisplayName       = @($principal.userDisplayName, $principal.displayName) | Where-Object { $_ } | Select-Object -First 1
        UserPrincipalName = $principal.userPrincipalName
        Id                = $principal.id
        RiskLevel         = $principal.riskLevel
        RiskState         = $principal.riskState
        RiskDetail        = $principal.riskDetail
        RiskLastUpdated   = ([datetime]$principal.riskLastUpdatedDateTime).ToUniversalTime()
        IsProcessing      = $principal.isProcessing
        IsDeleted         = $principal.isDeleted
    })
}
$detectionFilter = 'detectedDateTime ge {0}' -f [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) { $detectionFilter += " and userPrincipalName eq '{0}'" -f ($UserPrincipalName -replace "'", "''") }
try { $detections = Invoke-GraphPaged -Uri ('{0}/riskDetections?$filter={1}' -f $v1, $detectionFilter) }
catch { throw "Failed to read risk detections: $($_.Exception.Message)" }
$detectionRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($detection in $detections) {
    $info = [string]$detection.additionalInfo; if ($info.Length -gt 300) { $info = $info.Substring(0, 297) + '...' }
    $detectionRows.Add([PSCustomObject]@{
        DetectedDateTime  = ([datetime]$detection.detectedDateTime).ToUniversalTime()
        UserPrincipalName = $detection.userPrincipalName
        RiskEventType     = $detection.riskEventType
        RiskLevel         = $detection.riskLevel
        RiskState         = $detection.riskState
        RiskDetail        = $detection.riskDetail
        IPAddress         = $detection.ipAddress
        Location          = (@($detection.location.city, $detection.location.countryOrRegion) | Where-Object { $_ }) -join ', '
        AdditionalInfo    = $info
    })
}
if ($ConfirmCompromised -or $Dismiss) {
    $action = 'confirmCompromised'; if ($Dismiss) { $action = 'dismiss' }
    $target = $rows | Where-Object { $_.PrincipalType -eq 'User' -and $_.UserPrincipalName -eq $UserPrincipalName } | Select-Object -First 1
    if ($null -eq $target) { Write-Warning "$UserPrincipalName is not in the risky users list; nothing to $action." }
    elseif ($PSCmdlet.ShouldProcess($target.UserPrincipalName, "Risky user: $action (current state $($target.RiskState), level $($target.RiskLevel))")) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri "$v1/riskyUsers/$action" -Body @{ userIds = @($target.Id) } -ErrorAction Stop | Out-Null
            Write-Host ('{0}: {1} submitted; the risk state updates within a few minutes.' -f $target.UserPrincipalName, $action) -ForegroundColor Green
        }
        catch { Write-Warning "Failed to $action $($target.UserPrincipalName): $($_.Exception.Message)" }
    }
}
if ($rows.Count -gt 0) { $rows | Sort-Object -Property RiskLastUpdated -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No risky principals matched the filter; the principals CSV was not written.' }
if ($detectionRows.Count -gt 0) { $detectionRows | Sort-Object -Property DetectedDateTime -Descending | Export-Csv -Path $detectionsPath -NoTypeInformation -Encoding UTF8 }
$highCount = @($rows | Where-Object { $_.RiskLevel -eq 'high' }).Count
Write-Host ('Risky principals: {0} ({1} high) | risk detections (last {2} days): {3} -> {4}' -f $rows.Count, $highCount, $DaysBack, $detectionRows.Count, $OutputPath) -ForegroundColor Cyan
if ($PassThru) { $rows }
#endregion Main
