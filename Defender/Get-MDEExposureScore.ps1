<#
.SYNOPSIS
    Shows the Defender Vulnerability Management exposure score, Secure Score for Devices and exposure by device group, with top recommendations.
.DESCRIPTION
    Reads GET /exposureScore, GET /configurationScore and GET /exposureScore/ByMachineGroups from the Defender for Endpoint API,
    prints a console dashboard (exposure band, device score, per-group exposure) and exports the values as CSV rows (Scope,
    Group, Score, Time). With -IncludeRecommendations the security recommendations are read from GET /recommendations, the -Top
    entries by exposure impact are shown and saved to <base>_Recommendations.csv for the remediation backlog.
.PARAMETER TenantId
    Directory (tenant) ID or verified domain of the tenant that hosts the app registration.
.PARAMETER AppCredential
    PSCredential whose user name is the application (client) ID and whose password is the client secret.
.PARAMETER IncludeRecommendations
    Also exports the top security recommendations ranked by exposure impact.
.PARAMETER Top
    Number of recommendations to keep when -IncludeRecommendations is used (1-500). Default 25.
.PARAMETER OutputPath
    Path of the scores CSV. Defaults to .\Reports\MDEExposureScore_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the score rows to the pipeline.
.EXAMPLE
    PS> $cred = Get-Credential -UserName '<application-id>' -Message 'Client secret'
    PS> .\Get-MDEExposureScore.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred
    Prints the exposure dashboard and exports the organization and device-group scores.
.EXAMPLE
    PS> .\Get-MDEExposureScore.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -IncludeRecommendations -Top 50 -OutputPath C:\Reports\Exposure.csv
    Exports the scores to C:\Reports\Exposure.csv and the 50 most impactful recommendations to C:\Reports\Exposure_Recommendations.csv.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x (REST calls only, no modules)
    Permissions : Application permissions Score.Read.All and, for -IncludeRecommendations, SecurityRecommendation.Read.All granted with admin
                  consent to an app registration.
    Category    : Defender for Endpoint API
    Changes     : No
    Notes       : Requires Defender for Endpoint Plan 2 or a Defender Vulnerability Management licence. The exposure score is 0-100 (Low 0-29,
                  Medium 30-69, High 70-100); Secure Score for Devices is reported in points. Scores refresh roughly daily.
.LINK
    https://learn.microsoft.com/defender-endpoint/api/get-exposure-score
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [pscredential]$AppCredential,

    [Parameter()]
    [switch]$IncludeRecommendations,

    [Parameter()]
    [ValidateRange(1, 500)]
    [int]$Top = 25,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$baseUri = 'https://api.securitycenter.microsoft.com/api'

#region Helpers
function Get-MdeAccessToken {
    <# Acquires an app-only token for the Defender for Endpoint API with the client-credentials flow. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [pscredential]$AppCredential
    )
    $body = @{
        client_id     = $AppCredential.UserName
        client_secret = $AppCredential.GetNetworkCredential().Password
        scope         = 'https://api.securitycenter.microsoft.com/.default'
        grant_type    = 'client_credentials'
    }
    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $response = Invoke-RestMethod -Method POST -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    return $response.access_token
}

function Invoke-MdeRequest {
    <# Calls the Defender for Endpoint API; GET requests follow @odata.nextLink. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [Parameter()]
        [object]$Body
    )
    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    if ($Method -ne 'GET') {
        $json = $null
        if ($null -ne $Body) { $json = $Body | ConvertTo-Json -Depth 10 }
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json -ErrorAction Stop
    }
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $response = Invoke-RestMethod -Method GET -Uri $nextLink -Headers $headers -ErrorAction Stop
        if ($null -ne $response.PSObject.Properties['value']) { foreach ($item in $response.value) { $results.Add($item) } }
        else { $results.Add($response) }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}

function ConvertTo-UtcDateTime {
    <# Normalises an API date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('MDEExposureScore_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { $token = Get-MdeAccessToken -TenantId $TenantId -AppCredential $AppCredential }
catch { throw "Unable to acquire a Defender for Endpoint API token: $($_.Exception.Message)" }

try {
    $exposure = @(Invoke-MdeRequest -Token $token -Uri "$baseUri/exposureScore")[0]
    $configuration = @(Invoke-MdeRequest -Token $token -Uri "$baseUri/configurationScore")[0]
}
catch { throw "Failed to read the organization scores: $($_.Exception.Message)" }
try { $groupScores = @(Invoke-MdeRequest -Token $token -Uri "$baseUri/exposureScore/ByMachineGroups") }
catch { Write-Warning "Exposure score by device group is not available: $($_.Exception.Message)"; $groupScores = @() }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$rows.Add([PSCustomObject]@{ Scope = 'ExposureScore'; Group = 'Organization'; Score = [math]::Round([double]$exposure.score, 2); Time = ConvertTo-UtcDateTime -Value $exposure.time })
$rows.Add([PSCustomObject]@{ Scope = 'ConfigurationScore'; Group = 'Organization'; Score = [math]::Round([double]$configuration.score, 2); Time = ConvertTo-UtcDateTime -Value $configuration.time })
foreach ($entry in ($groupScores | Sort-Object -Property score -Descending)) {
    $rows.Add([PSCustomObject]@{ Scope = 'DeviceGroupExposureScore'; Group = $entry.rbacGroupName; Score = [math]::Round([double]$entry.score, 2); Time = ConvertTo-UtcDateTime -Value $entry.time })
}
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$recommendations = @()
if ($IncludeRecommendations) {
    try { $allRecommendations = @(Invoke-MdeRequest -Token $token -Uri "$baseUri/recommendations") }
    catch { throw "Failed to read the security recommendations: $($_.Exception.Message)" }
    $recommendations = @($allRecommendations | Sort-Object -Property @{ Expression = { [double]$_.exposureImpact }; Descending = $true } | Select-Object -First $Top | ForEach-Object {
            [PSCustomObject]@{
                ProductName            = $_.productName
                RecommendationName     = $_.recommendationName
                RecommendationCategory = $_.recommendationCategory
                ExposedMachinesCount   = $_.exposedMachinesCount
                ExposureImpact         = [math]::Round([double]$_.exposureImpact, 2)
                ConfigScoreImpact      = [math]::Round([double]$_.configScoreImpact, 2)
                SeverityScore          = $_.severityScore
                Status                 = $_.status
                RemediationType        = $_.remediationType
                PublicExploit          = $_.publicExploit
            }
        })
    $recommendationsPath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($OutputPath), [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_Recommendations.csv')
    $recommendations | Export-Csv -Path $recommendationsPath -NoTypeInformation -Encoding UTF8
}

$band = $(if ($rows[0].Score -lt 30) { 'Low' } elseif ($rows[0].Score -lt 70) { 'Medium' } else { 'High' })
$bandColour = switch ($band) { 'Low' { 'Green' } 'Medium' { 'Yellow' } default { 'Red' } }
Write-Host ('Defender Vulnerability Management scores as of {0:u}' -f $rows[0].Time) -ForegroundColor Cyan
Write-Host ('  Exposure score (0-100, lower is better)      : {0,7:N1}  {1}' -f $rows[0].Score, $band) -ForegroundColor $bandColour
Write-Host ('  Secure Score for Devices (points, higher is better): {0,7:N1}' -f $rows[1].Score) -ForegroundColor Green
foreach ($row in @($rows | Where-Object { $_.Scope -eq 'DeviceGroupExposureScore' })) {
    Write-Host ('  Device group {0,-36} {1,7:N1}' -f $row.Group, $row.Score) -ForegroundColor $(if ($row.Score -lt 30) { 'Green' } elseif ($row.Score -lt 70) { 'Yellow' } else { 'Red' })
}
if ($IncludeRecommendations) {
    Write-Host ('  Top {0} of {1} recommendations by exposure impact (saved to {2}):' -f $recommendations.Count, $allRecommendations.Count, $recommendationsPath) -ForegroundColor Cyan
    foreach ($item in @($recommendations | Select-Object -First 10)) {
        Write-Host ('    impact {0,6:N2}  {1,6} exposed  {2}' -f $item.ExposureImpact, $item.ExposedMachinesCount, $item.RecommendationName)
    }
}
Write-Host ('  Scores report: {0}' -f $OutputPath) -ForegroundColor Green

if ($PassThru) { $rows }
#endregion Main
