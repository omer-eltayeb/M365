<#
.SYNOPSIS
    Exports the Microsoft Defender for Endpoint custom indicators (IoCs) with expiry analysis and hygiene flags.
.DESCRIPTION
    Lists the tenant's indicators with GET /indicators (filtered server-side on -IndicatorType and -Action) and exports value,
    type, action, severity, title, creator, creation/expiry/update times, device groups, alert generation and application.
    -ExpiringWithinDays keeps only indicators that expire soon, -Expired only those already past their expiry. Allow indicators
    without an expiry date are flagged because they permanently exempt the value from detection.
.PARAMETER TenantId
    Directory (tenant) ID or verified domain of the tenant that hosts the app registration.
.PARAMETER AppCredential
    PSCredential whose user name is the application (client) ID and whose password is the client secret.
.PARAMETER IndicatorType
    Only return this indicator type: FileSha1, FileSha256, FileMd5, CertificateThumbprint, IpAddress, DomainName or Url.
.PARAMETER Action
    Only return indicators with this response action: Alert, Warn, Block, Audit, BlockAndRemediate, AlertAndBlock or Allowed.
.PARAMETER ExpiringWithinDays
    Only return indicators whose expiry falls within the next N days (1-365).
.PARAMETER Expired
    Only return indicators whose expiry date has already passed (candidates for clean-up).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\MDEIndicators_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the indicator objects to the pipeline.
.EXAMPLE
    PS> $cred = Get-Credential -UserName '<application-id>' -Message 'Client secret'
    PS> .\Get-MDEIndicators.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred
    Exports every indicator, prints the counts by type and action and warns about Allowed indicators that never expire.
.EXAMPLE
    PS> .\Get-MDEIndicators.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -Action Allowed -ExpiringWithinDays 14 -PassThru | Format-Table IndicatorValue, Title, ExpirationTime
    Lists the allow indicators that expire in the next two weeks so they can be reviewed before detection resumes.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x (REST calls only, no modules)
    Permissions : Application permission Ti.ReadWrite.All (or Ti.Read.All) granted with admin consent to an app registration.
    Category    : Defender for Endpoint API
    Changes     : No
    Notes       : Expired indicators stay in the list until they are deleted (see Import-MDEIndicators.ps1 -Remove). The tenant limit is
                  15,000 active indicators. Dates are UTC.
.LINK
    https://learn.microsoft.com/defender-endpoint/api/get-ti-indicators-collection
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [pscredential]$AppCredential,

    [Parameter()]
    [ValidateSet('FileSha1', 'FileSha256', 'FileMd5', 'CertificateThumbprint', 'IpAddress', 'DomainName', 'Url')]
    [string]$IndicatorType,

    [Parameter()]
    [ValidateSet('Alert', 'Warn', 'Block', 'Audit', 'BlockAndRemediate', 'AlertAndBlock', 'Allowed')]
    [string]$Action,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$ExpiringWithinDays,

    [Parameter()]
    [switch]$Expired,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('MDEIndicators_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { $token = Get-MdeAccessToken -TenantId $TenantId -AppCredential $AppCredential }
catch { throw "Unable to acquire a Defender for Endpoint API token: $($_.Exception.Message)" }

$filterParts = @()
if (-not [string]::IsNullOrEmpty($IndicatorType)) { $filterParts += "indicatorType eq '$IndicatorType'" }
if (-not [string]::IsNullOrEmpty($Action)) { $filterParts += "action eq '$Action'" }
$uri = "$baseUri/indicators"
if ($filterParts.Count -gt 0) { $uri = '{0}?$filter={1}' -f $uri, ($filterParts -join ' and ') }
Write-Verbose "Querying $uri"
try { $indicators = @(Invoke-MdeRequest -Token $token -Uri $uri) }
catch { throw "Failed to list indicators: $($_.Exception.Message)" }

$now = [datetime]::UtcNow
$rows = @(foreach ($indicator in $indicators) {
        $expires = ConvertTo-UtcDateTime -Value $indicator.expirationTime
        $isExpired = ($null -ne $expires -and $expires -lt $now)
        if ($Expired -and -not $isExpired) { continue }
        if ($ExpiringWithinDays -gt 0 -and ($null -eq $expires -or $isExpired -or $expires -gt $now.AddDays($ExpiringWithinDays))) { continue }
        [PSCustomObject]@{
            Id                      = $indicator.id
            IndicatorValue          = $indicator.indicatorValue
            IndicatorType           = $indicator.indicatorType
            Action                  = $indicator.action
            Severity                = $indicator.severity
            Title                   = $indicator.title
            Description             = $indicator.description
            CreatedBy               = $indicator.createdBy
            CreationTimeDateTimeUtc = ConvertTo-UtcDateTime -Value $indicator.creationTimeDateTimeUtc
            ExpirationTime          = $expires
            LastUpdateTime          = ConvertTo-UtcDateTime -Value $indicator.lastUpdateTime
            RbacGroupNames          = (@($indicator.rbacGroupNames) -join ';')
            GenerateAlert           = $indicator.generateAlert
            Application             = $indicator.application
            IsExpired               = $isExpired
            Flag                    = $(if ($indicator.action -eq 'Allowed' -and $null -eq $expires) { 'AllowedWithoutExpiry' } else { $null })
        }
    })
$rows = @($rows | Sort-Object -Property IndicatorType, Action, IndicatorValue)
if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 } else { Write-Warning 'No indicator matched the given filter; nothing was exported.' }

$flagged = @($rows | Where-Object { $_.Flag -eq 'AllowedWithoutExpiry' })
Write-Host ('Defender for Endpoint indicators: {0} of {1} returned by the API (report: {2})' -f $rows.Count, $indicators.Count, $OutputPath) -ForegroundColor Cyan
foreach ($dimension in @('IndicatorType', 'Action', 'Severity')) {
    $groups = @($rows | Group-Object -Property $dimension | Sort-Object -Property Count -Descending | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count })
    Write-Host ('  {0,-14} {1}' -f $dimension, ($groups -join ', ')) -ForegroundColor Green
}
$expiredCount = @($rows | Where-Object { $_.IsExpired }).Count
$noExpiryCount = @($rows | Where-Object { $null -eq $_.ExpirationTime }).Count
$expiringSoon = @($rows | Where-Object { -not $_.IsExpired -and $null -ne $_.ExpirationTime -and $_.ExpirationTime -le $now.AddDays(30) }).Count
Write-Host ('  {0,-14} expired={1}, expiring in 30 days={2}, no expiry={3}' -f 'Expiry', $expiredCount, $expiringSoon, $noExpiryCount) -ForegroundColor Green
if ($flagged.Count -gt 0) {
    Write-Warning ('{0} Allowed indicator(s) have no expiry and permanently exempt their value from detection: {1}' -f $flagged.Count,
        ((@($flagged | Select-Object -First 5 | ForEach-Object { $_.IndicatorValue }) -join ', ') + $(if ($flagged.Count -gt 5) { ', ...' } else { '' })))
}

if ($PassThru) { $rows }
#endregion Main
