<#
.SYNOPSIS
    Bulk-imports custom indicators (IoCs) into Microsoft Defender for Endpoint from a CSV, or deletes the listed indicators.
.DESCRIPTION
    Reads -InputCsv (IndicatorValue, IndicatorType, Action, Severity, Title, Description; optional ExpirationDays, RecommendedActions,
    GenerateAlert), validates each value against the syntax of its type (SHA1/SHA256/MD5, IPv4/IPv6, domain, URL, certificate
    thumbprint) and submits the valid rows with POST /indicators/import in batches of 500, each batch confirmed through ShouldProcess.
    With -Remove the matching existing indicators are deleted (DELETE /indicators/{id}). A results CSV records status, id and failure reason.
.PARAMETER TenantId
    Directory (tenant) ID or verified domain of the tenant that hosts the app registration.
.PARAMETER AppCredential
    PSCredential whose user name is the application (client) ID and whose password is the client secret.
.PARAMETER InputCsv
    CSV file with the indicators. IndicatorType: FileSha1, FileSha256, FileMd5, CertificateThumbprint, IpAddress, DomainName or Url.
.PARAMETER DefaultExpirationDays
    Expiry applied to rows without an ExpirationDays value (0 = never expires). Default 90.
.PARAMETER Remove
    Deletes the indicators whose value matches a CSV row instead of importing them (IndicatorValue and IndicatorType suffice).
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\MDEIndicatorImport_yyyyMMdd-HHmm.csv.
.EXAMPLE
    PS> $cred = Get-Credential -UserName '<application-id>' -Message 'Client secret'
    PS> .\Import-MDEIndicators.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -InputCsv .\iocs.csv -DefaultExpirationDays 30
    Validates the CSV, asks for confirmation per batch and imports the indicators with a 30-day expiry unless a row sets ExpirationDays.
.EXAMPLE
    PS> .\Import-MDEIndicators.ps1 -TenantId contoso.onmicrosoft.com -AppCredential $cred -InputCsv .\iocs.csv -Remove -WhatIf
    Shows which existing indicators would be deleted for the values in the CSV without deleting anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x (REST calls only, no modules)
    Permissions : Application permission Ti.ReadWrite.All granted with admin consent to an app registration.
    Category    : Defender for Endpoint API
    Changes     : Yes
    Notes       : Action: Alert, Warn, Block, Audit, BlockAndRemediate, AlertAndBlock or Allowed. Severity: Informational (default), Low, Medium, High.
                  GenerateAlert: true/false (default true for Alert and AlertAndBlock). Limits: 30 import calls/min, 15,000 active indicators per tenant.
.LINK
    https://learn.microsoft.com/defender-endpoint/api/import-ti-indicators
#>
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [pscredential]$AppCredential,

    [Parameter(Mandatory = $true)]
    [string]$InputCsv,

    [Parameter()]
    [ValidateRange(0, 3650)]
    [int]$DefaultExpirationDays = 90,

    [Parameter()]
    [switch]$Remove,

    [Parameter()]
    [string]$OutputPath
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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('MDEIndicatorImport_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
# Value syntax per indicator type; the IPv6 pattern is deliberately loose (hex groups separated by colons).
$patterns = @{ FileSha1 = '^[A-Fa-f0-9]{40}$'; FileSha256 = '^[A-Fa-f0-9]{64}$'; FileMd5 = '^[A-Fa-f0-9]{32}$'; CertificateThumbprint = '^[A-Fa-f0-9]{40}$'
    IpAddress  = '^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$|^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+$'
    DomainName = '^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$'; Url = '^(https?://)?[^\s/?#]+\.[^\s/?#]+(/\S*)?$' }
$actions = @('Alert', 'Warn', 'Block', 'Audit', 'BlockAndRemediate', 'AlertAndBlock', 'Allowed')
$operation = $(if ($Remove) { 'Remove' } else { 'Import' })
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$imports = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($entry in @(Import-Csv -Path $InputCsv)) {
    $value = ([string]$entry.IndicatorValue).Trim()
    # Matching against the allowed lists normalises the casing the API expects (for example 'filesha1' becomes 'FileSha1').
    $type = @($patterns.Keys | Where-Object { $_ -eq ([string]$entry.IndicatorType).Trim() })[0]
    $action = @($actions | Where-Object { $_ -eq ([string]$entry.Action).Trim() })[0]
    $severity = @(@('Informational', 'Low', 'Medium', 'High') | Where-Object { $_ -eq ([string]$entry.Severity).Trim() })[0]; if (-not $severity) { $severity = 'Informational' }
    $days = $(if ("$($entry.ExpirationDays)" -match '^\d{1,4}$') { [int]$entry.ExpirationDays } else { $DefaultExpirationDays })
    $expiration = $(if ($days -gt 0) { [datetime]::UtcNow.AddDays($days).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) } else { $null })
    $row = [PSCustomObject]@{ IndicatorValue = $value; IndicatorType = $type; Action = $action; Severity = $severity; Title = ([string]$entry.Title).Trim()
        ExpirationTime = $expiration; Operation = $operation; Status = 'Pending'; Id = $null; FailureReason = $null }
    $rows.Add($row)
    if ([string]::IsNullOrWhiteSpace($value) -or $null -eq $type) { $row.Status = 'InvalidFormat'; $row.FailureReason = 'IndicatorValue is empty or IndicatorType is unknown'; continue }
    if ($value -notmatch $patterns[$type]) { $row.Status = 'InvalidFormat'; $row.FailureReason = "Value does not match the $type syntax"; continue }
    if ($Remove) { continue }
    if ($null -eq $action) { $row.Status = 'InvalidFormat'; $row.FailureReason = "Action is not one of $($actions -join ', ')"; continue }
    if ([string]::IsNullOrWhiteSpace($row.Title)) { $row.Status = 'InvalidFormat'; $row.FailureReason = 'Title is required'; continue }
    $generateAlert = $(if ([string]::IsNullOrWhiteSpace($entry.GenerateAlert)) { $action -in @('Alert', 'AlertAndBlock') } else { ([string]$entry.GenerateAlert).Trim() -in @('true', 'yes', '1') })
    $body = @{ indicatorValue = $value; indicatorType = $type; action = $action; severity = $severity; title = $row.Title; generateAlert = $generateAlert
        description = $(if ([string]::IsNullOrWhiteSpace($entry.Description)) { $row.Title } else { ([string]$entry.Description).Trim() }) }
    if ($null -ne $expiration) { $body['expirationTime'] = $expiration }
    if (-not [string]::IsNullOrWhiteSpace($entry.RecommendedActions)) { $body['recommendedActions'] = ([string]$entry.RecommendedActions).Trim() }
    $imports.Add([PSCustomObject]@{ Row = $row; Body = $body })
}
if ($rows.Count -eq 0) { throw "No rows were found in $InputCsv." }
try { $token = Get-MdeAccessToken -TenantId $TenantId -AppCredential $AppCredential }
catch { throw "Unable to acquire a Defender for Endpoint API token: $($_.Exception.Message)" }

if ($Remove) {
    try { $existing = @(Invoke-MdeRequest -Token $token -Uri "$baseUri/indicators") }
    catch { throw "Failed to list the existing indicators: $($_.Exception.Message)" }
    $byValue = @{}
    foreach ($group in ($existing | Group-Object -Property { ([string]$_.indicatorValue).ToLowerInvariant() })) { $byValue[$group.Name] = @($group.Group) }
    foreach ($row in @($rows | Where-Object { $_.Status -eq 'Pending' })) {
        $hits = @($byValue[$row.IndicatorValue.ToLowerInvariant()] | Where-Object { $null -ne $_ })
        if ($hits.Count -eq 0) { $row.Status = 'NotFound'; $row.FailureReason = 'No indicator with this value exists'; continue }
        if (-not $PSCmdlet.ShouldProcess("$($row.IndicatorType) $($row.IndicatorValue)", "Delete $($hits.Count) indicator(s)")) { $row.Status = 'Skipped'; continue }
        foreach ($indicator in $hits) {
            try { Invoke-MdeRequest -Token $token -Uri "$baseUri/indicators/$($indicator.id)" -Method DELETE | Out-Null; $row.Status = 'Removed'; $row.Id = $indicator.id }
            catch {
                $row.Status = 'Failed'; $row.FailureReason = $(if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message })
                Write-Warning "$($row.IndicatorValue): $($row.FailureReason)"
            }
            Start-Sleep -Milliseconds 200
        }
    }
}
else {
    for ($offset = 0; $offset -lt $imports.Count; $offset += 500) {
        $batch = @($imports[$offset..([math]::Min($offset + 499, $imports.Count - 1))])
        $batchRows = @($batch | ForEach-Object { $_.Row })
        $preview = (@($batchRows | Select-Object -First 5 | ForEach-Object { $_.IndicatorValue }) -join ', ') + $(if ($batchRows.Count -gt 5) { ', ...' } else { '' })
        if (-not $PSCmdlet.ShouldProcess("$($batchRows.Count) indicator(s): $preview", 'Import indicators')) { foreach ($row in $batchRows) { $row.Status = 'Skipped' }; continue }
        try {
            $response = Invoke-MdeRequest -Token $token -Uri "$baseUri/indicators/import" -Method POST -Body @{ Indicators = @($batch | ForEach-Object { $_.Body }) }
            foreach ($result in @($response.value)) {
                foreach ($row in @($batchRows | Where-Object { $_.IndicatorValue -eq [string]$result.indicator })) {
                    $row.Id = $result.id
                    if ($result.isFailed) { $row.Status = 'Failed'; $row.FailureReason = $result.failureReason } else { $row.Status = 'Imported' }
                }
            }
            foreach ($row in @($batchRows | Where-Object { $_.Status -eq 'Pending' })) { $row.Status = 'Failed'; $row.FailureReason = 'The API returned no result for this value' }
        }
        catch {
            $reason = $(if ($_.ErrorDetails) { $_.ErrorDetails.Message } else { $_.Exception.Message })
            foreach ($row in $batchRows) { $row.Status = 'Failed'; $row.FailureReason = $reason }; Write-Warning "Import batch $([int]($offset / 500) + 1) was rejected: $reason"
        }
        # The import API is limited to 30 calls per minute.
        if ($offset + 500 -lt $imports.Count) { Start-Sleep -Seconds 2 }
    }
}
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$summary = @($rows | Group-Object -Property Status | Sort-Object -Property Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '
Write-Host ('Defender for Endpoint indicator {0}: {1} CSV row(s) - {2} (results: {3})' -f $operation.ToLowerInvariant(), $rows.Count, $summary, $OutputPath) -ForegroundColor Cyan
$rows
#endregion Main
