<#
.SYNOPSIS
    Bulk-updates Microsoft Defender XDR alerts: status, classification, determination and assignment.
.DESCRIPTION
    Selects alerts by id (-AlertId) or by filter (-Filter with -Title, -Severity, -ServiceSource, -DaysBack, -CurrentStatus
    against GET /security/alerts_v2) and sends one PATCH /security/alerts_v2/{id} per alert with the requested -Status,
    -Classification, -Determination and/or -AssignedTo. Each alert is read first so the confirmation prompt shows its title,
    severity and status; every change goes through ShouldProcess (ConfirmImpact High), so -WhatIf previews and
    -Confirm:$false runs unattended. Emits one result object per alert (Updated, Skipped or Failed).
.PARAMETER AlertId
    One or more alert ids as returned by the alerts_v2 API (for example the Id column of Get-DefenderAlertsReport.ps1).
.PARAMETER Filter
    Selects alerts with the filter parameters below; a deliberate opt-in because a broad filter can touch many alerts.
.PARAMETER Title
    Wildcard pattern matched against the alert title, for example 'Suspicious PowerShell*'. Filter mode only.
.PARAMETER Severity
    Only alerts with this severity: informational, low, medium or high. Filter mode only.
.PARAMETER ServiceSource
    Only alerts raised by this service, for example microsoftDefenderForEndpoint or microsoftSentinel. Filter mode only.
.PARAMETER DaysBack
    Look-back window on createdDateTime in filter mode. Default 7, maximum 365.
.PARAMETER CurrentStatus
    Only alerts that currently have this status: new, inProgress or resolved. Filter mode only.
.PARAMETER Status
    New alert status: new, inProgress or resolved.
.PARAMETER Classification
    New classification: unknown, falsePositive, truePositive or informationalExpectedActivity.
.PARAMETER Determination
    New determination using the Graph names, for example malware, phishing, securityTesting, compromisedUser or clean.
.PARAMETER AssignedTo
    User principal name of the analyst the alerts are assigned to.
.EXAMPLE
    PS> .\Update-DefenderAlerts.ps1 -AlertId 'da637551227677560813_-961444813' -Status inProgress -AssignedTo analyst@contoso.com
    Assigns the alert to the analyst and marks it in progress after a confirmation prompt.
.EXAMPLE
    PS> .\Update-DefenderAlerts.ps1 -Filter -Title 'Attack simulation*' -DaysBack 30 -Status resolved -Classification informationalExpectedActivity -Determination securityTesting -WhatIf
    Previews which alerts of the last 30 days would be closed as expected security testing.
.EXAMPLE
    PS> .\Update-DefenderAlerts.ps1 -AlertId (Import-Csv .\Reports\FalsePositives.csv).Id -Classification falsePositive -Determination clean -Status resolved -Confirm:$false
    Closes every alert listed in a reviewed CSV as a clean false positive without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityAlert.ReadWrite.All (delegated); Security Operator or Security Administrator in Defender XDR.
    Category    : Defender XDR alerts & incidents
    Changes     : Yes
    Notes       : Graph determination names differ from the portal labels (compromisedUser = compromised account, clean =
                  not malicious, insufficientData = not enough data to validate). Alert changes also update the incident.
.LINK
    https://learn.microsoft.com/graph/api/security-alert-update
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'ById')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
    [string[]]$AlertId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Filter')]
    [switch]$Filter,

    [Parameter(ParameterSetName = 'Filter')]
    [string]$Title,

    [Parameter(ParameterSetName = 'Filter')]
    [ValidateSet('informational', 'low', 'medium', 'high')]
    [string]$Severity,

    [Parameter(ParameterSetName = 'Filter')]
    [string]$ServiceSource,

    [Parameter(ParameterSetName = 'Filter')]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 7,

    [Parameter(ParameterSetName = 'Filter')]
    [ValidateSet('new', 'inProgress', 'resolved')]
    [string]$CurrentStatus,

    [Parameter()]
    [ValidateSet('new', 'inProgress', 'resolved')]
    [string]$Status,

    [Parameter()]
    [ValidateSet('unknown', 'falsePositive', 'truePositive', 'informationalExpectedActivity')]
    [string]$Classification,

    [Parameter()]
    [ValidateSet('unknown', 'apt', 'malware', 'securityPersonnel', 'securityTesting', 'unwantedSoftware', 'other', 'multiStagedAttack',
        'compromisedUser', 'phishing', 'maliciousUserActivity', 'clean', 'insufficientData', 'confirmedUserActivity', 'lineOfBusinessApplication')]
    [string]$Determination,

    [Parameter()]
    [string]$AssignedTo
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
$body = @{}
if (-not [string]::IsNullOrEmpty($Status)) { $body['status'] = $Status }
if (-not [string]::IsNullOrEmpty($Classification)) { $body['classification'] = $Classification }
if (-not [string]::IsNullOrEmpty($Determination)) { $body['determination'] = $Determination }
if (-not [string]::IsNullOrWhiteSpace($AssignedTo)) { $body['assignedTo'] = $AssignedTo.Trim() }
if ($body.Count -eq 0) { throw 'Specify at least one change: -Status, -Classification, -Determination or -AssignedTo.' }
$changeSummary = (@($body.Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, $body[$_] }) -join ', ')
$bodyJson = $body | ConvertTo-Json -Compress

try { Connect-GraphIfNeeded -Scopes @('SecurityAlert.ReadWrite.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$select = '$select=id,title,severity,status,serviceSource,classification,assignedTo,createdDateTime'
$results = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSCmdlet.ParameterSetName -eq 'Filter') {
    if (@($Title, $Severity, $ServiceSource, $CurrentStatus | Where-Object { $_ }).Count -eq 0) { Write-Warning "No filter criteria given: every alert of the last $DaysBack days is selected." }
    # InvariantCulture keeps ':' as the time separator regardless of the local culture, so the OData literal stays valid.
    $since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $filterParts = @("createdDateTime ge $since")
    if (-not [string]::IsNullOrEmpty($Severity)) { $filterParts += "severity eq '$Severity'" }
    if (-not [string]::IsNullOrEmpty($ServiceSource)) { $filterParts += "serviceSource eq '$ServiceSource'" }
    if (-not [string]::IsNullOrEmpty($CurrentStatus)) { $filterParts += "status eq '$CurrentStatus'" }
    $listUri = '{0}/security/alerts_v2?{1}&$top=100&$filter={2}' -f $graphV1, $select, ($filterParts -join ' and ')
    try { $alerts = @(Invoke-GraphPaged -Uri $listUri) }
    catch { throw "Failed to query alerts: $($_.Exception.Message)" }
    if (-not [string]::IsNullOrEmpty($Title)) { $alerts = @($alerts | Where-Object { [string]$_.title -like $Title }) }
}
else {
    $alerts = @(foreach ($id in @($AlertId | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)) {
            $getUri = '{0}/security/alerts_v2/{1}?{2}' -f $graphV1, [uri]::EscapeDataString($id), $select
            try { Invoke-MgGraphRequest -Method GET -Uri $getUri -OutputType PSObject -ErrorAction Stop }
            catch {
                Write-Warning ('Alert {0} could not be read: {1}' -f $id, $_.Exception.Message)
                $results.Add([PSCustomObject]@{ Id = $id; Title = $null; Severity = $null; ServiceSource = $null; PreviousStatus = $null; PreviousClassification = $null
                        Changes = $changeSummary; Result = 'Failed'; Error = $_.Exception.Message })
            }
            Start-Sleep -Milliseconds 200
        })
}
if ($alerts.Count -eq 0 -and $results.Count -eq 0) { Write-Warning 'No alerts matched the selection; nothing to do.'; return }
$index = 0
foreach ($alert in $alerts) {
    $index++
    Write-Progress -Activity 'Updating Defender XDR alerts' -Status ('{0} of {1}: {2}' -f $index, $alerts.Count, $alert.title) -PercentComplete ([int](($index / $alerts.Count) * 100))
    $result = 'Skipped'; $errorMessage = $null
    $target = '{0} - "{1}" ({2}, {3}, {4})' -f $alert.id, $alert.title, $alert.severity, $alert.status, $alert.serviceSource
    if ($PSCmdlet.ShouldProcess($target, ('Update alert ({0})' -f $changeSummary))) {
        $patchUri = '{0}/security/alerts_v2/{1}' -f $graphV1, [uri]::EscapeDataString([string]$alert.id)
        try { Invoke-MgGraphRequest -Method PATCH -Uri $patchUri -Body $bodyJson -ContentType 'application/json' -ErrorAction Stop | Out-Null; $result = 'Updated' }
        catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ('Update failed for alert {0}: {1}' -f $alert.id, $errorMessage) }
        Start-Sleep -Milliseconds 200
    }
    $results.Add([PSCustomObject]@{
            Id = $alert.id; Title = $alert.title; Severity = $alert.severity; ServiceSource = $alert.serviceSource; PreviousStatus = $alert.status
            PreviousClassification = $alert.classification; Changes = $changeSummary; Result = $result; Error = $errorMessage
        })
}
Write-Progress -Activity 'Updating Defender XDR alerts' -Completed

$updated = @($results | Where-Object { $_.Result -eq 'Updated' }).Count; $failed = @($results | Where-Object { $_.Result -eq 'Failed' }).Count
Write-Host ('Defender XDR alert update ({0})' -f $changeSummary) -ForegroundColor Cyan
Write-Host ('  Selected {0} | Updated {1} | Skipped {2} | Failed {3}' -f $results.Count, $updated, ($results.Count - $updated - $failed), $failed) -ForegroundColor Green

$results
#endregion Main
