<#
.SYNOPSIS
    Lists Microsoft Purview DLP alerts through the Microsoft Graph security API and optionally resolves them.
.DESCRIPTION
    Calls GET /security/alerts_v2 (v1.0) filtered on serviceSource eq 'dataLossPrevention' and createdDateTime, optionally
    on severity and status, follows @odata.nextLink and flattens each alert: id, title, severity, status, category, created
    time, owner, classification, determination, incident id, the users, files, mailboxes and devices from the evidence
    collection and the portal link. With -Resolve -AlertId the given alerts are set to status resolved (plus the optional
    -Classification) through PATCH /security/alerts_v2/{id} under ShouldProcess. Writes a CSV and prints a summary.
.PARAMETER DaysBack
    Days to look back for the alert list, 1-180 (default 7).
.PARAMETER Severity
    One or more of informational, low, medium, high. Default: all.
.PARAMETER Status
    One or more of new, inProgress, resolved. Default: all.
.PARAMETER Resolve
    Resolve the alerts given in -AlertId instead of producing the report.
.PARAMETER AlertId
    One or more alert ids (the Id column of the report) to resolve.
.PARAMETER Classification
    Optional classification written together with the resolved status: falsePositive, truePositive or informationalExpectedActivity.
.PARAMETER OutputPath
    Path of the CSV (alert report, or resolution results with -Resolve). Defaults to .\Reports\PurviewDlpAlerts_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewDlpAlertsViaGraph.ps1 -DaysBack 30 -Severity high, medium -Status new
    Exports the open high and medium DLP alerts of the last 30 days with the affected users, files and devices.
.EXAMPLE
    PS> .\Get-PurviewDlpAlertsViaGraph.ps1 -Resolve -AlertId 'da637...', 'da638...' -Classification falsePositive -WhatIf
    Shows which alerts would be resolved as false positives; drop -WhatIf to apply (each alert is confirmed).
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Delegated SecurityAlert.Read.All (report) or SecurityAlert.ReadWrite.All (-Resolve) plus Security Reader / Operator
    Category    : Data loss prevention
    Changes     : Optional (-Resolve)
    Notes       : DLP alerts reach the Defender XDR queue (180-day retention) when Purview DLP alert policies are enabled. The Graph
                  serviceSource is dataLossPrevention; alerts_v2 documents $filter/$top only, so the full alert (with evidence) is read.
.LINK
    https://learn.microsoft.com/graph/api/security-list-alerts_v2
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Report')]
param(
    [Parameter(ParameterSetName = 'Report')]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 7,

    [Parameter(ParameterSetName = 'Report')]
    [ValidateSet('informational', 'low', 'medium', 'high')]
    [string[]]$Severity,

    [Parameter(ParameterSetName = 'Report')]
    [ValidateSet('new', 'inProgress', 'resolved')]
    [string[]]$Status,

    [Parameter(Mandatory = $true, ParameterSetName = 'Resolve')]
    [switch]$Resolve,

    [Parameter(Mandatory = $true, ParameterSetName = 'Resolve')]
    [string[]]$AlertId,

    [Parameter(ParameterSetName = 'Resolve')]
    [ValidateSet('falsePositive', 'truePositive', 'informationalExpectedActivity')]
    [string]$Classification,

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

function Get-EvidenceText {
    <# Joins one property (dotted path allowed) of every evidence item of the given @odata.type, e.g. user UPNs or file names. #>
    param([Parameter()][AllowNull()]$Evidence, [Parameter(Mandatory = $true)][string]$Type, [Parameter(Mandatory = $true)][string]$Property)
    $values = foreach ($item in @($Evidence)) {
        if ($null -eq $item -or [string]$item.'@odata.type' -ne "#microsoft.graph.security.$Type") { continue }
        $value = $item
        foreach ($segment in $Property.Split('.')) { if ($null -ne $value) { $value = $value.$segment } }
        [string]$value
    }
    return (@($values | Where-Object { $_ } | Select-Object -Unique) -join '; ')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewDlpAlerts_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$results = New-Object -TypeName System.Collections.Generic.List[object]
try { Connect-GraphIfNeeded -Scopes @($(if ($Resolve) { 'SecurityAlert.ReadWrite.All' } else { 'SecurityAlert.Read.All' })) }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

if ($Resolve) {
    $body = @{ status = 'resolved' }
    if (-not [string]::IsNullOrEmpty($Classification)) { $body['classification'] = $Classification }
    $bodyJson = $body | ConvertTo-Json -Compress
    foreach ($id in $AlertId) {
        $uri = 'https://graph.microsoft.com/v1.0/security/alerts_v2/{0}' -f [uri]::EscapeDataString($id)
        try { $alert = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop }
        catch { Write-Warning ('Alert {0} could not be read: {1}' -f $id, $_.Exception.Message); continue }
        $result = 'Skipped'
        if ([string]$alert.status -eq 'resolved') { $result = 'AlreadyResolved' }
        elseif ($PSCmdlet.ShouldProcess(('{0} ({1})' -f $alert.title, $id), ('Resolve DLP alert: {0}' -f $bodyJson))) {
            try { Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $bodyJson -ContentType 'application/json' -ErrorAction Stop | Out-Null; $result = 'Resolved' }
            catch { Write-Warning ('Alert {0} could not be updated: {1}' -f $id, $_.Exception.Message); $result = 'Failed' }
            Start-Sleep -Milliseconds 200
        }
        $results.Add([PSCustomObject]@{ Id = [string]$alert.id; Title = [string]$alert.title; Severity = [string]$alert.severity; PreviousStatus = [string]$alert.status; Result = $result })
    }
}
else {
    # InvariantCulture keeps ':' as the time separator regardless of the local culture, so the OData literal stays valid.
    $since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $filterParts = @("serviceSource eq 'dataLossPrevention'", "createdDateTime ge $since")
    if ($Severity) { $filterParts += '(' + (@($Severity | ForEach-Object { "severity eq '$_'" }) -join ' or ') + ')' }
    if ($Status) { $filterParts += '(' + (@($Status | ForEach-Object { "status eq '$_'" }) -join ' or ') + ')' }
    $listUri = 'https://graph.microsoft.com/v1.0/security/alerts_v2?$top=100&$filter={0}' -f [uri]::EscapeDataString(($filterParts -join ' and '))
    try { $alerts = @(Invoke-GraphPaged -Uri $listUri) }
    catch { throw "Failed to query DLP alerts: $($_.Exception.Message)" }
    foreach ($alert in ($alerts | Sort-Object -Property createdDateTime -Descending)) {
        $results.Add([PSCustomObject]@{
                Id              = [string]$alert.id
                Title           = [string]$alert.title
                Severity        = [string]$alert.severity
                Status          = [string]$alert.status
                Category        = (@($alert.categories | Where-Object { $_ }) -join ';')
                CreatedDateTime = [datetime]$alert.createdDateTime
                AssignedTo      = [string]$alert.assignedTo
                Classification  = [string]$alert.classification
                Determination   = [string]$alert.determination
                IncidentId      = [string]$alert.incidentId
                Users           = Get-EvidenceText -Evidence $alert.evidence -Type 'userEvidence' -Property 'userAccount.userPrincipalName'
                Files           = Get-EvidenceText -Evidence $alert.evidence -Type 'fileEvidence' -Property 'fileDetails.fileName'
                Mailboxes       = Get-EvidenceText -Evidence $alert.evidence -Type 'mailboxEvidence' -Property 'primaryAddress'
                Devices         = Get-EvidenceText -Evidence $alert.evidence -Type 'deviceEvidence' -Property 'deviceDnsName'
                AlertWebUrl     = [string]$alert.alertWebUrl
            })
    }
}

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No DLP alerts matched the request.' }

Write-Host ('Purview DLP alerts summary: {0} {1}' -f $results.Count, $(if ($Resolve) { 'alert(s) processed' } else { "alert(s) in the last $DaysBack days" })) -ForegroundColor Cyan
foreach ($property in $(if ($Resolve) { @('Result') } else { @('Severity', 'Status') })) {
    $parts = @($results | Group-Object -Property $property | Sort-Object -Property Count -Descending | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name })
    Write-Host ('  By {0,-9}: {1}' -f $property.ToLower(), ($parts -join ', '))
}
Write-Host ('  Report      : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
