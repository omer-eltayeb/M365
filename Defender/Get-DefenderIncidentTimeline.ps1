<#
.SYNOPSIS
    Builds a chronological timeline of one Microsoft Defender XDR incident: alerts, typed evidence and comments.
.DESCRIPTION
    Reads one incident with its alerts expanded (GET /security/incidents/{id}?$expand=alerts) and flattens it into timeline
    rows (Time, Kind, Title, Severity, Status, Source, AlertId, Detail): the incident creation, every alert with its activity
    window, category, MITRE techniques and trimmed recommended actions, every evidence item typed by entity (device, user,
    IP, file, process, URL, mailbox, analysed message, cloud app, registry key) with verdict and remediation status, and the
    analyst comments. Exports the timeline CSV plus <base>_Entities.csv (unique entities, worst verdict, alert count).
.PARAMETER IncidentId
    The incident id (the numeric id shown in the portal URL and in Get-DefenderIncidentsReport.ps1).
.PARAMETER OutputPath
    Path of the timeline CSV. Defaults to .\Reports\DefenderIncidentTimeline_<id>_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the timeline rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderIncidentTimeline.ps1 -IncidentId 4521
    Exports the timeline and entity list of incident 4521 and prints the summary.
.EXAMPLE
    PS> .\Get-DefenderIncidentTimeline.ps1 -IncidentId 4521 -PassThru | Where-Object { $_.Kind -eq 'Evidence' -and $_.Status -eq 'malicious' } | Format-Table Time, Title, Detail
    Shows only the evidence that Defender judged malicious, oldest first.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityIncident.Read.All and SecurityAlert.Read.All (delegated); Security Reader, Security Operator or
                  Security Administrator in Microsoft Defender XDR.
    Category    : Defender XDR alerts & incidents
    Changes     : No
    Notes       : Evidence timestamps are when the entity was first seen in the alert, not the raw event time (use advanced
                  hunting for event-level detail). Command lines and recommended actions are truncated to 200 characters.
.LINK
    https://learn.microsoft.com/graph/api/security-incident-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$IncidentId,

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

function ConvertTo-TimelineRow {
    <# Builds one timeline row with a normalised UTC timestamp. #>
    param([object]$Time, [string]$Kind, [string]$Title, [string]$Severity, [string]$Status, [string]$Source, [string]$AlertId, [string]$Detail)
    return [PSCustomObject]@{ Time = ConvertTo-UtcDateTime -Value $Time; Kind = $Kind; Title = $Title; Severity = $Severity; Status = $Status; Source = $Source; AlertId = $AlertId; Detail = $Detail }
}

function Get-EvidenceSummary {
    <# Maps a typed alertEvidence object to an entity type, its key value and a one-line detail string. #>
    param([Parameter(Mandatory = $true)][object]$Evidence)
    $type = ([string]$Evidence.'@odata.type') -replace '^#microsoft\.graph\.security\.', '' -replace 'Evidence$', ''
    $value = $null; $parts = @()
    switch ($type) {
        'device' { $value = $Evidence.deviceDnsName; $parts = @("risk=$($Evidence.riskScore)", "health=$($Evidence.healthStatus)", "onboarding=$($Evidence.onboardingStatus)") }
        'user' { $value = $Evidence.userAccount.userPrincipalName; if (-not $value) { $value = '{0}\{1}' -f $Evidence.userAccount.domainName, $Evidence.userAccount.accountName } }
        'ip' { $value = $Evidence.ipAddress; $parts = @("country=$($Evidence.countryLetterCode)") }
        'file' { $value = $Evidence.fileDetails.fileName; $parts = @("path=$($Evidence.fileDetails.filePath)", "sha256=$($Evidence.fileDetails.sha256)") }
        'process' { $value = $Evidence.imageFile.fileName; $parts = @("pid=$($Evidence.processId)", ('cmd=' + (([string]$Evidence.processCommandLine) -replace '(?s)^(.{200}).+$', '$1...'))) }
        'url' { $value = $Evidence.url }
        'mailbox' { $value = $Evidence.primaryAddress; $parts = @("name=$($Evidence.displayName)") }
        'analyzedMessage' { $value = $Evidence.subject; $parts = @("from=$($Evidence.p2Sender.emailAddress)", "to=$($Evidence.recipientEmailAddress)", "delivery=$($Evidence.deliveryAction)") }
        'cloudApplication' { $value = $Evidence.displayName; $parts = @("appId=$($Evidence.appId)", "instance=$($Evidence.instanceName)") }
        'registryKey' { $value = $Evidence.registryKey; $parts = @("hive=$($Evidence.registryHive)") }
        default { $value = $Evidence.displayName }
    }
    if ([string]::IsNullOrWhiteSpace([string]$value)) { $value = '(no identifier)' }
    return [PSCustomObject]@{ Type = $type; Value = [string]$value; Detail = (@($parts | Where-Object { $_ -notmatch '=$' }) -join '; ') }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderIncidentTimeline_{0}_{1}.csv' -f $IncidentId, (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
$entitiesPath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($OutputPath), $baseName + '_Entities.csv')
try { Connect-GraphIfNeeded -Scopes @('SecurityIncident.Read.All', 'SecurityAlert.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$uri = 'https://graph.microsoft.com/v1.0/security/incidents/{0}?$expand=alerts' -f [uri]::EscapeDataString($IncidentId)
try { $incident = @(Invoke-GraphPaged -Uri $uri)[0] }
catch { throw "Failed to read incident ${IncidentId}: $($_.Exception.Message)" }
if ($null -eq $incident) { throw "Incident $IncidentId was not found." }
$alerts = @($incident.alerts | Where-Object { $null -ne $_ })
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$entities = @{}
$verdictRank = @{ malicious = 3; suspicious = 2; noThreatsFound = 1; unknown = 0 }
$incidentRow = @{ Time = $incident.createdDateTime; Kind = 'Incident'; Title = $incident.displayName; Severity = $incident.severity; Status = $incident.status; Source = 'Defender XDR' }
$incidentRow['Detail'] = 'Incident created. Classification: {0}; Determination: {1}; Assigned to: {2}; Tags: {3}; {4}' -f $incident.classification, $incident.determination,
    $incident.assignedTo, ((@($incident.customTags) + @($incident.systemTags)) -join ','), $incident.incidentWebUrl
$rows.Add((ConvertTo-TimelineRow @incidentRow))
foreach ($alert in $alerts) {
    $recommended = (([string]$alert.recommendedActions) -replace '\s*[\r\n]+\s*', ' ') -replace '^(.{200}).+$', '$1...'
    $alertRow = @{ Time = $alert.createdDateTime; Kind = 'Alert'; Title = $alert.title; Severity = $alert.severity; Status = $alert.status; AlertId = $alert.id
        Source = '{0}/{1}' -f $alert.serviceSource, $alert.detectionSource
        Detail = 'Category: {0}; First activity: {1:u}; Last activity: {2:u}; MITRE: {3}; Recommended: {4}' -f $alert.category, (ConvertTo-UtcDateTime -Value $alert.firstActivityDateTime),
        (ConvertTo-UtcDateTime -Value $alert.lastActivityDateTime), (@($alert.mitreTechniques) -join ','), $recommended
    }
    $rows.Add((ConvertTo-TimelineRow @alertRow))
    foreach ($evidence in @($alert.evidence | Where-Object { $null -ne $_ })) {
        $summary = Get-EvidenceSummary -Evidence $evidence
        $evidenceRow = @{ Time = @($evidence.createdDateTime, $alert.createdDateTime | Where-Object { $_ })[0]; Kind = 'Evidence'; Severity = $alert.severity; Status = $evidence.verdict
            Title = '{0}: {1}' -f $summary.Type, $summary.Value; Source = $alert.serviceSource; AlertId = $alert.id
            Detail = ('Remediation: {0}; Roles: {1}; {2}' -f $evidence.remediationStatus, (@($evidence.roles) -join ','), $summary.Detail).TrimEnd(' ;')
        }
        $rows.Add((ConvertTo-TimelineRow @evidenceRow))
        $key = '{0}|{1}' -f $summary.Type, $summary.Value
        if (-not $entities.ContainsKey($key)) {
            $entities[$key] = @{ Type = $summary.Type; Value = $summary.Value; Verdict = [string]$evidence.verdict; RemediationStatus = [string]$evidence.remediationStatus; AlertIds = @{} }
        }
        $entity = $entities[$key]
        # Keep the worst verdict seen for an entity across all alerts of the incident.
        if ([int]$verdictRank[[string]$evidence.verdict] -gt [int]$verdictRank[$entity.Verdict]) {
            $entity.Verdict = [string]$evidence.verdict; $entity.RemediationStatus = [string]$evidence.remediationStatus
        }
        $entity.AlertIds[[string]$alert.id] = $true
    }
}
foreach ($comment in @($incident.comments | Where-Object { $null -ne $_ })) {
    $rows.Add((ConvertTo-TimelineRow -Time $comment.createdDateTime -Kind 'Comment' -Title ('Comment by {0}' -f $comment.createdByDisplayName) -Source 'Analyst' -Detail $comment.comment))
}
$timeline = @($rows | Sort-Object -Property Time, Kind)
$timeline | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$entityRows = @($entities.Values |
    ForEach-Object { [PSCustomObject]@{ Type = $_.Type; Value = $_.Value; Verdict = $_.Verdict; RemediationStatus = $_.RemediationStatus; AlertCount = $_.AlertIds.Count } } |
    Sort-Object -Property @{ Expression = { [int]$verdictRank[[string]$_.Verdict] }; Descending = $true }, @{ Expression = 'AlertCount'; Descending = $true }, Type, Value)
if ($entityRows.Count -gt 0) { $entityRows | Export-Csv -Path $entitiesPath -NoTypeInformation -Encoding UTF8 }

$evidenceCount = @($timeline | Where-Object { $_.Kind -eq 'Evidence' }).Count; $commentCount = @($timeline | Where-Object { $_.Kind -eq 'Comment' }).Count
$entityTypes = @($entityRows | Group-Object -Property Type | Sort-Object -Property Count -Descending | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '
Write-Host ('Incident {0} - "{1}" ({2}, {3})' -f $incident.id, $incident.displayName, $incident.severity, $incident.status) -ForegroundColor Cyan
Write-Host ('  Created {0:u} | Last updated {1:u}' -f (ConvertTo-UtcDateTime -Value $incident.createdDateTime), (ConvertTo-UtcDateTime -Value $incident.lastUpdateDateTime))
Write-Host ('  Alerts {0} | Evidence {1} | Comments {2} | Unique entities {3} ({4})' -f $alerts.Count, $evidenceCount, $commentCount, $entityRows.Count, $entityTypes)
$malicious = @($entityRows | Where-Object { $_.Verdict -eq 'malicious' } | Select-Object -First 10)
if ($malicious.Count -gt 0) { Write-Host '  Malicious entities (remediation | type | value):' -ForegroundColor Red }
foreach ($item in $malicious) { Write-Host ('    {0,-18} | {1,-16} | {2}' -f $item.RemediationStatus, $item.Type, $item.Value) }
Write-Host ('  Timeline rows {0} -> {1}' -f $timeline.Count, $OutputPath)
if ($entityRows.Count -gt 0) { Write-Host ('  Entities {0} -> {1}' -f $entityRows.Count, $entitiesPath) }

if ($PassThru) { $timeline }
#endregion Main
