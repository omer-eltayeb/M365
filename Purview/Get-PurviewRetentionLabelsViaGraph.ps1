<#
.SYNOPSIS
    Reports Microsoft Purview retention labels (and optionally event types and events) through the Microsoft Graph records management API.
.DESCRIPTION
    Uses Invoke-MgGraphRequest against v1.0 /security/labels/retentionLabels (expanding retentionEventType and
    dispositionReviewStages) to list every retention label with its retention behaviour, action after the retention
    period, trigger, duration (days and years, or Forever), usage flag, record behaviour, relabel target, disposition
    review stages and audit information. -IncludeEventTypes adds /security/triggerTypes/retentionEventTypes and
    -IncludeEvents adds /security/triggers/retentionEvents (with event queries and propagation results), each written
    to its own CSV next to the main report. No Exchange or Security & Compliance session is required.
.PARAMETER IncludeEventTypes
    Also export the retention event types to <OutputPath base>_EventTypes.csv.
.PARAMETER IncludeEvents
    Also export the retention events to <OutputPath base>_Events.csv.
.PARAMETER OutputPath
    Path of the label CSV report. Defaults to .\Reports\PurviewRetentionLabelsGraph_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the label objects to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewRetentionLabelsViaGraph.ps1
    Exports all retention labels to .\Reports\PurviewRetentionLabelsGraph_<timestamp>.csv and prints a summary.
.EXAMPLE
    PS> .\Get-PurviewRetentionLabelsViaGraph.ps1 -IncludeEventTypes -IncludeEvents -PassThru | Where-Object { -not $_.IsInUse } | Select-Object DisplayName, RetentionTrigger, RetentionYears
    Exports labels, event types and events, and lists the labels that are not in use anywhere.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : RecordsManagement.Read.All (delegated; the records management API has no application permissions)
    Category    : Retention & records management
    Changes     : No
    Notes       : The signed-in user also needs a Purview records management role (for example Records Management). If the
                  service rejects the $expand clause the script retries with a smaller expansion, so those columns can be
                  empty. Where a label is published is not exposed by this API - see Export-PurviewRetentionLabels.ps1.
.LINK
    https://learn.microsoft.com/graph/api/security-labelsroot-list-retentionlabel
.LINK
    https://learn.microsoft.com/graph/api/security-triggersroot-list-retentionevents
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeEventTypes,

    [Parameter()]
    [switch]$IncludeEvents,

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

function Get-IdentityName {
    <# Returns the display name (or id) of the user or application inside a Graph identitySet. #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()]$IdentitySet)
    foreach ($kind in 'user', 'application') {
        $identity = $IdentitySet.$kind
        if ($null -ne $identity) { if ($identity.displayName) { return [string]$identity.displayName } else { return [string]$identity.id } }
    }
    return $null
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewRetentionLabelsGraph_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$baseUri = 'https://graph.microsoft.com/v1.0/security'

try { Connect-GraphIfNeeded -Scopes @('RecordsManagement.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# Not every tenant accepts both expansions yet; fall back to a smaller expand before giving up.
foreach ($expand in @('$expand=retentionEventType,dispositionReviewStages', '$expand=retentionEventType', '')) {
    $uri = "$baseUri/labels/retentionLabels"
    if ($expand) { $uri = '{0}?{1}' -f $uri, $expand }
    try { $labels = @(Invoke-GraphPaged -Uri $uri); break }
    catch {
        if (-not $expand) { throw "Failed to list retention labels: $($_.Exception.Message)" }
        Write-Warning "Request with '$expand' failed ($($_.Exception.Message)); retrying with a smaller expansion."
    }
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($label in ($labels | Sort-Object -Property displayName)) {
    $duration = $label.retentionDuration
    $durationDays = $null
    if ($null -ne $duration -and $null -ne $duration.PSObject.Properties['days']) { $durationDays = [int]$duration.days }
    $durationText = if ($null -ne $durationDays) { "$durationDays days" } elseif ($null -ne $duration) { 'Forever' } else { $null }  # retentionDurationForever has no days
    $stages = @(foreach ($stage in @($label.dispositionReviewStages)) { if ($null -ne $stage) { '{0}:{1} ({2})' -f $stage.stageNumber, $stage.name, (@($stage.reviewersEmailAddresses) -join ',') } })
    $rows.Add([PSCustomObject]@{
            DisplayName                   = [string]$label.displayName
            Id                            = [string]$label.id
            BehaviorDuringRetentionPeriod = [string]$label.behaviorDuringRetentionPeriod
            ActionAfterRetentionPeriod    = [string]$label.actionAfterRetentionPeriod
            RetentionTrigger              = [string]$label.retentionTrigger
            RetentionDuration             = $durationText
            RetentionYears                = $(if ($null -ne $durationDays) { [math]::Round($durationDays / 365, 1) } else { $null })
            IsInUse                       = [bool]$label.isInUse
            DefaultRecordBehavior         = [string]$label.defaultRecordBehavior
            LabelToBeApplied              = [string]$label.labelToBeApplied
            RetentionEventType            = [string]$label.retentionEventType.displayName
            DispositionReviewStages       = ($stages -join ' | ')
            DescriptionForAdmins          = [string]$label.descriptionForAdmins
            DescriptionForUsers           = [string]$label.descriptionForUsers
            CreatedBy                     = Get-IdentityName -IdentitySet $label.createdBy
            CreatedDateTime               = $label.createdDateTime
            LastModifiedBy                = Get-IdentityName -IdentitySet $label.lastModifiedBy
            LastModifiedDateTime          = $label.lastModifiedDateTime
        })
}
if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

$pathBase = [System.IO.Path]::Combine((Split-Path -Path $OutputPath -Parent), [System.IO.Path]::GetFileNameWithoutExtension($OutputPath))
if ($IncludeEventTypes) {
    try {
        $typeRows = @(foreach ($type in @(Invoke-GraphPaged -Uri "$baseUri/triggerTypes/retentionEventTypes")) {
                [PSCustomObject]@{
                    DisplayName = [string]$type.displayName; Id = [string]$type.id; Description = [string]$type.description
                    CreatedBy   = Get-IdentityName -IdentitySet $type.createdBy; CreatedDateTime = $type.createdDateTime; LastModifiedDateTime = $type.lastModifiedDateTime
                }
            })
        if ($typeRows.Count -gt 0) { $typeRows | Export-Csv -Path "${pathBase}_EventTypes.csv" -NoTypeInformation -Encoding UTF8 }
        Write-Host ('Retention event types : {0} -> {1}' -f $typeRows.Count, "${pathBase}_EventTypes.csv")
    }
    catch { Write-Warning "Failed to list retention event types: $($_.Exception.Message)" }
}
if ($IncludeEvents) {
    try {
        $eventRows = @(foreach ($event in @(Invoke-GraphPaged -Uri "$baseUri/triggers/retentionEvents")) {
                [PSCustomObject]@{
                    DisplayName             = [string]$event.displayName; Id = [string]$event.id; Description = [string]$event.description
                    EventTriggerDateTime    = $event.eventTriggerDateTime; CreatedDateTime = $event.createdDateTime; CreatedBy = Get-IdentityName -IdentitySet $event.createdBy
                    EventQueries            = (@(foreach ($query in @($event.eventQueries)) { '{0}={1}' -f $query.queryType, $query.query }) -join ' | ')
                    EventStatus             = [string]$event.eventStatus.status
                    EventPropagationResults = (@(foreach ($result in @($event.eventPropagationResults)) { '{0}:{1}={2}' -f $result.serviceName, $result.location, $result.status }) -join ' | ')
                }
            })
        if ($eventRows.Count -gt 0) { $eventRows | Export-Csv -Path "${pathBase}_Events.csv" -NoTypeInformation -Encoding UTF8 }
        Write-Host ('Retention events      : {0} -> {1}' -f $eventRows.Count, "${pathBase}_Events.csv")
    }
    catch { Write-Warning "Failed to list retention events: $($_.Exception.Message)" }
}

Write-Host "`nRetention label summary (Microsoft Graph)" -ForegroundColor Cyan
Write-Host ('  Retention labels      : {0} ({1} in use)' -f $rows.Count, @($rows | Where-Object { $_.IsInUse }).Count)
Write-Host ('  Record labels         : {0}' -f @($rows | Where-Object { $_.BehaviorDuringRetentionPeriod -like 'retainAs*' }).Count)
Write-Host ('  Event-based labels    : {0}' -f @($rows | Where-Object { $_.RetentionTrigger -eq 'dateOfEvent' }).Count)
Write-Host ('  Report                : {0}' -f $OutputPath)

if ($PassThru) {
    $rows
}
#endregion Main
