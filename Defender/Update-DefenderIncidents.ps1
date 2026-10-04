<#
.SYNOPSIS
    Bulk-updates Microsoft Defender XDR incidents: status, classification, determination, owner and custom tags.
.DESCRIPTION
    Selects incidents by id (-IncidentId) or by filter (-Filter with -DisplayName, -Severity, -DaysBack, -CurrentStatus
    against GET /security/incidents) and sends one PATCH /security/incidents/{id} per incident with the requested -Status,
    -Classification, -Determination, -AssignedTo and/or -CustomTags. Each incident is read first so the prompt shows its name,
    severity and status; every change goes through ShouldProcess (ConfirmImpact High): -WhatIf previews, -Confirm:$false runs unattended.
.PARAMETER IncidentId
    One or more incident ids (the numeric id shown in the portal URL and in Get-DefenderIncidentsReport.ps1).
.PARAMETER Filter
    Selects incidents with the filter parameters below; a deliberate opt-in because a broad filter can touch many incidents.
.PARAMETER DisplayName
    Wildcard pattern matched against the incident name, for example '*Attack simulation*'. Filter mode only.
.PARAMETER Severity
    Only incidents with this severity: informational, low, medium or high. Filter mode only.
.PARAMETER DaysBack
    Look-back window on createdDateTime in filter mode. Default 30, maximum 365.
.PARAMETER CurrentStatus
    Only incidents that currently have this status: active, inProgress, resolved or redirected. Filter mode only.
.PARAMETER Status
    New incident status: active, inProgress or resolved (redirected is set by the service when incidents are merged).
.PARAMETER Classification
    New classification: unknown, falsePositive, truePositive or informationalExpectedActivity.
.PARAMETER Determination
    New determination using the Graph names, for example malware, phishing, securityTesting, compromisedUser or clean.
.PARAMETER AssignedTo
    User principal name of the analyst the incidents are assigned to.
.PARAMETER CustomTags
    Custom tags to set; the list REPLACES the existing tags. Pass an empty array (-CustomTags @()) to clear them.
.EXAMPLE
    PS> .\Update-DefenderIncidents.ps1 -IncidentId 4521, 4530 -Status inProgress -AssignedTo analyst@contoso.com -CustomTags 'Tier2', 'Ransomware'
    Assigns two incidents to the analyst, marks them in progress and replaces their custom tags after confirmation.
.EXAMPLE
    PS> .\Update-DefenderIncidents.ps1 -Filter -DisplayName '*simulation*' -CurrentStatus active -Status resolved -Classification informationalExpectedActivity -WhatIf
    Previews which active incidents of the last 30 days would be closed as expected activity.
.EXAMPLE
    PS> .\Update-DefenderIncidents.ps1 -IncidentId (Import-Csv .\Reports\Reviewed.csv).Id -Classification falsePositive -Determination clean -Status resolved -Confirm:$false
    Closes every incident listed in a reviewed CSV as a clean false positive without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityIncident.ReadWrite.All (delegated); Security Operator or Security Administrator in Defender XDR.
    Category    : Defender XDR alerts & incidents
    Changes     : Yes
    Notes       : Resolving an incident resolves its alerts; the classification and determination are propagated to them.
                  Use Add-DefenderIncidentComment.ps1 to document the reason as an incident comment.
.LINK
    https://learn.microsoft.com/graph/api/security-incident-update
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'ById')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
    [string[]]$IncidentId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Filter')]
    [switch]$Filter,

    [Parameter(ParameterSetName = 'Filter')]
    [string]$DisplayName,

    [Parameter(ParameterSetName = 'Filter')]
    [ValidateSet('informational', 'low', 'medium', 'high')]
    [string]$Severity,

    [Parameter(ParameterSetName = 'Filter')]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [Parameter(ParameterSetName = 'Filter')]
    [ValidateSet('active', 'inProgress', 'resolved', 'redirected')]
    [string]$CurrentStatus,

    [Parameter()]
    [ValidateSet('active', 'inProgress', 'resolved')]
    [string]$Status,

    [Parameter()]
    [ValidateSet('unknown', 'falsePositive', 'truePositive', 'informationalExpectedActivity')]
    [string]$Classification,

    [Parameter()]
    [ValidateSet('unknown', 'apt', 'malware', 'securityPersonnel', 'securityTesting', 'unwantedSoftware', 'other', 'multiStagedAttack',
        'compromisedUser', 'phishing', 'maliciousUserActivity', 'clean', 'insufficientData', 'confirmedUserActivity', 'lineOfBusinessApplication')]
    [string]$Determination,

    [Parameter()]
    [string]$AssignedTo,

    [Parameter()]
    [string[]]$CustomTags
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
# ContainsKey (not a null test) so that -CustomTags @() is honoured as "clear all tags".
if ($PSBoundParameters.ContainsKey('CustomTags')) { $body['customTags'] = @($CustomTags | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) }
if ($body.Count -eq 0) { throw 'Specify at least one change: -Status, -Classification, -Determination, -AssignedTo or -CustomTags.' }
$changeSummary = (@($body.Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, (@($body[$_]) -join '|') }) -join ', ')
$bodyJson = $body | ConvertTo-Json -Compress

try { Connect-GraphIfNeeded -Scopes @('SecurityIncident.ReadWrite.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$select = '$select=id,displayName,severity,status,classification,assignedTo,customTags,createdDateTime'
$results = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSCmdlet.ParameterSetName -eq 'Filter') {
    if (@($DisplayName, $Severity, $CurrentStatus | Where-Object { $_ }).Count -eq 0) { Write-Warning "No filter criteria given: every incident of the last $DaysBack days is selected." }
    # InvariantCulture keeps ':' as the time separator regardless of the local culture, so the OData literal stays valid.
    $since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    $filterParts = @("createdDateTime ge $since")
    if (-not [string]::IsNullOrEmpty($Severity)) { $filterParts += "severity eq '$Severity'" }
    if (-not [string]::IsNullOrEmpty($CurrentStatus)) { $filterParts += "status eq '$CurrentStatus'" }
    $listUri = '{0}/security/incidents?{1}&$filter={2}' -f $graphV1, $select, ($filterParts -join ' and ')
    try { $incidents = @(Invoke-GraphPaged -Uri $listUri) }
    catch { throw "Failed to query incidents: $($_.Exception.Message)" }
    if (-not [string]::IsNullOrEmpty($DisplayName)) { $incidents = @($incidents | Where-Object { [string]$_.displayName -like $DisplayName }) }
}
else {
    $incidents = @(foreach ($id in @($IncidentId | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)) {
            $getUri = '{0}/security/incidents/{1}?{2}' -f $graphV1, [uri]::EscapeDataString($id), $select
            try { Invoke-MgGraphRequest -Method GET -Uri $getUri -OutputType PSObject -ErrorAction Stop }
            catch {
                Write-Warning ('Incident {0} could not be read: {1}' -f $id, $_.Exception.Message)
                $results.Add([PSCustomObject]@{ Id = $id; DisplayName = $null; Severity = $null; PreviousStatus = $null; PreviousClassification = $null; PreviousCustomTags = $null
                        Changes = $changeSummary; Result = 'Failed'; Error = $_.Exception.Message })
            }
            Start-Sleep -Milliseconds 200
        })
}
if ($incidents.Count -eq 0 -and $results.Count -eq 0) { Write-Warning 'No incidents matched the selection; nothing to do.'; return }
$index = 0
foreach ($incident in $incidents) {
    $index++
    Write-Progress -Activity 'Updating Defender XDR incidents' -Status ('{0} of {1}' -f $index, $incidents.Count) -PercentComplete ([int](($index / $incidents.Count) * 100))
    $result = 'Skipped'; $errorMessage = $null
    $target = '{0} - "{1}" ({2}, {3})' -f $incident.id, $incident.displayName, $incident.severity, $incident.status
    if ($PSCmdlet.ShouldProcess($target, ('Update incident ({0})' -f $changeSummary))) {
        $patchUri = '{0}/security/incidents/{1}' -f $graphV1, [uri]::EscapeDataString([string]$incident.id)
        try { Invoke-MgGraphRequest -Method PATCH -Uri $patchUri -Body $bodyJson -ContentType 'application/json' -ErrorAction Stop | Out-Null; $result = 'Updated' }
        catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ('Update failed for incident {0}: {1}' -f $incident.id, $errorMessage) }
        Start-Sleep -Milliseconds 200
    }
    $results.Add([PSCustomObject]@{
            Id = $incident.id; DisplayName = $incident.displayName; Severity = $incident.severity; PreviousStatus = $incident.status; PreviousClassification = $incident.classification
            PreviousCustomTags = (@($incident.customTags) -join ';'); Changes = $changeSummary; Result = $result; Error = $errorMessage
        })
}
Write-Progress -Activity 'Updating Defender XDR incidents' -Completed

$updated = @($results | Where-Object { $_.Result -eq 'Updated' }).Count; $failed = @($results | Where-Object { $_.Result -eq 'Failed' }).Count
Write-Host ('Defender XDR incident update ({0})' -f $changeSummary) -ForegroundColor Cyan
Write-Host ('  Selected {0} | Updated {1} | Skipped {2} | Failed {3}' -f $results.Count, $updated, ($results.Count - $updated - $failed), $failed) -ForegroundColor Green

$results
#endregion Main
