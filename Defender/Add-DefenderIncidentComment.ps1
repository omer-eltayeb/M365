<#
.SYNOPSIS
    Adds the same analyst comment to one or more Microsoft Defender XDR incidents or alerts.
.DESCRIPTION
    Posts an alertComment object to POST /security/incidents/{id}/comments (default) or, with -AlertId, to
    POST /security/alerts_v2/{id}/comments through Microsoft Graph. The service returns the complete comment list of
    the target; the script picks the newest entry and emits one object per target with the author shown in the portal
    (createdByDisplayName), the timestamp and the total number of comments. Every post goes through ShouldProcess
    (ConfirmImpact High), so -WhatIf previews and -Confirm:$false runs unattended.
.PARAMETER IncidentId
    One or more incident ids (the numeric id shown in the portal URL). Default parameter set.
.PARAMETER AlertId
    One or more alert ids from the alerts_v2 API; the comment is added to the alerts instead of incidents.
.PARAMETER Comment
    Text of the comment, for example a ticket reference or the triage conclusion.
.EXAMPLE
    PS> .\Add-DefenderIncidentComment.ps1 -IncidentId 4521 -Comment 'Ticket INC0012345 - user confirmed the sign-in, closing as benign.'
    Adds the comment to incident 4521 after a confirmation prompt and shows the author and timestamp recorded by the service.
.EXAMPLE
    PS> .\Add-DefenderIncidentComment.ps1 -IncidentId (Import-Csv .\Reports\Reviewed.csv).Id -Comment 'Reviewed in weekly SOC triage 2026-10-04' -Confirm:$false
    Stamps every incident listed in a reviewed CSV with the same comment without prompting.
.EXAMPLE
    PS> .\Add-DefenderIncidentComment.ps1 -AlertId 'da637551227677560813_-961444813' -Comment 'Expected: approved pentest window' -WhatIf
    Shows which alert would receive the comment without posting anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : SecurityIncident.ReadWrite.All for incidents, SecurityAlert.ReadWrite.All for alerts (delegated);
                  Security Operator or Security Administrator in Microsoft Defender XDR.
    Category    : Defender XDR alerts & incidents
    Changes     : Yes
    Notes       : Comments cannot be edited or deleted through the API once posted. Comments are appended, so re-running
                  the script adds duplicate entries. The author is the signed-in account of the Graph session.
.LINK
    https://learn.microsoft.com/graph/api/security-incident-post-comments
.LINK
    https://learn.microsoft.com/graph/api/security-alert-post-comments
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Incident')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Incident')]
    [string[]]$IncidentId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Alert')]
    [string[]]$AlertId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Comment
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
    param(
        [Parameter()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}
#endregion Helpers

#region Main
if ($PSCmdlet.ParameterSetName -eq 'Alert') {
    $targetType = 'Alert'; $collection = 'alerts_v2'; $requiredScopes = @('SecurityAlert.ReadWrite.All'); $targetIds = $AlertId
}
else {
    $targetType = 'Incident'; $collection = 'incidents'; $requiredScopes = @('SecurityIncident.ReadWrite.All'); $targetIds = $IncidentId
}
$targetIds = @($targetIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
if ($targetIds.Count -eq 0) { throw "No $targetType ids were supplied." }
$Comment = $Comment.Trim()
$preview = $Comment
if ($preview.Length -gt 80) { $preview = $preview.Substring(0, 77) + '...' }
# The comments collection accepts a typed alertComment object; the same body works for incidents and alerts.
$bodyJson = @{ '@odata.type' = 'microsoft.graph.security.alertComment'; comment = $Comment } | ConvertTo-Json -Compress

try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$activity = 'Adding comment to Defender XDR {0}s' -f $targetType.ToLower()
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($id in $targetIds) {
    $index++
    Write-Progress -Activity $activity -Status ('{0} of {1}: {2}' -f $index, $targetIds.Count, $id) -PercentComplete ([int](($index / $targetIds.Count) * 100))
    $result = 'Skipped'; $errorMessage = $null; $created = $null; $totalComments = $null
    if ($PSCmdlet.ShouldProcess(('{0} {1}' -f $targetType, $id), ('Add comment "{0}"' -f $preview))) {
        $uri = '{0}/security/{1}/{2}/comments' -f $graphV1, $collection, [uri]::EscapeDataString($id)
        try {
            $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $bodyJson -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
            # The response is the full comment list of the target, so the newest entry is the comment just added.
            $comments = @()
            if ($null -ne $response.PSObject.Properties['value']) { $comments = @($response.value) } elseif ($null -ne $response) { $comments = @($response) }
            $totalComments = $comments.Count
            $created = $comments | Sort-Object -Property { ConvertTo-UtcDateTime -Value $_.createdDateTime } -Descending | Select-Object -First 1
            $result = 'Added'
        }
        catch {
            $result = 'Failed'; $errorMessage = $_.Exception.Message
            Write-Warning ('Comment could not be added to {0} {1}: {2}' -f $targetType.ToLower(), $id, $errorMessage)
        }
        Start-Sleep -Milliseconds 200
    }
    $results.Add([PSCustomObject]@{
            TargetType           = $targetType
            TargetId             = $id
            Comment              = $Comment
            CreatedByDisplayName = $created.createdByDisplayName
            CreatedDateTime      = ConvertTo-UtcDateTime -Value $created.createdDateTime
            TotalComments        = $totalComments
            Result               = $result
            Error                = $errorMessage
        })
}
Write-Progress -Activity $activity -Completed

$added = @($results | Where-Object { $_.Result -eq 'Added' }).Count
$failed = @($results | Where-Object { $_.Result -eq 'Failed' }).Count
Write-Host ''
Write-Host ('Defender XDR comment: "{0}"' -f $preview) -ForegroundColor Cyan
Write-Host ('  {0}s selected {1} | Added {2} | Skipped {3} | Failed {4}' -f $targetType, $results.Count, $added, ($results.Count - $added - $failed), $failed) -ForegroundColor Green
$lastAdded = $results | Where-Object { $_.Result -eq 'Added' } | Select-Object -Last 1
if ($null -ne $lastAdded) { Write-Host ('  Recorded as {0} at {1:yyyy-MM-dd HH:mm:ss} UTC' -f $lastAdded.CreatedByDisplayName, $lastAdded.CreatedDateTime) }

$results
#endregion Main
