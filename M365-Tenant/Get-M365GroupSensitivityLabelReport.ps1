<#
.SYNOPSIS
    Reports the sensitivity label of every Microsoft 365 group and can apply a label to groups that have none.
.DESCRIPTION
    Lists Microsoft 365 groups (GET /groups with a groupTypes filter, or the groups selected with -GroupName / -GroupId) with the
    sensitivity label from assignedLabels (name and ID), a HasLabel flag, visibility and Teams provisioning; -IncludeCounts adds the
    guest count and -IncludeSiteUrl the SharePoint site URL. -ApplyLabelId applies the given label (PATCH /groups/{id} with
    assignedLabels) to the selected groups without a label, honouring -WhatIf / -Confirm. Exports a CSV and prints the label distribution.
.PARAMETER GroupName
    One or more display names to include; wildcards are supported. Default: every Microsoft 365 group.
.PARAMETER GroupId
    Object ID of a single Microsoft 365 group.
.PARAMETER IncludeCounts
    Adds GuestsCount (guest members via /members/microsoft.graph.user/$count); one extra call per group.
.PARAMETER IncludeSiteUrl
    Adds SiteUrl from /groups/{id}/sites/root; requests Sites.Read.All and makes one extra call per group.
.PARAMETER ApplyLabelId
    GUID of the sensitivity label to apply to the selected unlabelled groups (requires -GroupName or -GroupId); labelled groups are
    skipped. Find the GUID in the Purview portal or with Get-Label (ImmutableId) in Security & Compliance PowerShell.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\M365GroupSensitivityLabels_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365GroupSensitivityLabelReport.ps1 -IncludeCounts
    Lists every Microsoft 365 group with its sensitivity label (HasLabel = False marks the gaps) and its guest count.
.EXAMPLE
    PS> .\Get-M365GroupSensitivityLabelReport.ps1 -GroupName 'Project-*' -ApplyLabelId 1b2c3d4e-0000-4000-8000-000000000000 -WhatIf
    Shows which Project groups would receive the label without changing anything; drop -WhatIf to apply it after confirmation.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All (delegated); -IncludeCounts adds GroupMember.Read.All, -IncludeSiteUrl adds Sites.Read.All and
                  -ApplyLabelId adds Group.ReadWrite.All (Groups Administrator role; assignedLabels cannot be set app-only).
    Category    : Microsoft 365 Groups governance
    Changes     : Optional (-ApplyLabelId)
    Notes       : Labels appear on groups only when EnableMIPLabels is true in the Group.Unified settings and the label is published
                  to the signed-in user with the "Groups & sites" scope. Applying a label also enforces its privacy, guest and
                  external-sharing settings on the group, Team and site. Label definitions are not read, only assigned labels are shown.
.LINK
    https://learn.microsoft.com/purview/sensitivity-labels-teams-groups-sites
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'ByName')]
    [string[]]$GroupName,

    [Parameter(ParameterSetName = 'ById')]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$GroupId,

    [Parameter()]
    [switch]$IncludeCounts,

    [Parameter()]
    [switch]$IncludeSiteUrl,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$ApplyLabelId,

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
$graphV1 = 'https://graph.microsoft.com/v1.0'
$eventual = @{ ConsistencyLevel = 'eventual' }
$applyRequested = -not [string]::IsNullOrWhiteSpace($ApplyLabelId)
if ($applyRequested -and $PSCmdlet.ParameterSetName -eq 'All') { throw "-ApplyLabelId requires -GroupName or -GroupId; pass -GroupName '*' to label every unlabelled group deliberately." }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365GroupSensitivityLabels_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$requiredScopes = @('Group.Read.All')
if ($IncludeCounts) { $requiredScopes += 'GroupMember.Read.All' }
if ($IncludeSiteUrl) { $requiredScopes += 'Sites.Read.All' }
if ($applyRequested) { $requiredScopes += 'Group.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$select = 'id,displayName,visibility,assignedLabels,resourceProvisioningOptions,groupTypes'
$filter = 'groupTypes/any(c:c eq ''Unified'')'
if ($PSCmdlet.ParameterSetName -eq 'ById') { $filter += " and id eq '$GroupId'" }
try { $groups = @(Invoke-GraphPaged -Uri ('{0}/groups?$filter={1}&$select={2}&$top=999' -f $graphV1, $filter, $select)) }
catch { throw "Failed to list Microsoft 365 groups: $($_.Exception.Message)" }
if ($PSCmdlet.ParameterSetName -eq 'ByName') { $groups = @($groups | Where-Object { $name = $_.displayName; @($GroupName | Where-Object { $name -like $_ }).Count -gt 0 }) }
if ($groups.Count -eq 0) { Write-Warning 'No Microsoft 365 group matched the selection; nothing to report.'; return }

$results = New-Object -TypeName System.Collections.Generic.List[object]; $processed = 0
foreach ($group in $groups) {
    $processed++
    Write-Progress -Activity 'Reading sensitivity labels' -Status "$processed of $($groups.Count): $($group.displayName)" -PercentComplete (($processed / $groups.Count) * 100)
    $groupUri = '{0}/groups/{1}' -f $graphV1, $group.id
    $label = $group.assignedLabels | Select-Object -First 1
    $guestsCount = $null; $siteUrl = $null; $action = 'None'
    if ($applyRequested -and $null -ne $label) { $action = 'SkippedHasLabel' }
    elseif ($applyRequested -and $PSCmdlet.ShouldProcess($group.displayName, "Apply sensitivity label $ApplyLabelId")) {
        try {
            Invoke-MgGraphRequest -Method PATCH -Uri $groupUri -Body @{ assignedLabels = @(@{ labelId = $ApplyLabelId }) } -ContentType 'application/json' -ErrorAction Stop | Out-Null
            # PATCH returns no content; re-read the group so the report shows the label name Graph resolved.
            $label = (Invoke-MgGraphRequest -Method GET -Uri ($groupUri + '?$select=assignedLabels') -OutputType PSObject -ErrorAction Stop).assignedLabels | Select-Object -First 1
            $action = 'LabelApplied'
        }
        catch { $action = 'Failed'; Write-Warning "Applying the label to '$($group.displayName)' failed: $($_.Exception.Message)" }
    }
    try {
        if ($IncludeCounts) {
            # Some tenants reject the filtered /$count segment; listing the guest members gives the same number.
            $countUri = $groupUri + '/members/microsoft.graph.user/$count?$filter=userType eq ''Guest'''
            try { $guestsCount = [int](([string](Invoke-MgGraphRequest -Method GET -Uri $countUri -Headers $eventual -ErrorAction Stop)).Trim()) }
            catch { $guestsCount = @(Invoke-GraphPaged -Uri ($groupUri + '/members/microsoft.graph.user?$filter=userType eq ''Guest''&$count=true&$select=id') -Headers $eventual).Count }
        }
        if ($IncludeSiteUrl) {
            try { $siteUrl = (Invoke-MgGraphRequest -Method GET -Uri ($groupUri + '/sites/root?$select=webUrl') -OutputType PSObject -ErrorAction Stop).webUrl }
            catch { Write-Verbose "No SharePoint site found for '$($group.displayName)' (not provisioned yet?): $($_.Exception.Message)" }
        }
    }
    catch { Write-Warning "Could not read every detail of '$($group.displayName)': $($_.Exception.Message)" }
    $results.Add([PSCustomObject]@{
        DisplayName = $group.displayName
        Label       = $label.displayName
        LabelId     = $label.labelId
        HasLabel    = ($null -ne $label)
        Visibility  = $group.visibility
        IsTeam      = (@($group.resourceProvisioningOptions) -contains 'Team')
        GuestsCount = $guestsCount
        SiteUrl     = $siteUrl
        ActionTaken = $action
        Id          = $group.id
    })
    if ($IncludeCounts -or $IncludeSiteUrl -or $action -ne 'None') { Start-Sleep -Milliseconds 200 }
}
Write-Progress -Activity 'Reading sensitivity labels' -Completed
$results | Sort-Object -Property Label, DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$unlabelled = @($results | Where-Object { -not $_.HasLabel }).Count
Write-Host 'Sensitivity label summary' -ForegroundColor Cyan
Write-Host ('  Groups                       : {0}' -f $results.Count)
Write-Host ('  Without label                : {0}' -f $unlabelled) -ForegroundColor $(if ($unlabelled -gt 0) { 'Yellow' } else { 'Green' })
foreach ($bucket in @($results | Where-Object { $_.HasLabel } | Group-Object -Property Label | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-40} {1}' -f $bucket.Name, $bucket.Count)
}
if ($applyRequested) {
    $applied = @($results | Where-Object { $_.ActionTaken -eq 'LabelApplied' }).Count; $failed = @($results | Where-Object { $_.ActionTaken -eq 'Failed' }).Count
    Write-Host ('  Labels applied / failed      : {0} / {1}' -f $applied, $failed)
}
Write-Host ('  Report                       : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
