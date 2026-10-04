<#
.SYNOPSIS
    Lists soft-deleted Microsoft 365 groups with their remaining recovery window and can restore or purge them.
.DESCRIPTION
    Reads the directory recycle bin for groups (GET /directory/deletedItems/microsoft.graph.group, advanced query with
    ConsistencyLevel=eventual) and reports every soft-deleted group with its deletion date, the days elapsed and the days left
    before Microsoft Entra ID purges it permanently (30-day window), the visibility, dynamic membership and whether it was a
    Team. -Restore recovers the selected groups through POST /directory/deletedItems/{id}/restore (group, mailbox, SharePoint
    site, Team and Planner come back); -PermanentlyDelete removes them for good through DELETE /directory/deletedItems/{id}.
    Exports a CSV.
.PARAMETER GroupName
    One or more display names to include; wildcards are supported. Default: every deleted Microsoft 365 group.
.PARAMETER GroupId
    Object ID of a single deleted group.
.PARAMETER Restore
    Restore the selected groups (requires -GroupName or -GroupId). Honours -WhatIf / -Confirm.
.PARAMETER PermanentlyDelete
    Permanently delete the selected groups (requires -GroupName or -GroupId); this cannot be undone. Honours -WhatIf / -Confirm.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\M365DeletedGroups_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365DeletedGroupsReport.ps1
    Exports every soft-deleted Microsoft 365 group with the days left before it is purged.
.EXAMPLE
    PS> .\Get-M365DeletedGroupsReport.ps1 -GroupName 'Project Phoenix' -Restore
    Restores the deleted Project Phoenix group (and its Team, site and mailbox) after confirmation.
.EXAMPLE
    PS> .\Get-M365DeletedGroupsReport.ps1 -GroupName 'Test-*' -PermanentlyDelete -WhatIf
    Shows which deleted test groups would be purged without deleting anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All (delegated); -Restore / -PermanentlyDelete add Group.ReadWrite.All (Groups Administrator role).
    Category    : Microsoft 365 Groups governance
    Changes     : Optional (-Restore / -PermanentlyDelete)
    Notes       : Only Microsoft 365 groups are soft-deleted; security and distribution groups are removed immediately. A restore
                  fails when the mail nickname has since been reused by another group, and SharePoint content can take up to
                  24 hours to reappear. Permanently deleted groups cannot be recovered by Microsoft support. Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/directory-deleteditems-list
.LINK
    https://learn.microsoft.com/graph/api/directory-deleteditems-restore
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
    [switch]$Restore,

    [Parameter()]
    [switch]$PermanentlyDelete,

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
if ($Restore -and $PermanentlyDelete) { throw 'Use either -Restore or -PermanentlyDelete, not both.' }
$action = $null
if ($Restore) { $action = 'Restore' } elseif ($PermanentlyDelete) { $action = 'PermanentlyDelete' }
if ($null -ne $action -and $PSCmdlet.ParameterSetName -eq 'All') { throw "-$action requires -GroupName or -GroupId; pass -GroupName '*' to target every deleted group deliberately." }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365DeletedGroups_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$requiredScopes = @('Group.Read.All')
if ($null -ne $action) { $requiredScopes += 'Group.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

Write-Verbose 'Reading the directory recycle bin for groups.'
$select = 'id,displayName,mail,deletedDateTime,groupTypes,visibility,resourceProvisioningOptions'
try { $deleted = @(Invoke-GraphPaged -Uri ('{0}/directory/deletedItems/microsoft.graph.group?$select={1}&$count=true&$top=999' -f $graphV1, $select) -Headers @{ ConsistencyLevel = 'eventual' }) }
catch { throw "Failed to list deleted groups: $($_.Exception.Message)" }
if ($PSCmdlet.ParameterSetName -eq 'ById') { $deleted = @($deleted | Where-Object { $_.id -eq $GroupId }) }
if ($PSCmdlet.ParameterSetName -eq 'ByName') { $deleted = @($deleted | Where-Object { $name = $_.displayName; @($GroupName | Where-Object { $name -like $_ }).Count -gt 0 }) }
if ($deleted.Count -eq 0) { Write-Warning 'No deleted Microsoft 365 group matched the selection; nothing to report.'; return }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$nowUtc = [datetime]::UtcNow; $processed = 0
foreach ($group in $deleted) {
    $processed++
    Write-Progress -Activity 'Processing deleted groups' -Status "$processed of $($deleted.Count): $($group.displayName)" -PercentComplete (($processed / $deleted.Count) * 100)
    $deletedAt = $null; if ($group.deletedDateTime) { $deletedAt = ([datetime]$group.deletedDateTime).ToUniversalTime() }
    $daysSince = $null; $daysLeft = $null
    if ($null -ne $deletedAt) { $daysSince = [int][math]::Floor(($nowUtc - $deletedAt).TotalDays); $daysLeft = [math]::Max(0, 30 - $daysSince) }

    $taken = 'None'
    if ($action -eq 'Restore' -and $PSCmdlet.ShouldProcess($group.displayName, 'Restore deleted group (with its Team, site and mailbox)')) {
        try { $null = Invoke-MgGraphRequest -Method POST -Uri ('{0}/directory/deletedItems/{1}/restore' -f $graphV1, $group.id) -ErrorAction Stop; $taken = 'Restored' }
        catch { $taken = 'Failed'; Write-Warning "Restoring '$($group.displayName)' failed: $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 200
    }
    elseif ($action -eq 'PermanentlyDelete' -and $PSCmdlet.ShouldProcess($group.displayName, 'PERMANENTLY delete the group (cannot be undone)')) {
        try { Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/directory/deletedItems/{1}' -f $graphV1, $group.id) -ErrorAction Stop | Out-Null; $taken = 'PermanentlyDeleted' }
        catch { $taken = 'Failed'; Write-Warning "Purging '$($group.displayName)' failed: $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 200
    }

    $results.Add([PSCustomObject]@{
        DisplayName                = $group.displayName
        Mail                       = $group.mail
        Visibility                 = $group.visibility
        IsTeam                     = (@($group.resourceProvisioningOptions) -contains 'Team')
        IsDynamic                  = (@($group.groupTypes) -contains 'DynamicMembership')
        DeletedDateTime            = $deletedAt
        DaysSinceDeletion          = $daysSince
        DaysUntilPermanentDeletion = $daysLeft
        ActionTaken                = $taken
        Id                         = $group.id
    })
}
Write-Progress -Activity 'Processing deleted groups' -Completed
$results | Sort-Object -Property DaysUntilPermanentDeletion, DisplayName | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host 'Deleted groups summary' -ForegroundColor Cyan
Write-Host ('  Soft-deleted groups          : {0}' -f $results.Count)
Write-Host ('  Of which Teams               : {0}' -f @($results | Where-Object { $_.IsTeam }).Count)
Write-Host ('  Purged within 7 days         : {0}' -f @($results | Where-Object { $null -ne $_.DaysUntilPermanentDeletion -and $_.DaysUntilPermanentDeletion -le 7 }).Count) -ForegroundColor Yellow
if ($null -ne $action) {
    $succeeded = @($results | Where-Object { $_.ActionTaken -in 'Restored', 'PermanentlyDeleted' }).Count
    Write-Host ('  {0} succeeded / failed       : {1} / {2}' -f $action, $succeeded, @($results | Where-Object { $_.ActionTaken -eq 'Failed' }).Count)
}
Write-Host ('  Report                       : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
