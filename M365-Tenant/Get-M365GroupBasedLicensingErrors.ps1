<#
.SYNOPSIS
    Lists every group that assigns licenses, its processing state and the members whose group-based assignment failed.
.DESCRIPTION
    Finds licensing groups with an advanced query on /groups (assignedLicenses/$count ne 0) including licenseProcessingState,
    then calls /groups/{id}/membersWithLicenseErrors for each group and reads the failed licenseAssignmentStates of every
    affected member (SKU, state and error such as CountViolation, MutuallyExclusiveViolation, DependencyViolation or
    ProhibitedInUsageLocationViolation). Outputs one row per group, SKU and user; with -Reprocess it posts
    /users/{id}/reprocessLicenseAssignment for every affected user after the root cause has been fixed.
.PARAMETER Reprocess
    Trigger license reprocessing for every user with an error (ShouldProcess; supports -WhatIf and -Confirm).
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365GroupLicensingErrors_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365GroupBasedLicensingErrors.ps1
    Exports all group-based licensing errors and prints the error types with the usual fix for each.
.EXAMPLE
    PS> .\Get-M365GroupBasedLicensingErrors.ps1 -Reprocess -Verbose
    After buying licenses or fixing usage locations, asks Entra ID to reprocess the affected users (prompts per user).
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, User.Read.All, Organization.Read.All (delegated); -Reprocess adds User.ReadWrite.All.
                  Global Reader or License Administrator can report; -Reprocess needs License Administrator or higher.
    Category    : Licensing
    Changes     : Optional (-Reprocess)
    Notes       : Group-based licensing is asynchronous: licenseProcessingState shows QueuedForProcessing, ProcessingInProgress or
                  ProcessingComplete, and reprocessing can take minutes to reflect in the report. Fix the root cause first -
                  reprocessing without more units or a usage location simply fails again. Group-based licensing requires
                  Microsoft Entra ID P1 (or an edition that includes it).
.LINK
    https://learn.microsoft.com/graph/api/group-list-memberswithlicenseerrors
.LINK
    https://learn.microsoft.com/graph/api/user-reprocesslicenseassignment
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$Reprocess,

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

# The usual remediation per licenseAssignmentState error, printed next to the error counts.
$fixHints = @{
    CountViolation                     = 'Not enough units: buy more or free licenses for that SKU, then reprocess.'
    ProhibitedInUsageLocationViolation = 'Set usageLocation on the user (see Get-M365UsageLocationReport.ps1), then reprocess.'
    MutuallyExclusiveViolation         = 'Conflicting service plans from another license/group: disable the duplicate plan.'
    DependencyViolation                = 'A plan depends on another plan that is disabled or missing: enable the prerequisite.'
    UniquenessViolation                = 'The same service plan is already assigned through another SKU: remove one source.'
    Other                              = 'Check the user in Microsoft Entra admin center > Licenses for the detailed message.'
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365GroupLicensingErrors_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('Group.Read.All', 'User.Read.All', 'Organization.Read.All')
if ($Reprocess) { $scopes += 'User.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try {
    $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber')
    $groupsUri = 'https://graph.microsoft.com/v1.0/groups?$filter=assignedLicenses/$count ne 0&$count=true&$select=id,displayName,assignedLicenses,licenseProcessingState'
    $groups = @(Invoke-GraphPaged -Uri $groupsUri -Headers @{ ConsistencyLevel = 'eventual' })
}
catch { throw "Failed to read subscribed SKUs or licensing groups: $($_.Exception.Message)" }
$skuNameById = @{}
foreach ($sku in $skus) { $skuNameById[[string]$sku.skuId] = [string]$sku.skuPartNumber }
Write-Verbose "Found $($groups.Count) groups that assign licenses."

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$groupsWithErrors = 0
$counter = 0
foreach ($group in $groups) {
    $counter++
    Write-Progress -Activity 'Checking licensing groups' -Status "$counter of $($groups.Count): $($group.displayName)" -PercentComplete ([int](($counter / $groups.Count) * 100))
    $groupSkus = @($group.assignedLicenses | ForEach-Object { $id = [string]$_.skuId; if ($skuNameById.ContainsKey($id)) { $skuNameById[$id] } else { $id } })
    $processingState = [string]$group.licenseProcessingState.state
    $membersUri = 'https://graph.microsoft.com/v1.0/groups/{0}/membersWithLicenseErrors?$select=id,displayName,userPrincipalName,licenseAssignmentStates' -f $group.id
    try { $members = @(Invoke-GraphPaged -Uri $membersUri) }
    catch { Write-Warning "Could not read members with license errors for group '$($group.displayName)': $($_.Exception.Message)"; continue }
    Write-Verbose ('{0}: {1} | state {2} | {3} members with errors' -f $group.displayName, ($groupSkus -join ';'), $processingState, $members.Count)
    if ($members.Count -gt 0) { $groupsWithErrors++ }
    foreach ($member in $members) {
        # Prefer the states produced by this group; fall back to any non-active state when Graph attributes it differently.
        $failed = @($member.licenseAssignmentStates | Where-Object { [string]$_.assignedByGroup -eq [string]$group.id -and $_.state -ne 'Active' })
        if ($failed.Count -eq 0) { $failed = @($member.licenseAssignmentStates | Where-Object { $_.state -ne 'Active' }) }
        if ($failed.Count -eq 0) { $failed = @([PSCustomObject]@{ skuId = ''; state = 'Unknown'; error = 'NotReported' }) }
        foreach ($state in $failed) {
            $skuId = [string]$state.skuId
            $skuName = $skuId
            if ($skuNameById.ContainsKey($skuId)) { $skuName = $skuNameById[$skuId] }
            $rows.Add([PSCustomObject]@{
                    Group             = $group.displayName
                    GroupId           = $group.id
                    GroupLicenses     = ($groupSkus -join ';')
                    ProcessingState   = $processingState
                    Sku               = $skuName
                    UserPrincipalName = $member.userPrincipalName
                    DisplayName       = $member.displayName
                    UserId            = $member.id
                    State             = $state.state
                    Error             = $state.error
                    Reprocessed       = ''
                })
        }
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Checking licensing groups' -Completed

$reprocessed = 0
if ($Reprocess) {
    foreach ($userId in @($rows | Select-Object -ExpandProperty UserId -Unique)) {
        $userRows = @($rows | Where-Object { $_.UserId -eq $userId })
        if (-not $PSCmdlet.ShouldProcess($userRows[0].UserPrincipalName, 'Reprocess license assignment')) { continue }
        try {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$userId/reprocessLicenseAssignment" | Out-Null
            foreach ($userRow in $userRows) { $userRow.Reprocessed = 'Requested' }
            $reprocessed++
        }
        catch {
            foreach ($userRow in $userRows) { $userRow.Reprocessed = "Failed: $($_.Exception.Message)" }
            Write-Warning "Reprocessing failed for $($userRows[0].UserPrincipalName): $($_.Exception.Message)"
        }
        Start-Sleep -Milliseconds 200
    }
}
$output = @($rows | Sort-Object -Property Group, UserPrincipalName, Sku)
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host 'Group-based licensing summary' -ForegroundColor Cyan
Write-Host ('  Licensing groups         : {0}' -f $groups.Count)
Write-Host ('  Groups with errors       : {0}' -f $groupsWithErrors) -ForegroundColor Yellow
Write-Host ('  Users with errors        : {0}' -f @($output | Select-Object -ExpandProperty UserId -Unique).Count) -ForegroundColor Yellow
foreach ($errorGroup in ($output | Group-Object -Property Error | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-36} {1,5}  {2}' -f $errorGroup.Name, $errorGroup.Count, $fixHints[[string]$errorGroup.Name])
}
if ($Reprocess) { Write-Host ('  Users reprocessed        : {0}' -f $reprocessed) }
Write-Host ('  CSV                      : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
