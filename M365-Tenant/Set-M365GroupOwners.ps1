<#
.SYNOPSIS
    Adds or removes Microsoft 365 group owners in bulk from a CSV or from -GroupName / -Owners, with last-owner protection.
.DESCRIPTION
    Builds a work list from -InputCsv (columns GroupName or GroupId, OwnerUpn, optional Action = Add | Remove) or from -GroupName
    combined with -Owners (-Remove switches the action), resolves groups by object ID or unique display name and users by UPN, and
    reads the current owners once per group (GET /groups/{id}/owners), so redundant changes come back as AlreadyOwner / NotAnOwner
    and removing the last owner is refused unless -AllowLastOwnerRemoval is given. Changes (POST /groups/{id}/owners/$ref, DELETE
    /groups/{id}/owners/{userId}/$ref) happen only with -Apply and honour -WhatIf / -Confirm. Writes a results CSV.
.PARAMETER InputCsv
    CSV with GroupName or GroupId, OwnerUpn and an optional Action column (Add is the default).
.PARAMETER GroupName
    One or more group display names or object IDs to change.
.PARAMETER Owners
    User principal names of the owners to add (or to remove with -Remove).
.PARAMETER Remove
    Remove the given owners instead of adding them.
.PARAMETER AlsoAddAsMember
    When adding an owner, also add the user as a member (Teams expects owners to be members).
.PARAMETER AllowLastOwnerRemoval
    Allow a removal that leaves the group without any owner.
.PARAMETER Apply
    Perform the changes. Without this switch the script only reports what would change (Result = Planned).
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\M365GroupOwnerChanges_yyyyMMdd-HHmm.csv.
.EXAMPLE
    PS> .\Set-M365GroupOwners.ps1 -GroupName 'Project Phoenix', 'Finance Team' -Owners it-governance@contoso.com -AlsoAddAsMember
    Shows what would happen when the governance account becomes owner (and member) of both groups; nothing is changed.
.EXAMPLE
    PS> .\Set-M365GroupOwners.ps1 -InputCsv .\owners.csv -Apply -Confirm:$false
    Applies every Add / Remove row of the CSV without prompting and writes the results CSV.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.ReadWrite.All, User.Read.All (delegated); the signed-in user needs the Groups Administrator role.
    Category    : Microsoft 365 Groups governance
    Changes     : Yes
    Notes       : Works for Microsoft 365 and cloud security groups (dynamic groups included). Groups synchronised from on-premises
                  AD are skipped and distribution lists fail because Exchange Online owns them. A removed owner keeps the membership.
.LINK
    https://learn.microsoft.com/graph/api/group-post-owners
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Direct')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateNotNullOrEmpty()]
    [string]$InputCsv,

    [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
    [string[]]$GroupName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
    [ValidatePattern('^[^@\s]+@[^@\s]+$')]
    [string[]]$Owners,

    [Parameter(ParameterSetName = 'Direct')]
    [switch]$Remove,

    [Parameter()]
    [switch]$AlsoAddAsMember,

    [Parameter()]
    [switch]$AllowLastOwnerRemoval,

    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [string]$OutputPath
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
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365GroupOwnerChanges_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$workItems = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    foreach ($row in @(Import-Csv -Path $InputCsv)) {
        $selector = ([string]$row.GroupId).Trim(); if (-not $selector) { $selector = ([string]$row.GroupName).Trim() }
        $upn = ([string]$row.OwnerUpn).Trim()
        if (-not $selector -or -not $upn) { Write-Warning 'Skipping a CSV row without GroupName/GroupId or OwnerUpn.'; continue }
        $workItems.Add([PSCustomObject]@{ Selector = $selector; OwnerUpn = $upn; Action = $(if ($row.Action -eq 'Remove') { 'Remove' } else { 'Add' }) })
    }
}
else {
    $action = 'Add'; if ($Remove) { $action = 'Remove' }
    foreach ($selector in $GroupName) { foreach ($upn in $Owners) { $workItems.Add([PSCustomObject]@{ Selector = $selector; OwnerUpn = $upn; Action = $action }) } }
}
if ($workItems.Count -eq 0) { throw 'No owner changes to process.' }

try { Connect-GraphIfNeeded -Scopes @('Group.ReadWrite.All', 'User.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$groupSelect = 'id,displayName,onPremisesSyncEnabled'
$groupCache = @{}; $userCache = @{}; $ownerCache = @{}; $processed = 0
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($item in $workItems) {
    $processed++
    Write-Progress -Activity 'Processing owner changes' -Status "$processed of $($workItems.Count): $($item.Selector)" -PercentComplete (($processed / $workItems.Count) * 100)
    if (-not $groupCache.ContainsKey($item.Selector)) {
        $lookupUri = '{0}/groups?$filter=displayName eq ''{1}''&$select={2}' -f $graphV1, $item.Selector.Replace("'", "''"), $groupSelect
        if ($item.Selector -match '^[0-9a-fA-F-]{36}$') { $lookupUri = '{0}/groups/{1}?$select={2}' -f $graphV1, $item.Selector, $groupSelect }
        try { $groupCache[$item.Selector] = @(Invoke-GraphPaged -Uri $lookupUri) }
        catch { Write-Warning "Could not resolve group '$($item.Selector)': $($_.Exception.Message)"; $groupCache[$item.Selector] = @() }
    }
    if (-not $userCache.ContainsKey($item.OwnerUpn)) {
        try { $userCache[$item.OwnerUpn] = Invoke-MgGraphRequest -Uri ('{0}/users/{1}?$select=id,userPrincipalName' -f $graphV1, [uri]::EscapeDataString($item.OwnerUpn)) -ErrorAction Stop }
        catch { Write-Warning "User '$($item.OwnerUpn)' was not found: $($_.Exception.Message)"; $userCache[$item.OwnerUpn] = $null }
    }
    $targets = $groupCache[$item.Selector]; $user = $userCache[$item.OwnerUpn]; $outcome = $null
    if ($targets.Count -eq 0) { $outcome = 'GroupNotFound' } elseif ($targets.Count -gt 1) { $outcome = 'AmbiguousGroupName' } elseif ($null -eq $user) { $outcome = 'UserNotFound' }
    if ($null -ne $outcome) { $results.Add([PSCustomObject]@{ GroupName = $item.Selector; GroupId = ''; OwnerUpn = $item.OwnerUpn; Action = $item.Action; Result = $outcome; Message = '' }); continue }
    $group = $targets[0]; $groupUri = '{0}/groups/{1}' -f $graphV1, $group.id
    $outcome = 'Planned'; $message = ''; $reference = @{ '@odata.id' = "$graphV1/users/$($user.id)" }
    try {
        if (-not $ownerCache.ContainsKey($group.id)) {
            $ownerCache[$group.id] = New-Object -TypeName System.Collections.Generic.List[string]
            foreach ($owner in @(Invoke-GraphPaged -Uri ($groupUri + '/owners?$select=id'))) { $ownerCache[$group.id].Add([string]$owner.id) }
        }
        $currentOwners = $ownerCache[$group.id]; $isOwner = $currentOwners.Contains([string]$user.id)
        if ($group.onPremisesSyncEnabled -eq $true) { $outcome = 'SkippedSynced' }
        elseif ($item.Action -eq 'Add' -and $isOwner) { $outcome = 'AlreadyOwner' }
        elseif ($item.Action -eq 'Remove' -and -not $isOwner) { $outcome = 'NotAnOwner' }
        elseif ($item.Action -eq 'Remove' -and $currentOwners.Count -le 1 -and -not $AllowLastOwnerRemoval) { $outcome = 'SkippedLastOwner'; $message = 'Use -AllowLastOwnerRemoval to allow this.' }
        elseif ($Apply -and -not $PSCmdlet.ShouldProcess($group.displayName, "$($item.Action) owner $($user.userPrincipalName)")) { $outcome = 'SkippedByOperator' }
        elseif ($Apply -and $item.Action -eq 'Add') {
            $null = Invoke-MgGraphRequest -Method POST -Uri ($groupUri + '/owners/$ref') -Body $reference -ContentType 'application/json' -ErrorAction Stop
            $currentOwners.Add([string]$user.id); $outcome = 'Added'
            if ($AlsoAddAsMember) {
                # Graph answers 400 "already exist" when the user is a member already, which is the desired state anyway.
                try { $null = Invoke-MgGraphRequest -Method POST -Uri ($groupUri + '/members/$ref') -Body $reference -ContentType 'application/json' -ErrorAction Stop; $outcome = 'AddedAndMember' }
                catch { if ($_.Exception.Message -notmatch 'already exist') { throw }; $outcome = 'AddedAlreadyMember' }
            }
        }
        elseif ($Apply) {
            Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/owners/{1}/$ref' -f $groupUri, $user.id) -ErrorAction Stop | Out-Null
            $null = $currentOwners.Remove([string]$user.id); $outcome = 'Removed'
        }
    }
    catch { $outcome = 'Failed'; $message = $_.Exception.Message; Write-Warning "$($item.Action) owner $($item.OwnerUpn) on '$($group.displayName)' failed: $message" }
    if ($Apply) { Start-Sleep -Milliseconds 200 }
    $results.Add([PSCustomObject]@{ GroupName = $group.displayName; GroupId = $group.id; OwnerUpn = $user.userPrincipalName; Action = $item.Action; Result = $outcome; Message = $message })
}
Write-Progress -Activity 'Processing owner changes' -Completed
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host 'Group owner changes summary' -ForegroundColor Cyan
Write-Host ('  Evaluated pairs              : {0} ({1})' -f $results.Count, $(if ($Apply) { 'applied' } else { 'preview only - add -Apply to change' }))
foreach ($bucket in @($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    Write-Host ('  {0,-29}: {1}' -f $bucket.Name, $bucket.Count) -ForegroundColor $(if ($bucket.Name -match 'Failed|NotFound|Ambiguous') { 'Yellow' } else { 'Gray' })
}
Write-Host ('  Results CSV                  : {0}' -f $OutputPath)
#endregion Main
