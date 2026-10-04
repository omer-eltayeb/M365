<#
.SYNOPSIS
    Finds groups without owners and/or without members, and can assign an owner to the ownerless ones.
.DESCRIPTION
    Lists every group through Microsoft Graph (GET /groups) and reads the owner and member counts of each group through
    the /groups/{id}/owners/$count and /groups/{id}/members/$count endpoints (ConsistencyLevel=eventual). Groups with
    zero owners and/or zero members are reported with a Finding of Ownerless, Empty or OwnerlessAndEmpty. Dynamic groups
    are still checked for owners but are not reported as Empty unless -IncludeDynamic is used, because their membership
    is calculated by the rule. Groups synchronised from on-premises AD are skipped by default (their owners and members
    are managed on-premises). With -AddOwner the given user is added as owner of every ownerless cloud group.
.PARAMETER IncludeDynamic
    Also reports dynamic groups with zero members as Empty.
.PARAMETER ExcludeOnPremSynced
    Skips groups with onPremisesSyncEnabled eq true. Default $true; pass -ExcludeOnPremSynced:$false to include them.
.PARAMETER AddOwner
    User principal name of the user to add as owner (POST /groups/{id}/owners/$ref) to every ownerless group.
    Honours -WhatIf / -Confirm. Distribution lists and mail-enabled security groups are skipped (owners are managed in
    Exchange Online), as are synchronised groups.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraOwnerlessEmptyGroups_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraOwnerlessAndEmptyGroups.ps1
    Reports every cloud group that has no owner and/or no members.
.EXAMPLE
    PS> .\Get-EntraOwnerlessAndEmptyGroups.ps1 -IncludeDynamic -ExcludeOnPremSynced:$false -OutputPath C:\Temp\groups.csv
    Includes dynamic groups with zero members and synchronised groups in the report.
.EXAMPLE
    PS> .\Get-EntraOwnerlessAndEmptyGroups.ps1 -AddOwner it-admin@contoso.com -WhatIf
    Shows which ownerless groups would receive the IT admin account as owner, without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All and GroupMember.Read.All for the report. Group.ReadWrite.All and User.ReadBasic.All are
                  requested only with -AddOwner (the signed-in user also needs the Groups Administrator role).
    Category    : Groups
    Changes     : Optional (-AddOwner)
    Notes       : Two /$count calls are made per group, so a tenant with 5,000 groups takes roughly 20 minutes. For
                  Microsoft 365 groups the new owner should normally also be a member (Teams expects owners to be
                  members); add the membership separately if required.
.LINK
    https://learn.microsoft.com/graph/api/group-list-owners
.LINK
    https://learn.microsoft.com/graph/api/group-post-owners
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [switch]$IncludeDynamic,

    [Parameter()]
    [bool]$ExcludeOnPremSynced = $true,

    [Parameter()]
    [ValidatePattern('^[^@\s]+@[^@\s]+$')]
    [string]$AddOwner,

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

function Get-GraphCount {
    <# Reads a /$count endpoint (advanced query, needs ConsistencyLevel=eventual) and returns the value as [int]. #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers @{ 'ConsistencyLevel' = 'eventual' } -ErrorAction Stop
    return [int](([string]$response).Trim())
}

function Get-GroupTypeName {
    <# Derives the admin-centre style group type (with a "Dynamic" prefix for rule-based groups) from the Graph flags. #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Group
    )
    $groupTypes = @($Group.groupTypes)
    if ($groupTypes -contains 'Unified') { $typeName = 'Microsoft 365' }
    elseif ($Group.mailEnabled -and $Group.securityEnabled) { $typeName = 'Mail-enabled security' }
    elseif ($Group.securityEnabled) { $typeName = 'Security' }
    else { $typeName = 'Distribution' }
    if ($groupTypes -contains 'DynamicMembership') { $typeName = 'Dynamic ' + $typeName }
    return $typeName
}
#endregion Helpers

#region Main
$requiredScopes = @('Group.Read.All', 'GroupMember.Read.All')
$addOwnerRequested = -not [string]::IsNullOrWhiteSpace($AddOwner)
if ($addOwnerRequested) { $requiredScopes += @('Group.ReadWrite.All', 'User.ReadBasic.All') }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraOwnerlessEmptyGroups_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes $requiredScopes
}
catch {
    throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0'
$newOwner = $null
if ($addOwnerRequested) {
    try {
        $newOwner = Invoke-MgGraphRequest -Method GET -Uri ('{0}/users/{1}?$select=id,userPrincipalName' -f $graphV1, [uri]::EscapeDataString($AddOwner)) -OutputType PSObject -ErrorAction Stop
    }
    catch {
        throw "The owner account '$AddOwner' could not be found: $($_.Exception.Message)"
    }
}

Write-Verbose 'Retrieving groups.'
try {
    $groups = Invoke-GraphPaged -Uri ('{0}/groups?$select=id,displayName,mail,groupTypes,mailEnabled,securityEnabled,onPremisesSyncEnabled,visibility,createdDateTime,resourceProvisioningOptions&$top=999' -f $graphV1)
}
catch {
    throw "Failed to list groups: $($_.Exception.Message)"
}
Write-Verbose "Checking owners and members of $($groups.Count) groups."

$results = New-Object -TypeName System.Collections.Generic.List[object]
$evaluated = 0
$processed = 0
foreach ($group in $groups) {
    $processed++
    Write-Progress -Activity 'Reading owner and member counts' -Status "$processed of $($groups.Count): $($group.displayName)" -PercentComplete (($processed / $groups.Count) * 100)
    if ($ExcludeOnPremSynced -and $group.onPremisesSyncEnabled -eq $true) { continue }
    $evaluated++
    try {
        $ownerCount = Get-GraphCount -Uri ('{0}/groups/{1}/owners/$count' -f $graphV1, $group.id)
        $memberCount = Get-GraphCount -Uri ('{0}/groups/{1}/members/$count' -f $graphV1, $group.id)
        Start-Sleep -Milliseconds 200
    }
    catch {
        Write-Warning "Could not read counts for '$($group.displayName)': $($_.Exception.Message)"
        continue
    }

    $isDynamic = (@($group.groupTypes) -contains 'DynamicMembership')
    $isOwnerless = ($ownerCount -eq 0)
    $isEmpty = ($memberCount -eq 0 -and ($IncludeDynamic -or -not $isDynamic))
    if (-not $isOwnerless -and -not $isEmpty) { continue }
    $finding = 'Ownerless'
    if ($isEmpty) { $finding = 'Empty' }
    if ($isOwnerless -and $isEmpty) { $finding = 'OwnerlessAndEmpty' }

    $results.Add([PSCustomObject]@{
        DisplayName           = $group.displayName
        GroupType             = Get-GroupTypeName -Group $group
        Finding               = $finding
        OwnerCount            = $ownerCount
        MemberCount           = $memberCount
        IsDynamic             = $isDynamic
        IsTeam                = (@($group.resourceProvisioningOptions) -contains 'Team')
        Mail                  = $group.mail
        Visibility            = $group.visibility
        OnPremisesSyncEnabled = ($group.onPremisesSyncEnabled -eq $true)
        CreatedDateTime       = $group.createdDateTime
        ActionTaken           = 'None'
        Id                    = $group.id
    })
}
Write-Progress -Activity 'Reading owner and member counts' -Completed

if ($null -ne $newOwner) {
    $ownerReference = @{ '@odata.id' = ('{0}/users/{1}' -f $graphV1, $newOwner.id) }
    foreach ($row in @($results | Where-Object { $_.OwnerCount -eq 0 })) {
        if ($row.OnPremisesSyncEnabled) { $row.ActionTaken = 'SkippedSynced'; continue }
        # Distribution lists and mail-enabled security groups are read-only in Graph; their owners live in Exchange Online.
        if ($row.GroupType -like '*Distribution' -or $row.GroupType -like '*Mail-enabled security') { $row.ActionTaken = 'SkippedExchangeManaged'; continue }
        if (-not $PSCmdlet.ShouldProcess($row.DisplayName, "Add owner $($newOwner.userPrincipalName)")) { continue }
        try {
            Invoke-MgGraphRequest -Method POST -Uri ('{0}/groups/{1}/owners/$ref' -f $graphV1, $row.Id) -Body $ownerReference -ContentType 'application/json' -ErrorAction Stop | Out-Null
            $row.ActionTaken = 'OwnerAdded'
            Start-Sleep -Milliseconds 200
        }
        catch {
            $row.ActionTaken = 'Failed'
            Write-Warning "Adding owner to '$($row.DisplayName)' failed: $($_.Exception.Message)"
        }
    }
}

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No ownerless or empty groups were found; no CSV was written.'
}

Write-Host ''
Write-Host 'Ownerless and empty group summary' -ForegroundColor Cyan
Write-Host ('  Groups in tenant  : {0}' -f $groups.Count)
Write-Host ('  Groups evaluated  : {0}' -f $evaluated)
Write-Host ('  Groups flagged    : {0}' -f $results.Count) -ForegroundColor Yellow
foreach ($bucket in ($results | Group-Object -Property Finding | Sort-Object -Property Name)) {
    Write-Host ('    {0,-18}: {1}' -f $bucket.Name, $bucket.Count)
}
if ($null -ne $newOwner) {
    foreach ($bucket in ($results | Group-Object -Property ActionTaken | Sort-Object -Property Name)) {
        Write-Host ('    Action {0,-11}: {1}' -f $bucket.Name, $bucket.Count)
    }
}
Write-Host ('  Report            : {0}' -f $OutputPath)

if ($PassThru) {
    $results
}
#endregion Main
