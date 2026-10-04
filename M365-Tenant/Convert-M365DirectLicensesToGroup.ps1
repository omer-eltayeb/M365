<#
.SYNOPSIS
    Migrates direct license assignments of one SKU to group-based licensing without interrupting the users' service.
.DESCRIPTION
    Resolves -Sku against /subscribedSkus and -GroupName against /groups (verifying that the group really assigns that SKU),
    then reads every user holding the SKU (/users filtered on assignedLicenses) with licenseAssignmentStates plus the group
    members. Per user with a direct assignment the Action is RemoveDirect (group assignment already Active, no interruption),
    AddToGroup (not a member; done with -AddMissingMembers), WaitForGroupProcessing (member, group assignment still pending) or
    FixGroupAssignment (group assignment in error). Report-only by default; -Remove posts /users/{id}/assignLicense removals.
.PARAMETER Sku
    SKU part number (for example SPE_E3) or SKU id to migrate.
.PARAMETER GroupName
    Display name of the group that already assigns the SKU (must be unique).
.PARAMETER AddMissingMembers
    Add users who only hold the SKU directly to the group (POST members/$ref). Group licensing is asynchronous: re-run later.
.PARAMETER Remove
    Remove the direct assignment for users whose group assignment of the same SKU is Active.
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\M365DirectToGroupMigration_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\Convert-M365DirectLicensesToGroup.ps1 -Sku SPE_E3 -GroupName 'LIC-M365-E3'
    Reports, per user, whether the direct E3 assignment can be removed now, needs group membership first, or must wait.
.EXAMPLE
    PS> .\Convert-M365DirectLicensesToGroup.ps1 -Sku SPE_E3 -GroupName 'LIC-M365-E3' -AddMissingMembers -Remove -Confirm:$false
    Adds missing users to the group, removes direct assignments where the group path is Active; re-run later for the new members.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, Group.Read.All, Organization.Read.All (delegated) for the report; -Remove adds User.ReadWrite.All,
                  -AddMissingMembers adds Group.ReadWrite.All. License Administrator plus Groups Administrator (or owner of the group).
    Category    : Licensing
    Changes     : Optional (-Remove, -AddMissingMembers)
    Notes       : A direct assignment is removed ONLY when the same user's group assignment state is Active, so the license never
                  drops. If the direct assignment disabled other service plans than the group, the group's plan set wins after the
                  removal - check PlanConfigDiffers first. Nested groups are not supported by group-based licensing (Entra ID P1).
.LINK
    https://learn.microsoft.com/entra/identity/users/licensing-groups-migrate-users
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$Sku,

    [Parameter(Mandatory = $true)]
    [string]$GroupName,

    [Parameter()]
    [switch]$AddMissingMembers,

    [Parameter()]
    [switch]$Remove,

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
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365DirectToGroupMigration_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('User.Read.All', 'Group.Read.All', 'Organization.Read.All')
if ($Remove) { $scopes += 'User.ReadWrite.All' }; if ($AddMissingMembers) { $scopes += 'Group.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try {
    $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber')
    $groupFilter = [uri]::EscapeDataString(("displayName eq '{0}'" -f $GroupName.Replace("'", "''")))
    $groups = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/groups?$filter={0}&$select=id,displayName,assignedLicenses' -f $groupFilter))
}
catch { throw "Failed to read subscribed SKUs or the group: $($_.Exception.Message)" }
$skuInfo = $skus | Where-Object { $_.skuPartNumber -eq $Sku -or [string]$_.skuId -eq $Sku } | Select-Object -First 1
if ($null -eq $skuInfo) { throw "SKU '$Sku' was not found in /subscribedSkus." }
if ($groups.Count -ne 1) { throw "Expected exactly one group named '$GroupName' but found $($groups.Count)." }
$group = $groups[0]
$skuId = [string]$skuInfo.skuId
$groupAssignsSku = @($group.assignedLicenses | Where-Object { [string]$_.skuId -eq $skuId }).Count -gt 0
if (-not $groupAssignsSku) { throw "Group '$($group.displayName)' does not assign $($skuInfo.skuPartNumber); configure group-based licensing on it first." }
try {
    $memberIds = @{}
    foreach ($member in @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/groups/{0}/members?$select=id&$top=999' -f $group.id))) { $memberIds[[string]$member.id] = $true }
    $userSelect = 'id,displayName,userPrincipalName,licenseAssignmentStates'
    $usersUri = 'https://graph.microsoft.com/v1.0/users?$filter=assignedLicenses/any(s:s/skuId eq {0})&$count=true&$top=999&$select={1}' -f $skuId, $userSelect
    $users = @(Invoke-GraphPaged -Uri $usersUri -Headers @{ ConsistencyLevel = 'eventual' })
}
catch { throw "Failed to read group members or users holding the SKU: $($_.Exception.Message)" }
Write-Verbose "$($users.Count) users hold $($skuInfo.skuPartNumber); group '$($group.displayName)' has $($memberIds.Count) members."
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($user in $users) {
    $counter++
    Write-Progress -Activity 'Evaluating direct assignments' -Status "$counter of $($users.Count)" -PercentComplete ([int](($counter / $users.Count) * 100))
    $states = @($user.licenseAssignmentStates | Where-Object { [string]$_.skuId -eq $skuId })
    $direct = $states | Where-Object { [string]::IsNullOrEmpty($_.assignedByGroup) } | Select-Object -First 1
    if ($null -eq $direct) { continue }
    $groupState = $states | Where-Object { [string]$_.assignedByGroup -eq [string]$group.id } | Select-Object -First 1
    $isMember = $memberIds.ContainsKey([string]$user.id)
    $groupStateText = 'None'
    if ($null -ne $groupState) { $groupStateText = (@([string]$groupState.state, [string]$groupState.error) | Where-Object { $_ -and $_ -ne 'None' }) -join ':' }
    $action = 'WaitForGroupProcessing'
    if ($null -ne $groupState -and $groupState.state -eq 'Active') { $action = 'RemoveDirect' }
    elseif ($null -ne $groupState) { $action = 'FixGroupAssignment' }
    elseif (-not $isMember) { $action = 'AddToGroup' }
    $directPlans = @($direct.disabledPlans | Where-Object { $null -ne $_ } | Sort-Object)
    $groupPlans = @($groupState.disabledPlans | Where-Object { $null -ne $_ } | Sort-Object)
    $row = [PSCustomObject]@{
        UserPrincipalName       = $user.userPrincipalName
        DisplayName             = $user.displayName
        Sku                     = $skuInfo.skuPartNumber
        IsGroupMember           = $isMember
        GroupAssignmentState    = $groupStateText
        DirectDisabledPlanCount = $directPlans.Count
        GroupDisabledPlanCount  = $groupPlans.Count
        PlanConfigDiffers       = (($null -ne $groupState) -and (($directPlans -join ',') -ne ($groupPlans -join ',')))
        Action                  = $action
        Result                  = 'ReportOnly'
    }
    $rows.Add($row)
    if ($action -eq 'AddToGroup' -and $AddMissingMembers) {
        if (-not $PSCmdlet.ShouldProcess($user.userPrincipalName, "Add to group '$($group.displayName)'")) { continue }
        try {
            $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.id)" } | ConvertTo-Json
            Invoke-MgGraphRequest -Method POST -Uri ('https://graph.microsoft.com/v1.0/groups/{0}/members/$ref' -f $group.id) -Body $body -ContentType 'application/json' | Out-Null
            $row.Result = 'AddedToGroup'
        }
        catch { $row.Result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not add $($user.userPrincipalName) to the group: $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 200
    }
    elseif ($action -eq 'RemoveDirect' -and $Remove) {
        if (-not $PSCmdlet.ShouldProcess($user.userPrincipalName, "Remove direct $($skuInfo.skuPartNumber) assignment (group assignment is Active)")) { continue }
        try {
            $body = @{ addLicenses = @(); removeLicenses = @($skuId) } | ConvertTo-Json
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/assignLicense" -Body $body -ContentType 'application/json' | Out-Null
            $row.Result = 'DirectRemoved'
        }
        catch { $row.Result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not remove the direct assignment of $($user.userPrincipalName): $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 200
    }
}
Write-Progress -Activity 'Evaluating direct assignments' -Completed
$output = @($rows | Sort-Object -Property Action, UserPrincipalName)
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ('Direct-to-group migration for {0} via {1}' -f $skuInfo.skuPartNumber, $group.displayName) -ForegroundColor Cyan
Write-Host ('  Users holding the SKU / direct : {0} / {1}' -f $users.Count, $output.Count)
foreach ($actionGroup in ($output | Group-Object -Property Action | Sort-Object -Property Name)) { Write-Host ('    {0,-24} {1,6}' -f $actionGroup.Name, $actionGroup.Count) }
Write-Host ('  Plan configuration differs     : {0}' -f @($output | Where-Object { $_.PlanConfigDiffers }).Count) -ForegroundColor Yellow
$changed = @($output | Where-Object { $_.Result -ne 'ReportOnly' } | Group-Object -Property Result | Sort-Object -Property Name)
foreach ($resultGroup in $changed) { Write-Host ('    {0,-24} {1,6}' -f $resultGroup.Name, $resultGroup.Count) }
if (-not $Remove) { Write-Host '  Report-only run: add -Remove to delete direct assignments where the group path is Active.' -ForegroundColor Yellow }
Write-Host ('  Results CSV                    : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
