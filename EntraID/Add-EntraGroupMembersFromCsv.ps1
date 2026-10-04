<#
.SYNOPSIS
    Adds or removes Microsoft Entra ID group members in bulk from a CSV file.
.DESCRIPTION
    Reads a CSV with the columns GroupName (or GroupId) and UserPrincipalName (or MemberId), resolves each group and
    each user once through Microsoft Graph, and skips dynamic groups, groups synced from on-premises AD, duplicate rows
    and rows whose membership is already in the requested state. Remaining members are added with PATCH /groups/{id}
    (members@odata.bind, 20 per request) or, with -Remove, removed through DELETE /groups/{id}/members/{memberId}/$ref.
    Every change supports -WhatIf / -Confirm; a results CSV with one row per input row is written.
.PARAMETER CsvPath
    Input CSV with the columns GroupName or GroupId, plus UserPrincipalName or MemberId (object ID of a user, group,
    device or service principal). GroupName must match exactly one group.
.PARAMETER Remove
    Removes the listed members instead of adding them.
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\EntraGroupMembersFromCsv_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the result objects to the pipeline.
.EXAMPLE
    PS> .\Add-EntraGroupMembersFromCsv.ps1 -CsvPath .\pilot-users.csv -WhatIf
    Resolves every row and shows which members would be added to which groups without changing anything.
.EXAMPLE
    PS> .\Add-EntraGroupMembersFromCsv.ps1 -CsvPath .\leavers.csv -Remove -Confirm:$false -PassThru | Where-Object { $_.Result -eq 'Failed' }
    Removes the listed members without prompting and shows the rows that failed.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : GroupMember.ReadWrite.All, User.Read.All, Group.Read.All (delegated)
    Category    : Groups
    Changes     : Yes
    Notes       : Result values: Added, Removed, WhatIf, Failed or Skipped (reason). Dynamic and synced groups cannot be
                  edited in Entra ID; role-assignable groups also need the Privileged Role Administrator role. A rejected
                  batch marks all of its rows Failed; fix the input and re-run, members already added are skipped.
.LINK
    https://learn.microsoft.com/graph/api/group-post-members
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$CsvPath,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraGroupMembersFromCsv_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$rows = @(Import-Csv -Path $CsvPath)
if ($rows.Count -eq 0) { throw "The CSV '$CsvPath' contains no data rows." }
try { Connect-GraphIfNeeded -Scopes @('GroupMember.ReadWrite.All', 'User.Read.All', 'Group.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$groupSelect = 'id,displayName,groupTypes,onPremisesSyncEnabled'
$action = 'Add'
$doneState = 'Added'
$batchSize = 20
# members@odata.bind accepts at most 20 references per PATCH; removals have no batch endpoint, so they run as batches of one.
if ($Remove) { $action = 'Remove'; $doneState = 'Removed'; $batchSize = 1 }

# One result row per CSV row; rows are then processed group by group so each group is resolved and read only once.
$results = New-Object -TypeName System.Collections.Generic.List[object]
$rowNumber = 1
foreach ($row in $rows) {
    $rowNumber++
    $item = [PSCustomObject]@{ Row = $rowNumber; GroupName = ([string]$row.GroupName).Trim(); GroupId = ([string]$row.GroupId).Trim()
        Member = ([string]$row.UserPrincipalName).Trim(); MemberId = ([string]$row.MemberId).Trim(); Action = $action; Result = $null; Error = $null }
    if ([string]::IsNullOrWhiteSpace($item.Member)) { $item.Member = $item.MemberId }
    if ([string]::IsNullOrWhiteSpace($item.GroupName + $item.GroupId) -or [string]::IsNullOrWhiteSpace($item.Member)) { $item.Result = 'Skipped (empty row)' }
    $results.Add($item)
}
# Resolve every distinct UPN once up-front; rows that already carry a MemberId need no lookup.
$userIds = @{}
foreach ($upn in @($results | Where-Object { $null -eq $_.Result -and [string]::IsNullOrWhiteSpace($_.MemberId) } | ForEach-Object { $_.Member.ToLowerInvariant() } | Sort-Object -Unique)) {
    # EscapeDataString keeps guest UPNs that contain '#EXT#' valid in the request URL.
    try { $userIds[$upn] = (Invoke-MgGraphRequest -Method GET -Uri ('{0}/users/{1}?$select=id' -f $graphV1, [uri]::EscapeDataString($upn)) -OutputType PSObject -ErrorAction Stop).id }
    catch { Write-Warning "User '$upn' could not be resolved: $($_.Exception.Message)" }
    Start-Sleep -Milliseconds 200
}
$buckets = @($results | Where-Object { $null -eq $_.Result } | Group-Object -Property { ('{0}|{1}' -f $_.GroupName, $_.GroupId).ToLowerInvariant() })
$processed = 0
foreach ($bucket in $buckets) {
    $processed++
    $first = $bucket.Group[0]
    Write-Progress -Activity "$action group members" -Status "$processed of $($buckets.Count): $($first.GroupName)$($first.GroupId)" -PercentComplete (($processed / $buckets.Count) * 100)
    $group = $null
    try {
        $groupUri = "{0}/groups?`$filter=displayName eq '{1}'&`$select={2}" -f $graphV1, $first.GroupName.Replace("'", "''"), $groupSelect
        if (-not [string]::IsNullOrWhiteSpace($first.GroupId)) { $groupUri = '{0}/groups/{1}?$select={2}' -f $graphV1, $first.GroupId, $groupSelect }
        $hits = @(Invoke-GraphPaged -Uri $groupUri)
        if ($hits.Count -eq 1) { $group = $hits[0] } else { Write-Warning "'$($first.GroupName)' matches $($hits.Count) groups; use a GroupId column to target it." }
    }
    catch { Write-Warning "Group '$($first.GroupName)$($first.GroupId)' could not be read: $($_.Exception.Message)" }
    if ($null -eq $group) { foreach ($item in $bucket.Group) { $item.Result = 'Skipped (group not found)' }; continue }
    foreach ($item in $bucket.Group) { $item.GroupName = $group.displayName; $item.GroupId = $group.id }
    $skipReason = $null
    if (@($group.groupTypes) -contains 'DynamicMembership') { $skipReason = 'dynamic group' }
    elseif ($group.onPremisesSyncEnabled -eq $true) { $skipReason = 'synced from on-premises AD' }
    if ($null -ne $skipReason) {
        Write-Warning "'$($group.displayName)' is a $skipReason; its membership cannot be edited here, so its rows are skipped."
        foreach ($item in $bucket.Group) { $item.Result = "Skipped ($skipReason)" }; continue
    }
    $existing = @{}
    try { foreach ($member in (Invoke-GraphPaged -Uri ('{0}/groups/{1}/members?$select=id&$top=999' -f $graphV1, $group.id))) { $existing[$member.id] = $true } }
    catch { Write-Warning "Cannot read the members of '$($group.displayName)': $($_.Exception.Message)"; $existing = $null }
    if ($null -eq $existing) { foreach ($item in $bucket.Group) { $item.Result = 'Failed'; $item.Error = 'Current members could not be read' }; continue }
    $work = New-Object -TypeName System.Collections.Generic.List[object]
    foreach ($item in $bucket.Group) {
        if ([string]::IsNullOrWhiteSpace($item.MemberId) -and $userIds.ContainsKey($item.Member.ToLowerInvariant())) { $item.MemberId = $userIds[$item.Member.ToLowerInvariant()] }
        if ([string]::IsNullOrWhiteSpace($item.MemberId)) { $item.Result = 'Skipped (member not found)'; continue }
        if ($work.Count -gt 0 -and $work.MemberId -contains $item.MemberId) { $item.Result = 'Skipped (duplicate row)'; continue }
        if ($Remove -and -not $existing.ContainsKey($item.MemberId)) { $item.Result = 'Skipped (not a member)'; continue }
        if (-not $Remove -and $existing.ContainsKey($item.MemberId)) { $item.Result = 'Skipped (already a member)'; continue }
        $work.Add($item)
    }
    for ($i = 0; $i -lt $work.Count; $i += $batchSize) {
        $batch = @($work[$i..([math]::Min($i + $batchSize - 1, $work.Count - 1))])
        if (-not $PSCmdlet.ShouldProcess($group.displayName, "$action member(s): $($batch.Member -join ', ')")) { foreach ($item in $batch) { $item.Result = 'WhatIf' }; continue }
        try {
            if ($Remove) {
                Invoke-MgGraphRequest -Method DELETE -Uri ('{0}/groups/{1}/members/{2}/$ref' -f $graphV1, $group.id, $batch[0].MemberId) -ErrorAction Stop | Out-Null
            }
            else {
                $body = @{ 'members@odata.bind' = @($batch | ForEach-Object { '{0}/directoryObjects/{1}' -f $graphV1, $_.MemberId }) }
                Invoke-MgGraphRequest -Method PATCH -Uri ('{0}/groups/{1}' -f $graphV1, $group.id) -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
            }
            foreach ($item in $batch) { $item.Result = $doneState }
        }
        catch {
            foreach ($item in $batch) { $item.Result = 'Failed'; $item.Error = $_.Exception.Message }
            Write-Warning "$action of $($batch.Count) member(s) in '$($group.displayName)' failed: $($_.Exception.Message)"
        }
        Start-Sleep -Milliseconds 200
    }
}
Write-Progress -Activity "$action group members" -Completed
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Group member $($action.ToLower()) summary ($($results.Count) rows)" -ForegroundColor Cyan
foreach ($bucket in ($results | Group-Object -Property Result | Sort-Object -Property Name)) { Write-Host ('  {0,-34}: {1}' -f $bucket.Name, $bucket.Count) }
Write-Host ('  Results CSV: {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
