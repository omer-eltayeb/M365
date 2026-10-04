<#
.SYNOPSIS
    Compares the membership of two Microsoft Entra ID groups (or a group and a CSV list of UPNs) and can synchronise them.
.DESCRIPTION
    Reads the members of -ReferenceGroup and -DifferenceGroup (/members, or /transitiveMembers with -Transitive) through
    Microsoft Graph, or compares the reference group with a list of UPNs from -DifferenceCsv, and reports one row per
    member with Status OnlyInReference, OnlyInDifference or InBoth plus UserPrincipalName, DisplayName and MemberType.
    -Sync makes the difference group match the reference group (POST /groups/{id}/members/$ref, DELETE .../members/{id}/$ref).
.PARAMETER ReferenceGroup
    Display name (exact, or a wildcard that matches exactly one group) or object ID of the reference group.
.PARAMETER DifferenceGroup
    Display name or object ID of the group to compare with (and to change when -Sync is used).
.PARAMETER DifferenceCsv
    CSV file with a UserPrincipalName column, or a text file with one UPN per line, to compare the reference group with.
.PARAMETER Transitive
    Compares the flattened membership (members of nested groups included). Cannot be combined with -Sync.
.PARAMETER Sync
    Adds the OnlyInReference members to the difference group and removes its OnlyInDifference members.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraGroupMembershipCompare_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the comparison rows to the pipeline.
.EXAMPLE
    PS> .\Compare-EntraGroupMembership.ps1 -ReferenceGroup 'SG-Finance' -DifferenceCsv .\hr-finance.csv -Transitive -PassThru | Where-Object { $_.Status -ne 'InBoth' }
    Shows where the flattened group membership drifts from the HR list; the list is matched by UPN, so no user lookups are needed.
.EXAMPLE
    PS> .\Compare-EntraGroupMembership.ps1 -ReferenceGroup 'SG-Template' -DifferenceGroup 'SG-NewTeam' -Sync -WhatIf
    Shows which members would be added to and removed from SG-NewTeam to mirror SG-Template; without -WhatIf each change is confirmed.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : GroupMember.Read.All; GroupMember.ReadWrite.All with -Sync (delegated)
    Category    : Groups
    Changes     : Optional (-Sync)
    Notes       : Two groups are matched by object ID; a CSV list is matched by UPN, so non-user members of the reference
                  group always appear as OnlyInReference. -Sync changes direct membership only (no -Transitive), refuses
                  dynamic and on-premises synced targets and needs Privileged Role Administrator for role-assignable groups.
.LINK
    https://learn.microsoft.com/graph/api/group-list-transitivemembers
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Group')]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReferenceGroup,

    [Parameter(Mandatory = $true, ParameterSetName = 'Group')]
    [string]$DifferenceGroup,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$DifferenceCsv,

    [Parameter()]
    [switch]$Transitive,

    [Parameter(ParameterSetName = 'Group')]
    [switch]$Sync,

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

function Resolve-SingleGroup {
    <# Resolves a display name (exact, or a wildcard matched client-side because Graph has no wildcard filter) or an object ID to exactly one group. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )
    $select = 'id,displayName,groupTypes,onPremisesSyncEnabled'
    $uri = "{0}/groups?`$filter=displayName eq '{1}'&`$select={2}" -f $script:GraphV1, $Identity.Replace("'", "''"), $select
    if ($Identity -match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') { $uri = '{0}/groups/{1}?$select={2}' -f $script:GraphV1, $Identity, $select }
    elseif ($Identity -match '[\*\?]') { $uri = '{0}/groups?$select={1}&$top=999' -f $script:GraphV1, $select }
    $hits = @(Invoke-GraphPaged -Uri $uri)
    if ($Identity -match '[\*\?]') { $hits = @($hits | Where-Object { $_.displayName -like $Identity }) }
    if ($hits.Count -ne 1) { throw "'$Identity' resolved to $($hits.Count) groups; use an exact display name or the object ID." }
    return $hits[0]
}
#endregion Helpers

#region Main
if ($Sync -and $Transitive) { throw '-Sync changes direct membership only and cannot be combined with -Transitive.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraGroupMembershipCompare_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('GroupMember.Read.All')
if ($Sync) { $scopes += 'GroupMember.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $scopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }
$script:GraphV1 = 'https://graph.microsoft.com/v1.0'
$memberUri = '{0}/groups/{1}/members?$select=id,displayName,userPrincipalName,mail&$top=999'
if ($Transitive) { $memberUri = $memberUri.Replace('/members?', '/transitiveMembers?') }
# Two groups are matched by object ID; a CSV list only carries UPNs, so the reference members are keyed by UPN instead.
$keyProperty = @{ Group = 'id'; Csv = 'userPrincipalName' }[$PSCmdlet.ParameterSetName]
$referenceMembers = @{}
$differenceMembers = @{}
try {
    $reference = Resolve-SingleGroup -Identity $ReferenceGroup
    foreach ($member in (Invoke-GraphPaged -Uri ($memberUri -f $script:GraphV1, $reference.id))) {
        $key = [string]$member.$keyProperty; if ([string]::IsNullOrEmpty($key)) { $key = $member.id }
        $referenceMembers[$key.ToLowerInvariant()] = $member
    }
    if ($PSCmdlet.ParameterSetName -eq 'Group') {
        $difference = Resolve-SingleGroup -Identity $DifferenceGroup
        $differenceName = $difference.displayName
        foreach ($member in (Invoke-GraphPaged -Uri ($memberUri -f $script:GraphV1, $difference.id))) { $differenceMembers[$member.id.ToLowerInvariant()] = $member }
    }
}
catch { throw "Failed to read the groups to compare: $($_.Exception.Message)" }
$lockedTarget = $Sync -and (@($difference.groupTypes) -contains 'DynamicMembership' -or $difference.onPremisesSyncEnabled -eq $true)
if ($lockedTarget) { throw "'$differenceName' is a dynamic or on-premises synced group; its membership cannot be changed in Entra ID." }
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $differenceName = Split-Path -Path $DifferenceCsv -Leaf
    if ((Get-Content -Path $DifferenceCsv -TotalCount 1) -match 'UserPrincipalName') { $upns = @(Import-Csv -Path $DifferenceCsv | ForEach-Object { $_.UserPrincipalName }) }
    else { $upns = @(Get-Content -Path $DifferenceCsv) }
    foreach ($upn in @($upns | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '@' })) {
        $differenceMembers[$upn.ToLowerInvariant()] = [PSCustomObject]@{ id = $null; displayName = $null; userPrincipalName = $upn; mail = $null; '@odata.type' = '#microsoft.graph.user' }
    }
}
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($key in @(@($referenceMembers.Keys) + @($differenceMembers.Keys) | Sort-Object -Unique)) {
    $status = 'InBoth'; $member = $referenceMembers[$key]
    if (-not $differenceMembers.ContainsKey($key)) { $status = 'OnlyInReference' }
    elseif (-not $referenceMembers.ContainsKey($key)) { $status = 'OnlyInDifference'; $member = $differenceMembers[$key] }
    $rows.Add([PSCustomObject]@{ Status = $status; UserPrincipalName = $member.userPrincipalName; DisplayName = $member.displayName; Mail = $member.mail
        MemberType = (([string]$member.'@odata.type') -replace '^#microsoft\.graph\.', ''); MemberId = $member.id
        ReferenceGroup = $reference.displayName; DifferenceGroup = $differenceName; SyncResult = $null })
}
if ($Sync) {
    $membersUri = '{0}/groups/{1}/members' -f $script:GraphV1, $difference.id
    foreach ($row in @($rows | Where-Object { $_.Status -ne 'InBoth' })) {
        $verb = @{ OnlyInReference = 'Add'; OnlyInDifference = 'Remove' }[$row.Status]
        $label = ('{0} {1}' -f $row.UserPrincipalName, $row.DisplayName).Trim()
        if (-not $PSCmdlet.ShouldProcess($differenceName, "$verb member $label")) { $row.SyncResult = 'WhatIf'; continue }
        try {
            if ($verb -eq 'Add') {
                $body = @{ '@odata.id' = '{0}/directoryObjects/{1}' -f $script:GraphV1, $row.MemberId }
                Invoke-MgGraphRequest -Method POST -Uri "$membersUri/`$ref" -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
            }
            else { Invoke-MgGraphRequest -Method DELETE -Uri "$membersUri/$($row.MemberId)/`$ref" -ErrorAction Stop | Out-Null }
            $row.SyncResult = @{ Add = 'Added'; Remove = 'Removed' }[$verb]
        }
        catch { $row.SyncResult = 'Failed'; Write-Warning "Could not $($verb.ToLower()) '$label': $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 200
    }
}
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ("Membership comparison: '{0}' vs '{1}' -> {2}" -f $reference.displayName, $differenceName, $OutputPath) -ForegroundColor Cyan
foreach ($status in 'OnlyInReference', 'OnlyInDifference', 'InBoth') { Write-Host ('  {0,-17}: {1}' -f $status, @($rows | Where-Object { $_.Status -eq $status }).Count) }
foreach ($bucket in @($rows.SyncResult | Where-Object { $_ } | Group-Object)) { Write-Host ('  Sync {0,-12}: {1}' -f $bucket.Name, $bucket.Count) -ForegroundColor Yellow }
if ($PassThru) { $rows }
#endregion Main
