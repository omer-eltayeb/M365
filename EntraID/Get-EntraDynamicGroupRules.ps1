<#
.SYNOPSIS
    Reports every dynamic membership group in Microsoft Entra ID with its rule, processing state and last evaluation status.
.DESCRIPTION
    Lists groups with $filter=groupTypes/any(c:c eq 'DynamicMembership') through Microsoft Graph and reports the display
    name, membership rule, processing state (On / Paused) and, from the beta membershipRuleProcessingStatus property, the
    last evaluation status, timestamp and error message. -IncludeCounts adds the member count, -TestUser evaluates one
    user against every rule (POST /groups/{id}/evaluateDynamicMembership, beta) and -ExportRulesJson saves the rules as JSON.
.PARAMETER GroupName
    One or more group display names (exact, or a wildcard matched client-side). Default: every dynamic group.
.PARAMETER GroupId
    One or more group object IDs.
.PARAMETER IncludeCounts
    Adds MemberCount by calling /groups/{id}/members/$count for each group.
.PARAMETER TestUser
    User principal name to evaluate against each rule; adds the TestUserMatches column.
.PARAMETER ExportRulesJson
    Also writes GroupName, GroupId, MembershipRule and ProcessingState to a .json file with the same base name as the CSV.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraDynamicGroupRules_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraDynamicGroupRules.ps1 -IncludeCounts -ExportRulesJson
    Reports all dynamic groups with member counts and saves the rules as JSON for change tracking.
.EXAMPLE
    PS> .\Get-EntraDynamicGroupRules.ps1 -GroupName 'DYN-*' -TestUser 'jane.doe@contoso.com' -PassThru | Where-Object { -not $_.TestUserMatches }
    Shows which DYN- groups would not include Jane, which is the quickest way to troubleshoot a missing dynamic membership.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Group.Read.All, GroupMember.Read.All, User.Read.All (delegated)
    Category    : Groups
    Changes     : No
    Notes       : membershipRuleProcessingStatus and evaluateDynamicMembership exist only on the beta endpoint and may change.
                  Dynamic groups need Microsoft Entra ID P1; when the licence lapses processing stops and the status shows
                  the error. A status of 'Running' shortly after a rule change is normal. -TestUser issues one POST per group.
.LINK
    https://learn.microsoft.com/graph/api/group-evaluatedynamicmembership
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$GroupName,

    [Parameter()]
    [string[]]$GroupId,

    [Parameter()]
    [switch]$IncludeCounts,

    [Parameter()]
    [string]$TestUser,

    [Parameter()]
    [switch]$ExportRulesJson,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraDynamicGroupRules_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('Group.Read.All', 'GroupMember.Read.All', 'User.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$graphBeta = 'https://graph.microsoft.com/beta'
$select = 'id,displayName,groupTypes,membershipRule,membershipRuleProcessingState'
$listUri = "{0}/groups?`$filter=groupTypes/any(c:c eq 'DynamicMembership'){1}&`$select={2}&`$count=true&`$top=999"
$advancedQuery = @{ ConsistencyLevel = 'eventual' }
$groups = New-Object -TypeName System.Collections.Generic.List[object]
try {
    foreach ($id in @($GroupId | Where-Object { $_ })) {
        $groups.Add((Invoke-MgGraphRequest -Method GET -Uri ('{0}/groups/{1}?$select={2}' -f $graphV1, $id, $select) -OutputType PSObject -ErrorAction Stop))
    }
    foreach ($name in @($GroupName | Where-Object { $_ })) {
        # Exact names are filtered server-side; Graph has no wildcard filter for displayName, so patterns are matched client-side.
        $nameFilter = " and displayName eq '{0}'" -f $name.Replace("'", "''")
        $pattern = '*'
        if ($name -match '[\*\?]') { $nameFilter = ''; $pattern = $name }
        $hits = @(Invoke-GraphPaged -Uri ($listUri -f $graphV1, $nameFilter, $select) -Headers $advancedQuery | Where-Object { $_.displayName -like $pattern })
        if ($hits.Count -eq 0) { Write-Warning "No dynamic group matches '$name'." }
        foreach ($hit in $hits) { $groups.Add($hit) }
    }
    if (@($GroupId).Count -eq 0 -and @($GroupName).Count -eq 0) {
        foreach ($hit in (Invoke-GraphPaged -Uri ($listUri -f $graphV1, '', $select) -Headers $advancedQuery)) { $groups.Add($hit) }
    }
}
catch { throw "Failed to list dynamic groups: $($_.Exception.Message)" }
foreach ($other in @($groups | Where-Object { @($_.groupTypes) -notcontains 'DynamicMembership' })) { Write-Warning "'$($other.displayName)' is not a dynamic group and is skipped." }
$groups = @($groups | Where-Object { @($_.groupTypes) -contains 'DynamicMembership' } | Sort-Object -Property id -Unique)
if ($groups.Count -eq 0) { throw 'No dynamic groups matched the selection.' }
$testUserId = $null
if (-not [string]::IsNullOrWhiteSpace($TestUser)) {
    try { $testUserId = (Invoke-MgGraphRequest -Method GET -Uri ('{0}/users/{1}?$select=id' -f $graphV1, [uri]::EscapeDataString($TestUser)) -OutputType PSObject -ErrorAction Stop).id }
    catch { throw "Test user '$TestUser' could not be resolved: $($_.Exception.Message)" }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($group in $groups) {
    $processed++
    Write-Progress -Activity 'Reading dynamic groups' -Status "$processed of $($groups.Count): $($group.displayName)" -PercentComplete (($processed / $groups.Count) * 100)
    # beta: membershipRuleProcessingStatus (last evaluation result, time and error) is not exposed on v1.0.
    $status = $null
    $statusUri = '{0}/groups/{1}?$select=membershipRuleProcessingStatus' -f $graphBeta, $group.id
    try { $status = (Invoke-MgGraphRequest -Method GET -Uri $statusUri -OutputType PSObject -ErrorAction Stop).membershipRuleProcessingStatus }
    catch { Write-Warning "Processing status of '$($group.displayName)' could not be read: $($_.Exception.Message)" }
    $memberCount = $null
    if ($IncludeCounts) {
        # /$count returns a plain number and needs ConsistencyLevel=eventual.
        $countUri = '{0}/groups/{1}/members/$count' -f $graphV1, $group.id
        try { $memberCount = [int](([string](Invoke-MgGraphRequest -Method GET -Uri $countUri -Headers $advancedQuery -ErrorAction Stop)).Trim()) }
        catch { Write-Warning "Member count of '$($group.displayName)' could not be read: $($_.Exception.Message)" }
    }
    $testMatches = $null
    if ($null -ne $testUserId) {
        # beta: evaluateDynamicMembership has no v1.0 equivalent.
        $evaluateUri = '{0}/groups/{1}/evaluateDynamicMembership' -f $graphBeta, $group.id
        try {
            $evaluation = Invoke-MgGraphRequest -Method POST -Uri $evaluateUri -Body @{ memberId = $testUserId } -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
            $testMatches = [bool]$evaluation.membershipRuleEvaluationResult
        }
        catch { Write-Warning "Rule evaluation for '$($group.displayName)' failed: $($_.Exception.Message)" }
    }
    $lastUpdated = $null
    if ($null -ne $status.lastMembershipUpdated) { $lastUpdated = [datetime]$status.lastMembershipUpdated }
    $groupType = 'Security'
    if (@($group.groupTypes) -contains 'Unified') { $groupType = 'Microsoft 365' }
    $results.Add([PSCustomObject]@{ GroupName = $group.displayName; GroupId = $group.id; GroupType = $groupType; MembershipRule = $group.membershipRule
        ProcessingState = $group.membershipRuleProcessingState; ProcessingStatus = $status.status; LastMembershipUpdated = $lastUpdated
        ProcessingError = $status.errorMessage; MemberCount = $memberCount; TestUser = $TestUser; TestUserMatches = $testMatches })
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading dynamic groups' -Completed

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($ExportRulesJson) {
    $jsonPath = [System.IO.Path]::ChangeExtension($OutputPath, '.json')
    ConvertTo-Json -InputObject @($results | Select-Object -Property GroupName, GroupId, MembershipRule, ProcessingState) -Depth 3 | Set-Content -Path $jsonPath -Encoding UTF8
}
Write-Host ('Dynamic group rules ({0} groups)' -f $results.Count) -ForegroundColor Cyan
Write-Host ('  Processing paused   : {0}' -f @($results | Where-Object { $_.ProcessingState -eq 'Paused' }).Count) -ForegroundColor Yellow
Write-Host ('  Last run with error : {0}' -f @($results | Where-Object { -not [string]::IsNullOrEmpty($_.ProcessingError) }).Count) -ForegroundColor Yellow
if ($null -ne $testUserId) { Write-Host ('  Rules matching user : {0} of {1}' -f @($results | Where-Object { $_.TestUserMatches -eq $true }).Count, $results.Count) }
Write-Host ('  Report              : {0}' -f $OutputPath)
if ($ExportRulesJson) { Write-Host ('  Rules JSON          : {0}' -f $jsonPath) }
if ($PassThru) { $results }
#endregion Main
