<#
.SYNOPSIS
    Reports Microsoft Entra ID groups (and Teams) that contain guest users, with guest counts, guest domains and owners.
.DESCRIPTION
    Lists the groups in scope through Microsoft Graph (all groups, -GroupName / -GroupId, or -OnlyTeams via
    resourceProvisioningOptions/Any(x:x eq 'Team')) and reads the guest members of each one with
    /groups/{id}/members/microsoft.graph.user?$filter=userType eq 'Guest' (ConsistencyLevel=eventual, $count=true). Groups
    with at least one guest become one row with GuestCount, GuestDomains, IsTeam, Visibility and (-IncludeOwners) the owner
    UPNs; -Detailed writes one row per guest instead. The console summary shows the most common external domains.
.PARAMETER GroupName
    One or more group display names (exact, or a wildcard matched client-side). Default: every group in the tenant.
.PARAMETER GroupId
    One or more group object IDs.
.PARAMETER OnlyTeams
    Restricts the report to Microsoft 365 groups that back a Microsoft Teams team.
.PARAMETER IncludeOwners
    Adds the Owners column (owner user principal names) at the cost of one extra request per group with guests.
.PARAMETER Detailed
    Writes one row per guest (GuestDisplayName, GuestMail, GuestUserPrincipalName, GuestDomain) instead of one row per group.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraGroupsWithGuests_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report rows to the pipeline.
.EXAMPLE
    PS> .\Get-EntraGroupsWithGuests.ps1 -OnlyTeams -IncludeOwners
    Lists every team that has guest members together with the guest domains and the team owners to contact.
.EXAMPLE
    PS> .\Get-EntraGroupsWithGuests.ps1 -GroupName 'Project-*' -Detailed -PassThru | Group-Object -Property GuestDomain | Sort-Object -Property Count -Descending
    Shows which external domains have access to the project groups, one guest per row.
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
    Notes       : One request is made per group (two with -IncludeOwners), so scanning 5,000 groups takes about 20 minutes;
                  use -OnlyTeams or -GroupName to narrow the scope. Only direct guest members are counted (nested groups are
                  not expanded). The guest domain comes from the mail address, falling back to the #EXT# part of the UPN.
.LINK
    https://learn.microsoft.com/graph/api/group-list-members
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
    [switch]$OnlyTeams,

    [Parameter()]
    [switch]$IncludeOwners,

    [Parameter()]
    [switch]$Detailed,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraGroupsWithGuests_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('Group.Read.All', 'GroupMember.Read.All', 'User.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$advancedQuery = @{ ConsistencyLevel = 'eventual' }
$groupSelect = 'id,displayName,visibility,mail,resourceProvisioningOptions'
$groups = New-Object -TypeName System.Collections.Generic.List[object]
try {
    foreach ($id in @($GroupId | Where-Object { $_ })) {
        $groups.Add((Invoke-MgGraphRequest -Method GET -Uri ('{0}/groups/{1}?$select={2}' -f $graphV1, $id, $groupSelect) -OutputType PSObject -ErrorAction Stop))
    }
    foreach ($name in @($GroupName | Where-Object { $_ })) {
        # Graph has no wildcard filter for displayName, so patterns are matched client-side against all groups.
        $uri = "{0}/groups?`$filter=displayName eq '{1}'&`$select={2}" -f $graphV1, $name.Replace("'", "''"), $groupSelect
        $pattern = '*'
        if ($name -match '[\*\?]') { $uri = '{0}/groups?$select={1}&$top=999' -f $graphV1, $groupSelect; $pattern = $name }
        $hits = @(Invoke-GraphPaged -Uri $uri | Where-Object { $_.displayName -like $pattern })
        if ($hits.Count -eq 0) { Write-Warning "No group matches '$name'." }
        foreach ($hit in $hits) { $groups.Add($hit) }
    }
    if (@($GroupId).Count -eq 0 -and @($GroupName).Count -eq 0) {
        $uri = '{0}/groups?$select={1}&$top=999' -f $graphV1, $groupSelect
        if ($OnlyTeams) { $uri = "{0}/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$select={1}&`$top=999" -f $graphV1, $groupSelect }
        foreach ($hit in (Invoke-GraphPaged -Uri $uri)) { $groups.Add($hit) }
    }
}
catch { throw "Failed to resolve the groups to scan: $($_.Exception.Message)" }
$groups = @($groups | Sort-Object -Property id -Unique)
if ($OnlyTeams) { $groups = @($groups | Where-Object { @($_.resourceProvisioningOptions) -contains 'Team' }) }
if ($groups.Count -eq 0) { throw 'No groups matched the selection.' }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$guestIds = @{}
$processed = 0
foreach ($group in $groups) {
    $processed++
    Write-Progress -Activity 'Scanning groups for guests' -Status "$processed of $($groups.Count): $($group.displayName)" -PercentComplete (($processed / $groups.Count) * 100)
    # Casting members to user and filtering on userType is an advanced query (ConsistencyLevel=eventual + $count=true).
    $guestUri = "{0}/groups/{1}/members/microsoft.graph.user?`$filter=userType eq 'Guest'&`$count=true&`$select=id,displayName,mail,userPrincipalName&`$top=999" -f $graphV1, $group.id
    try { $guests = @(Invoke-GraphPaged -Uri $guestUri -Headers $advancedQuery) }
    catch { Write-Warning "Guest members of '$($group.displayName)' could not be read: $($_.Exception.Message)"; continue }
    Start-Sleep -Milliseconds 200
    if ($guests.Count -eq 0) { continue }
    $owners = $null
    if ($IncludeOwners) {
        try { $owners = (@(Invoke-GraphPaged -Uri ('{0}/groups/{1}/owners?$select=userPrincipalName,displayName' -f $graphV1, $group.id) | ForEach-Object { $_.userPrincipalName }) -join '; ') }
        catch { Write-Warning "Owners of '$($group.displayName)' could not be read: $($_.Exception.Message)" }
        Start-Sleep -Milliseconds 200
    }
    $groupInfo = [ordered]@{ GroupName = $group.displayName; GroupId = $group.id; IsTeam = (@($group.resourceProvisioningOptions) -contains 'Team')
        Visibility = $group.visibility; GroupMail = $group.mail }
    $domains = New-Object -TypeName System.Collections.Generic.List[string]
    foreach ($guest in $guests) {
        $guestIds[$guest.id] = $true
        # Guests invited without a mailbox have no mail; their UPN is <local>_<domain>#EXT#@<tenant>, so rebuild the address from it.
        $address = [string]$guest.mail
        if ([string]::IsNullOrEmpty($address) -and $guest.userPrincipalName -match '^(.+)_([^_#]+)#EXT#@') { $address = '{0}@{1}' -f $Matches[1], $Matches[2] }
        $domain = ([string]($address -split '@')[-1]).ToLowerInvariant()
        if (-not [string]::IsNullOrEmpty($domain) -and -not $domains.Contains($domain)) { $domains.Add($domain) }
        if ($Detailed) {
            $row = [ordered]@{} + $groupInfo
            $row['GuestDisplayName'] = $guest.displayName; $row['GuestMail'] = $guest.mail; $row['GuestUserPrincipalName'] = $guest.userPrincipalName
            $row['GuestDomain'] = $domain; $row['GuestId'] = $guest.id; $row['Owners'] = $owners
            $rows.Add([PSCustomObject]$row)
        }
    }
    if (-not $Detailed) {
        $row = [ordered]@{} + $groupInfo
        $row['GuestCount'] = $guests.Count; $row['GuestDomains'] = (($domains | Sort-Object) -join '; '); $row['Owners'] = $owners
        $rows.Add([PSCustomObject]$row)
    }
}
Write-Progress -Activity 'Scanning groups for guests' -Completed
if ($rows.Count -gt 0) { $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'None of the scanned groups has guest members; no CSV was written.' }
Write-Host ('Groups with guests: {0} of {1} scanned' -f @($rows | Select-Object -Property GroupId -Unique).Count, $groups.Count) -ForegroundColor Cyan
Write-Host ('  Teams with guests     : {0}' -f @($rows | Where-Object { $_.IsTeam } | Select-Object -Property GroupId -Unique).Count)
Write-Host ('  Distinct guest users  : {0}' -f $guestIds.Count)
Write-Host '  Top external domains  :'
$domainColumn = @{ $true = 'GuestDomain'; $false = 'GuestDomains' }[[bool]$Detailed]
foreach ($bucket in ($rows | ForEach-Object { $_.$domainColumn -split '; ' } | Where-Object { $_ } | Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 5)) {
    Write-Host ('    {0,-34}: {1} group membership(s)' -f $bucket.Name, $bucket.Count)
}
Write-Host ('  Report                : {0}' -f $OutputPath)
if ($PassThru) { $rows }
#endregion Main
