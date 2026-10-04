<#
.SYNOPSIS
    Creates Microsoft Teams teams in bulk from a CSV file, including owners, members and channels.
.DESCRIPTION
    Reads a CSV with the columns TeamName, Owners (semicolon-separated UPNs) and optionally Description, Visibility
    (Public|Private, default Private), Members, Template (default standard) and Channels (semicolon-separated names).
    Accounts are resolved through /users/{upn}; each team is created with POST /teams, the asynchronous operation from the
    Location header is polled until it succeeds, then members are added with POST /teams/{id}/members/add and channels with
    POST /teams/{id}/channels. Rows whose display name already exists as a team (checked through /groups) are skipped.
    Without -Apply the script only validates the rows and resolves the accounts. A results CSV records every row's outcome.
.PARAMETER InputCsv
    Path to the CSV file. Required columns: TeamName, Owners. Optional: Description, Visibility, Members, Template, Channels.
.PARAMETER Apply
    Create the teams. Without this switch valid rows are reported as WouldCreate and nothing is changed.
.PARAMETER TimeoutMinutes
    Maximum time to wait for each team provisioning operation. Default 5.
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\NewTeamsFromCsv_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\New-TeamsFromCsv.ps1 -InputCsv .\teams.csv
    Validates every row, resolves all owner and member accounts and reports which teams would be created, without creating anything.
.EXAMPLE
    PS> .\New-TeamsFromCsv.ps1 -InputCsv .\teams.csv -Apply -Confirm:$false -OutputPath C:\Temp\TeamsCreated.csv -Verbose
    Creates every team in the CSV without prompting, adds members and channels and writes the results to the given file.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Team.Create, TeamMember.ReadWrite.All, Channel.Create, User.Read.All, Group.Read.All (delegated). The signed-in
                  account must be allowed to create Microsoft 365 groups by the tenant's group creation policy.
    Category    : Teams apps, settings & usage
    Changes     : Yes
    Notes       : Team creation is asynchronous: Graph answers 202 Accepted and the script polls the operation every 5 seconds until
                  it succeeds, fails or -TimeoutMinutes is reached. With delegated permissions the signed-in account becomes an owner
                  as well; remove it afterwards if that is not wanted. A row fails when any owner cannot be resolved; unresolved
                  members are skipped and counted in the Detail column. Members are added in a single call (service limit 200 per
                  request). Templates other than standard (for example educationClass) need the matching licences in the tenant.
.LINK
    https://learn.microsoft.com/graph/api/team-post
.LINK
    https://learn.microsoft.com/graph/api/conversationmembers-add
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$TimeoutMinutes = 5,

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

function Split-CsvList {
    <# Splits a semicolon-separated CSV cell into trimmed, unique, non-empty values. #>
    param([Parameter()][AllowEmptyString()][string]$Value)
    return @($Value.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' } | Sort-Object -Unique)
}

function Resolve-UserId {
    <# Resolves a UPN to the user object id through /users/{upn}; results are cached, unknown accounts warn and return $null. #>
    param([Parameter(Mandatory = $true)][string]$UserPrincipalName, [Parameter(Mandatory = $true)][hashtable]$Cache)
    $key = $UserPrincipalName.ToLowerInvariant()
    if (-not $Cache.ContainsKey($key)) {
        try { $Cache[$key] = (Invoke-MgGraphRequest -Method GET -Uri ('https://graph.microsoft.com/v1.0/users/{0}?$select=id' -f [uri]::EscapeDataString($key)) -OutputType PSObject -ErrorAction Stop).id }
        catch { Write-Warning "Account '$key' could not be resolved: $($_.Exception.Message)"; $Cache[$key] = $null }
    }
    return $Cache[$key]
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('NewTeamsFromCsv_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
if ($rows.Count -eq 0) { throw "The CSV '$InputCsv' contains no rows." }
if (@(@('TeamName', 'Owners') | Where-Object { $rows[0].PSObject.Properties.Name -notcontains $_ }).Count -gt 0) { throw 'The CSV must contain the TeamName and Owners columns.' }
try { Connect-GraphIfNeeded -Scopes @('Team.Create', 'TeamMember.ReadWrite.All', 'Channel.Create', 'User.Read.All', 'Group.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$graphV1 = 'https://graph.microsoft.com/v1.0'
$userIds = @{}
$seenNames = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($row in $rows) {
    $counter++
    $name = ([string]$row.TeamName).Trim()
    Write-Progress -Activity 'Creating teams' -Status "$counter of $($rows.Count): $name" -PercentComplete ([int](($counter / $rows.Count) * 100))
    $result = [PSCustomObject]@{ TeamName = $name; TeamId = $null; Visibility = 'private'; Template = 'standard'; Owners = $null; MembersAdded = 0; ChannelsCreated = 0; Result = $null; Detail = $null }
    $results.Add($result)
    try {
        if ([string]::IsNullOrWhiteSpace($name)) { throw 'TeamName is empty.' }
        if ($seenNames.ContainsKey($name.ToLowerInvariant())) { throw 'Duplicate TeamName in the CSV; only the first row is processed.' }
        $seenNames[$name.ToLowerInvariant()] = $true
        if (-not [string]::IsNullOrWhiteSpace($row.Visibility)) { $result.Visibility = ([string]$row.Visibility).Trim().ToLowerInvariant() }
        if (@('public', 'private') -notcontains $result.Visibility) { throw "Visibility '$($row.Visibility)' is not Public or Private." }
        if (-not [string]::IsNullOrWhiteSpace($row.Template)) { $result.Template = ([string]$row.Template).Trim() }
        # One filtered lookup per row is cheaper than enumerating every group in the tenant; the Team check is done client-side.
        $lookupUri = '{0}/groups?$filter=displayName eq ''{1}''&$select=id,resourceProvisioningOptions' -f $graphV1, [uri]::EscapeDataString($name.Replace("'", "''"))
        $existing = @((Invoke-MgGraphRequest -Method GET -Uri $lookupUri -OutputType PSObject -ErrorAction Stop).value | Where-Object { @($_.resourceProvisioningOptions) -contains 'Team' })
        if ($existing.Count -gt 0) { $result.TeamId = $existing[0].id; $result.Result = 'Exists'; continue }

        $ownerUpns = @(Split-CsvList -Value $row.Owners)
        $ownerIds = @($ownerUpns | ForEach-Object { Resolve-UserId -UserPrincipalName $_ -Cache $userIds } | Where-Object { $null -ne $_ })
        if ($ownerIds.Count -eq 0 -or $ownerIds.Count -lt $ownerUpns.Count) { throw 'At least one owner is required and every owner must resolve to a user.' }
        $result.Owners = $ownerUpns -join ';'
        $memberUpns = @(Split-CsvList -Value $row.Members | Where-Object { $ownerUpns -notcontains $_ })
        $memberIds = @($memberUpns | ForEach-Object { Resolve-UserId -UserPrincipalName $_ -Cache $userIds } | Where-Object { $null -ne $_ })
        if ($memberIds.Count -lt $memberUpns.Count) { $result.Detail = '{0} member(s) could not be resolved and were skipped.' -f ($memberUpns.Count - $memberIds.Count) }
        $channelNames = @(Split-CsvList -Value $row.Channels | Where-Object { $_ -ne 'General' })
        if (-not $Apply) { $result.Result = 'WouldCreate'; continue }
        $action = 'Create {0} team with {1} owner(s), {2} member(s) and {3} channel(s)' -f $result.Visibility, $ownerIds.Count, $memberIds.Count, $channelNames.Count
        if (-not $PSCmdlet.ShouldProcess($name, $action)) { $result.Result = 'SkippedByUser'; continue }

        $body = @{ 'template@odata.bind' = "$graphV1/teamsTemplates('$($result.Template)')"; displayName = $name; visibility = $result.Visibility }
        if (-not [string]::IsNullOrWhiteSpace($row.Description)) { $body['description'] = ([string]$row.Description).Trim() }
        $body['members'] = @($ownerIds | ForEach-Object { @{ '@odata.type' = '#microsoft.graph.aadUserConversationMember'; roles = @('owner'); 'user@odata.bind' = "$graphV1/users('$_')" } })
        # 202 Accepted has no body; the HttpResponseMessage output exposes the Location header /teams('{id}')/operations('{id}').
        $response = Invoke-MgGraphRequest -Method POST -Uri "$graphV1/teams" -Body (ConvertTo-Json -InputObject $body -Depth 5) -ContentType 'application/json' -OutputType HttpResponseMessage -ErrorAction Stop
        if ([string]$response.Headers.Location -notmatch "teams\('(?<teamId>[^']+)'\)/operations\('(?<operationId>[^']+)'\)") {
            throw 'Graph accepted the request but returned no operation Location header; check the Teams admin center before retrying this row.'
        }
        $teamId = $Matches['teamId']
        $operationUri = '{0}/teams/{1}/operations/{2}' -f $graphV1, $teamId, $Matches['operationId']
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        do {
            Start-Sleep -Seconds 5
            $operation = Invoke-MgGraphRequest -Method GET -Uri $operationUri -OutputType PSObject -ErrorAction Stop
            Write-Verbose "Provisioning status for '$name': $($operation.status)"
            if ($operation.status -eq 'failed') { throw "Provisioning failed: $($operation.error.message)" }
        } while ($operation.status -ne 'succeeded' -and (Get-Date) -lt $deadline)
        if ($operation.status -ne 'succeeded') { throw "Provisioning did not finish within $TimeoutMinutes minutes (last status: $($operation.status))." }
        $result.TeamId = $teamId
        $result.Result = 'Created'
        if ($memberIds.Count -gt 0) {
            $addBody = @{ values = @($memberIds | ForEach-Object { @{ '@odata.type' = 'microsoft.graph.aadUserConversationMember'; roles = @(); 'user@odata.bind' = "$graphV1/users('$_')" } }) }
            $added = Invoke-MgGraphRequest -Method POST -Uri "$graphV1/teams/$teamId/members/add" -Body (ConvertTo-Json -InputObject $addBody -Depth 5) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
            $result.MembersAdded = @($added.value | Where-Object { $null -eq $_.error }).Count
            if ($result.MembersAdded -lt $memberIds.Count) { Write-Warning "Team '$name': $($memberIds.Count - $result.MembersAdded) member(s) were rejected by the service." }
        }
        foreach ($channelName in $channelNames) {
            try {
                Invoke-MgGraphRequest -Method POST -Uri "$graphV1/teams/$teamId/channels" -Body @{ displayName = $channelName; membershipType = 'standard' } -ContentType 'application/json' -ErrorAction Stop | Out-Null
                $result.ChannelsCreated++
            }
            catch { Write-Warning "Could not create channel '$channelName' in team '$name': $($_.Exception.Message)" }
            Start-Sleep -Milliseconds 200
        }
    }
    catch {
        # A failure after the team exists keeps Result = Created so the row is not re-run blindly; Detail explains what went wrong.
        if ($result.Result -ne 'Created') { $result.Result = 'Failed' }
        $result.Detail = $_.Exception.Message
        Write-Warning "Row $counter ('$name'): $($_.Exception.Message)"
    }
}
Write-Progress -Activity 'Creating teams' -Completed
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host ('Bulk team creation summary - {0}' -f $(if ($Apply) { 'APPLY' } else { 'validate only (add -Apply to create)' })) -ForegroundColor Cyan
Write-Host ('  Rows processed : {0}' -f $results.Count)
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = 'Yellow'
    if ($group.Name -eq 'Failed') { $colour = 'Red' } elseif ($group.Name -eq 'Created') { $colour = 'Green' }
    Write-Host ('  {0,-15}: {1}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
Write-Host ('  Results        : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
