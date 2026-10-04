<#
.SYNOPSIS
    One-page executive summary of external collaboration: guests, their domains, groups and teams with guests and the tenant sharing settings.
.DESCRIPTION
    Collects guest counts and ages from /users (userType eq 'Guest', signInActivity when available), the top guest domains, the
    Microsoft 365 groups and teams that contain guests (one $count query per group), the invitation settings from
    /policies/authorizationPolicy, the cross-tenant access defaults and partner count from /policies/crossTenantAccessPolicy and the
    SharePoint sharing capability from /admin/sharepoint/settings. Every area is collected independently, so a missing permission
    produces a NoAccess row instead of stopping the run. Outputs rows (Area, Metric, Value, Note) to CSV, the console and
    optionally a one-page HTML summary.
.PARAMETER DaysInactive
    Guests without a sign-in for this many days count as inactive. Default 90.
.PARAMETER SkipGroupScan
    Skip the per-group guest count (the slowest part in tenants with thousands of Microsoft 365 groups).
.PARAMETER HtmlPath
    Optional path of a one-page HTML summary.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365ExternalCollaboration_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the summary rows to the pipeline.
.EXAMPLE
    PS> .\Get-M365ExternalCollaborationSummary.ps1
    Prints the summary table and writes the CSV to the Reports folder.
.EXAMPLE
    PS> .\Get-M365ExternalCollaborationSummary.ps1 -HtmlPath C:\Temp\ExternalCollab.html -SkipGroupScan
    Writes the summary as HTML for management without scanning every group for guest members.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Read.All, AuditLog.Read.All, Group.Read.All, GroupMember.Read.All, Policy.Read.All,
                  SharePointTenantSettings.Read.All (delegated); Global Reader covers all of them.
    Category    : User lifecycle & tenant hygiene
    Changes     : No
    Notes       : signInActivity needs Entra ID P1; without it the never-signed-in and inactive guest figures are skipped.
                  Teams guest and external access settings are not exposed through Graph; use Get-TeamsGuestAccessReport.ps1 in
                  the Teams-SharePoint folder for them. The group scan sends one request per Microsoft 365 group (about 200 ms each).
.LINK
    https://learn.microsoft.com/graph/api/authorizationpolicy-get
.LINK
    https://learn.microsoft.com/graph/api/crosstenantaccesspolicy-list-partners
.LINK
    https://learn.microsoft.com/graph/api/sharepointsettings-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 90,

    [Parameter()]
    [switch]$SkipGroupScan,

    [Parameter()]
    [string]$HtmlPath,

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

function Add-Row {
    param([string]$Area, [string]$Metric, [AllowNull()] $Value, [string]$Note = '')
    $script:rows.Add([PSCustomObject]@{ Area = $Area; Metric = $Metric; Value = [string]$Value; Note = $Note })
}

function Invoke-Section {
    <# Runs one collection area; a failure becomes a NoAccess/Error row instead of aborting the summary. #>
    param([string]$Area, [scriptblock]$Action)
    try { & $Action }
    catch {
        $status = if ($_.Exception.Message -match 'Forbidden|Authorization_RequestDenied|403') { 'NoAccess' } else { 'Error' }
        Add-Row -Area $Area -Metric $status -Value '' -Note $_.Exception.Message
        Write-Warning "$Area - $status : $($_.Exception.Message)"
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365ExternalCollaboration_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$scopes = @('User.Read.All', 'AuditLog.Read.All', 'Group.Read.All', 'GroupMember.Read.All', 'Policy.Read.All', 'SharePointTenantSettings.Read.All')
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Could not connect to Microsoft Graph: $($_.Exception.Message)" }
$graphBase = 'https://graph.microsoft.com/v1.0'
$eventual = @{ ConsistencyLevel = 'eventual' }
$script:rows = New-Object -TypeName System.Collections.Generic.List[object]
$now = (Get-Date).ToUniversalTime()

Invoke-Section -Area 'Guests' -Action {
    $guestSelect = 'id,mail,userPrincipalName,accountEnabled,createdDateTime,externalUserState'
    $hasSignIn = $true
    try { $guests = Invoke-GraphPaged -Uri "$graphBase/users?`$filter=userType eq 'Guest'&`$select=$guestSelect,signInActivity" }
    catch { $hasSignIn = $false; $guests = Invoke-GraphPaged -Uri "$graphBase/users?`$filter=userType eq 'Guest'&`$select=$guestSelect" }
    Add-Row -Area 'Guests' -Metric 'Guest accounts' -Value $guests.Count
    Add-Row -Area 'Guests' -Metric 'Enabled' -Value @($guests | Where-Object { $_.accountEnabled }).Count
    Add-Row -Area 'Guests' -Metric 'Invitation pending' -Value @($guests | Where-Object { $_.externalUserState -eq 'PendingAcceptance' }).Count -Note 'Invited but never redeemed'
    Add-Row -Area 'Guests' -Metric "Created in the last 30 days" -Value @($guests | Where-Object { [datetime]$_.createdDateTime -ge $now.AddDays(-30) }).Count
    if ($hasSignIn) {
        $cutoff = $now.AddDays(-$DaysInactive)
        $never = @($guests | Where-Object { $null -eq $_.signInActivity -or [string]::IsNullOrEmpty([string]$_.signInActivity.lastSignInDateTime) })
        $signedIn = @($guests | Where-Object { $null -ne $_.signInActivity -and -not [string]::IsNullOrEmpty([string]$_.signInActivity.lastSignInDateTime) })
        $inactive = @($signedIn | Where-Object { [datetime]$_.signInActivity.lastSignInDateTime -lt $cutoff })
        Add-Row -Area 'Guests' -Metric 'Never signed in' -Value $never.Count -Note 'Candidates for removal after review'
        Add-Row -Area 'Guests' -Metric "No sign-in for $DaysInactive days" -Value $inactive.Count
    }
    else { Add-Row -Area 'Guests' -Metric 'Sign-in activity' -Value 'NoAccess' -Note 'signInActivity needs Entra ID P1 and AuditLog.Read.All' }
    # Home domain: the mail attribute when present, otherwise the part between the last underscore and #EXT# of the UPN.
    $domains = $guests | ForEach-Object {
        if (-not [string]::IsNullOrEmpty($_.mail)) { ([string]$_.mail).Split('@')[-1].ToLowerInvariant() }
        elseif ($_.userPrincipalName -match '_([^_]+)#EXT#@') { $Matches[1].ToLowerInvariant() }
    }
    $domains | Group-Object | Sort-Object -Property Count -Descending | Select-Object -First 10 | ForEach-Object { Add-Row -Area 'Guest domains (top 10)' -Metric $_.Name -Value $_.Count }
}

if (-not $SkipGroupScan) {
    Invoke-Section -Area 'Groups and teams' -Action {
        $groups = @(Invoke-GraphPaged -Uri "$graphBase/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$select=id,displayName,resourceProvisioningOptions,visibility")
        $withGuests = New-Object -TypeName System.Collections.Generic.List[object]
        $index = 0
        foreach ($group in $groups) {
            $index++
            Write-Progress -Activity 'Counting guests per Microsoft 365 group' -Status $group.displayName -PercentComplete (($index / [math]::Max($groups.Count, 1)) * 100)
            $countUri = "$graphBase/groups/$($group.id)/members/microsoft.graph.user?`$count=true&`$filter=userType eq 'Guest'&`$select=id&`$top=1"
            $guestCount = [int](Invoke-MgGraphRequest -Method GET -Uri $countUri -Headers $eventual -OutputType PSObject -ErrorAction Stop).'@odata.count'
            if ($guestCount -gt 0) {
                $withGuests.Add([PSCustomObject]@{ Name = $group.displayName; Guests = $guestCount; IsTeam = ($group.resourceProvisioningOptions -contains 'Team'); Visibility = $group.visibility })
            }
            Start-Sleep -Milliseconds 200
        }
        Write-Progress -Activity 'Counting guests per Microsoft 365 group' -Completed
        Add-Row -Area 'Groups and teams' -Metric 'Microsoft 365 groups' -Value $groups.Count
        Add-Row -Area 'Groups and teams' -Metric 'Groups with guests' -Value $withGuests.Count
        Add-Row -Area 'Groups and teams' -Metric 'Teams with guests' -Value @($withGuests | Where-Object { $_.IsTeam }).Count
        Add-Row -Area 'Groups and teams' -Metric 'Guest memberships' -Value ($withGuests | Measure-Object -Property Guests -Sum).Sum
        $withGuests | Sort-Object -Property Guests -Descending | Select-Object -First 10 |
            ForEach-Object { Add-Row -Area 'Groups with most guests' -Metric $_.Name -Value $_.Guests -Note "$($_.Visibility); team: $($_.IsTeam)" }
    }
}

Invoke-Section -Area 'Invitation settings' -Action {
    $guestRoles = @{ 'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'Same as members'; '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Limited (default)'; '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'Restricted' }
    $policy = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/policies/authorizationPolicy" -OutputType PSObject
    Add-Row -Area 'Invitation settings' -Metric 'Who can invite guests' -Value $policy.allowInvitesFrom -Note 'Recommended: adminsAndGuestInviters or none'
    $roleName = if ($guestRoles.ContainsKey([string]$policy.guestUserRoleId)) { $guestRoles[[string]$policy.guestUserRoleId] } else { $policy.guestUserRoleId }
    Add-Row -Area 'Invitation settings' -Metric 'Guest user access' -Value $roleName -Note 'Recommended: Restricted'
    Add-Row -Area 'Invitation settings' -Metric 'Email-verified users can join' -Value $policy.allowEmailVerifiedUsersToJoinOrganization -Note 'Self-service sign-up of external users'
}

Invoke-Section -Area 'Cross-tenant access' -Action {
    $default = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/policies/crossTenantAccessPolicy/default" -OutputType PSObject
    Add-Row -Area 'Cross-tenant access' -Metric 'B2B collaboration inbound (default)' -Value $default.b2bCollaborationInbound.usersAndGroups.accessType
    Add-Row -Area 'Cross-tenant access' -Metric 'B2B collaboration outbound (default)' -Value $default.b2bCollaborationOutbound.usersAndGroups.accessType
    Add-Row -Area 'Cross-tenant access' -Metric 'B2B direct connect inbound (default)' -Value $default.b2bDirectConnectInbound.usersAndGroups.accessType -Note 'Teams shared channels'
    Add-Row -Area 'Cross-tenant access' -Metric 'B2B direct connect outbound (default)' -Value $default.b2bDirectConnectOutbound.usersAndGroups.accessType
    Add-Row -Area 'Cross-tenant access' -Metric 'Trust MFA from other tenants' -Value $default.inboundTrust.isMfaAccepted
    $partners = @(Invoke-GraphPaged -Uri "$graphBase/policies/crossTenantAccessPolicy/partners")
    Add-Row -Area 'Cross-tenant access' -Metric 'Partner-specific policies' -Value $partners.Count -Note (($partners | Select-Object -First 10 | ForEach-Object { $_.tenantId }) -join ', ')
}

Invoke-Section -Area 'SharePoint sharing' -Action {
    $spo = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/admin/sharepoint/settings" -OutputType PSObject
    $levels = 'From strict to open: disabled, existingExternalUserSharingOnly, externalUserSharingOnly, externalUserAndGuestSharing'
    Add-Row -Area 'SharePoint sharing' -Metric 'Sharing capability' -Value $spo.sharingCapability -Note $levels
    Add-Row -Area 'SharePoint sharing' -Metric 'Domain restriction' -Value $spo.sharingDomainRestrictionMode -Note ((@($spo.sharingAllowedDomainList) + @($spo.sharingBlockedDomainList)) -join ', ')
    Add-Row -Area 'SharePoint sharing' -Metric 'Guests can reshare' -Value $spo.isResharingByExternalUsersEnabled
}
Add-Row -Area 'Teams' -Metric 'Guest and external access' -Value 'n/a' -Note 'Not exposed in Graph; run Get-TeamsGuestAccessReport.ps1 (Teams-SharePoint folder)'

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if (-not [string]::IsNullOrWhiteSpace($HtmlPath)) {
    $style = '<style>body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;margin:24px}h1{font-size:20px}h2{font-size:15px;margin-top:20px}' +
        'table{border-collapse:collapse}th,td{border:1px solid #d0d0d0;padding:4px 10px;text-align:left}th{background:#f3f3f3}</style>'
    $sections = foreach ($area in ($rows | Select-Object -ExpandProperty Area -Unique)) {
        "<h2>$area</h2>" + (($rows | Where-Object { $_.Area -eq $area } | Select-Object -Property Metric, Value, Note | ConvertTo-Html -Fragment) -join "`n")
    }
    $title = 'External collaboration summary - tenant {0} - {1:yyyy-MM-dd HH:mm} UTC' -f (Get-MgContext).TenantId, $now
    ConvertTo-Html -Head $style -Title $title -Body ("<h1>$title</h1>" + ($sections -join "`n")) | Set-Content -Path $HtmlPath -Encoding UTF8
    Write-Host "HTML summary: $HtmlPath" -ForegroundColor Cyan
}
$rows | Format-Table -Property Area, Metric, Value, Note -AutoSize -Wrap | Out-Host
Write-Host "Report: $OutputPath" -ForegroundColor Cyan
if ($PassThru) { $rows }
#endregion Main
