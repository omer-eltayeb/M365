<#
.SYNOPSIS
    Invites external users as Microsoft Entra B2B guests, in bulk from a list of addresses or a CSV file, and adds them to groups.
.DESCRIPTION
    Takes e-mail addresses from -EmailAddress or from a CSV file (columns EmailAddress, DisplayName, Groups, Message), skips
    addresses that already exist as users in the tenant (GET /users filtered on mail or otherMails), creates the invitation
    (POST /invitations with the redirect URL, optional custom message and optional e-mail suppression) and adds the new guest to
    the requested groups (POST /groups/{id}/members/$ref). Every invitation is wrapped in ShouldProcess, so -WhatIf previews the
    run and -Confirm:$false runs it unattended. One result object per address is emitted with the redemption URL.
.PARAMETER EmailAddress
    One or more e-mail addresses to invite.
.PARAMETER InputCsv
    Path of a CSV file with the column EmailAddress and the optional columns DisplayName, Groups (semicolon-separated) and Message.
.PARAMETER Groups
    Display names of groups every invited guest is added to (CSV rows with their own Groups column override this list).
.PARAMETER Message
    Custom text for the invitation e-mail (a CSV Message column overrides it).
.PARAMETER RedirectUrl
    URL the guest lands on after redeeming the invitation. Default https://myapps.microsoft.com.
.PARAMETER NoEmail
    Creates the invitation without sending the Microsoft invitation e-mail; the redemption URL is returned instead.
.EXAMPLE
    PS> .\New-EntraGuestInvitation.ps1 -EmailAddress 'partner@fabrikam.com' -Groups 'SG-Project-Falcon' -WhatIf
    Shows that the partner would be invited and added to the group without creating anything.
.EXAMPLE
    PS> .\New-EntraGuestInvitation.ps1 -InputCsv C:\Temp\guests.csv -NoEmail -Confirm:$false | Export-Csv C:\Temp\invited.csv -NoTypeInformation
    Invites everyone in the CSV without e-mails or prompts and saves the redemption URLs for distribution through another channel.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.Invite.All, User.Read.All, plus GroupMember.ReadWrite.All when groups are requested (delegated); Guest Inviter role.
    Category    : Roles, governance & tenant policy
    Changes     : Yes
    Notes       : Invitations respect the tenant's external collaboration settings (allowed/blocked domains, who may invite).
                  Dynamic and on-premises synchronised groups cannot receive members through Graph and are skipped with a warning.
.LINK
    https://learn.microsoft.com/graph/api/invitation-post
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Email')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Email', Position = 0)]
    [string[]]$EmailAddress,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [string[]]$Groups,

    [Parameter()]
    [string]$Message,

    [Parameter()]
    [ValidatePattern('^https://')]
    [string]$RedirectUrl = 'https://myapps.microsoft.com',

    [Parameter()]
    [switch]$NoEmail
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

function Resolve-GroupId {
    <# Resolves a group display name to its id (cached); dynamic and on-premises synced groups are rejected because Graph cannot add members to them. #>
    param([string]$DisplayName)
    if ($script:GroupCache.ContainsKey($DisplayName)) { return $script:GroupCache[$DisplayName] }
    $groupId = $null
    try {
        $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '{0}'&`$select=id,groupTypes,onPremisesSyncEnabled" -f ($DisplayName -replace "'", "''")
        $found = @(Invoke-GraphPaged -Uri $uri)
        if ($found.Count -ne 1) { Write-Warning ('Group "{0}" matched {1} groups; it is skipped.' -f $DisplayName, $found.Count) }
        elseif (@($found[0].groupTypes) -contains 'DynamicMembership' -or $found[0].onPremisesSyncEnabled) { Write-Warning ('Group "{0}" is dynamic or on-premises synced; skipped.' -f $DisplayName) }
        else { $groupId = $found[0].id }
    }
    catch { Write-Warning ('Group "{0}" could not be resolved: {1}' -f $DisplayName, $_.Exception.Message) }
    $script:GroupCache[$DisplayName] = $groupId
    return $groupId
}
#endregion Helpers

#region Main
$invitees = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    foreach ($row in (Import-Csv -Path $InputCsv)) {
        $rowGroups = $Groups
        if (-not [string]::IsNullOrWhiteSpace($row.Groups)) { $rowGroups = @($row.Groups -split ';' | ForEach-Object { $_.Trim() }) }
        $rowMessage = $Message
        if (-not [string]::IsNullOrWhiteSpace($row.Message)) { $rowMessage = $row.Message }
        $invitees.Add([PSCustomObject]@{ EmailAddress = ([string]$row.EmailAddress).Trim(); DisplayName = $row.DisplayName; Groups = @($rowGroups | Where-Object { $_ }); Message = $rowMessage })
    }
}
else {
    foreach ($address in $EmailAddress) { $invitees.Add([PSCustomObject]@{ EmailAddress = $address.Trim(); DisplayName = $null; Groups = @($Groups | Where-Object { $_ }); Message = $Message }) }
}
if ($invitees.Count -eq 0) { throw 'No e-mail addresses to invite were found.' }
$v1 = 'https://graph.microsoft.com/v1.0'
$requiredScopes = @('User.Invite.All', 'User.Read.All')
if (@($invitees | Where-Object { $_.Groups.Count -gt 0 }).Count -gt 0) { $requiredScopes += 'GroupMember.ReadWrite.All' }
try { Connect-GraphIfNeeded -Scopes $requiredScopes }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$script:GroupCache = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($invitee in $invitees) {
    $processed++
    Write-Progress -Activity 'Inviting guests' -Status $invitee.EmailAddress -PercentComplete (($processed / $invitees.Count) * 100)
    $result = [PSCustomObject]@{ EmailAddress = $invitee.EmailAddress; DisplayName = $invitee.DisplayName; InvitedUserId = $null; Status = $null; RedeemUrl = $null
        Groups = $null; Result = $null; Error = $null }
    $results.Add($result)
    if ($invitee.EmailAddress -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { $result.Result = 'Skipped (invalid address)'; continue }

    try {
        $escaped = $invitee.EmailAddress -replace "'", "''"
        # ConsistencyLevel=eventual with $count=true enables the advanced query path needed for the 'or' across mail and otherMails.
        $existing = @(Invoke-GraphPaged -Uri "$v1/users?`$filter=mail eq '$escaped' or otherMails/any(m:m eq '$escaped')&`$select=id,userType&`$count=true" -Headers @{ ConsistencyLevel = 'eventual' })
    }
    catch { $result.Result = 'Failed'; $result.Error = "Lookup failed: $($_.Exception.Message)"; Write-Warning ('{0}: {1}' -f $invitee.EmailAddress, $result.Error); continue }
    if ($existing.Count -gt 0) { $result.InvitedUserId = $existing[0].id; $result.Result = 'Skipped (already exists as {0})' -f $existing[0].userType; continue }

    $groupIds = @{}
    foreach ($groupName in $invitee.Groups) {
        $groupId = Resolve-GroupId -DisplayName $groupName
        if ($null -ne $groupId) { $groupIds[$groupName] = $groupId }
    }
    $action = 'Send guest invitation'
    if ($groupIds.Count -gt 0) { $action = 'Send guest invitation and add to: {0}' -f (($groupIds.Keys | Sort-Object) -join ', ') }
    if (-not $PSCmdlet.ShouldProcess($invitee.EmailAddress, $action)) { $result.Result = 'WhatIf'; continue }

    try {
        $body = @{ invitedUserEmailAddress = $invitee.EmailAddress; inviteRedirectUrl = $RedirectUrl; sendInvitationMessage = (-not $NoEmail); invitedUserType = 'Guest' }
        if (-not [string]::IsNullOrWhiteSpace($invitee.DisplayName)) { $body['invitedUserDisplayName'] = $invitee.DisplayName }
        if (-not [string]::IsNullOrWhiteSpace($invitee.Message)) { $body['invitedUserMessageInfo'] = @{ customizedMessageBody = $invitee.Message } }
        $invitation = Invoke-MgGraphRequest -Method POST -Uri "$v1/invitations" -Body $body -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
        $result.InvitedUserId = $invitation.invitedUser.id
        $result.Status = $invitation.status
        $result.RedeemUrl = $invitation.inviteRedeemUrl
        $result.Result = 'Invited'
    }
    catch { $result.Result = 'Failed'; $result.Error = $_.Exception.Message; Write-Warning ('{0}: invitation failed. {1}' -f $invitee.EmailAddress, $_.Exception.Message); continue }

    $added = @()
    foreach ($groupName in ($groupIds.Keys | Sort-Object)) {
        try {
            $reference = @{ '@odata.id' = '{0}/directoryObjects/{1}' -f $v1, $result.InvitedUserId }
            Invoke-MgGraphRequest -Method POST -Uri ('{0}/groups/{1}/members/$ref' -f $v1, $groupIds[$groupName]) -Body $reference -ContentType 'application/json' -ErrorAction Stop | Out-Null
            $added += $groupName
        }
        catch { Write-Warning ('{0}: could not be added to group "{1}". {2}' -f $invitee.EmailAddress, $groupName, $_.Exception.Message); $result.Error = "Group add failed: $groupName" }
    }
    $result.Groups = ($added -join '; ')
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Inviting guests' -Completed

Write-Host 'Guest invitation summary' -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    Write-Host ('  {0,-36}: {1}' -f $group.Name, $group.Count)
}
if ($NoEmail -and @($results | Where-Object { $_.Result -eq 'Invited' }).Count -gt 0) { Write-Host '  No e-mails were sent; share the RedeemUrl values with the guests.' -ForegroundColor Yellow }

$results
#endregion Main
