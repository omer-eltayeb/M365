<#
.SYNOPSIS
    Marks Message Center posts as read/unread, archives/unarchives or favorites/unfavorites them in bulk, by ID or by filter.
.DESCRIPTION
    Selects Message Center posts either by -MessageId or by filters (older than N days, category, service, tag, read or
    unread state) read from /admin/serviceAnnouncement/messages (Microsoft Graph v1.0), skips the posts that are already
    in the requested state and applies -Action with the bulk endpoints
    /admin/serviceAnnouncement/messages/markRead | markUnread | archive | unarchive | favorite | unfavorite in batches
    of 50 IDs. Every change is guarded by ShouldProcess (ConfirmImpact High), so -WhatIf previews the selection. One
    result object per post is emitted (Applied, AlreadyInState, Skipped after -WhatIf or a declined prompt, or Failed).
    The flags are per admin: they change only the signed-in user's view of the Message Center, not what other admins see.
.PARAMETER Action
    MarkRead, MarkUnread, Archive, Unarchive, Favorite or Unfavorite.
.PARAMETER MessageId
    One or more post IDs such as MC123456. Each ID is read first to validate it and to get its current state.
.PARAMETER OlderThanDays
    Select posts whose lastModifiedDateTime is more than N days ago (server-side filter).
.PARAMETER Category
    Select only planForChange, stayInformed or preventOrFixIssue posts.
.PARAMETER Service
    Wildcard filter on the affected services, for example 'Microsoft Intune' or '*Teams*'. A value without wildcards is matched as *value*.
.PARAMETER Tag
    Wildcard filter on the tags, for example 'Retirement' or 'Admin impact'.
.PARAMETER ReadOnly
    Select only posts already marked as read (typical before archiving).
.PARAMETER UnreadOnly
    Select only unread posts.
.EXAMPLE
    PS> .\Invoke-M365MessageCenterTriage.ps1 -Action Archive -OlderThanDays 90 -ReadOnly -WhatIf
    Lists the read posts not updated for 90 days that would be archived, without changing anything.
.EXAMPLE
    PS> .\Invoke-M365MessageCenterTriage.ps1 -Action MarkRead -Category stayInformed -Service 'Microsoft Teams'
    Marks every Teams "stay informed" post as read after a confirmation prompt that shows the number of posts.
.EXAMPLE
    PS> .\Invoke-M365MessageCenterTriage.ps1 -Action Favorite -MessageId MC123456, MC234567 -Confirm:$false
    Favorites two posts without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : ServiceMessage.Read.All and ServiceMessageViewpoint.Write (delegated). The signed-in user needs a role
                  that can read the Message Center, for example Message Center Reader or Service Support Administrator.
    Category    : Tenant configuration & health
    Changes     : Yes
    Notes       : The viewpoint endpoints only work with delegated (user) sign-in, not app-only. A filter run refuses to
                  act when no filter is given, so the whole Message Center is never changed by accident. Archived posts
                  stay available in the admin center under the Archive tab and can be unarchived with -Action Unarchive.
.LINK
    https://learn.microsoft.com/graph/api/serviceupdatemessage-archive
.LINK
    https://learn.microsoft.com/graph/api/serviceupdatemessage-markread
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'ByFilter')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('MarkRead', 'MarkUnread', 'Archive', 'Unarchive', 'Favorite', 'Unfavorite')]
    [string]$Action,

    [Parameter(ParameterSetName = 'ById', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$MessageId,

    [Parameter(ParameterSetName = 'ByFilter')]
    [ValidateRange(1, 3650)]
    [int]$OlderThanDays,

    [Parameter(ParameterSetName = 'ByFilter')]
    [ValidateSet('planForChange', 'stayInformed', 'preventOrFixIssue')]
    [string]$Category,

    [Parameter(ParameterSetName = 'ByFilter')]
    [string]$Service,

    [Parameter(ParameterSetName = 'ByFilter')]
    [string]$Tag,

    [Parameter(ParameterSetName = 'ByFilter')]
    [switch]$ReadOnly,

    [Parameter(ParameterSetName = 'ByFilter')]
    [switch]$UnreadOnly
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

function ConvertTo-WildcardPattern {
    <# Returns $null for an empty filter, otherwise the value wrapped in * unless it already contains wildcards. #>
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Value -match '[\*\?]') { return $Value }
    return "*$Value*"
}
#endregion Helpers

#region Main
# Each action maps to a bulk endpoint and to the viewPoint flag/value it produces, so posts already in that state are skipped.
$actions = @{
    MarkRead   = @{ Endpoint = 'markRead'; Flag = 'isRead'; Value = $true }
    MarkUnread = @{ Endpoint = 'markUnread'; Flag = 'isRead'; Value = $false }
    Archive    = @{ Endpoint = 'archive'; Flag = 'isArchived'; Value = $true }
    Unarchive  = @{ Endpoint = 'unarchive'; Flag = 'isArchived'; Value = $false }
    Favorite   = @{ Endpoint = 'favorite'; Flag = 'isFavorited'; Value = $true }
    Unfavorite = @{ Endpoint = 'unfavorite'; Flag = 'isFavorited'; Value = $false }
}
$selected = $actions[$Action]
if ($ReadOnly -and $UnreadOnly) { throw '-ReadOnly and -UnreadOnly cannot be combined.' }
$filterNames = @('OlderThanDays', 'Category', 'Service', 'Tag', 'ReadOnly', 'UnreadOnly')
if ($PSCmdlet.ParameterSetName -eq 'ByFilter' -and @($PSBoundParameters.Keys | Where-Object { $filterNames -contains $_ }).Count -eq 0) {
    throw 'Pass -MessageId or at least one filter (-OlderThanDays, -Category, -Service, -Tag, -ReadOnly, -UnreadOnly); refusing to act on every post.'
}

try {
    Connect-GraphIfNeeded -Scopes @('ServiceMessage.Read.All', 'ServiceMessageViewpoint.Write')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$messagesUri = 'https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/messages'
$select = '$select=id,title,category,services,tags,lastModifiedDateTime,viewPoint'
$candidates = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSCmdlet.ParameterSetName -eq 'ById') {
    foreach ($id in @($MessageId | Select-Object -Unique)) {
        try {
            $candidates.Add((Invoke-MgGraphRequest -Method GET -Uri ('{0}/{1}?{2}' -f $messagesUri, $id, $select) -OutputType PSObject -ErrorAction Stop))
        }
        catch {
            Write-Warning "Post $id could not be read and is skipped: $($_.Exception.Message)"
        }
        Start-Sleep -Milliseconds 200
    }
}
else {
    $query = $select
    if ($PSBoundParameters.ContainsKey('OlderThanDays')) {
        $query += '&$filter=lastModifiedDateTime le {0:yyyy-MM-ddTHH:mm:ssZ}' -f [datetime]::UtcNow.AddDays(-$OlderThanDays)
    }
    Write-Verbose 'Reading Message Center posts.'
    try {
        $posts = @(Invoke-GraphPaged -Uri ('{0}?{1}' -f $messagesUri, $query))
    }
    catch {
        # Fall back to the plain list if the service rejects the query options; the age filter is re-applied below.
        Write-Warning "Server-side query failed ($($_.Exception.Message)); reading the full message list instead."
        try { $posts = @(Invoke-GraphPaged -Uri $messagesUri) } catch { throw "Failed to read Message Center posts: $($_.Exception.Message)" }
    }
    $servicePattern = ConvertTo-WildcardPattern -Value $Service
    $tagPattern = ConvertTo-WildcardPattern -Value $Tag
    $cutoff = [datetime]::UtcNow.AddDays(-$OlderThanDays)
    foreach ($post in $posts) {
        if ($PSBoundParameters.ContainsKey('OlderThanDays') -and $null -ne $post.lastModifiedDateTime) {
            if (([datetime]$post.lastModifiedDateTime).ToUniversalTime() -gt $cutoff) { continue }
        }
        if (-not [string]::IsNullOrWhiteSpace($Category) -and [string]$post.category -ne $Category) { continue }
        if ($null -ne $servicePattern -and @($post.services | Where-Object { $_ -like $servicePattern }).Count -eq 0) { continue }
        if ($null -ne $tagPattern -and @($post.tags | Where-Object { $_ -like $tagPattern }).Count -eq 0) { continue }
        if ($ReadOnly -and -not [bool]$post.viewPoint.isRead) { continue }
        if ($UnreadOnly -and [bool]$post.viewPoint.isRead) { continue }
        $candidates.Add($post)
    }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$targets = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($post in $candidates) {
    $state = 'Pending'
    if ($null -ne $post.viewPoint -and [bool]$post.viewPoint.($selected.Flag) -eq $selected.Value) { $state = 'AlreadyInState' } else { $targets.Add($post) }
    $results.Add([PSCustomObject]@{ Id = $post.id; Title = $post.title; Category = $post.category; Action = $Action; Result = $state })
}
Write-Host ''
Write-Host ('Message Center triage: {0}' -f $Action) -ForegroundColor Cyan
Write-Host ('  Posts selected       : {0}' -f $candidates.Count)
Write-Host ('  Already in state     : {0}' -f ($candidates.Count - $targets.Count))

if ($targets.Count -gt 0) {
    $preview = @($targets | Select-Object -First 5 | ForEach-Object { $_.id }) -join ', '
    if ($targets.Count -gt 5) { $preview += ', ...' }
    $outcome = 'Skipped'
    if ($PSCmdlet.ShouldProcess(('{0} Message Center post(s): {1}' -f $targets.Count, $preview), $Action)) {
        $outcome = 'Applied'
        # The bulk endpoints accept a list of IDs; 50 per call keeps requests small and limits the blast radius of a failure.
        for ($offset = 0; $offset -lt $targets.Count; $offset += 50) {
            $batch = @($targets | Select-Object -Skip $offset -First 50)
            $batchIds = @($batch | ForEach-Object { $_.id })
            $batchResult = 'Applied'
            try {
                $body = @{ messageIds = $batchIds } | ConvertTo-Json -Compress
                Invoke-MgGraphRequest -Method POST -Uri ('{0}/{1}' -f $messagesUri, $selected.Endpoint) -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
            }
            catch {
                $batchResult = 'Failed: ' + $_.Exception.Message
                Write-Warning "Batch starting at post $offset failed: $($_.Exception.Message)"
            }
            foreach ($row in @($results | Where-Object { $batchIds -contains $_.Id })) { $row.Result = $batchResult }
        }
    }
    foreach ($row in @($results | Where-Object { $_.Result -eq 'Pending' })) { $row.Result = $outcome }
}

$appliedCount = @($results | Where-Object { $_.Result -eq 'Applied' }).Count
$failedCount = @($results | Where-Object { $_.Result -like 'Failed*' }).Count
Write-Host ('  Applied              : {0}' -f $appliedCount) -ForegroundColor Green
if ($failedCount -gt 0) { Write-Host ('  Failed               : {0}' -f $failedCount) -ForegroundColor Red }
if ($WhatIfPreference) { Write-Host ('  WhatIf               : {0} post(s) would be changed' -f $targets.Count) -ForegroundColor Yellow }

$results
#endregion Main
