<#
.SYNOPSIS
    Exports a digest of Microsoft 365 Message Center posts (CSV and optional HTML) with action deadlines, tags, services and links.
.DESCRIPTION
    Reads the Message Center posts modified in the last -DaysBack days from /admin/serviceAnnouncement/messages
    (Microsoft Graph v1.0, server-side $filter and $orderby on lastModifiedDateTime) and exports one row per post with
    category, severity, services, tags, major-change flag, action-required date and days left, read/archived/favorite
    state of the signed-in admin, a plain-text summary, roadmap IDs and the blog or external link. Posts can be filtered
    by service, category, tag, action required, major changes or unread state. -HtmlPath writes a digest grouped by
    category with a link to every post in the admin center, ready to paste into a change-advisory mail or wiki.
.PARAMETER DaysBack
    Keep posts whose lastModifiedDateTime is within the last N days. Default 30, maximum 365.
.PARAMETER Service
    Wildcard filter on the affected services, for example 'Microsoft Intune' or '*SharePoint*'. A value without wildcards is matched as *value*.
.PARAMETER Category
    Keep only planForChange, stayInformed or preventOrFixIssue posts.
.PARAMETER Tag
    Wildcard filter on the tags, for example 'Admin impact', 'User impact', 'New feature', 'Retirement' or 'Updated message'.
.PARAMETER ActionRequiredOnly
    Keep only posts that have an actionRequiredByDateTime.
.PARAMETER MajorChangesOnly
    Keep only posts flagged as major change.
.PARAMETER UnreadOnly
    Keep only posts the signed-in admin has not read yet (viewPoint.isRead = false).
.PARAMETER HtmlPath
    Path of an HTML digest grouped by category with admin center links. Not written when omitted.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\M365MessageCenterDigest_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the post objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365MessageCenterDigest.ps1
    Exports every post updated in the last 30 days and prints counts per category, deadlines within 30 days and unread posts.
.EXAMPLE
    PS> .\Get-M365MessageCenterDigest.ps1 -DaysBack 14 -Service 'Microsoft Intune' -Tag 'Admin impact' -HtmlPath C:\Temp\IntuneDigest.html
    Builds a two-week Intune digest of posts with admin impact as HTML for the weekly change-advisory mail.
.EXAMPLE
    PS> .\Get-M365MessageCenterDigest.ps1 -Category planForChange -ActionRequiredOnly -PassThru | Sort-Object DaysUntilAction
    Lists the planned changes that still need an admin action, soonest deadline first.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : ServiceMessage.Read.All (delegated). The signed-in user needs a role that can read the Message Center,
                  for example Message Center Reader, Service Support Administrator or Global Reader.
    Category    : Tenant configuration & health
    Changes     : No
    Notes       : All date/time values are UTC. Read, archived and favorite flags come from viewPoint and are per admin,
                  so they are empty for app-only sign-ins. Only posts for services the tenant is subscribed to are
                  returned. Use Invoke-M365MessageCenterTriage.ps1 from this folder to mark, archive or favorite posts in bulk.
.LINK
    https://learn.microsoft.com/graph/api/serviceannouncement-list-messages
.LINK
    https://learn.microsoft.com/graph/api/resources/serviceupdatemessage
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [Parameter()]
    [string]$Service,

    [Parameter()]
    [ValidateSet('planForChange', 'stayInformed', 'preventOrFixIssue')]
    [string]$Category,

    [Parameter()]
    [string]$Tag,

    [Parameter()]
    [switch]$ActionRequiredOnly,

    [Parameter()]
    [switch]$MajorChangesOnly,

    [Parameter()]
    [switch]$UnreadOnly,

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

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; $null when empty. #>
    param([Parameter()][AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
    }
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $parsed }
    return $null
}

function ConvertFrom-Html {
    <# Turns an HTML fragment into single-line plain text (tags stripped, entities decoded) and truncates it. #>
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$Html, [Parameter()][int]$MaxLength = 0)
    if ([string]::IsNullOrWhiteSpace($Html)) { return $null }
    $text = $Html -replace '(?i)<br\s*/?>|</p>|</li>|</div>|</tr>|</h[1-6]>', ' '
    $text = [System.Net.WebUtility]::HtmlDecode(($text -replace '<[^>]+>', ''))
    $text = ($text -replace '\s+', ' ').Trim()
    if ($MaxLength -gt 3 -and $text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength - 3) + '...' }
    return $text
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
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365MessageCenterDigest_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
foreach ($path in @($OutputPath, $HtmlPath)) {
    $folder = $null
    if (-not [string]::IsNullOrWhiteSpace($path)) { $folder = Split-Path -Path $path -Parent }
    if (-not [string]::IsNullOrWhiteSpace($folder) -and -not (Test-Path -Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
}

try {
    Connect-GraphIfNeeded -Scopes @('ServiceMessage.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$nowUtc = [datetime]::UtcNow
$since = $nowUtc.AddDays(-$DaysBack)
$servicePattern = ConvertTo-WildcardPattern -Value $Service
$tagPattern = ConvertTo-WildcardPattern -Value $Tag
$messagesUri = 'https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/messages'
Write-Verbose "Reading Message Center posts modified since $($since.ToString('u'))."
try {
    $messages = @(Invoke-GraphPaged -Uri ('{0}?$filter=lastModifiedDateTime ge {1:yyyy-MM-ddTHH:mm:ssZ}&$orderby=lastModifiedDateTime desc' -f $messagesUri, $since))
}
catch {
    # Fall back to the unfiltered list if the service rejects the query options; the window is re-applied below.
    Write-Warning "Server-side filter failed ($($_.Exception.Message)); reading the full message list instead."
    try { $messages = @(Invoke-GraphPaged -Uri $messagesUri) } catch { throw "Failed to read Message Center posts: $($_.Exception.Message)" }
}

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($message in $messages) {
    $lastModified = ConvertTo-UtcDateTime -Value $message.lastModifiedDateTime
    if ($null -ne $lastModified -and $lastModified -lt $since) { continue }
    if (-not [string]::IsNullOrWhiteSpace($Category) -and [string]$message.category -ne $Category) { continue }
    if ($MajorChangesOnly -and -not [bool]$message.isMajorChange) { continue }
    if ($UnreadOnly -and [bool]$message.viewPoint.isRead) { continue }
    $services = @($message.services | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $tags = @($message.tags | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($null -ne $servicePattern -and @($services | Where-Object { $_ -like $servicePattern }).Count -eq 0) { continue }
    if ($null -ne $tagPattern -and @($tags | Where-Object { $_ -like $tagPattern }).Count -eq 0) { continue }
    $actionRequiredBy = ConvertTo-UtcDateTime -Value $message.actionRequiredByDateTime
    if ($ActionRequiredOnly -and $null -eq $actionRequiredBy) { continue }
    $daysUntilAction = $null
    if ($null -ne $actionRequiredBy) { $daysUntilAction = [int][math]::Ceiling(($actionRequiredBy - $nowUtc).TotalDays) }
    $details = @($message.details)
    $url = @($details | Where-Object { $_.name -in @('BlogLink', 'ExternalLink') -and -not [string]::IsNullOrWhiteSpace($_.value) } | Select-Object -First 1).value

    $rows.Add([PSCustomObject]@{
            Id                       = $message.id
            Title                    = $message.title
            Category                 = $message.category
            Severity                 = $message.severity
            Services                 = ($services -join '; ')
            Tags                     = ($tags -join '; ')
            IsMajorChange            = [bool]$message.isMajorChange
            ActionRequiredByDateTime = $actionRequiredBy
            DaysUntilAction          = $daysUntilAction
            StartDateTime            = ConvertTo-UtcDateTime -Value $message.startDateTime
            LastModifiedDateTime     = $lastModified
            IsRead                   = $message.viewPoint.isRead
            IsArchived               = $message.viewPoint.isArchived
            IsFavorited              = $message.viewPoint.isFavorited
            HasAttachments           = [bool]$message.hasAttachments
            Summary                  = ConvertFrom-Html -Html ([string]$message.body.content) -MaxLength 400
            RoadmapIds               = (@($details | Where-Object { $_.name -eq 'RoadmapIds' } | ForEach-Object { $_.value }) -join '; ')
            Url                      = $url
        })
}
# Deadlines first (soonest on top), then the rest by last update.
$deadlineFirst = @{ Expression = { if ($null -eq $_.DaysUntilAction) { [int]::MaxValue } else { $_.DaysUntilAction } } }
$output = @($rows | Sort-Object -Property $deadlineFirst, @{ Expression = 'LastModifiedDateTime'; Descending = $true })
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No Message Center posts matched the filters; no CSV was written.' }

$categoryNames = [ordered]@{ planForChange = 'Plan for change'; preventOrFixIssue = 'Prevent or fix issues'; stayInformed = 'Stay informed' }
if (-not [string]::IsNullOrWhiteSpace($HtmlPath)) {
    $html = New-Object -TypeName System.Text.StringBuilder
    [void]$html.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Microsoft 365 Message Center digest</title><style>')
    [void]$html.AppendLine('body{font-family:"Segoe UI",Arial,sans-serif;margin:24px;color:#222}h2{border-bottom:1px solid #ccc;margin-top:28px}')
    [void]$html.AppendLine('article{margin:12px 0;padding:10px 12px;border-left:4px solid #0078d4;background:#f7f9fb}article.high{border-color:#d83b01}')
    [void]$html.AppendLine('article.critical{border-color:#a4262c}.meta{color:#555;font-size:.9em}')
    [void]$html.AppendLine('.tag{background:#e1e8f0;border-radius:3px;padding:1px 6px;margin-right:4px;font-size:.85em}</style></head><body>')
    [void]$html.AppendLine(('<h1>Microsoft 365 Message Center digest</h1><p class="meta">{0} posts updated in the last {1} days; generated {2:yyyy-MM-dd HH:mm} UTC</p>' -f
            $output.Count, $DaysBack, $nowUtc))
    foreach ($categoryKey in $categoryNames.Keys) {
        $posts = @($output | Where-Object { $_.Category -eq $categoryKey })
        if ($posts.Count -eq 0) { continue }
        [void]$html.AppendLine(('<h2>{0} ({1})</h2>' -f $categoryNames[$categoryKey], $posts.Count))
        foreach ($post in $posts) {
            $meta = @(('Services: ' + $post.Services), ('Severity: ' + $post.Severity), ('Updated: {0:yyyy-MM-dd}' -f $post.LastModifiedDateTime))
            if ($null -ne $post.ActionRequiredByDateTime) { $meta += ('Action required by {0:yyyy-MM-dd} ({1} days)' -f $post.ActionRequiredByDateTime, $post.DaysUntilAction) }
            if ($post.IsMajorChange) { $meta += 'Major change' }
            $tagHtml = @($post.Tags -split '; ' | Where-Object { $_ } | ForEach-Object { '<span class="tag">{0}</span>' -f [System.Net.WebUtility]::HtmlEncode($_) }) -join ''
            $link = 'https://admin.microsoft.com/#/MessageCenter/:/messages/{0}' -f $post.Id
            [void]$html.AppendLine(('<article class="{0}"><strong><a href="{1}">{2}</a></strong> <span class="meta">{3}</span>' -f
                    $post.Severity, $link, [System.Net.WebUtility]::HtmlEncode($post.Title), $post.Id))
            [void]$html.AppendLine(('<div class="meta">{0}</div><div>{1}</div><p>{2}</p>' -f
                    [System.Net.WebUtility]::HtmlEncode(($meta -join ' | ')), $tagHtml, [System.Net.WebUtility]::HtmlEncode($post.Summary)))
            if (-not [string]::IsNullOrWhiteSpace($post.Url)) {
                [void]$html.AppendLine(('<p class="meta"><a href="{0}">{0}</a></p>' -f [System.Net.WebUtility]::HtmlEncode($post.Url)))
            }
            [void]$html.AppendLine('</article>')
        }
    }
    [void]$html.AppendLine('</body></html>')
    $html.ToString() | Set-Content -Path $HtmlPath -Encoding UTF8
}

$dueSoon = @($output | Where-Object { $null -ne $_.DaysUntilAction -and $_.DaysUntilAction -le 30 })
Write-Host ''
Write-Host 'Message Center digest summary' -ForegroundColor Cyan
Write-Host ('  Posts exported        : {0} -> {1}' -f $output.Count, $OutputPath)
foreach ($categoryKey in $categoryNames.Keys) {
    Write-Host ('    {0,-24} {1,4}' -f $categoryNames[$categoryKey], @($output | Where-Object { $_.Category -eq $categoryKey }).Count)
}
Write-Host ('  High / critical       : {0}' -f @($output | Where-Object { $_.Severity -in @('high', 'critical') }).Count)
Write-Host ('  Major changes         : {0}' -f @($output | Where-Object { $_.IsMajorChange }).Count)
Write-Host ('  Unread                : {0}' -f @($output | Where-Object { $_.IsRead -eq $false }).Count)
$dueColor = 'Green'
if ($dueSoon.Count -gt 0) { $dueColor = 'Yellow' }
Write-Host ('  Action due in 30 days : {0}' -f $dueSoon.Count) -ForegroundColor $dueColor
foreach ($post in ($dueSoon | Sort-Object -Property DaysUntilAction)) {
    Write-Host ('    {0,-10} due in {1,4} days  {2}' -f $post.Id, $post.DaysUntilAction, $post.Title)
}
if (-not [string]::IsNullOrWhiteSpace($HtmlPath)) { Write-Host ('  HTML digest           : {0}' -f $HtmlPath) }

if ($PassThru) { $output }
#endregion Main
