<#
.SYNOPSIS
    Reports current Microsoft 365 service incidents and advisories and, optionally, Message Center changes that need action.
.DESCRIPTION
    Reads service health issues from /admin/serviceAnnouncement/issues and keeps the unresolved ones (or all
    with -IncludeResolved) that were modified in the last -DaysBack days, optionally limited to one service.
    Every issue is exported with its classification, status, timing, hours open, impact description and the
    latest post from Microsoft (HTML stripped). With -IncludeMessageCenter the Message Center posts from
    /admin/serviceAnnouncement/messages are exported to a second CSV named <OutputPath base>_MessageCenter.csv,
    with the action-required date and the days left to act. Prints active incidents by service, the number
    of advisories and the major changes that need action within 30 days.
.PARAMETER DaysBack
    Only keep issues and messages whose lastModifiedDateTime is within the last N days. Default 7.
.PARAMETER Service
    Wildcard filter on the service name, for example 'Microsoft Intune', 'Exchange Online' or '*Teams*'.
    A value without wildcards is matched as *value*. Applies to issues and Message Center posts.
.PARAMETER IncludeResolved
    Also keep issues that are already resolved (useful for post-incident reporting).
.PARAMETER IncludeMessageCenter
    Also export Message Center posts. Requests the ServiceMessage.Read.All scope.
.PARAMETER ActionRequiredOnly
    With -IncludeMessageCenter, keep only posts that have an actionRequiredByDateTime.
.PARAMETER OutputPath
    Path of the issues CSV file. Defaults to .\Reports\M365ServiceHealth_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the issue objects (and, with -IncludeMessageCenter, the message objects) to the pipeline.
.EXAMPLE
    PS> .\Get-M365ServiceHealthReport.ps1
    Exports the unresolved incidents and advisories updated in the last 7 days and lists active incidents per service.
.EXAMPLE
    PS> .\Get-M365ServiceHealthReport.ps1 -Service 'Microsoft Intune' -DaysBack 30 -IncludeResolved -Verbose
    Exports every Intune issue, resolved or not, that was updated in the last 30 days.
.EXAMPLE
    PS> .\Get-M365ServiceHealthReport.ps1 -IncludeMessageCenter -ActionRequiredOnly -DaysBack 60 -OutputPath C:\Temp\Health.csv
    Also writes C:\Temp\Health_MessageCenter.csv with the Message Center posts from the last 60 days that have an action deadline.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : ServiceHealth.Read.All (delegated), plus ServiceMessage.Read.All with -IncludeMessageCenter. The signed-in
                  user needs a role that can see service health, for example Service Support Administrator or Global Reader.
    Category    : Tenant configuration & health
    Changes     : No
    Notes       : All date/time values are UTC. The service announcement API only returns issues and messages for
                  services the tenant is subscribed to. Filtering is done client-side on purpose: the whole issue history
                  is a few hundred rows and it keeps the script independent of $filter support changes on this endpoint.
                  HoursOpen counts from startDateTime to endDateTime for resolved issues, otherwise to now.
.LINK
    https://learn.microsoft.com/graph/api/serviceannouncement-list-issues
.LINK
    https://learn.microsoft.com/graph/api/serviceannouncement-list-messages
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 7,

    [Parameter()]
    [string]$Service,

    [Parameter()]
    [switch]$IncludeResolved,

    [Parameter()]
    [switch]$IncludeMessageCenter,

    [Parameter()]
    [switch]$ActionRequiredOnly,

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
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )
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
    <# Turns the HTML body of an announcement into single-line plain text (tags stripped, entities decoded) and truncates it. #>
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Html,

        [Parameter()]
        [int]$MaxLength = 0
    )
    if ([string]::IsNullOrWhiteSpace($Html)) { return $null }
    # Block-level closings become spaces first so that words from adjacent paragraphs do not stick together.
    $text = $Html -replace '(?i)<br\s*/?>|</p>|</li>|</div>|</tr>|</h[1-6]>', ' '
    $text = $text -replace '<[^>]+>', ''
    $text = [System.Net.WebUtility]::HtmlDecode($text)
    $text = ($text -replace '\s+', ' ').Trim()
    if ($MaxLength -gt 3 -and $text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength - 3) + '...' }
    return $text
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365ServiceHealth_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
# Path.Combine tolerates an empty folder (bare file name in -OutputPath) where Join-Path would throw.
$messagesOutputPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_MessageCenter.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))

$scopes = @('ServiceHealth.Read.All')
if ($IncludeMessageCenter) { $scopes += 'ServiceMessage.Read.All' }
try {
    Connect-GraphIfNeeded -Scopes $scopes
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$nowUtc = [datetime]::UtcNow
$since = $nowUtc.AddDays(-$DaysBack)
$servicePattern = $null
if (-not [string]::IsNullOrWhiteSpace($Service)) {
    $servicePattern = $Service
    if ($servicePattern -notmatch '[\*\?]') { $servicePattern = "*$servicePattern*" }
}

Write-Verbose 'Reading service health issues.'
try {
    $issues = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/issues')
}
catch {
    throw "Failed to read service health issues: $($_.Exception.Message)"
}
Write-Verbose "Received $($issues.Count) issues; applying filters."

$issueRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($issue in $issues) {
    $isResolved = [bool]$issue.isResolved
    if ($isResolved -and -not $IncludeResolved) { continue }
    $lastModified = ConvertTo-UtcDateTime -Value $issue.lastModifiedDateTime
    if ($null -ne $lastModified -and $lastModified -lt $since) { continue }
    if ($null -ne $servicePattern -and [string]$issue.service -notlike $servicePattern) { continue }

    $start = ConvertTo-UtcDateTime -Value $issue.startDateTime
    $end = ConvertTo-UtcDateTime -Value $issue.endDateTime
    $hoursOpen = $null
    if ($null -ne $start) {
        $openUntil = $nowUtc
        if ($isResolved -and $null -ne $end) { $openUntil = $end }
        $hoursOpen = [math]::Round(($openUntil - $start).TotalHours, 1)
    }
    $latestUpdate = $null
    $latestPost = @($issue.posts | Where-Object { $null -ne $_ }) | Sort-Object -Property createdDateTime | Select-Object -Last 1
    if ($null -ne $latestPost) { $latestUpdate = ConvertFrom-Html -Html ([string]$latestPost.description.content) -MaxLength 500 }

    $issueRows.Add([PSCustomObject]@{
            Id                   = $issue.id
            Title                = $issue.title
            Service              = $issue.service
            Feature              = $issue.feature
            Classification       = $issue.classification
            Status               = $issue.status
            Origin               = $issue.origin
            StartDateTime        = $start
            LastModifiedDateTime = $lastModified
            EndDateTime          = $end
            IsResolved           = $isResolved
            HoursOpen            = $hoursOpen
            ImpactDescription    = ConvertFrom-Html -Html ([string]$issue.impactDescription) -MaxLength 300
            LatestUpdate         = $latestUpdate
        })
}
$issueOutput = @($issueRows | Sort-Object -Property IsResolved, @{ Expression = 'LastModifiedDateTime'; Descending = $true })
if ($issueOutput.Count -gt 0) {
    $issueOutput | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No service health issues matched the filters; no issues CSV was written.'
}

$messageRows = New-Object -TypeName System.Collections.Generic.List[object]
if ($IncludeMessageCenter) {
    Write-Verbose 'Reading Message Center posts.'
    try {
        $messages = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/messages')
    }
    catch {
        throw "Failed to read Message Center posts: $($_.Exception.Message)"
    }
    Write-Verbose "Received $($messages.Count) messages; applying filters."
    foreach ($message in $messages) {
        $lastModified = ConvertTo-UtcDateTime -Value $message.lastModifiedDateTime
        if ($null -ne $lastModified -and $lastModified -lt $since) { continue }
        $actionRequiredBy = ConvertTo-UtcDateTime -Value $message.actionRequiredByDateTime
        if ($ActionRequiredOnly -and $null -eq $actionRequiredBy) { continue }
        $services = @($message.services | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($null -ne $servicePattern -and @($services | Where-Object { $_ -like $servicePattern }).Count -eq 0) { continue }
        $daysUntilActionRequired = $null
        if ($null -ne $actionRequiredBy) { $daysUntilActionRequired = [int][math]::Ceiling(($actionRequiredBy - $nowUtc).TotalDays) }

        $messageRows.Add([PSCustomObject]@{
                Id                       = $message.id
                Title                    = $message.title
                Category                 = $message.category
                Severity                 = $message.severity
                Services                 = ($services -join ';')
                Tags                     = (@($message.tags | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ';')
                IsMajorChange            = [bool]$message.isMajorChange
                StartDateTime            = ConvertTo-UtcDateTime -Value $message.startDateTime
                LastModifiedDateTime     = $lastModified
                ActionRequiredByDateTime = $actionRequiredBy
                DaysUntilActionRequired  = $daysUntilActionRequired
                Summary                  = ConvertFrom-Html -Html ([string]$message.body.content) -MaxLength 500
            })
    }
    # Deadlines first (soonest on top), then the rest by last update.
    $deadlineFirst = @{ Expression = { if ($null -eq $_.DaysUntilActionRequired) { [int]::MaxValue } else { $_.DaysUntilActionRequired } } }
    $messageOutput = @($messageRows | Sort-Object -Property $deadlineFirst, @{ Expression = 'LastModifiedDateTime'; Descending = $true })
    if ($messageOutput.Count -gt 0) {
        $messageOutput | Export-Csv -Path $messagesOutputPath -NoTypeInformation -Encoding UTF8
    }
    else {
        Write-Warning 'No Message Center posts matched the filters; no Message Center CSV was written.'
    }
}

$activeIncidents = @($issueOutput | Where-Object { -not $_.IsResolved -and $_.Classification -eq 'incident' })
$advisories = @($issueOutput | Where-Object { $_.Classification -eq 'advisory' })
$incidentColor = 'Green'
if ($activeIncidents.Count -gt 0) { $incidentColor = 'Red' }
Write-Host ''
Write-Host 'Service health summary' -ForegroundColor Cyan
Write-Host ('  Window / service filter      : last {0} days / {1}' -f $DaysBack, $(if ($null -eq $servicePattern) { 'all services' } else { $servicePattern }))
Write-Host ('  Issues exported              : {0} -> {1}' -f $issueOutput.Count, $OutputPath)
Write-Host ('  Active incidents             : {0}' -f $activeIncidents.Count) -ForegroundColor $incidentColor
foreach ($group in @($activeIncidents | Group-Object -Property Service | Sort-Object -Property Count -Descending)) {
    Write-Host ('    {0,-40} {1,3}' -f $group.Name, $group.Count)
}
Write-Host ('  Advisories                   : {0}' -f $advisories.Count)
if ($IncludeMessageCenter) {
    $majorChangesDue = @($messageRows | Where-Object { $_.IsMajorChange -and $null -ne $_.DaysUntilActionRequired -and $_.DaysUntilActionRequired -le 30 })
    Write-Host ('  Message Center posts         : {0} -> {1}' -f $messageRows.Count, $messagesOutputPath)
    Write-Host ('  Major changes due in 30 days : {0}' -f $majorChangesDue.Count) -ForegroundColor Yellow
    foreach ($change in ($majorChangesDue | Sort-Object -Property DaysUntilActionRequired)) {
        Write-Host ('    {0,-10} due in {1,4} days  {2}' -f $change.Id, $change.DaysUntilActionRequired, $change.Title)
    }
}

if ($PassThru) {
    $issueOutput
    if ($IncludeMessageCenter) { $messageOutput }
}
#endregion Main
