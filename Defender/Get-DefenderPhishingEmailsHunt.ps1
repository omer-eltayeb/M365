<#
.SYNOPSIS
    Hunts phishing and malware emails detected by Defender for Office 365, with delivery outcome, policies applied and optional URL clicks.
.DESCRIPTION
    Runs an Advanced Hunting query through Microsoft Graph (POST v1.0 /security/runHuntingQuery) over EmailEvents where ThreatTypes contains
    Phish or Malware and returns one row per message: sender addresses and IP, recipient, subject, threat names, detection methods, delivery
    action and location, authentication results, confidence level, org- and user-level actions, attachment and URL counts. -OnlyDelivered keeps
    messages that reached a mailbox, -IncludeClicks joins UrlClickEvents, and -Summary exports a breakdown per domain, threat type, action and recipient.
.PARAMETER Days
    Timespan of the query in days (1-30, default 7).
.PARAMETER RecipientAddress
    Exact (case-insensitive) match on RecipientEmailAddress.
.PARAMETER SenderDomain
    Exact (case-insensitive) match on SenderFromDomain (the From: header domain).
.PARAMETER Subject
    Case-insensitive 'contains' match on Subject.
.PARAMETER OnlyDelivered
    Keeps messages with DeliveryAction Delivered and DeliveryLocation Inbox/folder or Junk folder, i.e. the ones users could open.
.PARAMETER Summary
    Exports Dimension/Name/Messages/Delivered rows per SenderFromDomain, ThreatTypes, DeliveryAction and the top 20 recipients. Ignores -IncludeClicks.
.PARAMETER IncludeClicks
    Left-joins UrlClickEvents on NetworkMessageId and adds ClickTime, Url, ClickAction and IsClickedThrough (one row per click).
.PARAMETER OutputPath
    CSV path. Defaults to .\Reports\DefenderPhishingEmailsHunt_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emits the rows to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderPhishingEmailsHunt.ps1 -OnlyDelivered -IncludeClicks
    Exports phishing and malware messages that landed in a mailbox during the last 7 days, together with any Safe Links clicks on them.
.EXAMPLE
    PS> .\Get-DefenderPhishingEmailsHunt.ps1 -Days 30 -Summary -OutputPath C:\Temp\PhishSummary.csv -PassThru | Where-Object { $_.Dimension -eq 'RecipientEmailAddress' }
    Builds a 30-day breakdown and shows the 20 most targeted recipients in the console.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : ThreatHunting.Read.All (delegated); the signed-in user also needs Security Reader or another Defender XDR role with advanced hunting access.
    Category    : Advanced hunting (Graph)
    Changes     : No
    Notes       : Advanced hunting caps results per query (10,000 rows in the portal, 100,000 through the API); -Days maps to the Timespan
                  property (P<n>D). EmailEvents and UrlClickEvents need Defender for Office 365 Plan 2; the summary is computed from the returned rows.
.LINK
    https://learn.microsoft.com/graph/api/security-security-runhuntingquery
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$Days = 7,

    [Parameter()]
    [string]$RecipientAddress,

    [Parameter()]
    [string]$SenderDomain,

    [Parameter()]
    [string]$Subject,

    [Parameter()]
    [switch]$OnlyDelivered,

    [Parameter()]
    [switch]$Summary,

    [Parameter()]
    [switch]$IncludeClicks,

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

function Invoke-HuntingQuery {
    <# Runs an Advanced Hunting KQL query through Microsoft Graph and returns the result rows. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$Days = 7
    )
    $body = @{ Query = $Query; Timespan = ('P{0}D' -f $Days) }
    $response = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' -OutputType PSObject -ErrorAction Stop
    if ($null -eq $response.results) { return @() }
    return @($response.results)
}

function ConvertTo-ReportRow {
    <# Copies one hunting result row into a PSCustomObject in projection order: dynamic arrays joined with '; ', ISO timestamps as UTC [datetime]. #>
    param([Parameter(Mandatory = $true)][object]$Row)
    $shaped = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [array]) { $value = @($value | ForEach-Object { if ($_ -is [string] -or $_ -is [ValueType]) { [string]$_ } else { $_ | ConvertTo-Json -Compress } }) -join '; ' }
        elseif ($value -is [string] -and $value -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}') { $value = [datetime]::Parse($value, [cultureinfo]::InvariantCulture, 'AdjustToUniversal') }
        $shaped[$property.Name] = $value
    }
    return [PSCustomObject]$shaped
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderPhishingEmailsHunt_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('ThreatHunting.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

# Backslash and single quote are escaped so user values are safe KQL string literals.
$filters = @()
if (-not [string]::IsNullOrWhiteSpace($RecipientAddress)) { $filters += "| where RecipientEmailAddress =~ '{0}'" -f $RecipientAddress.Replace('\', '\\').Replace("'", "\'") }
if (-not [string]::IsNullOrWhiteSpace($SenderDomain)) { $filters += "| where SenderFromDomain =~ '{0}'" -f $SenderDomain.Replace('\', '\\').Replace("'", "\'") }
if (-not [string]::IsNullOrWhiteSpace($Subject)) { $filters += "| where Subject contains '{0}'" -f $Subject.Replace('\', '\\').Replace("'", "\'") }
if ($OnlyDelivered) { $filters += "| where DeliveryAction == 'Delivered' and DeliveryLocation in ('Inbox/folder','Junk folder')" }
$withClicks = $IncludeClicks -and -not $Summary
$clickJoin = if ($withClicks) { '| join kind=leftouter (UrlClickEvents | project NetworkMessageId, ClickTime=Timestamp, Url, ClickAction=ActionType, IsClickedThrough) on NetworkMessageId' }
$clickColumns = if ($withClicks) { ', ClickTime, Url, ClickAction, IsClickedThrough' }
$query = @"
EmailEvents
| where ThreatTypes has_any ('Phish','Malware')
$($filters -join "`n")
$clickJoin
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, SenderFromDomain, SenderIPv4, RecipientEmailAddress, Subject, ThreatTypes, ThreatNames,
    DetectionMethods, DeliveryAction, DeliveryLocation, AuthenticationDetails, ConfidenceLevel, OrgLevelAction, OrgLevelPolicy, UserLevelAction, AttachmentCount, UrlCount, EmailDirection$clickColumns
| order by Timestamp desc
"@
try { $rows = @(Invoke-HuntingQuery -Query $query -Days $Days) }
catch { throw "Advanced hunting query failed: $($_.Exception.Message)" }
if ($rows.Count -eq 0) { Write-Warning ('No phishing or malware emails matched in the last {0} day(s); nothing exported.' -f $Days); return }
$messages = @(foreach ($row in $rows) { ConvertTo-ReportRow -Row $row })
$report = $messages
if ($Summary) {
    $report = @(foreach ($dimension in @('SenderFromDomain', 'ThreatTypes', 'DeliveryAction', 'RecipientEmailAddress')) {
        $top = if ($dimension -eq 'RecipientEmailAddress') { 20 } else { [int]::MaxValue }
        foreach ($group in ($messages | Group-Object -Property $dimension | Sort-Object -Property Count -Descending | Select-Object -First $top)) {
            [PSCustomObject]@{ Dimension = $dimension; Name = $group.Name; Messages = $group.Count; Delivered = @($group.Group | Where-Object { $_.DeliveryAction -eq 'Delivered' }).Count }
        }
    })
}
$report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$messageCount = @($messages | Select-Object -ExpandProperty NetworkMessageId -Unique).Count
$delivered = @($messages | Where-Object { $_.DeliveryAction -eq 'Delivered' } | Select-Object -ExpandProperty NetworkMessageId -Unique).Count
Write-Host ('Phishing and malware emails (last {0} days): {1} message(s), {2} delivered to a mailbox' -f $Days, $messageCount, $delivered) -ForegroundColor Cyan
if ($withClicks) { Write-Host ('  Safe Links clicks on these messages: {0}' -f @($messages | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ClickAction) }).Count) -ForegroundColor Yellow }
foreach ($dimension in @('SenderFromDomain', 'ThreatTypes', 'DeliveryAction')) {
    $parts = $messages | Group-Object -Property $dimension | Sort-Object -Property Count -Descending | Select-Object -First 5 | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }
    Write-Host ('  {0,-17}: {1}' -f $dimension, (@($parts) -join ' | ')) -ForegroundColor Yellow
}
Write-Host ('  Report -> {0}' -f $OutputPath)
if ($PassThru) { $report }
#endregion Main
