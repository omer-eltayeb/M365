<#
.SYNOPSIS
    Sends a report by e-mail through Microsoft Graph, with CSV or HTML attachments and an optional inline table built from a CSV.
.DESCRIPTION
    Utility for scheduled reporting: builds a message with text or HTML body, inlines up to -MaxRows rows of a CSV as a styled
    HTML table, attaches files below 3 MB as base64 fileAttachment objects and sends it with POST /me/sendMail or, with -From,
    POST /users/{from}/sendMail (shared mailbox or another user; the signed-in account needs Send As rights or the app needs
    Mail.Send). Larger attachments are skipped with a warning when -SkipLarge is set, otherwise they stop the script. The send
    runs inside ShouldProcess, so -WhatIf shows recipients, size and attachments without sending. Returns one summary object.
.PARAMETER To
    One or more recipient addresses.
.PARAMETER Cc
    Optional carbon-copy addresses.
.PARAMETER Subject
    Message subject.
.PARAMETER Body
    Plain-text body. Line breaks are kept.
.PARAMETER BodyHtmlPath
    HTML file used as the body instead of -Body.
.PARAMETER SummaryFromCsv
    CSV whose first -MaxRows rows are rendered as an HTML table under the body (the full CSV is a good -Attachments candidate).
.PARAMETER MaxRows
    Rows of -SummaryFromCsv to inline. Default 50.
.PARAMETER Attachments
    Files to attach. Each must be smaller than 3 MB (Graph limit for inline attachments on sendMail).
.PARAMETER SkipLarge
    Skip attachments of 3 MB or more with a warning instead of failing.
.PARAMETER From
    UPN of the mailbox to send from, for example a shared reports mailbox. Defaults to the signed-in user.
.PARAMETER SaveToSentItems
    Keep a copy in the Sent Items folder of the sending mailbox.
.EXAMPLE
    PS> .\Send-M365ReportByEmail.ps1 -To it-ops@contoso.com -Subject 'Stale devices' -SummaryFromCsv .\Reports\Stale.csv -Attachments .\Reports\Stale.csv
    Sends the first 50 rows as a table in the body and attaches the complete CSV.
.EXAMPLE
    PS> .\Send-M365ReportByEmail.ps1 -To ciso@contoso.com -Cc it-ops@contoso.com -Subject 'Scorecard' -BodyHtmlPath .\Scorecard.html -From reports@contoso.com -SaveToSentItems -Confirm:$false
    Sends an HTML page as the body from the shared reports mailbox without prompting (for scheduled tasks).
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Mail.Send (delegated or application); Mail.Send.Shared is requested in addition when -From is used with a
                  delegated session, and the signed-in user needs Send As (or Send on Behalf) on that mailbox.
    Category    : User lifecycle & tenant hygiene
    Changes     : Yes
    Notes       : Graph rejects sendMail requests above about 4 MB in total; base64 inflates attachments by a third, hence the
                  3 MB limit per file. For bigger files share a OneDrive or SharePoint link instead. For unattended use create an
                  app registration with New-M365GraphAppRegistrationForAutomation.ps1 and restrict Mail.Send with an Exchange
                  application access policy to the reports mailbox.
.LINK
    https://learn.microsoft.com/graph/api/user-sendmail
.LINK
    https://learn.microsoft.com/graph/api/resources/fileattachment
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$To,

    [Parameter()]
    [string[]]$Cc,

    [Parameter(Mandatory = $true)]
    [string]$Subject,

    [Parameter()]
    [string]$Body,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$BodyHtmlPath,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$SummaryFromCsv,

    [Parameter()]
    [ValidateRange(1, 1000)]
    [int]$MaxRows = 50,

    [Parameter()]
    [string[]]$Attachments,

    [Parameter()]
    [switch]$SkipLarge,

    [Parameter()]
    [string]$From,

    [Parameter()]
    [switch]$SaveToSentItems
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

function Get-ContentTypeForFile {
    param([string]$Path)
    switch ([System.IO.Path]::GetExtension($Path).ToLowerInvariant()) {
        '.csv' { return 'text/csv' }
        '.html' { return 'text/html' }
        '.htm' { return 'text/html' }
        '.json' { return 'application/json' }
        '.txt' { return 'text/plain' }
        '.pdf' { return 'application/pdf' }
        '.zip' { return 'application/zip' }
        '.xlsx' { return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }
        default { return 'application/octet-stream' }
    }
}
#endregion Helpers

#region Main
$maxAttachmentBytes = 3MB
if ([string]::IsNullOrWhiteSpace($Body) -and [string]::IsNullOrWhiteSpace($BodyHtmlPath) -and [string]::IsNullOrWhiteSpace($SummaryFromCsv)) {
    throw 'Provide a message body with -Body, -BodyHtmlPath or -SummaryFromCsv.'
}
$context = Get-MgContext
$scopes = @('Mail.Send')
if (-not [string]::IsNullOrWhiteSpace($From) -and ($null -eq $context -or $context.AuthType -ne 'AppOnly')) { $scopes += 'Mail.Send.Shared' }
try { Connect-GraphIfNeeded -Scopes $scopes } catch { throw "Could not connect to Microsoft Graph: $($_.Exception.Message)" }

# Body: HTML when an HTML file or a CSV table is involved, otherwise plain text.
$isHtml = -not [string]::IsNullOrWhiteSpace($BodyHtmlPath) -or -not [string]::IsNullOrWhiteSpace($SummaryFromCsv)
if (-not [string]::IsNullOrWhiteSpace($BodyHtmlPath)) { $content = Get-Content -Path $BodyHtmlPath -Raw }
elseif ($isHtml -and -not [string]::IsNullOrWhiteSpace($Body)) { $content = '<p>' + ([System.Net.WebUtility]::HtmlEncode($Body) -replace "`r?`n", '<br/>') + '</p>' }
else { $content = [string]$Body }
if (-not [string]::IsNullOrWhiteSpace($SummaryFromCsv)) {
    $allRows = @(Import-Csv -Path $SummaryFromCsv)
    $table = $allRows | Select-Object -First $MaxRows | ConvertTo-Html -Fragment
    $cellStyle = 'border:1px solid #d0d0d0;padding:4px 8px;text-align:left;font-family:Segoe UI,Arial,sans-serif;font-size:12px'
    $table = ($table -join "`n") -replace '<table>', '<table style="border-collapse:collapse">'
    $table = $table -replace '<th>', "<th style=`"$cellStyle;background:#f3f3f3`">" -replace '<td>', "<td style=`"$cellStyle`">"
    $caption = '<p style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#666">{0}: showing {1} of {2} rows</p>' -f
        (Split-Path -Path $SummaryFromCsv -Leaf), [math]::Min($MaxRows, $allRows.Count), $allRows.Count
    $content = $content + $caption + $table
}

$attachmentObjects = @()
$totalBytes = 0
foreach ($path in @($Attachments)) {
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    $file = Get-Item -Path $path -ErrorAction Stop
    if ($file.Length -ge $maxAttachmentBytes) {
        if ($SkipLarge) { Write-Warning "$($file.Name) is $([math]::Round($file.Length / 1MB, 1)) MB and exceeds the 3 MB inline limit; skipped."; continue }
        throw "$($file.Name) is $([math]::Round($file.Length / 1MB, 1)) MB; inline attachments must stay below 3 MB (use -SkipLarge or share a link)."
    }
    $totalBytes += $file.Length
    $attachmentObjects += @{
        '@odata.type' = '#microsoft.graph.fileAttachment'
        name          = $file.Name
        contentType   = Get-ContentTypeForFile -Path $file.FullName
        contentBytes  = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($file.FullName))
    }
}
if ($totalBytes -gt $maxAttachmentBytes) { Write-Warning "Attachments total $([math]::Round($totalBytes / 1MB, 1)) MB; Graph may reject the request above about 4 MB including base64 overhead." }

$message = @{
    subject      = $Subject
    body         = @{ contentType = $(if ($isHtml) { 'HTML' } else { 'Text' }); content = $content }
    toRecipients = @($To | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
}
if (@($Cc).Count -gt 0) { $message['ccRecipients'] = @($Cc | ForEach-Object { @{ emailAddress = @{ address = $_ } } }) }
if ($attachmentObjects.Count -gt 0) { $message['attachments'] = $attachmentObjects }
$graphBase = 'https://graph.microsoft.com/v1.0'
$sender = if ([string]::IsNullOrWhiteSpace($From)) { 'me' } else { $From }
$sendUri = if ($sender -eq 'me') { "$graphBase/me/sendMail" } else { "$graphBase/users/$([uri]::EscapeDataString($From))/sendMail" }
$payload = ConvertTo-Json -InputObject @{ message = $message; saveToSentItems = [bool]$SaveToSentItems } -Depth 8

$target = "$($To -join ', ') (subject '$Subject', $($attachmentObjects.Count) attachment(s), $([math]::Round($payload.Length / 1KB)) KB payload)"
$sent = $false
if ($PSCmdlet.ShouldProcess($target, "Send mail from $sender")) {
    try { Invoke-MgGraphRequest -Method POST -Uri $sendUri -Body $payload -ContentType 'application/json' -ErrorAction Stop | Out-Null; $sent = $true }
    catch { throw "sendMail failed: $($_.Exception.Message)" }
    Write-Host "Mail '$Subject' sent from $sender to $($To -join ', ')." -ForegroundColor Green
}
[PSCustomObject]@{
    Sent            = $sent
    From            = $sender
    To              = ($To -join ';')
    Cc              = (@($Cc) -join ';')
    Subject         = $Subject
    BodyType        = $(if ($isHtml) { 'HTML' } else { 'Text' })
    Attachments     = (@($attachmentObjects | ForEach-Object { $_.name }) -join ';')
    PayloadKB       = [math]::Round($payload.Length / 1KB)
    SaveToSentItems = [bool]$SaveToSentItems
}
#endregion Main
