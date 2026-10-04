<#
.SYNOPSIS
    Reports inbox rules of Exchange Online mailboxes, flags suspicious rules and can disable them.
.DESCRIPTION
    Runs Get-InboxRule once per selected mailbox and reports every rule with a summary of its actions and conditions.
    A rule is Suspicious when it deletes, hides, marks as read or forwards mail matching keywords (password, invoice,
    payment, hack, phish, mfa); moves mail to RSS Feeds, Conversation History or Archive; forwards outside the accepted
    domains; or has a one/two-character or punctuation-only name - the usual traces of business e-mail compromise.
    -Disable turns suspicious enabled rules off with Disable-InboxRule inside ShouldProcess. Writes a CSV report.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID).
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to report.
.PARAMETER IncludeHidden
    Also return hidden rules (Get-InboxRule -IncludeHidden), which attackers create through MAPI/EWS to evade Outlook.
.PARAMETER OnlySuspicious
    Export only rules marked Suspicious.
.PARAMETER Disable
    Disable every suspicious rule that is currently enabled. Supports -WhatIf / -Confirm.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOInboxRules_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOInboxRulesReport.ps1 -OnlySuspicious -IncludeHidden
    Scans every user mailbox (slow) and exports only suspicious rules, hidden ones included, to .\Reports\EXOInboxRules_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOInboxRulesReport.ps1 -Identity compromised.user@contoso.com -Disable
    Lists all rules of one mailbox and disables the suspicious ones after confirmation.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients or Global Reader for the report; Exchange Administrator (Mail Recipients role) for -Disable
    Category    : Mailbox content & settings
    Changes     : Optional (-Disable)
    Notes       : Get-InboxRule is a slow RPS cmdlet (one call per mailbox); tenant-wide runs take hours. Folder names are matched
                  in English. Disabling a rule server-side removes client-only Outlook rules of that mailbox (the Exchange prompt is
                  suppressed because ShouldProcess already confirmed). Check the audit log for who created a suspicious rule.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-inboxrule
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$IncludeHidden,

    [Parameter()]
    [switch]$OnlySuspicious,

    [Parameter()]
    [switch]$Disable,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-ExchangeIfNeeded {
    <# Connects to Exchange Online (or Security & Compliance PowerShell) only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Compliance
    )
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($Compliance) {
        $active = @($connections | Where-Object { $_.ConnectionUri -like '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Security & Compliance PowerShell.'
            Connect-IPPSSession -ErrorAction Stop
        }
    }
    else {
        $active = @($connections | Where-Object { $_.ConnectionUri -notlike '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
    }
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOInboxRules_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }
try { $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() }) }
catch { throw "Failed to read accepted domains: $($_.Exception.Message)" }

$selection = @()
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
elseif ($PSCmdlet.ParameterSetName -eq 'Identity') { $selection = @($Identity) }

$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($selection.Count -gt 0) {
    foreach ($id in $selection) {
        try { $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties DisplayName, UserPrincipalName -ErrorAction Stop)) }
        catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)" }
    }
}
else {
    Write-Warning 'No -Identity or -InputCsv specified: Get-InboxRule runs against every user mailbox in the tenant. This is slow and can take hours.'
    try { foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -ErrorAction Stop)) { $mailboxes.Add($mailbox) } }
    catch { throw "Failed to retrieve mailboxes: $($_.Exception.Message)" }
}

$keywords = @('password', 'invoice', 'payment', 'hack', 'phish', 'mfa')
$conditionNames = @('From', 'SentTo', 'SubjectContainsWords', 'SubjectOrBodyContainsWords', 'BodyContainsWords', 'FromAddressContainsWords', 'HasAttachment', 'MyNameInToBox', 'SentOnlyToMe')
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $upn = $mailbox.UserPrincipalName
    Write-Progress -Activity 'Reading inbox rules' -Status "$index of $($mailboxes.Count) - $upn" -PercentComplete (($index / $mailboxes.Count) * 100)
    try { $rules = @(Get-InboxRule -Mailbox $upn -IncludeHidden:$IncludeHidden -ErrorAction Stop) }
    catch { Write-Warning "Could not read the inbox rules of '$upn': $($_.Exception.Message)"; continue }

    foreach ($rule in $rules) {
        $actions = @()
        foreach ($flag in @('DeleteMessage', 'SoftDeleteMessage', 'MarkAsRead', 'StopProcessingRules')) { if ($rule.$flag) { $actions += $flag } }
        foreach ($name in @('MoveToFolder', 'ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo')) {
            if ($rule.$name) { $actions += ('{0}={1}' -f $name, (@($rule.$name | ForEach-Object { [string]$_ }) -join ', ')) }
        }
        $conditions = @()
        foreach ($name in $conditionNames) {
            $values = @($rule.$name | Where-Object { $null -ne $_ -and $_ -ne $false -and [string]$_ -ne '' })
            if ($values.Count -gt 0) { $conditions += ('{0}={1}' -f $name, (@($values | ForEach-Object { [string]$_ }) -join ', ')) }
        }
        # Forwarding targets look like "Name" [SMTP:user@domain] (or [EX:...] for internal recipients) or plain addresses.
        $external = @()
        foreach ($entry in @(@($rule.ForwardTo) + @($rule.ForwardAsAttachmentTo) + @($rule.RedirectTo) | ForEach-Object { [string]$_ })) {
            $text = $entry
            if ($text -match '(?i)\[SMTP:([^\]]+)\]') { $text = $Matches[1] }
            if ($text -match '^[^\s"\[\]]+@([^\s"\[\]]+)$' -and $acceptedDomains -notcontains $Matches[1].ToLowerInvariant()) { $external += $text }
        }
        $keywordHits = @($keywords | Where-Object { ((@($rule.SubjectContainsWords) + @($rule.SubjectOrBodyContainsWords) + @($rule.BodyContainsWords)) -join ' ') -match $_ })
        $folder = [string]$rule.MoveToFolder
        $hidesMail = ($folder -match '\\(RSS Feeds|RSS Subscriptions|Conversation History|Archive)$')
        $destroysMail = ($rule.DeleteMessage -or $rule.SoftDeleteMessage -or $folder -match '\\(Deleted Items|Junk Email)$')
        $riskyAction = ($destroysMail -or $hidesMail -or $rule.StopProcessingRules -or $rule.MarkAsRead -or $external.Count -gt 0)
        $reasons = @()
        if ($keywordHits.Count -gt 0 -and $riskyAction) { $reasons += ('Keyword(s) {0} with delete/hide/forward action' -f ($keywordHits -join ', ')) }
        if ($hidesMail) { $reasons += ('Moves mail to {0}' -f $folder.Substring($folder.LastIndexOf('\') + 1)) }
        if ($external.Count -gt 0) { $reasons += ('Forwards externally to {0}' -f ($external -join ', ')) }
        if (([string]$rule.Name).Trim().Length -le 2 -or $rule.Name -match '^[\W_]+$') { $reasons += 'Suspicious rule name' }
        $suspicious = ($reasons.Count -gt 0)
        if ($OnlySuspicious -and -not $suspicious) { continue }
        $result = 'Report only'
        if ($Disable -and $suspicious -and $rule.Enabled -and $PSCmdlet.ShouldProcess("$upn - rule '$($rule.Name)'", 'Disable inbox rule')) {
            try { Disable-InboxRule -Identity ([string]$rule.Identity) -Mailbox $upn -Confirm:$false -ErrorAction Stop; $result = 'Disabled' }
            catch { $result = "Failed: $($_.Exception.Message)"; Write-Warning "Could not disable rule '$($rule.Name)' in '$upn': $($_.Exception.Message)" }
        }
        elseif ($Disable -and $suspicious -and $rule.Enabled) { $result = 'Not confirmed' }
        $results.Add([PSCustomObject]@{
                DisplayName        = $mailbox.DisplayName
                UserPrincipalName  = $upn
                RuleName           = [string]$rule.Name
                Enabled            = [bool]$rule.Enabled
                Priority           = $rule.Priority
                Description        = (([string]$rule.Description -replace '\s+', ' ').Trim() -replace '(?s)^(.{300}).+', '$1...')
                Actions            = ($actions -join '; ')
                Conditions         = ($conditions -join '; ')
                ExternalRecipients = ($external -join '; ')
                Suspicious         = $suspicious
                Reasons            = ($reasons -join '; ')
                RuleIdentity       = [string]$rule.Identity
                Result             = $result
            })
    }
}
Write-Progress -Activity 'Reading inbox rules' -Completed

if ($results.Count -eq 0) { Write-Warning 'No inbox rules matched the selection; nothing to export.'; return }
$results | Sort-Object -Property @{ Expression = 'Suspicious'; Descending = $true }, UserPrincipalName, Priority | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$suspiciousRows = @($results | Where-Object { $_.Suspicious })
$affectedMailboxes = @($suspiciousRows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
$failed = @($results | Where-Object { $_.Result -like 'Failed*' }).Count
$disabled = @($results | Where-Object { $_.Result -eq 'Disabled' }).Count

Write-Host "Inbox rule summary ($($results.Count) rules in $($mailboxes.Count) mailboxes)" -ForegroundColor Cyan
Write-Host ('  Suspicious rules   : {0} in {1} mailboxes' -f $suspiciousRows.Count, $affectedMailboxes) -ForegroundColor $(if ($suspiciousRows.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($row in @($suspiciousRows | Select-Object -First 15)) {
    Write-Host ('    {0}  "{1}"  {2}' -f $row.UserPrincipalName, $row.RuleName, $row.Reasons) -ForegroundColor Yellow
}
if ($Disable) { Write-Host ('  Disabled / failed  : {0} / {1}' -f $disabled, $failed) -ForegroundColor $(if ($failed -gt 0) { 'Red' } else { 'Green' }) }
Write-Host ('  Report             : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
