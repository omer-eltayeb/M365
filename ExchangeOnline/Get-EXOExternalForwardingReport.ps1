<#
.SYNOPSIS
    Finds mail leaving the tenant through mailbox forwarding or inbox rules, and optionally removes it.
.DESCRIPTION
    Builds the list of accepted domains with Get-AcceptedDomain and treats every other domain as external.
    For each mailbox it checks (a) mailbox-level forwarding (ForwardingSmtpAddress and ForwardingAddress, the
    latter resolved with Get-EXORecipient so mail contacts and mail users that point outside are detected) and
    (b) inbox rules (Get-InboxRule) that forward, forward as attachment or redirect to external recipients - the
    classic business email compromise (BEC) persistence technique.
    One row per finding is written to CSV. With -Remediate (and confirmation) offending inbox rules are
    disabled and mailbox-level forwarding is cleared; the default is a read-only report.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID). When omitted, all user and
    shared mailboxes are scanned.
.PARAMETER IncludeInternalForwarding
    Also report forwarding to recipients inside the tenant (IsExternal = False). Internal rows are never remediated.
.PARAMETER Remediate
    Disable each external forwarding inbox rule (Disable-InboxRule) and clear mailbox-level forwarding
    (Set-Mailbox). Every change is wrapped in ShouldProcess, so -WhatIf and -Confirm work.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOExternalForwarding_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the finding objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOExternalForwardingReport.ps1
    Scans all user and shared mailboxes and writes every external forward to .\Reports\EXOExternalForwarding_<timestamp>.csv.
.EXAMPLE
    PS> .\Get-EXOExternalForwardingReport.ps1 -Identity finance@contoso.com -IncludeInternalForwarding -PassThru
    Lists every forward (internal and external) configured on one mailbox and returns the rows to the pipeline.
.EXAMPLE
    PS> .\Get-EXOExternalForwardingReport.ps1 -Remediate -WhatIf
    Shows which inbox rules would be disabled and which mailboxes would have forwarding cleared, without changing anything.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients for the report; Exchange Administrator (or Mail Recipients role) for -Remediate
    Category    : Mailbox content & settings
    Changes     : Optional (-Remediate)
    Notes       : Get-InboxRule is a per-mailbox call and is the slow part - expect 1-3 seconds per mailbox, so run
                  large tenants during off-hours. Changing inbox rules through PowerShell deletes any rules the user
                  previously turned off in Outlook, which is why Disable-InboxRule is called with -Force.
                  Prevention beats detection: block automatic forwarding in the Defender for Office 365 outbound spam
                  policy (Set-HostedOutboundSpamFilterPolicy -AutoForwardingMode Off), or use a mail flow (transport)
                  rule that rejects auto-forwarded messages sent to recipients outside the organization.
.LINK
    https://learn.microsoft.com/defender-office-365/outbound-spam-policies-external-email-forwarding
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-inboxrule
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$Identity,

    [Parameter()]
    [switch]$IncludeInternalForwarding,

    [Parameter()]
    [switch]$Remediate,

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

function Resolve-ForwardingTarget {
    <# Turns a forwarding entry - "Name" [SMTP:addr], "Name" [EX:legacyDN], smtp:addr or a recipient identity - into an SMTP address.
       Directory recipients are resolved through a cached Get-EXORecipient lookup so mail contacts and mail users expose their external address. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Entry
    )
    $text = $Entry.Trim() -replace '^smtp:', ''
    if ($text -match '\[SMTP:([^\]]+)\]') { return $Matches[1] }
    if ($text -match '^[^\s"@\[\]]+@[^\s"@\[\]]+$') { return $text }

    $lookupKey = $text
    if ($text -match '\[EX:([^\]]+)\]') { $lookupKey = $Matches[1] }
    if (-not $script:RecipientCache.ContainsKey($lookupKey)) {
        $resolved = $text
        try {
            $recipientParams = @{ Properties = 'PrimarySmtpAddress', 'ExternalEmailAddress'; ErrorAction = 'Stop' }
            if ($lookupKey -like '/o=*') {
                $recipientParams['Filter'] = "LegacyExchangeDN -eq '$lookupKey'"
            }
            else {
                $recipientParams['Identity'] = $lookupKey
            }
            $recipient = Get-EXORecipient @recipientParams | Select-Object -First 1
            if ($null -ne $recipient) {
                if (-not [string]::IsNullOrWhiteSpace($recipient.ExternalEmailAddress)) {
                    $resolved = ([string]$recipient.ExternalEmailAddress -replace '^smtp:', '')
                }
                elseif (-not [string]::IsNullOrWhiteSpace($recipient.PrimarySmtpAddress)) {
                    $resolved = [string]$recipient.PrimarySmtpAddress
                }
            }
        }
        catch {
            Write-Verbose "Could not resolve forwarding recipient '$lookupKey': $($_.Exception.Message)"
        }
        $script:RecipientCache[$lookupKey] = $resolved
    }
    return $script:RecipientCache[$lookupKey]
}

function Test-ExternalAddress {
    <# True when the value is an SMTP address whose domain is not an accepted domain of the tenant. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Address
    )
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    if ($Address -match '^[^\s"@\[\]]+@([^\s"@\[\]]+)$') {
        return ($script:AcceptedDomains -notcontains $Matches[1].ToLowerInvariant())
    }
    # Unresolved directory entries ("Name" [EX:...]) stay inside the tenant and are not flagged.
    return $false
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOExternalForwarding_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

$script:RecipientCache = @{}
try {
    $script:AcceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() })
}
catch {
    throw "Failed to read accepted domains: $($_.Exception.Message)"
}
if ($script:AcceptedDomains.Count -eq 0) { throw 'Get-AcceptedDomain returned no domains; external recipients cannot be classified.' }
Write-Verbose "Accepted domains: $($script:AcceptedDomains -join ', ')"

$mailboxProperties = @('DisplayName', 'UserPrincipalName', 'PrimarySmtpAddress', 'RecipientTypeDetails', 'ForwardingAddress', 'ForwardingSmtpAddress', 'DeliverToMailboxAndForward')
$mailboxes = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSBoundParameters.ContainsKey('Identity')) {
    foreach ($id in $Identity) {
        try {
            $mailboxes.Add((Get-EXOMailbox -Identity $id -Properties $mailboxProperties -ErrorAction Stop))
        }
        catch {
            Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)"
        }
    }
}
else {
    try {
        foreach ($mailbox in (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox -Properties $mailboxProperties -ErrorAction Stop)) {
            $mailboxes.Add($mailbox)
        }
    }
    catch {
        throw "Failed to retrieve mailboxes: $($_.Exception.Message)"
    }
}
Write-Verbose "Scanning $($mailboxes.Count) mailbox(es)."

# Inbox-rule properties that send mail elsewhere, mapped to the FindingType they produce.
$ruleTargetTypes = @{ ForwardTo = 'InboxRuleForward'; ForwardAsAttachmentTo = 'InboxRuleForwardAsAttachment'; RedirectTo = 'InboxRuleRedirect' }
$findings = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($mailbox in $mailboxes) {
    $index++
    $status = '{0} of {1} - {2} ({3} findings so far)' -f $index, $mailboxes.Count, $mailbox.UserPrincipalName, $findings.Count
    Write-Progress -Activity 'Checking forwarding and inbox rules' -Status $status -PercentComplete (($index / $mailboxes.Count) * 100)

    $candidates = New-Object -TypeName System.Collections.Generic.List[object]
    if (-not [string]::IsNullOrWhiteSpace($mailbox.ForwardingSmtpAddress)) {
        $candidates.Add(@{ Type = 'MailboxForwardingSmtp'; Rule = $null; Entries = @([string]$mailbox.ForwardingSmtpAddress) })
    }
    if (-not [string]::IsNullOrWhiteSpace($mailbox.ForwardingAddress)) {
        $candidates.Add(@{ Type = 'MailboxForwardingRecipient'; Rule = $null; Entries = @([string]$mailbox.ForwardingAddress) })
    }

    try {
        $rules = @(Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not read inbox rules for '$($mailbox.UserPrincipalName)': $($_.Exception.Message)"
        $rules = @()
    }
    foreach ($rule in $rules) {
        foreach ($propertyName in $ruleTargetTypes.Keys) {
            $entries = @($rule.$propertyName | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
            if ($entries.Count -gt 0) {
                $candidates.Add(@{ Type = $ruleTargetTypes[$propertyName]; Rule = $rule; Entries = $entries })
            }
        }
    }

    foreach ($candidate in $candidates) {
        $addresses = @(foreach ($entry in $candidate.Entries) { Resolve-ForwardingTarget -Entry $entry })
        $external = @($addresses | Where-Object { Test-ExternalAddress -Address $_ })
        if ($external.Count -eq 0 -and -not $IncludeInternalForwarding) { continue }

        $rule = $candidate.Rule
        $description = $null
        if ($null -ne $rule -and -not [string]::IsNullOrWhiteSpace($rule.Description)) {
            $description = ([string]$rule.Description -replace '\s+', ' ').Trim()
            if ($description.Length -gt 300) { $description = $description.Substring(0, 300) }
        }
        $findings.Add([PSCustomObject]@{
                Mailbox                    = $mailbox.DisplayName
                UserPrincipalName          = $mailbox.UserPrincipalName
                FindingType                = $candidate.Type
                RuleName                   = $(if ($null -ne $rule) { [string]$rule.Name } else { $null })
                RuleIdentity               = $(if ($null -ne $rule) { [string]$rule.RuleIdentity } else { $null })
                RuleEnabled                = $(if ($null -ne $rule) { [bool]$rule.Enabled } else { $null })
                IsExternal                 = ($external.Count -gt 0)
                ExternalRecipients         = ($external -join ';')
                AllRecipients              = ($addresses -join ';')
                DeliverToMailboxAndForward = [bool]$mailbox.DeliverToMailboxAndForward
                RuleDescription            = $description
                Remediated                 = $false
            })
    }
}
Write-Progress -Activity 'Checking forwarding and inbox rules' -Completed

if ($Remediate) {
    $clearedMailboxes = @{}
    foreach ($finding in @($findings | Where-Object { $_.IsExternal })) {
        try {
            if ($finding.FindingType -like 'InboxRule*') {
                if ($finding.RuleEnabled -and $PSCmdlet.ShouldProcess($finding.UserPrincipalName, "Disable inbox rule '$($finding.RuleName)' forwarding to $($finding.ExternalRecipients)")) {
                    Disable-InboxRule -Identity $finding.RuleIdentity -Mailbox $finding.UserPrincipalName -Force -Confirm:$false -ErrorAction Stop
                    $finding.Remediated = $true
                }
            }
            elseif (-not $clearedMailboxes.ContainsKey($finding.UserPrincipalName)) {
                if ($PSCmdlet.ShouldProcess($finding.UserPrincipalName, "Clear mailbox forwarding to $($finding.ExternalRecipients)")) {
                    Set-Mailbox -Identity $finding.UserPrincipalName -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false -ErrorAction Stop
                    $clearedMailboxes[$finding.UserPrincipalName] = $true
                    $finding.Remediated = $true
                }
            }
            else {
                # Both ForwardingSmtpAddress and ForwardingAddress were set; a single Set-Mailbox already cleared them.
                $finding.Remediated = $true
            }
        }
        catch {
            Write-Warning "Remediation failed for '$($finding.UserPrincipalName)' ($($finding.FindingType)): $($_.Exception.Message)"
        }
    }
}

if ($findings.Count -gt 0) {
    $findings | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Verbose 'No forwarding was found; no CSV written.'
}

$externalFindings = @($findings | Where-Object { $_.IsExternal })
$affectedMailboxes = @($externalFindings | Select-Object -ExpandProperty UserPrincipalName -Unique)
$externalRules = @($externalFindings | Where-Object { $_.FindingType -like 'InboxRule*' })
$externalMailboxLevel = @($externalFindings | Where-Object { $_.FindingType -like 'MailboxForwarding*' })

Write-Host ''
Write-Host 'External forwarding summary' -ForegroundColor Cyan
Write-Host ('  Mailboxes scanned                  : {0}' -f $mailboxes.Count)
Write-Host ('  Mailboxes with external forwarding : {0}' -f $affectedMailboxes.Count) -ForegroundColor $(if ($affectedMailboxes.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  External inbox rules               : {0}' -f $externalRules.Count)
Write-Host ('  Mailbox-level external forwards    : {0}' -f $externalMailboxLevel.Count)
if ($IncludeInternalForwarding) {
    Write-Host ('  Internal forwards (informational)  : {0}' -f @($findings | Where-Object { -not $_.IsExternal }).Count)
}
if ($Remediate) {
    Write-Host ('  Remediated                         : {0}' -f @($findings | Where-Object { $_.Remediated }).Count) -ForegroundColor Green
}
if ($findings.Count -gt 0) {
    Write-Host ('  Report                             : {0}' -f $OutputPath)
}

if ($PassThru) {
    $findings
}
#endregion Main
