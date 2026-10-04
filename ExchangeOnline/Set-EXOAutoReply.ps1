<#
.SYNOPSIS
    Enables, schedules or disables automatic replies on Exchange Online mailboxes with templated messages, typically for leavers.
.DESCRIPTION
    Resolves each selected mailbox with Get-EXOMailbox, reads the current state with Get-MailboxAutoReplyConfiguration
    and - with -Apply - writes state, messages, external audience and schedule with Set-MailboxAutoReplyConfiguration
    inside ShouldProcess. Messages come from -InternalMessage / -ExternalMessage or an HTML -MessageFile; the tokens
    {DisplayName}, {ManagerName} and {ManagerEmail} are replaced per mailbox (manager via Get-User). The default run is
    a pre-flight report. One result object per mailbox is emitted to the pipeline - pipe to Export-Csv to keep a record.
.PARAMETER Identity
    One or more mailbox identities (UPN, primary SMTP address, alias or GUID).
.PARAMETER InputCsv
    Path of a CSV file with a UserPrincipalName column listing the mailboxes to process.
.PARAMETER AutoReplyState
    Enabled (until turned off), Scheduled (between -StartTime and -EndTime) or Disabled.
.PARAMETER InternalMessage
    Reply sent to senders inside the organisation. HTML allowed. Overrides -MessageFile for the internal reply.
.PARAMETER ExternalMessage
    Reply sent to external senders. HTML allowed. Overrides -MessageFile for the external reply.
.PARAMETER MessageFile
    Path of an HTML (or text) file used for both replies unless -InternalMessage / -ExternalMessage are given.
.PARAMETER ExternalAudience
    Who receives the external reply: None, Known (contacts only) or All. Omit to keep the mailbox's current setting.
.PARAMETER StartTime
    Start of the schedule; required with -AutoReplyState Scheduled.
.PARAMETER EndTime
    End of the schedule; required with -AutoReplyState Scheduled and must be later than -StartTime.
.PARAMETER Apply
    Perform the changes. Without this switch the script is read-only and reports what would be set.
.EXAMPLE
    PS> .\Set-EXOAutoReply.ps1 -InputCsv .\Leavers.csv -AutoReplyState Enabled -MessageFile .\LeaverReply.html -ExternalAudience All
    Pre-flight: shows the current state of every leaver and the resolved manager, without changing anything.
.EXAMPLE
    PS> .\Set-EXOAutoReply.ps1 -Identity adele.vance@contoso.com -AutoReplyState Enabled -InternalMessage '{DisplayName} has left. Contact {ManagerName} ({ManagerEmail}).' -Apply
    Enables a reply naming the manager after confirmation (add -WhatIf to only show the call); -AutoReplyState Disabled -Apply turns it off again.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator (Mail Recipients role) for -Apply; View-Only Recipients for the pre-flight report
    Category    : Mailbox content & settings
    Changes     : Yes
    Notes       : Only the messages supplied are written; the other reply keeps its current text. The external reply is not
                  sent while ExternalAudience is None (the script warns). Convert leavers to shared mailboxes before removing
                  the license - automatic replies keep working on an unlicensed shared mailbox.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/set-mailboxautoreplyconfiguration
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Identity')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Identity')]
    [string[]]$Identity,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Enabled', 'Scheduled', 'Disabled')]
    [string]$AutoReplyState,

    [Parameter()]
    [string]$InternalMessage,

    [Parameter()]
    [string]$ExternalMessage,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$MessageFile,

    [Parameter()]
    [ValidateSet('None', 'Known', 'All')]
    [string]$ExternalAudience,

    [Parameter()]
    [datetime]$StartTime,

    [Parameter()]
    [datetime]$EndTime,

    [Parameter()]
    [switch]$Apply
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

function Expand-MessageTemplate {
    <# Replaces the {DisplayName}, {ManagerName} and {ManagerEmail} tokens (case-sensitive) in an auto-reply template. #>
    param(
        [Parameter()][string]$Template,
        [Parameter()][hashtable]$Tokens
    )
    $text = $Template
    foreach ($key in $Tokens.Keys) { $text = $text.Replace($key, [string]$Tokens[$key]) }
    return $text
}
#endregion Helpers

#region Main
if ($AutoReplyState -eq 'Scheduled') {
    if (-not ($PSBoundParameters.ContainsKey('StartTime') -and $PSBoundParameters.ContainsKey('EndTime'))) { throw '-StartTime and -EndTime are required for a Scheduled automatic reply.' }
    if ($EndTime -le $StartTime) { throw '-EndTime must be later than -StartTime.' }
    if ($EndTime -le (Get-Date)) { Write-Warning 'The scheduled window has already ended; the reply would never be sent.' }
}
$fileTemplate = $null
if ($MessageFile) { $fileTemplate = Get-Content -Path $MessageFile -Raw -Encoding UTF8 }
$internalTemplate = $InternalMessage
if ([string]::IsNullOrWhiteSpace($internalTemplate)) { $internalTemplate = $fileTemplate }
$externalTemplate = $ExternalMessage
if ([string]::IsNullOrWhiteSpace($externalTemplate)) { $externalTemplate = $fileTemplate }
if ($AutoReplyState -ne 'Disabled' -and -not ($internalTemplate -or $externalTemplate)) { throw 'Enabled/Scheduled replies need -InternalMessage, -ExternalMessage or -MessageFile.' }
$needsManager = ($AutoReplyState -ne 'Disabled' -and "$internalTemplate$externalTemplate" -match '\{Manager(Name|Email)\}')

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }
$selection = @($Identity)
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $selection = @(Import-Csv -Path $InputCsv | ForEach-Object { [string]$_.UserPrincipalName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($selection.Count -eq 0) { throw "No UserPrincipalName values were found in '$InputCsv'." }
}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($id in $selection) {
    $index++
    Write-Progress -Activity 'Processing automatic replies' -Status "$index of $($selection.Count) - $id" -PercentComplete (($index / $selection.Count) * 100)
    try {
        $mailbox = Get-EXOMailbox -Identity $id -Properties DisplayName, UserPrincipalName -ErrorAction Stop
        $before = Get-MailboxAutoReplyConfiguration -Identity $mailbox.UserPrincipalName -ErrorAction Stop
    }
    catch { Write-Warning "Mailbox '$id' was not found or is not accessible: $($_.Exception.Message)"; continue }
    $upn = $mailbox.UserPrincipalName
    $manager = $null
    if ($needsManager) {
        try {
            $managerId = [string](Get-User -Identity $upn -ErrorAction Stop).Manager
            if ($managerId) { $manager = Get-User -Identity $managerId -ErrorAction Stop }
            else { Write-Warning "'$upn' has no manager in the directory; the manager tokens will be empty." }
        }
        catch { Write-Warning "Could not resolve the manager of '$upn': $($_.Exception.Message)" }
    }
    $tokens = @{ '{DisplayName}' = [string]$mailbox.DisplayName; '{ManagerName}' = [string]$manager.DisplayName; '{ManagerEmail}' = [string]$manager.WindowsEmailAddress }

    $setParams = @{ AutoReplyState = $AutoReplyState }
    $effectiveAudience = [string]$before.ExternalAudience
    if ($AutoReplyState -ne 'Disabled') {
        if ($internalTemplate) { $setParams['InternalMessage'] = Expand-MessageTemplate -Template $internalTemplate -Tokens $tokens }
        if ($externalTemplate) { $setParams['ExternalMessage'] = Expand-MessageTemplate -Template $externalTemplate -Tokens $tokens }
        if ($ExternalAudience) { $setParams['ExternalAudience'] = $ExternalAudience; $effectiveAudience = $ExternalAudience }
        if ($AutoReplyState -eq 'Scheduled') { $setParams['StartTime'] = $StartTime; $setParams['EndTime'] = $EndTime }
        if ($setParams.ContainsKey('ExternalMessage') -and $effectiveAudience -eq 'None') { Write-Warning "'$upn': ExternalAudience is None, so the external reply is never sent." }
    }

    $status = 'Would change'
    if ($AutoReplyState -eq 'Disabled' -and [string]$before.AutoReplyState -eq 'Disabled') { $status = 'Already disabled' }
    elseif ($Apply -and $PSCmdlet.ShouldProcess($upn, "Set automatic reply state to $AutoReplyState")) {
        try { Set-MailboxAutoReplyConfiguration -Identity $upn @setParams -ErrorAction Stop; $status = 'Changed' }
        catch { $status = "Failed: $($_.Exception.Message)"; Write-Warning "Could not update '$upn': $($_.Exception.Message)" }
    }
    elseif ($Apply) { $status = 'Not confirmed' }

    $results.Add([PSCustomObject]@{
            DisplayName       = $mailbox.DisplayName
            UserPrincipalName = $upn
            StateBefore       = [string]$before.AutoReplyState
            StateAfter        = $AutoReplyState
            ExternalAudience  = $effectiveAudience
            StartTime         = $(if ($AutoReplyState -eq 'Scheduled') { $StartTime } else { $before.StartTime })
            EndTime           = $(if ($AutoReplyState -eq 'Scheduled') { $EndTime } else { $before.EndTime })
            ManagerName       = $tokens['{ManagerName}']
            ManagerEmail      = $tokens['{ManagerEmail}']
            Status            = $status
        })
}
Write-Progress -Activity 'Processing automatic replies' -Completed

if ($results.Count -eq 0) { Write-Warning 'No mailboxes could be evaluated.'; return }
Write-Host "Automatic reply summary ($($results.Count) mailboxes evaluated, target state $AutoReplyState)" -ForegroundColor Cyan
foreach ($state in @('Already disabled', 'Would change', 'Changed', 'Not confirmed', 'Failed*')) {
    $count = @($results | Where-Object { $_.Status -like $state }).Count
    Write-Host ('  {0,-17}: {1}' -f $state.TrimEnd('*'), $count) -ForegroundColor $(if ($count -gt 0 -and $state -eq 'Failed*') { 'Red' } else { 'White' })
}
if ($needsManager) { Write-Host ('  Manager not found: {0}' -f @($results | Where-Object { -not $_.ManagerName }).Count) -ForegroundColor Yellow }
if (-not $Apply) { Write-Host '  Pre-flight only - re-run with -Apply to change the automatic replies.' -ForegroundColor Yellow }

$results
#endregion Main
