<#
.SYNOPSIS
    Documents journaling, transport limits, archiving and messaging records management (MRM) retention configuration.
.DESCRIPTION
    Collects Get-JournalRule (scope, journaled recipient, journal mailbox), the transport settings from Get-TransportConfig
    (journaling NDR mailbox, SMTP AUTH, postmaster address, size and recipient limits), the archiving switches from
    Get-OrganizationConfig and the MRM configuration from Get-RetentionPolicy / Get-RetentionPolicyTag. Three CSV files are
    written: a Setting / Value table with notes, the journal rules, and the retention tags with the policies that link them.
    Flags: no dedicated journaling NDR mailbox, SMTP AUTH enabled, Managed Folder Assistant disabled, Default MRM Policy customised.
.PARAMETER OutputPath
    Path of the settings CSV (default .\Reports\EXOJournalAndArchiving_yyyyMMdd-HHmm.csv); _JournalRules.csv and _RetentionTags.csv are written next to it.
.PARAMETER PassThru
    Also emits the setting rows, followed by the journal rule rows and the retention tag rows, to the pipeline.
.EXAMPLE
    PS> .\Get-EXOJournalAndArchivingConfig.ps1
    Writes the three CSV files to .\Reports and prints the journaling, archiving and retention summary with any flags.
.EXAMPLE
    PS> .\Get-EXOJournalAndArchivingConfig.ps1 -PassThru | Where-Object { $_.DefaultTagStatus -eq 'Modified' }
    Lists the built-in retention tags of the Default MRM Policy whose age limit or action no longer matches the default.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Exchange Administrator or Global Reader (View-Only Organization Management).
    Category    : Mail flow & organization
    Changes     : No
    Notes       : Microsoft Purview retention policies and labels (Security & Compliance PowerShell) are not covered here. The
                  Default MRM Policy check compares tag names, age limits and actions with the values Microsoft ships for new tenants.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-journalrule
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-retentionpolicytag
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
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

function Add-SettingRow {
    <# Appends one Area / Setting / Value / Note row; arrays are joined with ';' and the empty address marker <> becomes blank. #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Area,

        [Parameter(Mandatory = $true)]
        [string]$Setting,

        [Parameter()]
        [object]$Value,

        [Parameter()]
        [string]$Note
    )
    $text = (@(foreach ($item in @($Value)) { [string]$item }) -join ';')
    if ($text -eq '<>') { $text = '' }
    if ([string]::IsNullOrEmpty($Note)) { $Note = $script:Notes[('{0}={1}' -f $Setting, $text)] }
    $script:Settings.Add([PSCustomObject]@{ Area = $Area; Setting = $Setting; Value = $text; Note = $Note })
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOJournalAndArchiving_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$journalPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_JournalRules.csv')
$tagPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_RetentionTags.csv')

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

try {
    $journalRules = @(Get-JournalRule -ErrorAction Stop)
    $transportConfig = Get-TransportConfig -ErrorAction Stop
    $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
    $policies = @(Get-RetentionPolicy -ErrorAction Stop)
    $tags = @(Get-RetentionPolicyTag -ErrorAction Stop | Sort-Object -Property Type, Name)
}
catch {
    throw "Failed to read the configuration: $($_.Exception.Message)"
}

$script:Settings = New-Object -TypeName System.Collections.Generic.List[object]
# Notes attached automatically by Add-SettingRow when a setting has the given value.
$script:Notes = @{
    'SmtpClientAuthenticationDisabled=False' = 'SMTP AUTH is allowed organization-wide; disable it and enable per mailbox where needed'
    'AutoExpandingArchiveEnabled=False'      = 'Auto-expanding archiving is off; archives stop at the licensed 50 / 100 GB'
    'ElcProcessingDisabled=True'             = 'Managed Folder Assistant is disabled; retention tags are not applied'
}
$ndrTo = ([string]$transportConfig.JournalingReportNdrTo) -replace '^<>$', ''
$ndrNote = $null
if ($journalRules.Count -gt 0 -and ($ndrTo -eq '' -or $ndrTo -like 'postmaster@*' -or $ndrTo -eq [string]$transportConfig.ExternalPostmasterAddress)) {
    $ndrNote = 'Set a dedicated, non-journaled mailbox with Set-TransportConfig -JournalingReportNdrTo so undeliverable journal reports are kept'
}
Add-SettingRow -Area 'Journaling' -Setting 'JournalRules' -Value $journalRules.Count -Note $(if ($journalRules.Count -eq 0) { 'No journal rules configured' } else { $null })
Add-SettingRow -Area 'Journaling' -Setting 'JournalingReportNdrTo' -Value $ndrTo -Note $ndrNote
foreach ($name in 'SmtpClientAuthenticationDisabled', 'ExternalPostmasterAddress', 'MaxReceiveSize', 'MaxSendSize', 'MaxRecipientEnvelopeLimit',
    'InternalSMTPServers', 'AllowLegacyTLSClients', 'MessageExpiration') {
    Add-SettingRow -Area 'TransportConfig' -Setting $name -Value $transportConfig.$name
}
foreach ($name in 'AutoExpandingArchiveEnabled', 'ElcProcessingDisabled') {
    Add-SettingRow -Area 'Archiving' -Setting $name -Value $organizationConfig.$name
}

$journalRows = @(foreach ($rule in $journalRules) {
        [PSCustomObject]@{
            Name                = $rule.Name
            Enabled             = [bool]$rule.Enabled
            Scope               = [string]$rule.Scope
            Recipient           = $(if ([string]::IsNullOrEmpty([string]$rule.Recipient)) { 'All recipients' } else { [string]$rule.Recipient })
            JournalEmailAddress = [string]$rule.JournalEmailAddress
        }
    })

# Tag name -> "<age limit in days>|<action>" as shipped in the Default MRM Policy of a new tenant.
$defaultTags = @{
    'Default 2 year move to archive' = '730|MoveToArchive'; 'Recoverable Items 14 days move to archive' = '14|MoveToArchive'
    'Personal 1 year move to archive' = '365|MoveToArchive'; 'Personal 5 year move to archive' = '1825|MoveToArchive'; 'Personal never move to archive' = '|MoveToArchive'
    '1 Week Delete' = '7|DeleteAndAllowRecovery'; '1 Month Delete' = '30|DeleteAndAllowRecovery'; '6 Month Delete' = '180|DeleteAndAllowRecovery'
    '1 Year Delete' = '365|DeleteAndAllowRecovery'; '5 Year Delete' = '1825|DeleteAndAllowRecovery'; 'Never Delete' = '|DeleteAndAllowRecovery'
    'Junk Email' = '30|DeleteAndAllowRecovery'
}
$defaultPolicy = $policies | Where-Object { $_.Name -eq 'Default MRM Policy' } | Select-Object -First 1
$defaultPolicyTags = @($(if ($null -ne $defaultPolicy) { $defaultPolicy.RetentionPolicyTagLinks } else { @() }) | ForEach-Object { [string]$_ })
$tagRows = @(foreach ($tag in $tags) {
        $ageDays = $null
        $span = [timespan]::Zero
        if ([timespan]::TryParse([string]$tag.AgeLimitForRetention, [ref]$span)) { $ageDays = [int]$span.TotalDays }
        $status = 'Custom'
        if ($defaultTags.ContainsKey($tag.Name)) {
            $status = $(if ($defaultTags[$tag.Name] -eq ('{0}|{1}' -f $ageDays, [string]$tag.RetentionAction)) { 'Default' } else { 'Modified' })
        }
        [PSCustomObject]@{
            Name             = $tag.Name
            Type             = [string]$tag.Type
            RetentionEnabled = [bool]$tag.RetentionEnabled
            AgeLimitDays     = $ageDays
            RetentionAction  = [string]$tag.RetentionAction
            MessageClass     = [string]$tag.MessageClass
            LinkedPolicies   = (@($policies | Where-Object { @($_.RetentionPolicyTagLinks | ForEach-Object { [string]$_ }) -contains $tag.Name } | Select-Object -ExpandProperty Name) -join ';')
            InDefaultPolicy  = ($defaultPolicyTags -contains $tag.Name)
            DefaultTagStatus = $status
        }
    })
$customisedDefault = @($tagRows | Where-Object { $_.InDefaultPolicy -and $_.DefaultTagStatus -ne 'Default' })
foreach ($policy in ($policies | Sort-Object -Property Name)) {
    $note = $null
    if ($policy.IsDefault) { $note = 'Assigned to new mailboxes' }
    if ($policy.Name -eq 'Default MRM Policy' -and $customisedDefault.Count -gt 0) {
        $note = 'Default MRM Policy customised: ' + (@($customisedDefault | Select-Object -ExpandProperty Name) -join ', ')
    }
    Add-SettingRow -Area 'RetentionPolicy' -Setting $policy.Name -Value $policy.RetentionPolicyTagLinks -Note $note
}

$script:Settings | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
if ($journalRows.Count -gt 0) { $journalRows | Export-Csv -Path $journalPath -NoTypeInformation -Encoding UTF8 }
if ($tagRows.Count -gt 0) { $tagRows | Export-Csv -Path $tagPath -NoTypeInformation -Encoding UTF8 }

$flags = @($script:Settings | Where-Object { -not [string]::IsNullOrEmpty($_.Note) -and $_.Note -ne 'Assigned to new mailboxes' })
$enabledRules = @($journalRows | Where-Object { $_.Enabled }).Count
$ndrText = $(if ($ndrTo) { $ndrTo } else { 'not set' })
Write-Host ''
Write-Host 'Journaling, archiving and retention summary' -ForegroundColor Cyan
Write-Host ('  Journal rules            : {0} ({1} enabled); NDR mailbox: {2}' -f $journalRules.Count, $enabledRules, $ndrText)
Write-Host ('  Retention policies / tags: {0} / {1} (custom tags {2})' -f $policies.Count, $tagRows.Count, @($tagRows | Where-Object { $_.DefaultTagStatus -eq 'Custom' }).Count)
Write-Host ('  Flags                    : {0}' -f $flags.Count) -ForegroundColor $(if ($flags.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($flag in $flags) { Write-Host ('    {0}/{1}: {2}' -f $flag.Area, $flag.Setting, $flag.Note) -ForegroundColor Yellow }
Write-Host ('  Reports                  : {0} (+ _JournalRules.csv, _RetentionTags.csv)' -f $OutputPath)

if ($PassThru) {
    $script:Settings
    $journalRows
    $tagRows
}
#endregion Main
