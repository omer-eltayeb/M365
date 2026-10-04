<#
.SYNOPSIS
    Exports the Exchange Online organization and transport configuration as a JSON snapshot plus a key-settings CSV, with optional diff.
.DESCRIPTION
    Reads Get-OrganizationConfig and Get-TransportConfig and writes EXOConfigSnapshot.json (both objects in full, with the
    export time and tenant name) and KeySettings.csv, a Source / Setting / Value / Note table of the settings administrators
    review most: modern authentication, auditing, Outlook on the web idle timeout, MailTips, EWS and connector controls,
    Bookings, Microsoft 365 Groups defaults, archiving, SMTP AUTH, postmaster and journaling NDR addresses, message size and
    recipient limits. Notes flag risky values such as IsDehydrated (run Enable-OrganizationCustomization first), modern
    authentication off, auditing off or SMTP AUTH allowed. With -CompareWith <previous EXOConfigSnapshot.json> every changed
    property of both objects is listed as Setting / Old / New in Changes.csv - a cheap change-tracking baseline.
.PARAMETER OutputFolder
    Folder that receives EXOConfigSnapshot.json, KeySettings.csv and Changes.csv. Defaults to .\EXOOrgConfigExport_yyyyMMdd-HHmm.
.PARAMETER CompareWith
    Path of an EXOConfigSnapshot.json produced by an earlier run; differences are written to Changes.csv and shown in the console.
.PARAMETER PassThru
    Also emits the key-setting rows (and, with -CompareWith, the change rows) to the pipeline.
.EXAMPLE
    PS> .\Export-EXOOrganizationConfig.ps1
    Creates .\EXOOrgConfigExport_<timestamp>\ with the JSON snapshot and KeySettings.csv and prints the flagged settings.
.EXAMPLE
    PS> .\Export-EXOOrganizationConfig.ps1 -OutputFolder C:\Baselines\EXO -CompareWith C:\Baselines\EXO-2026-09\EXOConfigSnapshot.json
    Exports the current configuration and lists every organization or transport setting that changed since the September snapshot.
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
    Notes       : The snapshot is serialised with ConvertTo-Json -Depth 6; compare snapshots produced by the same PowerShell
                  major version because Windows PowerShell and PowerShell 7 format dates differently. Timestamps (WhenChanged,
                  WhenCreated) and session properties are ignored by the comparison. Settings that do not exist in a tenant
                  (older or government clouds) appear with an empty value.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-organizationconfig
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-transportconfig
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$CompareWith,

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

function ConvertTo-SettingText {
    <# Renders a configuration value as one comparable string: $null becomes empty, collections are joined with ';'. #>
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) { return (@(foreach ($item in $Value) { ConvertTo-SettingText -Value $item }) -join ';') }
    return [string]$Value
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = Join-Path -Path (Get-Location).Path -ChildPath ('EXOOrgConfigExport_{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

try {
    $organizationConfig = Get-OrganizationConfig -ErrorAction Stop
    $transportConfig = Get-TransportConfig -ErrorAction Stop
}
catch {
    throw "Failed to read the organization configuration: $($_.Exception.Message)"
}

$snapshot = [PSCustomObject]@{
    ExportedAt         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Organization       = [string]$organizationConfig.Name
    OrganizationConfig = $organizationConfig
    TransportConfig    = $transportConfig
}
# Depth 6 covers every nested value that matters; deeper internals are cut off silently rather than warned about on PowerShell 7.
$json = $snapshot | ConvertTo-Json -Depth 6 -WarningAction SilentlyContinue
$jsonPath = Join-Path -Path $OutputFolder -ChildPath 'EXOConfigSnapshot.json'
Set-Content -Path $jsonPath -Value $json -Encoding UTF8

$keySettings = @{
    OrganizationConfig = @('IsDehydrated', 'Name', 'OAuth2ClientProfileEnabled', 'DefaultAuthenticationPolicy', 'AuditDisabled', 'CustomerLockboxEnabled',
        'ActivityBasedAuthenticationTimeoutEnabled', 'ActivityBasedAuthenticationTimeoutInterval', 'ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled',
        'SendFromAliasEnabled', 'DisablePlusAddressInRecipients', 'FocusedInboxOn', 'MessageRecallEnabled', 'ReadTrackingEnabled', 'LinkPreviewEnabled',
        'MailTipsAllTipsEnabled', 'MailTipsExternalRecipientsTipsEnabled', 'MailTipsGroupMetricsEnabled', 'MailTipsLargeAudienceThreshold',
        'EwsEnabled', 'EwsApplicationAccessPolicy', 'EwsAllowList', 'EwsBlockList', 'ConnectorsEnabled', 'ConnectorsEnabledForOutlook',
        'ConnectorsEnabledForTeams', 'ConnectorsEnabledForSharepoint', 'ConnectorsEnabledForYammer', 'AppsForOfficeEnabled', 'SmtpActionableMessagesEnabled',
        'BookingsEnabled', 'DefaultGroupAccessType', 'DirectReportsGroupAutoCreationEnabled', 'PublicFoldersEnabled', 'OnlineMeetingsByDefaultEnabled',
        'AutoExpandingArchiveEnabled', 'ElcProcessingDisabled', 'ExchangeNotificationEnabled', 'ExchangeNotificationRecipients', 'OutlookPayEnabled',
        'RefreshSessionEnabled', 'SharedDomainEmailAddressFlowEnabled', 'OutlookMobileGCCRestrictionsEnabled', 'MaskClientIpInReceivedHeadersEnabled',
        'WebPushNotificationsDisabled', 'WebSuggestedRepliesDisabled', 'OutlookGifPickerDisabled', 'UnblockUnsafeSenderPromptEnabled')
    TransportConfig    = @('SmtpClientAuthenticationDisabled', 'AllowLegacyTLSClients', 'ExternalPostmasterAddress', 'JournalingReportNdrTo', 'MaxReceiveSize',
        'MaxSendSize', 'MaxRecipientEnvelopeLimit', 'MessageExpiration', 'ReplyAllStormProtectionEnabled', 'ReplyAllStormDetectionMinimumRecipients',
        'ReplyAllStormDetectionMinimumReplies', 'ReplyAllStormBlockDurationHours', 'Rfc2231EncodingEnabled', 'HeaderPromotionModeSetting', 'DSNConversionMode')
}
# Notes are attached when a setting has the given value ("Setting=Value").
$notes = @{
    'IsDehydrated=True'                               = 'Run Enable-OrganizationCustomization before changing organization-level settings'
    'OAuth2ClientProfileEnabled=False'                = 'Modern authentication is disabled for Exchange Online clients'
    'AuditDisabled=True'                              = 'Mailbox auditing is disabled for the whole organization'
    'ActivityBasedAuthenticationTimeoutEnabled=False' = 'Outlook on the web idle-session timeout is disabled'
    'MailTipsExternalRecipientsTipsEnabled=False'     = 'Users are not warned when they add external recipients'
    'SmtpClientAuthenticationDisabled=False'          = 'SMTP AUTH is allowed organization-wide; disable it and enable per mailbox where needed'
}
$sources = @{ OrganizationConfig = $organizationConfig; TransportConfig = $transportConfig }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($source in 'OrganizationConfig', 'TransportConfig') {
    foreach ($name in $keySettings[$source]) {
        $text = ConvertTo-SettingText -Value $sources[$source].$name
        $rows.Add([PSCustomObject]@{ Source = $source; Setting = $name; Value = $text; Note = $notes[('{0}={1}' -f $name, $text)] })
    }
}
$rows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'KeySettings.csv') -NoTypeInformation -Encoding UTF8

$changes = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSBoundParameters.ContainsKey('CompareWith')) {
    try {
        $previous = Get-Content -Path $CompareWith -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "The previous snapshot '$CompareWith' could not be read: $($_.Exception.Message)"
    }
    # Both sides are compared after a JSON round trip so dates and nested values are rendered the same way.
    $current = $json | ConvertFrom-Json
    $ignored = @('WhenChanged', 'WhenChangedUTC', 'WhenCreated', 'WhenCreatedUTC', 'RunspaceId', 'PSComputerName', 'PSShowComputerName', 'ObjectState')
    foreach ($source in 'OrganizationConfig', 'TransportConfig') {
        $old = $previous.$source
        $new = $current.$source
        if ($null -eq $old) { Write-Warning "The previous snapshot has no $source section; skipping its comparison."; continue }
        $names = @(@($old.PSObject.Properties.Name) + @($new.PSObject.Properties.Name) | Sort-Object -Unique | Where-Object { $ignored -notcontains $_ })
        foreach ($name in $names) {
            $oldText = ConvertTo-SettingText -Value $old.$name
            $newText = ConvertTo-SettingText -Value $new.$name
            if ($oldText -ne $newText) { $changes.Add([PSCustomObject]@{ Source = $source; Setting = $name; Old = $oldText; New = $newText }) }
        }
    }
    if ($changes.Count -gt 0) { $changes | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath 'Changes.csv') -NoTypeInformation -Encoding UTF8 }
}

$flags = @($rows | Where-Object { -not [string]::IsNullOrEmpty($_.Note) })
Write-Host ''
Write-Host ('Exchange Online configuration export for {0}' -f $snapshot.Organization) -ForegroundColor Cyan
Write-Host ('  Key settings  : {0}' -f $rows.Count)
Write-Host ('  Flags         : {0}' -f $flags.Count) -ForegroundColor $(if ($flags.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($flag in $flags) { Write-Host ('    {0} = {1}: {2}' -f $flag.Setting, $flag.Value, $flag.Note) -ForegroundColor Yellow }
if ($PSBoundParameters.ContainsKey('CompareWith')) {
    Write-Host ('  Changes since {0}: {1}' -f $previous.ExportedAt, $changes.Count) -ForegroundColor $(if ($changes.Count -gt 0) { 'Yellow' } else { 'Green' })
    foreach ($change in $changes) { Write-Host ('    {0}.{1}: "{2}" -> "{3}"' -f $change.Source, $change.Setting, $change.Old, $change.New) }
}
Write-Host ('  Output folder : {0}' -f $OutputFolder)

if ($PassThru) {
    $rows
    $changes
}
#endregion Main
