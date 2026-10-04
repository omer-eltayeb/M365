<#
.SYNOPSIS
    Explains how users can report suspicious messages (user reported settings) and exports every setting as a Setting/Value CSV.
.DESCRIPTION
    Reads Get-ReportSubmissionPolicy (the single DefaultReportSubmissionPolicy) and Get-ReportSubmissionRule and works
    out the effective user reporting experience: Microsoft integrated reporting with the Outlook Report button, a
    non-Microsoft reporting add-in, or reporting turned off; whether reported messages go to Microsoft, to the
    reporting mailbox or both; the reporting mailbox named in the policy and in the rule (they must match); Teams
    message reporting; quarantine reporting; the result notifications users receive after admin review and the
    custom pre- and post-submission pop-ups. The console prints that explanation plus recommendations, and the CSV
    holds one Setting/Value row per policy property, rule property and derived conclusion. Read-only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderReportSubmissionSettings_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the Setting/Value objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderReportSubmissionSettings.ps1
    Prints how user reporting is configured, lists recommendations and writes the CSV to .\Reports\.
.EXAMPLE
    PS> .\Get-DefenderReportSubmissionSettings.ps1 -PassThru | Where-Object { $_.Source -eq 'Derived' }
    Shows only the derived conclusions (reporting experience, destinations, reporting mailbox, rule state).
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Security Administrator or Exchange Administrator; Security Reader or Global Reader is enough for this read-only report
    Category    : Defender for Office 365 policies
    Changes     : No
    Notes       : User reported settings exist in every tenant with Exchange Online mailboxes (EOP included); Defender for
                  Office 365 Plan 2 adds automated investigation of user reports. The reporting mailbox must be an
                  Exchange Online mailbox and Microsoft recommends excluding it from Safe Links, Safe Attachments and
                  anti-spam quarantine actions so reported messages arrive intact. Teams reporting also needs the Teams
                  messaging policy setting "Report a security concern" to be on.
.LINK
    https://learn.microsoft.com/defender-office-365/submissions-user-reported-messages-custom-mailbox
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-reportsubmissionpolicy
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

function ConvertTo-SettingText {
    <# Flattens multi-valued properties to 'a;b' and leaves scalars untouched so every Value fits one CSV cell. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )
    if ($null -eq $Value -or $Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) { return (@($Value | ForEach-Object { [string]$_ }) -join ';') }
    return $Value
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderReportSubmissionSettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try { $policy = Get-ReportSubmissionPolicy -ErrorAction Stop | Select-Object -First 1 }
catch { throw "Failed to read the report submission policy: $($_.Exception.Message)" }
if ($null -eq $policy) { throw 'Get-ReportSubmissionPolicy returned nothing; the tenant has no DefaultReportSubmissionPolicy.' }
# The rule only exists when a reporting mailbox was configured; its SentTo is where Outlook reports are delivered.
$rule = $null
try { $rule = Get-ReportSubmissionRule -ErrorAction Stop | Select-Object -First 1 }
catch { Write-Warning "Get-ReportSubmissionRule failed; the reporting mailbox rule is not reported: $($_.Exception.Message)" }

$toMicrosoft = [bool]$policy.EnableReportToMicrosoft
$toMailbox = [bool]$policy.ReportJunkToCustomizedAddress -or [bool]$policy.ReportNotJunkToCustomizedAddress -or [bool]$policy.ReportPhishToCustomizedAddress
$thirdParty = [bool]$policy.EnableThirdPartyAddress
$addressLists = @($policy.ReportJunkAddresses) + @($policy.ReportNotJunkAddresses) + @($policy.ReportPhishAddresses) + @($policy.ThirdPartyReportAddresses)
$policyMailboxes = @($addressLists | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique)
$ruleMailboxes = @($rule.SentTo | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).ToLowerInvariant() })
$ruleState = $(if ($null -ne $rule) { [string]$rule.State } else { 'Not configured' })

if ($thirdParty) {
    $experience = 'Non-Microsoft reporting add-in in Outlook'
    $destination = $(if ($toMicrosoft) { 'Microsoft and the reporting mailbox' } else { 'Reporting mailbox only (Microsoft receives metadata for the Submissions page)' })
}
elseif ($toMicrosoft) {
    $experience = 'Microsoft integrated reporting (Report button in Outlook)'
    $destination = $(if ($toMailbox) { 'Microsoft and the reporting mailbox' } else { 'Microsoft only' })
}
elseif ($toMailbox) {
    $experience = 'Microsoft integrated reporting (Report button in Outlook)'
    $destination = 'Reporting mailbox only - nothing is sent to Microsoft'
}
else {
    $experience = 'Reporting in Outlook is turned off'
    $destination = 'None - the Report button is not available to users'
}

$settingNames = @(
    'EnableReportToMicrosoft', 'EnableThirdPartyAddress', 'ThirdPartyReportAddresses', 'ReportJunkToCustomizedAddress', 'ReportJunkAddresses',
    'ReportNotJunkToCustomizedAddress', 'ReportNotJunkAddresses', 'ReportPhishToCustomizedAddress', 'ReportPhishAddresses',
    'ReportChatMessageEnabled', 'ReportChatMessageToCustomizedAddressEnabled', 'ReportChatMessageAddresses', 'DisableQuarantineReportingOption',
    'EnableUserEmailNotification', 'EnableCustomNotificationSender', 'NotificationSenderAddress', 'NotificationFooterMessage',
    'JunkReviewResultMessage', 'NotJunkReviewResultMessage', 'PhishingReviewResultMessage', 'EnableOrganizationBranding', 'EnableCustomizedMsg',
    'PreSubmitMessageEnabled', 'PreSubmitMessageTitle', 'PreSubmitMessage', 'PostSubmitMessageEnabled', 'PostSubmitMessageTitle', 'PostSubmitMessage',
    'WhenChanged'
)
$rows = New-Object -TypeName System.Collections.Generic.List[object]
$derived = @(
    @{ Setting = 'ReportingExperience'; Value = $experience }
    @{ Setting = 'ReportedMessagesGoTo'; Value = $destination }
    @{ Setting = 'ReportingMailboxInPolicy'; Value = ($policyMailboxes -join ';') }
    @{ Setting = 'ReportingMailboxInRule'; Value = ($ruleMailboxes -join ';') }
    @{ Setting = 'ReportSubmissionRuleState'; Value = $ruleState }
    @{ Setting = 'TeamsMessageReporting'; Value = $(if ([bool]$policy.ReportChatMessageEnabled) { 'On' } else { 'Off' }) }
)
foreach ($item in $derived) { $rows.Add([PSCustomObject]@{ Source = 'Derived'; Setting = $item.Setting; Value = $item.Value }) }
foreach ($name in $settingNames) {
    $rows.Add([PSCustomObject]@{ Source = 'ReportSubmissionPolicy'; Setting = $name; Value = (ConvertTo-SettingText -Value $policy.$name) })
}
if ($null -ne $rule) {
    foreach ($name in 'Name', 'State', 'SentTo', 'ReportSubmissionPolicy', 'WhenChanged') {
        $rows.Add([PSCustomObject]@{ Source = 'ReportSubmissionRule'; Setting = $name; Value = (ConvertTo-SettingText -Value $rule.$name) })
    }
}
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$recommendations = New-Object -TypeName System.Collections.Generic.List[string]
if (-not $toMicrosoft -and -not $toMailbox -and -not $thirdParty) {
    $recommendations.Add('Users cannot report messages from Outlook. Turn on Microsoft integrated reporting (Set-ReportSubmissionPolicy -EnableReportToMicrosoft $true).')
}
elseif (-not $toMicrosoft) {
    $recommendations.Add('Reported messages are not sent to Microsoft, so they do not improve filtering or trigger automated investigation; consider sending them to Microsoft as well.')
}
if (($toMailbox -or $thirdParty) -and ($ruleState -ne 'Enabled' -or $ruleMailboxes.Count -eq 0)) {
    $recommendations.Add('A reporting mailbox is configured in the policy but the report submission rule is missing, disabled or has no SentTo address; reported messages will not reach the mailbox.')
}
elseif ($ruleMailboxes.Count -gt 0 -and @($policyMailboxes | Where-Object { $ruleMailboxes -notcontains $_ }).Count -gt 0) {
    $recommendations.Add(('The reporting mailbox differs between the policy ({0}) and the rule ({1}); keep both identical.' -f ($policyMailboxes -join ';'), ($ruleMailboxes -join ';')))
}
if (($toMicrosoft -or $toMailbox) -and -not [bool]$policy.EnableUserEmailNotification) {
    $recommendations.Add('Users receive no result email after an admin reviews their report; enable EnableUserEmailNotification to close the feedback loop.')
}
if ([bool]$policy.DisableQuarantineReportingOption) { $recommendations.Add('Users cannot report messages from quarantine (DisableQuarantineReportingOption); consider allowing it.') }
if (-not [bool]$policy.ReportChatMessageEnabled) { $recommendations.Add('Teams message reporting is off (ReportChatMessageEnabled); users cannot report suspicious Teams messages.') }

Write-Host ''
Write-Host 'User reported message settings' -ForegroundColor Cyan
Write-Host ('  Reporting experience  : {0}' -f $experience) -ForegroundColor $(if ($experience -like '*turned off*') { 'Red' } else { 'Green' })
Write-Host ('  Reported messages go  : {0}' -f $destination)
$policyMailboxText = $(if ($policyMailboxes.Count -gt 0) { $policyMailboxes -join ';' } else { 'none' })
$ruleMailboxText = $(if ($ruleMailboxes.Count -gt 0) { $ruleMailboxes -join ';' } else { 'none' })
Write-Host ('  Reporting mailbox     : {0} (rule {1}, SentTo {2})' -f $policyMailboxText, $ruleState, $ruleMailboxText)
Write-Host ('  Teams reporting       : {0}' -f $(if ([bool]$policy.ReportChatMessageEnabled) { 'On' } else { 'Off' }))
Write-Host ('  Quarantine reporting  : {0}' -f $(if ([bool]$policy.DisableQuarantineReportingOption) { 'Off' } else { 'On' }))
Write-Host ('  Result notifications  : {0}' -f $(if ([bool]$policy.EnableUserEmailNotification) { 'On' } else { 'Off' }))
Write-Host ('  Pre/post submit popup : {0} / {1}' -f [bool]$policy.PreSubmitMessageEnabled, [bool]$policy.PostSubmitMessageEnabled)
if ($recommendations.Count -gt 0) {
    Write-Host '  Recommendations' -ForegroundColor Yellow
    foreach ($recommendation in $recommendations) { Write-Host ('    - {0}' -f $recommendation) }
}
Write-Host ('  Report                : {0}' -f $OutputPath)

if ($PassThru) { $rows }
#endregion Main
