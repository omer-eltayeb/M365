<#
.SYNOPSIS
    Reports every quarantine policy with its decoded end-user permissions, notification settings and the threat policies that use it.
.DESCRIPTION
    Reads Get-QuarantinePolicy and decodes EndUserQuarantinePermissionsValue into the individual permissions (view
    header, download, allow sender, block sender, request release, release, preview, delete) and the matching preset
    level (No access, Limited access, Full access or Custom), together with quarantine notifications (ESNEnabled) and
    whether notifications include messages from blocked senders. The global policy (Get-QuarantinePolicy
    -QuarantinePolicyType GlobalQuarantinePolicy) adds the notification frequency, custom sender address, branding
    and languages. Each row also lists which anti-spam, anti-phishing, anti-malware and Safe Attachments policies
    reference the quarantine policy through their *QuarantineTag settings, so unused policies are easy to spot. Read-only.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\DefenderQuarantinePolicies_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-DefenderQuarantinePolicies.ps1
    Writes one row per quarantine policy (plus the global settings row) to .\Reports\ and prints a summary.
.EXAMPLE
    PS> .\Get-DefenderQuarantinePolicies.ps1 -PassThru | Where-Object { $_.UsedByCount -eq 0 -and $_.QuarantinePolicyType -eq 'QuarantinePolicy' } | Select-Object Name, AccessLevel
    Lists quarantine policies that no threat policy references.
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
    Notes       : Quarantine policies are part of Exchange Online Protection; the Safe Attachments usage join needs Defender
                  for Office 365 Plan 1 or 2 and is skipped with a warning in EOP-only tenants. Permission bit values:
                  ViewHeader 1, Download 2, AllowSender 4, BlockSender 8, RequestRelease 16, Release 32, Preview 64,
                  Delete 128 (DefaultFullAccessPolicy = 236); the raw permission text is kept for cross-checking. The
                  access level follows the release permission: Release = Full access, Request release = Limited access.
                  Users can never release malware or high confidence phishing themselves, only request the release.
.LINK
    https://learn.microsoft.com/defender-office-365/quarantine-policies
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-quarantinepolicy
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

function ConvertFrom-PermissionValue {
    <# Decodes the EndUserQuarantinePermissionsValue bit mask into permission names (lowest bit first). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Value
    )
    $bits = @(
        @{ Bit = 1; Name = 'PermissionToViewHeader' }
        @{ Bit = 2; Name = 'PermissionToDownload' }
        @{ Bit = 4; Name = 'PermissionToAllowSender' }
        @{ Bit = 8; Name = 'PermissionToBlockSender' }
        @{ Bit = 16; Name = 'PermissionToRequestRelease' }
        @{ Bit = 32; Name = 'PermissionToRelease' }
        @{ Bit = 64; Name = 'PermissionToPreview' }
        @{ Bit = 128; Name = 'PermissionToDelete' }
    )
    return @($bits | Where-Object { ($Value -band $_.Bit) -ne 0 } | ForEach-Object { $_.Name })
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('DefenderQuarantinePolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try { $policies = @(Get-QuarantinePolicy -ErrorAction Stop) }
catch { throw "Failed to read quarantine policies: $($_.Exception.Message)" }
try { $policies += @(Get-QuarantinePolicy -QuarantinePolicyType GlobalQuarantinePolicy -ErrorAction Stop) }
catch { Write-Warning "The global quarantine notification settings could not be read: $($_.Exception.Message)" }

# Every threat policy property that ends in QuarantineTag points at a quarantine policy by name.
$consumerSources = @(
    @{ Kind = 'Anti-spam'; Command = 'Get-HostedContentFilterPolicy' }
    @{ Kind = 'Anti-phishing'; Command = 'Get-AntiPhishPolicy' }
    @{ Kind = 'Anti-malware'; Command = 'Get-MalwareFilterPolicy' }
    @{ Kind = 'Safe Attachments'; Command = 'Get-SafeAttachmentPolicy' }
)
$consumers = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($source in $consumerSources) {
    if ($null -eq (Get-Command -Name $source.Command -ErrorAction SilentlyContinue)) {
        Write-Warning "$($source.Command) is not available in this tenant (Defender for Office 365 required); $($source.Kind) usage is not reported."
        continue
    }
    try {
        foreach ($policy in @(& $source.Command -ErrorAction Stop)) {
            foreach ($property in @($policy.PSObject.Properties | Where-Object { $_.Name -like '*QuarantineTag' -and -not [string]::IsNullOrWhiteSpace([string]$_.Value) })) {
                $consumers.Add([PSCustomObject]@{ Kind = $source.Kind; Policy = [string]$policy.Name; Setting = $property.Name; Tag = [string]$property.Value })
            }
        }
    }
    catch { Write-Warning "$($source.Command) failed; $($source.Kind) usage is incomplete: $($_.Exception.Message)" }
}

$frequencyText = @{ '04:00:00' = 'Every 4 hours'; '1.00:00:00' = 'Daily'; '7.00:00:00' = 'Weekly' }
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($policy in $policies) {
    $value = [int]$policy.EndUserQuarantinePermissionsValue
    $permissions = ConvertFrom-PermissionValue -Value $value
    $uses = @($consumers | Where-Object { $_.Tag -eq [string]$policy.Name })
    $isGlobal = ([string]$policy.QuarantinePolicyType -eq 'GlobalQuarantinePolicy')
    $frequency = $null
    if ($isGlobal -and $null -ne $policy.EndUserSpamNotificationFrequency) { $frequency = [string]$policy.EndUserSpamNotificationFrequency }
    if ($null -ne $frequency -and $frequencyText.ContainsKey($frequency)) { $frequency = '{0} ({1})' -f $frequencyText[$frequency], $frequency }
    # The portal presets differ only in the release action: Release = Full access, Request release = Limited access.
    $accessLevel = 'Custom (no release action)'
    if ($isGlobal) { $accessLevel = 'n/a (global settings)' }
    elseif ($value -eq 0) { $accessLevel = 'No access' }
    elseif ($permissions -contains 'PermissionToRelease') { $accessLevel = 'Full access' }
    elseif ($permissions -contains 'PermissionToRequestRelease') { $accessLevel = 'Limited access' }

    $rows.Add([PSCustomObject]@{
            Name                                    = [string]$policy.Name
            QuarantinePolicyType                    = [string]$policy.QuarantinePolicyType
            AccessLevel                             = $accessLevel
            PermissionsValue                        = $value
            Permissions                             = ($permissions -join ';')
            PermissionsRaw                          = (([string]$policy.EndUserQuarantinePermissions) -replace '\s+', ' ').Trim()
            CanRelease                              = ($permissions -contains 'PermissionToRelease')
            CanRequestRelease                       = ($permissions -contains 'PermissionToRequestRelease')
            ESNEnabled                              = [bool]$policy.ESNEnabled
            IncludeMessagesFromBlockedSenderAddress = [bool]$policy.IncludeMessagesFromBlockedSenderAddress
            UsedByCount                             = $uses.Count
            UsedBy                                  = (@($uses | ForEach-Object { '{0}: {1} ({2})' -f $_.Kind, $_.Policy, $_.Setting }) -join '; ')
            NotificationFrequency                   = $frequency
            NotificationSenderAddress               = $(if ($isGlobal) { [string]$policy.EndUserSpamNotificationCustomFromAddress } else { $null })
            OrganizationBrandingEnabled             = $(if ($isGlobal) { [bool]$policy.OrganizationBrandingEnabled } else { $null })
            MultiLanguageSetting                    = $(if ($isGlobal) { (@($policy.MultiLanguageSetting) -join ';') } else { $null })
            WhenChanged                             = $policy.WhenChanged
        })
}
$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$quarantineRows = @($rows | Where-Object { $_.QuarantinePolicyType -ne 'GlobalQuarantinePolicy' })
$globalRow = @($rows | Where-Object { $_.QuarantinePolicyType -eq 'GlobalQuarantinePolicy' }) | Select-Object -First 1
$unused = @($quarantineRows | Where-Object { $_.UsedByCount -eq 0 })
$releaseWithoutEsn = @($quarantineRows | Where-Object { $_.CanRelease -and -not $_.ESNEnabled -and $_.UsedByCount -gt 0 })

Write-Host ''
Write-Host 'Quarantine policy summary' -ForegroundColor Cyan
Write-Host ('  Quarantine policies      : {0}' -f $quarantineRows.Count)
foreach ($row in $quarantineRows) {
    Write-Host ('    {0,-42} {1,-15} ESN={2,-5} used by {3}' -f $row.Name, $row.AccessLevel, $row.ESNEnabled, $row.UsedByCount)
}
if ($null -ne $globalRow) {
    $sender = $globalRow.NotificationSenderAddress
    if ([string]::IsNullOrWhiteSpace($sender)) { $sender = 'quarantine@messaging.microsoft.com (default)' }
    Write-Host ('  Notification frequency   : {0}' -f $globalRow.NotificationFrequency)
    Write-Host ('  Notification sender      : {0}' -f $sender)
    Write-Host ('  Organization branding    : {0}' -f $globalRow.OrganizationBrandingEnabled)
}
Write-Host ('  Unused policies          : {0}' -f $unused.Count) -ForegroundColor $(if ($unused.Count -gt 0) { 'Yellow' } else { 'Green' })
if ($releaseWithoutEsn.Count -gt 0) {
    $names = ($releaseWithoutEsn | ForEach-Object { $_.Name }) -join ', '
    Write-Warning ('{0} quarantine policy(ies) in use let users release messages but send no quarantine notifications, so users rarely know what is waiting: {1}' -f $releaseWithoutEsn.Count, $names)
}
Write-Host ('  Report                   : {0}' -f $OutputPath)

if ($PassThru) { $rows }
#endregion Main
