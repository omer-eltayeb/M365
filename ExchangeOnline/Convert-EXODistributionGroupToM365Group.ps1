<#
.SYNOPSIS
    Lists distribution groups eligible for upgrade to Microsoft 365 Groups, explains blockers, and optionally submits the upgrade.
.DESCRIPTION
    Uses Get-EligibleDistributionGroupForMigration as the authoritative eligibility list. By default only eligible groups
    are reported; with -IncludeIneligible (or for explicitly passed groups) every group in scope is evaluated and the
    documented blockers detectable locally are listed (directory-synced, security group, room list, owner count, no
    members, nested/unsupported members, alias characters, member of another group), plus settings to review after the
    upgrade. With -Upgrade, eligible groups are submitted in batches of ten with Upgrade-DistributionGroup (ShouldProcess).
.PARAMETER Identity
    One or more distribution group identities (name, alias, primary SMTP address or GUID). These groups are always fully evaluated.
.PARAMETER InputCsv
    Path to a CSV with an Identity or PrimarySmtpAddress column listing the groups to evaluate.
.PARAMETER IncludeIneligible
    Evaluate every distribution group, not only the eligible ones, and explain the blockers (two extra calls per ineligible group).
.PARAMETER Upgrade
    Submit the eligible groups in scope for upgrade. The upgrade is asynchronous and cannot be reverted.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXODistributionGroupUpgrade_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Convert-EXODistributionGroupToM365Group.ps1
    Lists the distribution groups that can be upgraded today. Nothing is changed.
.EXAMPLE
    PS> .\Convert-EXODistributionGroupToM365Group.ps1 -IncludeIneligible -PassThru | Where-Object { -not $_.Eligible } | Format-Table DisplayName, Blockers
    Shows every group that cannot be upgraded together with the detected reasons.
.EXAMPLE
    PS> .\Convert-EXODistributionGroupToM365Group.ps1 -InputCsv .\Wave1.csv -Upgrade
    Submits the eligible groups of the first migration wave for upgrade, prompting before each batch.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients for the report; Exchange Administrator (Distribution Groups role) for -Upgrade
    Category    : Distribution groups
    Changes     : Optional (-Upgrade)
    Notes       : SuccessfullySubmittedForUpgrade only means the request was queued; the new group appears in Get-UnifiedGroup after a
                  few minutes and replaces the distribution group. Blockers the service checks but this script cannot detect: forwarding
                  target of a shared mailbox, sender restriction in another group, email address policies with IncludeUnifiedGroupRecipients.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/upgrade-distributiongroup
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'Identity', Mandatory = $true)]
    [string[]]$Identity,

    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(ParameterSetName = 'All')]
    [switch]$IncludeIneligible,

    [Parameter()]
    [switch]$Upgrade,

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

function Get-UpgradeBlocker {
    <# Returns the documented upgrade blockers (KB 4481100) detectable from the group object, its members and its parents. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Group
    )
    $blockers = New-Object -TypeName System.Collections.Generic.List[string]
    if ($Group.IsDirSynced) { $blockers.Add('Managed on-premises (directory-synced)') }
    if ([string]$Group.RecipientTypeDetails -in @('MailUniversalSecurityGroup', 'RoomList')) { $blockers.Add("Type: $($Group.RecipientTypeDetails)") }
    $ownerCount = @($Group.ManagedBy | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count
    if ($ownerCount -eq 0) { $blockers.Add('No owner') } elseif ($ownerCount -gt 100) { $blockers.Add('More than 100 owners') }
    if ([string]$Group.Alias -notmatch '^[A-Za-z0-9._-]+$') { $blockers.Add('Alias contains special characters') }
    try {
        $members = @(Get-DistributionGroupMember -Identity ([string]$Group.PrimarySmtpAddress) -ResultSize Unlimited -ErrorAction Stop)
        if ($members.Count -eq 0) { $blockers.Add('No members') }
        $unsupported = @($members | ForEach-Object { [string]$_.RecipientTypeDetails } | Where-Object { $_ -notin @('UserMailbox', 'SharedMailbox', 'TeamMailbox', 'MailUser') } | Sort-Object -Unique)
        if ($unsupported.Count -gt 0) { $blockers.Add(('Nested group or unsupported member type(s): {0}' -f ($unsupported -join ','))) }
    }
    catch { Write-Warning "Members of '$($Group.PrimarySmtpAddress)' could not be read: $($_.Exception.Message)" }
    try {
        # Parent groups are found through the filterable Members property, which expects the distinguished name.
        $dn = ([string]$Group.DistinguishedName) -replace "'", "''"
        if (@(Get-Recipient -Filter "Members -eq '$dn'" -ResultSize 1 -ErrorAction Stop).Count -gt 0) { $blockers.Add('Member of another group') }
    }
    catch { Write-Verbose "Parent group lookup failed for '$($Group.PrimarySmtpAddress)': $($_.Exception.Message)" }
    return $blockers
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXODistributionGroupUpgrade_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
    $column = @('Identity', 'PrimarySmtpAddress') | Where-Object { $rows.Count -gt 0 -and $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
    if ($null -eq $column) { throw "InputCsv must contain an 'Identity' or 'PrimarySmtpAddress' column." }
    $Identity = @($rows | ForEach-Object { $_.$column } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }
try { $eligibleGroups = @(Get-EligibleDistributionGroupForMigration -ResultSize Unlimited -ErrorAction Stop) }
catch { throw "Get-EligibleDistributionGroupForMigration failed: $($_.Exception.Message)" }
$eligibleIndex = @{}
foreach ($eligible in $eligibleGroups) { $eligibleIndex[([string]$eligible.PrimarySmtpAddress).ToLowerInvariant()] = $true }

# Without explicit identities the eligible list itself is the scope, unless -IncludeIneligible asks for every group.
if (($null -eq $Identity -or $Identity.Count -eq 0) -and -not $IncludeIneligible) { $Identity = @($eligibleIndex.Keys) }
if ($null -ne $Identity -and $Identity.Count -gt 0) {
    $groups = @(foreach ($id in $Identity) { try { Get-DistributionGroup -Identity $id -ErrorAction Stop } catch { Write-Warning "Group '$id' not found: $($_.Exception.Message)" } })
}
else {
    try { $groups = @(Get-DistributionGroup -ResultSize Unlimited -ErrorAction Stop) } catch { throw "Failed to retrieve distribution groups: $($_.Exception.Message)" }
}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($group in $groups) {
    $index++
    $smtp = [string]$group.PrimarySmtpAddress
    Write-Progress -Activity 'Evaluating upgrade eligibility' -Status "$index of $($groups.Count) - $smtp" -PercentComplete (($index / $groups.Count) * 100)
    $isEligible = $eligibleIndex.ContainsKey($smtp.ToLowerInvariant())
    $blockers = @($(if (-not $isEligible) { Get-UpgradeBlocker -Group $group }))
    $reviewChecks = @{ 'Moderation enabled' = [bool]$group.ModerationEnabled; 'Hidden from address lists' = [bool]$group.HiddenFromAddressListsEnabled
        'Send on behalf delegates' = (@($group.GrantSendOnBehalfTo | Where-Object { $null -ne $_ }).Count -gt 0); 'External senders allowed' = (-not $group.RequireSenderAuthenticationEnabled) }
    $review = @($reviewChecks.Keys | Where-Object { $reviewChecks[$_] } | Sort-Object)
    $results.Add([PSCustomObject]@{
            DisplayName               = [string]$group.DisplayName
            PrimarySmtpAddress        = $smtp
            ExternalDirectoryObjectId = [string]$group.ExternalDirectoryObjectId
            Eligible                  = $isEligible
            Blockers                  = ($blockers -join '; ')
            ReviewAfterUpgrade        = ($review -join '; ')
            UpgradeStatus             = $(if ($Upgrade -and $isEligible) { 'Pending' } else { 'NotRequested' })
            UpgradeDetail             = ''
        })
}
Write-Progress -Activity 'Evaluating upgrade eligibility' -Completed
# Upgrade-DistributionGroup accepts up to ten groups per call; results are matched back by ExternalDirectoryObjectId.
$pending = @($results | Where-Object { $_.UpgradeStatus -eq 'Pending' })
for ($start = 0; $start -lt $pending.Count; $start += 10) {
    $batch = @($pending[$start..([Math]::Min($start + 10, $pending.Count) - 1)])
    $addresses = @($batch | ForEach-Object { $_.PrimarySmtpAddress })
    if (-not $PSCmdlet.ShouldProcess(($addresses -join ', '), 'Upgrade to Microsoft 365 Group (irreversible)')) { foreach ($row in $batch) { $row.UpgradeStatus = 'Skipped' }; continue }
    try {
        $responses = @(Upgrade-DistributionGroup -DlIdentities $addresses -ErrorAction Stop)
        for ($i = 0; $i -lt $batch.Count; $i++) {
            $response = $responses | Where-Object { [string]$_.ExternalDirectoryObjectId -eq $batch[$i].ExternalDirectoryObjectId } | Select-Object -First 1
            if ($null -eq $response -and $responses.Count -eq $batch.Count) { $response = $responses[$i] }
            if ($null -eq $response) { $batch[$i].UpgradeStatus = 'Unknown'; continue }
            $batch[$i].UpgradeStatus = $(if ($response.SuccessfullySubmittedForUpgrade) { 'Submitted' } else { 'Rejected' })
            $batch[$i].UpgradeDetail = [string]$response.ErrorReason
        }
    }
    catch {
        foreach ($row in $batch) { $row.UpgradeStatus = 'Failed'; $row.UpgradeDetail = $_.Exception.Message }
        Write-Warning "Upgrade-DistributionGroup failed for the batch starting at '$($addresses[0])': $($_.Exception.Message)"
    }
}

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'Distribution group upgrade summary' -ForegroundColor Cyan
Write-Host ('  Groups evaluated : {0}' -f $results.Count)
Write-Host ('  Eligible         : {0}' -f @($results | Where-Object { $_.Eligible }).Count) -ForegroundColor Green
foreach ($statusGroup in ($results | Where-Object { $_.UpgradeStatus -ne 'NotRequested' } | Group-Object -Property UpgradeStatus | Sort-Object -Property Name)) {
    Write-Host ('    {0,-14}: {1}' -f $statusGroup.Name, $statusGroup.Count) -ForegroundColor $(if ($statusGroup.Name -eq 'Submitted') { 'Green' } else { 'Yellow' })
}
if ($results.Count -gt 0) { Write-Host ('  Report           : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
