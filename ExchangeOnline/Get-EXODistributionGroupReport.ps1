<#
.SYNOPSIS
    Inventories distribution groups, mail-enabled security groups, room lists and (optionally) dynamic distribution groups.
.DESCRIPTION
    Lists every group returned by Get-DistributionGroup (plus Get-DynamicDistributionGroup with -IncludeDynamic) with
    its type, resolved owners, member count, delivery restrictions (external senders, moderation, sender allow list),
    join/leave restrictions, address-list visibility, directory-sync state and timestamps. Owners are resolved to SMTP
    addresses with a cached Get-EXORecipient lookup. Groups that accept mail from external senders
    (RequireSenderAuthenticationEnabled = $false) are flagged. The script is read-only.
.PARAMETER Identity
    One or more group identities (name, alias, primary SMTP address or GUID). When omitted, every group is reported.
.PARAMETER InputCsv
    Path to a CSV with an Identity or PrimarySmtpAddress column listing the groups to report.
.PARAMETER IncludeDynamic
    Also include dynamic distribution groups (member count uses Get-DynamicDistributionGroupMember).
.PARAMETER SkipMemberCount
    Skip the per-group member enumeration (one call per group) for a much faster run on large tenants.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXODistributionGroups_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXODistributionGroupReport.ps1
    Reports every distribution, mail-enabled security and room list group with member counts.
.EXAMPLE
    PS> .\Get-EXODistributionGroupReport.ps1 -IncludeDynamic -SkipMemberCount -PassThru | Where-Object { $_.ExternalSendersAllowed }
    Fast inventory including dynamic groups, filtered to the groups that accept mail from outside the organisation.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients (Exchange Online) for the report
    Category    : Distribution groups
    Changes     : No
    Notes       : Member counting calls Get-DistributionGroupMember once per group (about one second each); use -SkipMemberCount
                  for a quick inventory. Microsoft 365 Groups are not included - use Get-UnifiedGroup for those.
                  AcceptMessagesOnlyFromCount covers AcceptMessagesOnlyFromSendersOrMembers (individual senders and groups).
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-distributiongroup
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(ParameterSetName = 'Identity', Mandatory = $true)]
    [string[]]$Identity,

    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$IncludeDynamic,

    [Parameter()]
    [switch]$SkipMemberCount,

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

function Resolve-OwnerAddress {
    <# Resolves a ManagedBy entry (canonical name, display name or GUID) to a primary SMTP address; cached per run. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OwnerId
    )
    if (-not $script:OwnerCache.ContainsKey($OwnerId)) {
        $address = $OwnerId
        try {
            $recipient = Get-EXORecipient -Identity $OwnerId -Properties PrimarySmtpAddress -ErrorAction Stop | Select-Object -First 1
            if (-not [string]::IsNullOrWhiteSpace($recipient.PrimarySmtpAddress)) { $address = [string]$recipient.PrimarySmtpAddress }
        }
        catch { Write-Verbose "Owner '$OwnerId' could not be resolved: $($_.Exception.Message)" }
        $script:OwnerCache[$OwnerId] = $address
    }
    return $script:OwnerCache[$OwnerId]
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXODistributionGroups_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

$groups = New-Object -TypeName System.Collections.Generic.List[object]
if ($null -ne $Identity -and $Identity.Count -gt 0) {
    foreach ($id in $Identity) {
        # A static lookup failing may simply mean the identity is a dynamic group.
        try { $groups.Add((Get-DistributionGroup -Identity $id -ErrorAction Stop)) }
        catch {
            $dynamic = $(if ($IncludeDynamic) { Get-DynamicDistributionGroup -Identity $id -ErrorAction SilentlyContinue } else { $null })
            if ($null -ne $dynamic) { $groups.Add($dynamic) } else { Write-Warning "Group '$id' was not found: $($_.Exception.Message)" }
        }
    }
}
else {
    try {
        foreach ($group in @(Get-DistributionGroup -ResultSize Unlimited -ErrorAction Stop)) { $groups.Add($group) }
        if ($IncludeDynamic) { foreach ($group in @(Get-DynamicDistributionGroup -ResultSize Unlimited -ErrorAction Stop)) { $groups.Add($group) } }
    }
    catch { throw "Failed to retrieve distribution groups: $($_.Exception.Message)" }
}

$typeNames = @{ MailUniversalSecurityGroup = 'Mail-enabled security'; RoomList = 'RoomList'; DynamicDistributionGroup = 'Dynamic' }
$script:OwnerCache = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($group in $groups) {
    $index++
    $smtp = [string]$group.PrimarySmtpAddress
    $typeDetails = [string]$group.RecipientTypeDetails
    Write-Progress -Activity 'Collecting distribution groups' -Status "$index of $($groups.Count) - $smtp" -PercentComplete (($index / $groups.Count) * 100)
    $groupType = $(if ($typeNames.ContainsKey($typeDetails)) { $typeNames[$typeDetails] } else { 'Distribution' })
    $memberCount = $null
    if (-not $SkipMemberCount) {
        try {
            if ($typeDetails -eq 'DynamicDistributionGroup') { $memberCount = @(Get-DynamicDistributionGroupMember -Identity $smtp -ResultSize Unlimited -ErrorAction Stop).Count }
            else { $memberCount = @(Get-DistributionGroupMember -Identity $smtp -ResultSize Unlimited -ErrorAction Stop).Count }
        }
        catch { Write-Warning "Members of '$smtp' could not be counted: $($_.Exception.Message)" }
    }
    $owners = @(foreach ($owner in @($group.ManagedBy)) { if (-not [string]::IsNullOrWhiteSpace([string]$owner)) { Resolve-OwnerAddress -OwnerId ([string]$owner) } })
    $results.Add([PSCustomObject]@{
            DisplayName                        = [string]$group.DisplayName
            PrimarySmtpAddress                 = $smtp
            GroupType                          = $groupType
            RecipientTypeDetails               = $typeDetails
            ManagedBy                          = ($owners -join '; ')
            OwnerCount                         = $owners.Count
            MemberCount                        = $memberCount
            RequireSenderAuthenticationEnabled = [bool]$group.RequireSenderAuthenticationEnabled
            ExternalSendersAllowed             = (-not [bool]$group.RequireSenderAuthenticationEnabled)
            HiddenFromAddressListsEnabled      = [bool]$group.HiddenFromAddressListsEnabled
            MemberJoinRestriction              = [string]$group.MemberJoinRestriction
            MemberDepartRestriction            = [string]$group.MemberDepartRestriction
            ModerationEnabled                  = [bool]$group.ModerationEnabled
            AcceptMessagesOnlyFromCount        = @($group.AcceptMessagesOnlyFromSendersOrMembers | Where-Object { $null -ne $_ }).Count
            IsDirSynced                        = [bool]$group.IsDirSynced
            WhenCreated                        = $group.WhenCreated
            WhenChanged                        = $group.WhenChanged
        })
}
Write-Progress -Activity 'Collecting distribution groups' -Completed

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

$external = @($results | Where-Object { $_.ExternalSendersAllowed })
Write-Host ''
Write-Host 'Distribution group summary' -ForegroundColor Cyan
Write-Host ('  Groups reported          : {0}' -f $results.Count)
foreach ($typeGroup in ($results | Group-Object -Property GroupType | Sort-Object -Property Name)) {
    Write-Host ('    {0,-23}: {1}' -f $typeGroup.Name, $typeGroup.Count)
}
Write-Host ('  External senders allowed : {0}' -f $external.Count) -ForegroundColor $(if ($external.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Without owner            : {0}' -f @($results | Where-Object { $_.OwnerCount -eq 0 }).Count)
if (-not $SkipMemberCount) { Write-Host ('  Empty (0 members)        : {0}' -f @($results | Where-Object { $_.MemberCount -eq 0 }).Count) }
Write-Host ('  Directory-synced         : {0}' -f @($results | Where-Object { $_.IsDirSynced }).Count)
if ($results.Count -gt 0) { Write-Host ('  Report                   : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
