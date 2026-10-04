<#
.SYNOPSIS
    Bulk-adds (or, with -Remove, removes) members of distribution groups from a CSV or from parameters, skipping no-op changes.
.DESCRIPTION
    Builds a list of group/member pairs from -InputCsv (GroupIdentity, MemberIdentity columns) or from -Identity and
    -Members, resolves each group once (Get-DistributionGroup) together with its current membership and each member
    through Get-EXORecipient, then calls Add-DistributionGroupMember or Remove-DistributionGroupMember with
    -BypassSecurityGroupManagerCheck. Members that are already present (or absent, with -Remove) are skipped, as are
    directory-synced groups (manage them on-premises) and dynamic groups (filter-based membership). Nothing is changed
    unless -Apply is specified; every change is wrapped in ShouldProcess. A results CSV records the outcome of each pair.
.PARAMETER Identity
    One or more distribution group identities (name, alias, primary SMTP address or GUID) that receive -Members.
.PARAMETER Members
    One or more recipient identities (UPN, SMTP address, alias or GUID) to add to, or remove from, every group in -Identity.
.PARAMETER InputCsv
    Path to a CSV with GroupIdentity and MemberIdentity columns; one row per group/member pair.
.PARAMETER Remove
    Remove the listed members instead of adding them.
.PARAMETER Apply
    Perform the changes. Without this switch the script is read-only and reports what would be added or removed.
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\EXODistributionGroupMemberChanges_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the result objects to the pipeline.
.EXAMPLE
    PS> .\Add-EXODistributionGroupMembers.ps1 -InputCsv .\NewHires.csv
    Shows which rows of the CSV would result in a change (WouldAdd) and which members are already in place.
.EXAMPLE
    PS> .\Add-EXODistributionGroupMembers.ps1 -Identity sales@contoso.com, marketing@contoso.com -Members jane@contoso.com -Apply
    Adds Jane to both groups, prompting for confirmation before each change.
.EXAMPLE
    PS> .\Add-EXODistributionGroupMembers.ps1 -InputCsv .\Leavers.csv -Remove -Apply -Confirm:$false
    Removes the listed members from their groups without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Distribution Groups role (Recipient Management / Exchange Administrator); View-Only Recipients is enough without -Apply
    Category    : Distribution groups
    Changes     : Yes
    Notes       : Membership is read once per group and kept up to date in memory, so large CSVs cost one call per distinct
                  group plus one per distinct member. Microsoft 365 Groups are not supported - use Add-UnifiedGroupLinks.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/add-distributiongroupmember
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Direct')]
param(
    [Parameter(ParameterSetName = 'Direct', Mandatory = $true)]
    [string[]]$Identity,

    [Parameter(ParameterSetName = 'Direct', Mandatory = $true)]
    [string[]]$Members,

    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$Remove,

    [Parameter()]
    [switch]$Apply,

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

function Get-GroupContext {
    <# Resolves a group once and caches its object, its current membership (keyed by SMTP address) and any reason the
       script must not change it (not found, dynamic, directory-synced, membership unreadable). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId
    )
    if ($script:GroupCache.ContainsKey($GroupId)) { return $script:GroupCache[$GroupId] }
    $context = [PSCustomObject]@{ Group = $null; Members = @{}; SkipReason = '' }
    try { $context.Group = Get-DistributionGroup -Identity $GroupId -ErrorAction Stop }
    catch {
        $reason = $_.Exception.Message
        $dynamic = Get-DynamicDistributionGroup -Identity $GroupId -ErrorAction SilentlyContinue
        $context.SkipReason = $(if ($null -ne $dynamic) { 'Dynamic distribution group - membership is defined by its recipient filter' } else { "Group not found: $reason" })
    }
    if ($null -ne $context.Group -and $context.Group.IsDirSynced) { $context.SkipReason = 'Directory-synced group - manage membership on-premises' }
    elseif ($null -ne $context.Group) {
        try {
            foreach ($member in @(Get-DistributionGroupMember -Identity ([string]$context.Group.PrimarySmtpAddress) -ResultSize Unlimited -ErrorAction Stop)) {
                if (-not [string]::IsNullOrWhiteSpace($member.PrimarySmtpAddress)) { $context.Members[([string]$member.PrimarySmtpAddress).ToLowerInvariant()] = $true }
            }
        }
        catch { $context.SkipReason = "Membership could not be read: $($_.Exception.Message)" }
    }
    $script:GroupCache[$GroupId] = $context
    return $context
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXODistributionGroupMemberChanges_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

$operations = New-Object -TypeName System.Collections.Generic.List[object]
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)
    $missing = @(@('GroupIdentity', 'MemberIdentity') | Where-Object { $rows.Count -eq 0 -or $rows[0].PSObject.Properties.Name -notcontains $_ })
    if ($missing.Count -gt 0) { throw "InputCsv must contain 'GroupIdentity' and 'MemberIdentity' columns." }
    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace($row.GroupIdentity) -or [string]::IsNullOrWhiteSpace($row.MemberIdentity)) { continue }
        $operations.Add(@{ Group = $row.GroupIdentity.Trim(); Member = $row.MemberIdentity.Trim() })
    }
}
else {
    foreach ($groupId in $Identity) { foreach ($memberId in $Members) { $operations.Add(@{ Group = $groupId; Member = $memberId }) } }
}
if ($operations.Count -eq 0) { throw 'No group/member pairs to process.' }

try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

$operation = $(if ($Remove) { 'Remove' } else { 'Add' })
if (-not $Apply) { Write-Host "Read-only mode: add -Apply to $($operation.ToLower()) members." -ForegroundColor Yellow }
$script:GroupCache = @{}
$memberCache = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($op in $operations) {
    $index++
    Write-Progress -Activity "$operation distribution group members" -Status "$index of $($operations.Count) - $($op.Member) -> $($op.Group)" -PercentComplete (($index / $operations.Count) * 100)
    $context = Get-GroupContext -GroupId $op.Group
    $row = [PSCustomObject]@{ Group = $op.Group; GroupSmtp = ''; Member = $op.Member; MemberSmtp = ''; MemberType = ''; Operation = $operation; Result = ''; Detail = '' }
    if ($null -ne $context.Group) { $row.Group = [string]$context.Group.DisplayName; $row.GroupSmtp = [string]$context.Group.PrimarySmtpAddress }
    $results.Add($row)
    if (-not [string]::IsNullOrEmpty($context.SkipReason)) { $row.Result = 'Skipped'; $row.Detail = $context.SkipReason; continue }

    if (-not $memberCache.ContainsKey($op.Member)) {
        try { $memberCache[$op.Member] = Get-EXORecipient -Identity $op.Member -Properties PrimarySmtpAddress, RecipientTypeDetails -ErrorAction Stop | Select-Object -First 1 }
        catch { $memberCache[$op.Member] = $null; Write-Verbose "Member '$($op.Member)' could not be resolved: $($_.Exception.Message)" }
    }
    $recipient = $memberCache[$op.Member]
    if ($null -eq $recipient) { $row.Result = 'MemberNotFound'; continue }
    $row.MemberSmtp = [string]$recipient.PrimarySmtpAddress
    $row.MemberType = [string]$recipient.RecipientTypeDetails
    $key = $row.MemberSmtp.ToLowerInvariant()
    $isMember = $context.Members.ContainsKey($key)
    if (-not $Remove -and $isMember) { $row.Result = 'AlreadyMember'; continue }
    if ($Remove -and -not $isMember) { $row.Result = 'NotMember'; continue }
    if (-not $Apply) { $row.Result = "Would$operation"; continue }
    if (-not $PSCmdlet.ShouldProcess($row.GroupSmtp, "$operation member $($row.MemberSmtp)")) { $row.Result = 'Skipped'; $row.Detail = 'Declined or -WhatIf'; continue }
    $memberParams = @{ Identity = $row.GroupSmtp; Member = $row.MemberSmtp; BypassSecurityGroupManagerCheck = $true; Confirm = $false; ErrorAction = 'Stop' }
    try {
        if ($Remove) { Remove-DistributionGroupMember @memberParams; $context.Members.Remove($key); $row.Result = 'Removed' }
        else { Add-DistributionGroupMember @memberParams; $context.Members[$key] = $true; $row.Result = 'Added' }
    }
    catch { $row.Result = 'Failed'; $row.Detail = $_.Exception.Message; Write-Warning "$operation of '$($row.MemberSmtp)' on '$($row.GroupSmtp)' failed: $($_.Exception.Message)" }
}
Write-Progress -Activity "$operation distribution group members" -Completed

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host ('Distribution group member {0} summary' -f $operation.ToLower()) -ForegroundColor Cyan
Write-Host ('  Pairs processed  : {0} ({1} group(s))' -f $results.Count, $script:GroupCache.Count)
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = switch ($group.Name) { 'Added' { 'Green' } 'Removed' { 'Green' } 'Failed' { 'Red' } 'MemberNotFound' { 'Red' } default { 'Yellow' } }
    Write-Host ('    {0,-15}: {1}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
Write-Host ('  Results          : {0}' -f $OutputPath)

if ($PassThru) {
    $results
}
#endregion Main
