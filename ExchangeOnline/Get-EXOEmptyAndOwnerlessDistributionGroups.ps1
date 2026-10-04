<#
.SYNOPSIS
    Finds distribution groups that are empty and/or have no valid owner, with optional owner assignment or removal.
.DESCRIPTION
    Enumerates distribution groups (cloud-managed by default), counts members with Get-DistributionGroupMember and
    resolves every ManagedBy entry through Get-EXORecipient (account state via Get-User with -CheckOwnerStatus).
    Findings: Empty, NoOwner, NoValidOwner (all owners deleted/disabled), OwnerNotFound, OwnerDisabled. The report is
    read-only; -SetOwner adds an owner to groups without a valid owner and -RemoveEmpty deletes empty groups (ShouldProcess).
.PARAMETER Identity
    One or more group identities (name, alias, primary SMTP address or GUID). When omitted, every distribution group is evaluated.
.PARAMETER InputCsv
    Path to a CSV with an Identity or PrimarySmtpAddress column listing the groups to evaluate.
.PARAMETER CheckOwnerStatus
    Also flag owners whose account is disabled (one Get-User call per distinct owner).
.PARAMETER IncludeDirSynced
    Include directory-synced groups in the report. They are never changed because membership and owners are managed on-premises.
.PARAMETER SetOwner
    UPN or SMTP address to add as owner (ManagedBy) of every group that has no valid owner.
.PARAMETER RemoveEmpty
    Remove groups with zero members. Mail-enabled security groups are skipped unless -IncludeSecurityGroups is specified.
.PARAMETER IncludeSecurityGroups
    Allow -RemoveEmpty to delete empty mail-enabled security groups, which may still be used for permissions.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOEmptyOwnerlessGroups_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOEmptyAndOwnerlessDistributionGroups.ps1 -CheckOwnerStatus
    Reports cloud-managed groups that are empty or lack an enabled, existing owner.
.EXAMPLE
    PS> .\Get-EXOEmptyAndOwnerlessDistributionGroups.ps1 -SetOwner it-admins@contoso.com -RemoveEmpty -WhatIf
    Shows which ownerless groups would receive the IT admins group as owner and which empty groups would be removed.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients for the report; Distribution Groups role (Recipient Management / Exchange Administrator) for changes
    Category    : Distribution groups
    Changes     : Optional (-SetOwner / -RemoveEmpty)
    Notes       : Two calls per group (members, owners) plus one per distinct owner - roughly 1-2 seconds per group. Removed
                  groups are not recoverable; export the members first with Export-EXODistributionGroupMembers.ps1.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/set-distributiongroup
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

    [Parameter()]
    [switch]$CheckOwnerStatus,

    [Parameter()]
    [switch]$IncludeDirSynced,

    [Parameter()]
    [string]$SetOwner,

    [Parameter()]
    [switch]$RemoveEmpty,

    [Parameter()]
    [switch]$IncludeSecurityGroups,

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

function Resolve-Owner {
    <# Resolves a ManagedBy entry to its SMTP address and state (Valid, Disabled, NotFound); cached per run. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OwnerId
    )
    if ($script:OwnerCache.ContainsKey($OwnerId)) { return $script:OwnerCache[$OwnerId] }
    $owner = [PSCustomObject]@{ Address = $OwnerId; State = 'NotFound' }
    try {
        $recipient = Get-EXORecipient -Identity $OwnerId -Properties PrimarySmtpAddress, RecipientTypeDetails -ErrorAction Stop | Select-Object -First 1
        if ($null -eq $recipient) { throw 'no recipient returned' }
        $owner.Address = [string]$recipient.PrimarySmtpAddress
        $owner.State = 'Valid'
        # Shared mailboxes are disabled by design, so only user mailboxes and mail users are checked.
        $isUser = [string]$recipient.RecipientTypeDetails -in @('UserMailbox', 'MailUser')
        if ($CheckOwnerStatus -and $isUser -and (Get-User -Identity $owner.Address -ErrorAction Stop).AccountDisabled) { $owner.State = 'Disabled' }
    }
    catch { Write-Verbose "Owner '$OwnerId' could not be resolved: $($_.Exception.Message)" }
    $script:OwnerCache[$OwnerId] = $owner
    return $owner
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOEmptyOwnerlessGroups_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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
if ($null -ne $Identity -and $Identity.Count -gt 0) {
    $groups = @(foreach ($id in $Identity) { try { Get-DistributionGroup -Identity $id -ErrorAction Stop } catch { Write-Warning "Group '$id' was not found: $($_.Exception.Message)" } })
}
else {
    try { $groups = @(Get-DistributionGroup -ResultSize Unlimited -ErrorAction Stop) } catch { throw "Failed to retrieve distribution groups: $($_.Exception.Message)" }
}
if (-not $IncludeDirSynced) { $groups = @($groups | Where-Object { -not $_.IsDirSynced }) }

$script:OwnerCache = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($group in $groups) {
    $index++
    $smtp = [string]$group.PrimarySmtpAddress
    Write-Progress -Activity 'Evaluating distribution groups' -Status "$index of $($groups.Count) - $smtp" -PercentComplete (($index / $groups.Count) * 100)
    try { $memberCount = @(Get-DistributionGroupMember -Identity $smtp -ResultSize Unlimited -ErrorAction Stop).Count }
    catch { $memberCount = $null; Write-Warning "Members of '$smtp' could not be read: $($_.Exception.Message)" }
    $owners = @(foreach ($owner in @($group.ManagedBy)) { if (-not [string]::IsNullOrWhiteSpace([string]$owner)) { Resolve-Owner -OwnerId ([string]$owner) } })
    $validOwners = @($owners | Where-Object { $_.State -eq 'Valid' })
    $findings = New-Object -TypeName System.Collections.Generic.List[string]
    if ($memberCount -eq 0) { $findings.Add('Empty') }
    if ($owners.Count -eq 0) { $findings.Add('NoOwner') } elseif ($validOwners.Count -eq 0) { $findings.Add('NoValidOwner') }
    foreach ($state in @('NotFound', 'Disabled')) { if ($owners.State -contains $state) { $findings.Add("Owner$state") } }
    if ($findings.Count -eq 0) { continue }

    $actions = New-Object -TypeName System.Collections.Generic.List[string]
    if ($group.IsDirSynced -and ($RemoveEmpty -or -not [string]::IsNullOrWhiteSpace($SetOwner))) { $actions.Add('Skipped: directory-synced (managed on-premises)') }
    if ($RemoveEmpty -and $memberCount -eq 0 -and -not $group.IsDirSynced) {
        if ([string]$group.RecipientTypeDetails -eq 'MailUniversalSecurityGroup' -and -not $IncludeSecurityGroups) { $actions.Add('Remove skipped: security group') }
        elseif ($PSCmdlet.ShouldProcess($smtp, 'Remove empty distribution group')) {
            try { Remove-DistributionGroup -Identity $smtp -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop; $actions.Add('Removed') }
            catch { $actions.Add('Remove failed'); Write-Warning "Remove-DistributionGroup failed for '$smtp': $($_.Exception.Message)" }
        }
        else { $actions.Add('Remove skipped') }
    }
    if ($actions -notcontains 'Removed' -and -not [string]::IsNullOrWhiteSpace($SetOwner) -and $validOwners.Count -eq 0 -and -not $group.IsDirSynced) {
        if ($PSCmdlet.ShouldProcess($smtp, "Add owner $SetOwner")) {
            try { Set-DistributionGroup -Identity $smtp -ManagedBy @{ Add = $SetOwner } -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop; $actions.Add("Owner set: $SetOwner") }
            catch { $actions.Add('SetOwner failed'); Write-Warning "Set-DistributionGroup failed for '$smtp': $($_.Exception.Message)" }
        }
        else { $actions.Add('SetOwner skipped') }
    }
    $results.Add([PSCustomObject]@{
            DisplayName          = [string]$group.DisplayName
            PrimarySmtpAddress   = $smtp
            RecipientTypeDetails = [string]$group.RecipientTypeDetails
            IsDirSynced          = [bool]$group.IsDirSynced
            MemberCount          = $memberCount
            Owners               = (@($owners | ForEach-Object { '{0} ({1})' -f $_.Address, $_.State }) -join '; ')
            Finding              = ($findings -join '; ')
            Action               = ($actions -join '; ')
            WhenCreated          = $group.WhenCreated
        })
}
Write-Progress -Activity 'Evaluating distribution groups' -Completed

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'Empty and ownerless distribution groups' -ForegroundColor Cyan
Write-Host ('  Groups evaluated     : {0}' -f $groups.Count)
Write-Host ('  Groups with findings : {0}' -f $results.Count) -ForegroundColor $(if ($results.Count -gt 0) { 'Yellow' } else { 'Green' })
foreach ($finding in ($results | ForEach-Object { $_.Finding -split '; ' } | Group-Object | Sort-Object -Property Name)) { Write-Host ('    {0,-18}: {1}' -f $finding.Name, $finding.Count) }
if ($results.Count -gt 0) { Write-Host ('  Report               : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
