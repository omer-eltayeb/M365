<#
.SYNOPSIS
    Reports who holds Exchange Online admin permissions through role groups and direct management role assignments.
.DESCRIPTION
    Lists every role group (Get-RoleGroup: name, description, roles, ManagedBy) with its members (Get-RoleGroupMember) and
    adds the direct, non-delegating role assignments made to individual users (Get-ManagementRoleAssignment
    -RoleAssigneeType User). Custom role groups are flagged, empty built-in groups are hidden unless -IncludeBuiltInEmpty,
    and -CheckAccountStatus marks members whose account is disabled (Get-User). Writes a CSV and prints a summary that
    highlights the Organization Management membership.
.PARAMETER IncludeBuiltInEmpty
    Also list built-in role groups that have no members (they are hidden by default to keep the report short).
.PARAMETER CheckAccountStatus
    Look up each user member with Get-User and report whether the account is disabled (one extra call per unique member).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EXOAdminRoleAssignments_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EXOAdminRoleAssignments.ps1
    Reports all role group members and direct role assignments, hiding empty built-in groups.
.EXAMPLE
    PS> .\Get-EXOAdminRoleAssignments.ps1 -CheckAccountStatus -PassThru | Where-Object { $_.RoleGroup -eq 'Organization Management' }
    Returns the Organization Management members with their account status.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Organization Management (or Global Reader); View-Only Recipients for -CheckAccountStatus
    Category    : Administration, audit & migration
    Changes     : No
    Notes       : Entra ID roles (Global Administrator, Exchange Administrator, Global Reader, Security Administrator and others)
                  also grant Exchange permissions through hidden linked role groups that this report does not expand - review them
                  with EntraID\Get-EntraPrivilegedRoleMembers.ps1. Members that are groups are listed but not expanded.
.LINK
    https://learn.microsoft.com/exchange/permissions-exo/permissions-exo
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeBuiltInEmpty,

    [Parameter()]
    [switch]$CheckAccountStatus,

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

function Get-AccountDisabled {
    <# Returns $true/$false for the AccountDisabled flag of a user, $null when the lookup is skipped or fails; results are cached. #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserIdentity
    )
    if (-not $script:CheckAccountStatus -or [string]::IsNullOrWhiteSpace($UserIdentity)) { return $null }
    if (-not $script:accountCache.ContainsKey($UserIdentity)) {
        try { $script:accountCache[$UserIdentity] = [bool](Get-User -Identity $UserIdentity -ErrorAction Stop).AccountDisabled }
        catch { Write-Verbose "Account status of '$UserIdentity' could not be read: $($_.Exception.Message)"; $script:accountCache[$UserIdentity] = $null }
    }
    return $script:accountCache[$UserIdentity]
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXOAdminRoleAssignments_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-ExchangeIfNeeded }
catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

try { $roleGroups = @(Get-RoleGroup -ResultSize Unlimited -ErrorAction Stop | Sort-Object -Property Name) }
catch { throw "Failed to read the role groups: $($_.Exception.Message)" }

# Built-in groups: the documented Exchange Online names, linked/partner groups, and the hidden Entra-role groups with a GUID suffix.
$builtInNames = @('Organization Management', 'Recipient Management', 'View-Only Organization Management', 'Help Desk', 'Records Management',
    'Discovery Management', 'Compliance Management', 'Hygiene Management', 'Security Administrator', 'Security Reader', 'UM Management',
    'Public Folder Management', 'Server Management', 'Delegated Setup')
$accountCache = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$hiddenEmpty = 0
$index = 0
foreach ($group in $roleGroups) {
    $index++
    Write-Progress -Activity 'Reading role group members' -Status "$index of $($roleGroups.Count) - $($group.Name)" -PercentComplete (($index / $roleGroups.Count) * 100)
    $isBuiltIn = ($builtInNames -contains $group.Name) -or ([string]$group.RoleGroupType -ne 'Standard') -or ($group.Name -match '_[0-9a-fA-F-]{8,}$')
    $roles = (@($group.Roles | ForEach-Object { [string]$_ } | Sort-Object) -join '; ')
    $managedBy = (@($group.ManagedBy | ForEach-Object { [string]$_ }) -join '; ')
    try { $members = @(Get-RoleGroupMember -Identity ([string]$group.Identity) -ResultSize Unlimited -ErrorAction Stop) }
    catch { Write-Warning "Members of role group '$($group.Name)' could not be read: $($_.Exception.Message)"; $members = @() }

    if ($members.Count -eq 0) {
        if ($isBuiltIn -and -not $IncludeBuiltInEmpty) { $hiddenEmpty++; continue }
        $results.Add([PSCustomObject]@{
                AssignmentType = 'Role group'; RoleGroup = $group.Name; IsCustomRoleGroup = -not $isBuiltIn; Member = '(no members)'; MemberType = ''
                MemberAddress = ''; Roles = $roles; Scope = ''; ManagedBy = $managedBy; Description = [string]$group.Description; AccountDisabled = $null
            })
        continue
    }
    foreach ($member in $members) {
        $memberType = [string]$member.RecipientTypeDetails
        if ($memberType -eq '') { $memberType = [string]$member.RecipientType }
        $memberName = [string]$member.DisplayName
        if ($memberName -eq '') { $memberName = [string]$member.Name }
        $accountDisabled = $null
        if ($memberType -like '*User*' -or $memberType -like '*Mailbox*') { $accountDisabled = Get-AccountDisabled -UserIdentity ([string]$member.Identity) }
        $results.Add([PSCustomObject]@{
                AssignmentType = 'Role group'; RoleGroup = $group.Name; IsCustomRoleGroup = -not $isBuiltIn; Member = $memberName; MemberType = $memberType
                MemberAddress = [string]$member.PrimarySmtpAddress; Roles = $roles; Scope = ''; ManagedBy = $managedBy; Description = [string]$group.Description
                AccountDisabled = $accountDisabled
            })
    }
}
Write-Progress -Activity 'Reading role group members' -Completed

try { $directAssignments = @(Get-ManagementRoleAssignment -RoleAssigneeType User -Delegating:$false -ErrorAction Stop) }
catch { Write-Warning "Direct role assignments could not be read: $($_.Exception.Message)"; $directAssignments = @() }
foreach ($assignment in $directAssignments) {
    $scope = [string]$assignment.RecipientWriteScope
    if (-not [string]::IsNullOrEmpty([string]$assignment.CustomRecipientWriteScope)) { $scope = 'Custom: {0}' -f $assignment.CustomRecipientWriteScope }
    if (-not [bool]$assignment.Enabled) { $scope = "$scope (assignment disabled)" }
    $results.Add([PSCustomObject]@{
            AssignmentType = 'Direct'; RoleGroup = ''; IsCustomRoleGroup = $false; Member = [string]$assignment.RoleAssigneeName; MemberType = 'User (direct assignment)'
            MemberAddress = ''; Roles = [string]$assignment.Role; Scope = $scope; ManagedBy = ''; Description = [string]$assignment.Name
            AccountDisabled = (Get-AccountDisabled -UserIdentity ([string]$assignment.RoleAssignee))
        })
}

if ($results.Count -eq 0) { Write-Warning 'No role assignments were found; nothing to export.'; return }
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$orgMgmt = @($results | Where-Object { $_.RoleGroup -eq 'Organization Management' -and $_.Member -ne '(no members)' }).Count
$customGroups = @($results | Where-Object { $_.IsCustomRoleGroup } | Select-Object -Property RoleGroup -Unique).Count
$disabled = @($results | Where-Object { $_.AccountDisabled -eq $true }).Count
$groupMembers = @($results | Where-Object { $_.MemberType -like '*Group*' }).Count

Write-Host "Exchange admin role assignment summary ($($results.Count) rows)" -ForegroundColor Cyan
Write-Host ('  Role groups                 : {0} ({1} empty built-in groups hidden)' -f $roleGroups.Count, $hiddenEmpty)
Write-Host ('  Custom role groups          : {0}' -f $customGroups) -ForegroundColor $(if ($customGroups -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Organization Management     : {0} members' -f $orgMgmt) -ForegroundColor $(if ($orgMgmt -gt 5) { 'Yellow' } else { 'Green' })
Write-Host ('  Direct user assignments     : {0}' -f $directAssignments.Count) -ForegroundColor $(if ($directAssignments.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Group members (not expanded): {0}' -f $groupMembers)
if ($CheckAccountStatus) { Write-Host ('  Disabled member accounts    : {0}' -f $disabled) -ForegroundColor $(if ($disabled -gt 0) { 'Yellow' } else { 'Green' }) }
Write-Host '  Entra ID roles (Exchange Administrator, Global Administrator, ...) also grant access - see EntraID\Get-EntraPrivilegedRoleMembers.ps1.' -ForegroundColor DarkGray
Write-Host ('  Report                      : {0}' -f $OutputPath)

if ($PassThru) { $results }
#endregion Main
