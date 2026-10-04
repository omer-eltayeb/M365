<#
.SYNOPSIS
    Reports Microsoft Purview (Security & Compliance) role groups, their roles and members, plus the eDiscovery case admins.
.DESCRIPTION
    Connects to Security & Compliance PowerShell, enumerates every role group with Get-RoleGroup and resolves its members
    with Get-RoleGroupMember. Each member becomes one row (RoleGroup, Member, MemberType, Roles, IsBuiltIn); empty groups are
    kept as an informational row, Organization Management members are flagged and, with -CheckAccountStatus, disabled
    accounts are detected through Get-User in an Exchange Online session. Get-eDiscoveryCaseAdmin is exported to a second
    CSV. Prints a summary of custom groups, empty groups, flagged members and eDiscovery administrators.
.PARAMETER CheckAccountStatus
    Look up every user member with Get-User (Exchange Online session) and flag disabled accounts. Slower on large groups.
.PARAMETER OutputPath
    Path of the membership CSV. Defaults to .\Reports\PurviewComplianceRoleGroups_yyyyMMdd-HHmm.csv; eDiscovery case admins are written next to it as <base>_eDiscoveryAdmins.csv.
.PARAMETER PassThru
    Also emit the membership rows to the pipeline.
.EXAMPLE
    PS> .\Get-PurviewComplianceRoleGroups.ps1
    Exports every Purview role group membership and prints who holds Organization Management.
.EXAMPLE
    PS> .\Get-PurviewComplianceRoleGroups.ps1 -CheckAccountStatus -PassThru | Where-Object { $_.Flag }
    Also connects to Exchange Online to find disabled accounts that still hold compliance roles and shows only flagged rows.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Role Management role (Organization Management or Compliance Administrator role group) in Security & Compliance PowerShell;
                  Get-eDiscoveryCaseAdmin needs eDiscovery Manager or Organization Management; -CheckAccountStatus needs Exchange Online View-Only Recipients
    Category    : Risk, compliance & roles
    Changes     : No
    Notes       : Purview permissions are evaluated from two places: the Security & Compliance role groups reported here and Entra ID
                  roles. Users holding the Entra Global Administrator, Compliance Administrator or Compliance Data Administrator role
                  get the equivalent Purview access without appearing in any role group, so review Entra role assignments as well.
                  IsBuiltIn is derived from a list of well-known role group names; new Microsoft-created groups may show as custom.
.LINK
    https://learn.microsoft.com/purview/purview-compliance-portal-permissions
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-rolegroupmember
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewComplianceRoleGroups_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$adminsPath = [System.IO.Path]::ChangeExtension($OutputPath, $null) + '_eDiscoveryAdmins.csv'

# Well-known Microsoft-created role groups in the Purview portal; anything else is treated as custom.
$builtInGroups = @('Organization Management', 'Compliance Administrator', 'Compliance Data Administrator', 'Security Administrator', 'Security Operator',
    'Security Reader', 'Global Reader', 'eDiscovery Manager', 'Reviewer', 'Supervisory Review', 'Records Management', 'Data Investigator',
    'Data Source Administrators', 'Quarantine Administrator', 'MailFlow Administrator', 'Service Assurance User', 'Knowledge Administrators',
    'IRM Contributors', 'Billing Administrator', 'Attack Simulator Administrators', 'Attack Simulator Payload Authors',
    'Information Protection', 'Information Protection Admins', 'Information Protection Analysts', 'Information Protection Investigators',
    'Information Protection Readers', 'Insider Risk Management', 'Insider Risk Management Admins', 'Insider Risk Management Analysts',
    'Insider Risk Management Investigators', 'Insider Risk Management Auditors', 'Insider Risk Management Approvers',
    'Insider Risk Management Session Approvers', 'Communication Compliance', 'Communication Compliance Admins',
    'Communication Compliance Analysts', 'Communication Compliance Investigators', 'Communication Compliance Viewers',
    'Privacy Management', 'Privacy Management Administrators', 'Privacy Management Analysts', 'Privacy Management Investigators',
    'Privacy Management Viewers', 'Privacy Management Contributors', 'Subject Rights Request Administrators', 'Subject Rights Request Approvers',
    'Compliance Manager Administrators', 'Compliance Manager Assessors', 'Compliance Manager Contributors', 'Compliance Manager Readers',
    'Content Explorer Content Viewer', 'Content Explorer List Viewer')

try {
    Connect-ExchangeIfNeeded -Compliance
    $roleGroups = @(Get-RoleGroup -ErrorAction Stop | Sort-Object -Property Name)
}
catch {
    throw "Unable to read the Security & Compliance role groups: $($_.Exception.Message)"
}
if ($CheckAccountStatus) {
    try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online for -CheckAccountStatus: $($_.Exception.Message)" }
}

$accountCache = @{}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$index = 0
foreach ($group in $roleGroups) {
    $index++
    Write-Progress -Activity 'Reading role group members' -Status $group.Name -PercentComplete (100 * $index / $roleGroups.Count)
    $members = @()
    try {
        $members = @(Get-RoleGroupMember -Identity $group.Name -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not read the members of '$($group.Name)': $($_.Exception.Message)"
    }
    $roles = (@($group.Roles) -join '; ')
    $isBuiltIn = ($builtInGroups -contains [string]$group.Name)
    $isEmpty = ($members.Count -eq 0)
    # An empty group still gets one informational row so that it shows up in the report.
    if ($isEmpty) { $members = @([PSCustomObject]@{ Name = '(none)'; DisplayName = '(none)'; RecipientType = ''; WindowsLiveID = ''; PrimarySmtpAddress = '' }) }
    foreach ($member in $members) {
        $memberId = [string]$(if ($member.WindowsLiveID) { $member.WindowsLiveID } elseif ($member.PrimarySmtpAddress) { $member.PrimarySmtpAddress } else { $member.Name })
        $memberType = [string]$member.RecipientType
        $accountDisabled = $null
        if ($CheckAccountStatus -and ($memberType -like '*User*' -or $memberType -like '*Mailbox*')) {
            if (-not $accountCache.ContainsKey($memberId)) {
                try { $accountCache[$memberId] = [bool](Get-User -Identity $memberId -ErrorAction Stop).AccountDisabled }
                catch { Write-Warning "Get-User failed for '$memberId': $($_.Exception.Message)"; $accountCache[$memberId] = $null }
            }
            $accountDisabled = $accountCache[$memberId]
        }
        $flags = @()
        if ($isEmpty) { $flags += 'EmptyGroup' }
        elseif ($group.Name -eq 'Organization Management') { $flags += 'OrganizationManagement' }
        if ($accountDisabled -eq $true) { $flags += 'AccountDisabled' }
        $results.Add([PSCustomObject]@{
                RoleGroup       = [string]$group.Name
                Description     = [string]$group.Description
                Member          = [string]$(if ($member.DisplayName) { $member.DisplayName } else { $member.Name })
                MemberId        = $memberId
                MemberType      = $memberType
                Roles           = $roles
                IsBuiltIn       = $isBuiltIn
                AccountDisabled = $accountDisabled
                Flag            = ($flags -join '; ')
            })
    }
}
Write-Progress -Activity 'Reading role group members' -Completed

$caseAdmins = @()
try {
    $caseAdmins = @(Get-eDiscoveryCaseAdmin -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{ Name = [string]$_.Name; DisplayName = [string]$_.DisplayName; PrimarySmtpAddress = [string]$_.PrimarySmtpAddress }
        })
}
catch {
    Write-Warning "Could not read the eDiscovery case administrators (needs eDiscovery Manager or Organization Management): $($_.Exception.Message)"
}

if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
if ($caseAdmins.Count -gt 0) { $caseAdmins | Export-Csv -Path $adminsPath -NoTypeInformation -Encoding UTF8 }

$memberRows = @($results | Where-Object { $_.Flag -ne 'EmptyGroup' })
$customCount = @($results | Where-Object { -not $_.IsBuiltIn } | Select-Object -Property RoleGroup -Unique).Count
Write-Host ''
Write-Host 'Purview role group summary' -ForegroundColor Cyan
Write-Host ('  Role groups        : {0}  (custom {1}, empty {2})' -f $roleGroups.Count, $customCount, @($results | Where-Object { $_.Flag -eq 'EmptyGroup' }).Count)
Write-Host ('  Memberships        : {0}  ({1} distinct members)' -f $memberRows.Count, @($memberRows | Select-Object -Property MemberId -Unique).Count)
Write-Host '  Organization Management members:' -ForegroundColor Yellow
foreach ($row in ($memberRows | Where-Object { $_.RoleGroup -eq 'Organization Management' })) { Write-Host ('    {0} ({1})' -f $row.Member, $row.MemberId) }
if ($CheckAccountStatus) { Write-Host ('  Disabled accounts  : {0}' -f @($memberRows | Where-Object { $_.AccountDisabled -eq $true }).Count) -ForegroundColor Yellow }
Write-Host ('  eDiscovery admins  : {0}' -f $caseAdmins.Count)
Write-Host '  Note: Entra ID Global Administrator, Compliance Administrator and Compliance Data Administrator roles also grant Purview access.'
if ($results.Count -gt 0) { Write-Host ('  Report             : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
