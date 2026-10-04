<#
.SYNOPSIS
    Exports the members of distribution groups (optionally expanding nested groups) to one CSV or one CSV per group.
.DESCRIPTION
    Enumerates the members of every group in scope with Get-DistributionGroupMember (Get-DynamicDistributionGroupMember
    for dynamic groups with -IncludeDynamic). With -Recursive, nested distribution groups, mail-enabled security groups,
    room lists and dynamic groups are expanded; the Nested column shows the path to the containing group and every group
    is expanded once per top-level group (cycle protection). Rows: Group, GroupSmtp, Member, MemberSmtp, MemberType, Nested.
.PARAMETER Identity
    One or more group identities (name, alias, primary SMTP address or GUID). When omitted, every distribution group is exported.
.PARAMETER InputCsv
    Path to a CSV with an Identity or PrimarySmtpAddress column listing the groups to export.
.PARAMETER IncludeDynamic
    Also export dynamic distribution groups (their membership is the one last calculated by Exchange Online).
.PARAMETER Recursive
    Expand nested groups and report their members with the nesting path.
.PARAMETER OneFilePerGroup
    Write one CSV per group (named after the group's SMTP address) into -OutputFolder instead of a single CSV.
.PARAMETER OutputFolder
    Folder for -OneFilePerGroup. Defaults to .\Reports\EXODistributionGroupMembers_yyyyMMdd-HHmm\.
.PARAMETER OutputPath
    Path of the single CSV report. Defaults to .\Reports\EXODistributionGroupMembers_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the member rows to the pipeline.
.EXAMPLE
    PS> .\Export-EXODistributionGroupMembers.ps1
    Exports the direct members of every distribution group into a single CSV.
.EXAMPLE
    PS> .\Export-EXODistributionGroupMembers.ps1 -Identity all-staff@contoso.com -Recursive -PassThru | Where-Object { $_.Nested }
    Expands the nested groups of one distribution list and shows only the members that come from nested groups.
.EXAMPLE
    PS> .\Export-EXODistributionGroupMembers.ps1 -InputCsv .\Groups.csv -IncludeDynamic -OneFilePerGroup -OutputFolder C:\Temp\Members
    Writes one CSV per listed group, including dynamic groups, into C:\Temp\Members.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : View-Only Recipients (Exchange Online)
    Category    : Distribution groups
    Changes     : No
    Notes       : One Get-DistributionGroupMember call per group (and per nested group with -Recursive). Microsoft 365 Groups
                  nested in a distribution list are listed as members (GroupMailbox) but not expanded - use Get-UnifiedGroupLinks.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/get-distributiongroupmember
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
    [switch]$Recursive,

    [Parameter()]
    [switch]$OneFilePerGroup,

    [Parameter()]
    [string]$OutputFolder,

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

function Get-GroupMemberRow {
    <# Emits one row per member of $Container, attributed to the top-level $Group. With -Expand, nested groups are
       expanded recursively; $Visited records every group already expanded under this top-level group (cycle guard). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Group,

        [Parameter(Mandatory = $true)]
        [object]$Container,

        [Parameter()]
        [string]$NestedPath = '',

        [Parameter(Mandatory = $true)]
        [hashtable]$Visited,

        [Parameter()]
        [switch]$Expand
    )
    $expandableTypes = @('MailUniversalDistributionGroup', 'MailUniversalSecurityGroup', 'RoomList', 'DynamicDistributionGroup')
    $containerSmtp = [string]$Container.PrimarySmtpAddress
    $Visited[$containerSmtp.ToLowerInvariant()] = $true
    if ([string]$Container.RecipientTypeDetails -eq 'DynamicDistributionGroup') { $members = @(Get-DynamicDistributionGroupMember -Identity $containerSmtp -ResultSize Unlimited -ErrorAction Stop) }
    else { $members = @(Get-DistributionGroupMember -Identity $containerSmtp -ResultSize Unlimited -ErrorAction Stop) }
    foreach ($member in $members) {
        $memberSmtp = [string]$member.PrimarySmtpAddress
        $memberType = [string]$member.RecipientTypeDetails
        [PSCustomObject]@{
            Group      = [string]$Group.DisplayName
            GroupSmtp  = [string]$Group.PrimarySmtpAddress
            Member     = [string]$member.DisplayName
            MemberSmtp = $memberSmtp
            MemberType = $memberType
            Nested     = $NestedPath
        }
        if (-not $Expand -or $memberType -notin $expandableTypes -or [string]::IsNullOrWhiteSpace($memberSmtp)) { continue }
        if ($Visited.ContainsKey($memberSmtp.ToLowerInvariant())) { Write-Verbose "'$memberSmtp' was already expanded under '$($Group.PrimarySmtpAddress)' (cycle or duplicate path)."; continue }
        $childPath = $(if ([string]::IsNullOrEmpty($NestedPath)) { $memberSmtp } else { '{0} > {1}' -f $NestedPath, $memberSmtp })
        try { Get-GroupMemberRow -Group $Group -Container $member -NestedPath $childPath -Visited $Visited -Expand }
        catch { Write-Warning "Nested group '$memberSmtp' could not be expanded: $($_.Exception.Message)" }
    }
}
#endregion Helpers

#region Main
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
if ($OneFilePerGroup -and [string]::IsNullOrWhiteSpace($OutputFolder)) { $OutputFolder = Join-Path -Path $reportFolder -ChildPath ('EXODistributionGroupMembers_{0}' -f $stamp) }
if (-not $OneFilePerGroup -and [string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EXODistributionGroupMembers_{0}.csv' -f $stamp) }
$targetFolder = $(if ($OneFilePerGroup) { $OutputFolder } else { Split-Path -Path $OutputPath -Parent })
if (-not [string]::IsNullOrWhiteSpace($targetFolder) -and -not (Test-Path -Path $targetFolder)) { New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null }

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

$results = New-Object -TypeName System.Collections.Generic.List[object]
$filesWritten = 0
$index = 0
foreach ($group in $groups) {
    $index++
    $smtp = [string]$group.PrimarySmtpAddress
    Write-Progress -Activity 'Exporting group members' -Status "$index of $($groups.Count) - $smtp" -PercentComplete (($index / $groups.Count) * 100)
    try { $memberRows = @(Get-GroupMemberRow -Group $group -Container $group -Visited @{} -Expand:$Recursive) }
    catch { Write-Warning "Members of '$smtp' could not be read: $($_.Exception.Message)"; continue }
    if ($OneFilePerGroup -and $memberRows.Count -gt 0) {
        $fileName = ($smtp -replace '[\\/:*?"<>|]', '_') + '.csv'
        $memberRows | Export-Csv -Path (Join-Path -Path $OutputFolder -ChildPath $fileName) -NoTypeInformation -Encoding UTF8
        $filesWritten++
    }
    foreach ($row in $memberRows) { $results.Add($row) }
}
Write-Progress -Activity 'Exporting group members' -Completed

if (-not $OneFilePerGroup -and $results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'Distribution group members summary' -ForegroundColor Cyan
Write-Host ('  Groups processed     : {0}' -f $groups.Count)
Write-Host ('  Member rows          : {0}' -f $results.Count)
if ($Recursive) { Write-Host ('  Nested groups walked : {0}' -f @($results | Where-Object { $_.Nested } | Select-Object -ExpandProperty Nested -Unique).Count) }
if ($OneFilePerGroup) { Write-Host ('  Files written        : {0} in {1}' -f $filesWritten, $OutputFolder) }
elseif ($results.Count -gt 0) { Write-Host ('  Report               : {0}' -f $OutputPath) }

if ($PassThru) {
    $results
}
#endregion Main
