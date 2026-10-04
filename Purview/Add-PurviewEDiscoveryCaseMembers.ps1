<#
.SYNOPSIS
    Adds, removes or replaces the members of eDiscovery cases, skipping existing members and warning about users outside the eDiscovery Manager role group.
.DESCRIPTION
    Takes case/member pairs from -CaseName with -Members, or from a CSV with the columns CaseName and Member, and calls
    Add-ComplianceCaseMember for members that are not yet on the case (existing members are skipped). -Remove calls
    Remove-ComplianceCaseMember instead, and -ReplaceWith replaces the whole member list with Update-ComplianceCaseMember.
    Before adding, each member is checked against the eDiscovery Manager role group (Get-RoleGroupMember) and the eDiscovery
    Administrators (Get-eDiscoveryCaseAdmin); users outside both get a warning because case membership alone grants no access.
    Every change is wrapped in ShouldProcess, so -WhatIf previews the result. One result object per case/member pair.
.PARAMETER CaseName
    Name of the eDiscovery (Standard or Premium) case.
.PARAMETER Members
    One or more members (UPN, email address or name) to add to or remove from the case.
.PARAMETER ReplaceWith
    Complete new member list for the case; members not in the list are removed (Update-ComplianceCaseMember).
.PARAMETER InputCsv
    CSV file with the columns CaseName and Member; one row per change, several cases allowed.
.PARAMETER Remove
    Remove the given members instead of adding them.
.EXAMPLE
    PS> .\Add-PurviewEDiscoveryCaseMembers.ps1 -CaseName 'Legal 7' -Members alex@contoso.com, dana@contoso.com
    Adds the two users to the case after confirmation; members that are already on the case are skipped.
.EXAMPLE
    PS> .\Add-PurviewEDiscoveryCaseMembers.ps1 -InputCsv .\case-members.csv -Remove -WhatIf
    Shows which members would be removed from which cases without changing anything.
.EXAMPLE
    PS> .\Add-PurviewEDiscoveryCaseMembers.ps1 -CaseName 'HR-42' -ReplaceWith hr-lead@contoso.com -Confirm:$false
    Replaces the member list of the case with a single member without prompting.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : eDiscovery Manager (member of the case) or eDiscovery Administrator in Security & Compliance PowerShell;
                  reading the role group needs the Role Management or View-Only Configuration role.
    Category    : eDiscovery & content search
    Changes     : Yes
    Notes       : A user must be in the eDiscovery Manager role group (or be an eDiscovery Administrator) to open a case they are a
                  member of; add them with Add-RoleGroupMember 'eDiscovery Manager' if the warning appears. eDiscovery Administrators
                  can access every case without being added as members.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/add-compliancecasemember
.LINK
    https://learn.microsoft.com/powershell/module/exchange/update-compliancecasemember
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Direct')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
    [string]$CaseName,

    [Parameter(ParameterSetName = 'Direct')]
    [string[]]$Members,

    [Parameter(ParameterSetName = 'Direct')]
    [string[]]$ReplaceWith,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [switch]$Remove
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

function Get-IdentityKey {
    <# Returns the identifiers (UPN, SMTP address, alias, name, display name) of a recipient-like object so members match whichever form the caller used. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Recipient
    )
    $keys = @()
    if ($null -eq $Recipient) { return $keys }
    foreach ($name in 'WindowsLiveID', 'PrimarySmtpAddress', 'Alias', 'Name', 'DisplayName', 'ExternalDirectoryObjectId') {
        $property = $Recipient.PSObject.Properties[$name]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) { $keys += [string]$property.Value }
    }
    return $keys
}
#endregion Helpers

#region Main
if ($PSCmdlet.ParameterSetName -eq 'Direct') {
    if (($null -eq $Members) -eq ($null -eq $ReplaceWith)) { throw 'Specify either -Members or -ReplaceWith (not both).' }
    if ($Remove -and $null -ne $ReplaceWith) { throw '-Remove cannot be combined with -ReplaceWith.' }
    $pairs = @()
    foreach ($member in @($Members | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) { $pairs += [PSCustomObject]@{ CaseName = $CaseName; Member = $member.Trim() } }
}
else {
    $rows = @(Import-Csv -Path $InputCsv)
    if ($rows.Count -eq 0 -or $null -eq $rows[0].PSObject.Properties['CaseName'] -or $null -eq $rows[0].PSObject.Properties['Member']) { throw 'The CSV needs the columns CaseName and Member.' }
    $pairs = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.CaseName) -and -not [string]::IsNullOrWhiteSpace($_.Member) } |
            ForEach-Object { [PSCustomObject]@{ CaseName = $_.CaseName.Trim(); Member = $_.Member.Trim() } })
}

try { Connect-ExchangeIfNeeded -Compliance } catch { throw "Unable to connect to Security & Compliance PowerShell: $($_.Exception.Message)" }

# Case membership alone grants nothing: the user also needs the eDiscovery Manager role group (or to be an eDiscovery Administrator).
$roleKeys = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
$roleCheck = $true
try { foreach ($entry in @(Get-RoleGroupMember -Identity 'eDiscovery Manager' -ErrorAction Stop)) { foreach ($key in Get-IdentityKey -Recipient $entry) { $null = $roleKeys.Add($key) } } }
catch { $roleCheck = $false; Write-Warning "Could not read the eDiscovery Manager role group; the role membership check is skipped: $($_.Exception.Message)" }
try { foreach ($entry in @(Get-eDiscoveryCaseAdmin -ErrorAction Stop)) { foreach ($key in Get-IdentityKey -Recipient $entry) { $null = $roleKeys.Add($key) } } }
catch { Write-Verbose "Could not read the eDiscovery Administrators: $($_.Exception.Message)" }

$results = New-Object -TypeName System.Collections.Generic.List[object]
$caseNames = @($pairs | Select-Object -ExpandProperty CaseName -Unique)
if ($null -ne $ReplaceWith) { $caseNames = @($CaseName) }
foreach ($name in $caseNames) {
    $case = $null
    foreach ($caseType in 'eDiscovery', 'AdvancedEdiscovery') {
        if ($null -eq $case) { $case = Get-ComplianceCase -Identity $name -CaseType $caseType -ErrorAction SilentlyContinue | Select-Object -First 1 }
    }
    if ($null -eq $case) {
        Write-Warning ("Case '{0}' was not found." -f $name)
        foreach ($pair in @($pairs | Where-Object { $_.CaseName -eq $name })) {
            $results.Add([PSCustomObject]@{ CaseName = $name; Member = $pair.Member; Action = 'Lookup'; Result = 'Failed'; InRoleGroup = $null; Error = 'Case not found' })
        }
        continue
    }
    $existingKeys = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    try {
        foreach ($entry in @(Get-ComplianceCaseMember -Case $case.Identity -ResultSize Unlimited -ErrorAction Stop)) {
            foreach ($key in Get-IdentityKey -Recipient $entry) { $null = $existingKeys.Add($key) }
        }
    }
    catch { Write-Warning ("Could not read the current members of '{0}': {1}" -f $case.Name, $_.Exception.Message) }

    $action = $(if ($null -ne $ReplaceWith) { 'Replace' } elseif ($Remove) { 'Remove' } else { 'Add' })
    $members = @($pairs | Where-Object { $_.CaseName -eq $name } | ForEach-Object { $_.Member })
    if ($action -eq 'Replace') { $members = @($ReplaceWith | ForEach-Object { $_.Trim() }) }
    foreach ($member in $members) {
        $inRole = $null
        if ($roleCheck) { $inRole = $roleKeys.Contains($member) }
        if ($action -ne 'Remove' -and $inRole -eq $false) { Write-Warning ("'{0}' is not in the eDiscovery Manager role group and will not be able to open case '{1}'." -f $member, $case.Name) }
        if ($action -eq 'Replace') { continue }
        $result = 'Skipped'; $errorMessage = $null
        try {
            if ($action -eq 'Add' -and $existingKeys.Contains($member)) { $errorMessage = 'Already a member' }
            elseif ($action -eq 'Remove' -and -not $existingKeys.Contains($member)) { $errorMessage = 'Not a member' }
            elseif ($PSCmdlet.ShouldProcess(('{0} on case {1}' -f $member, $case.Name), $action)) {
                if ($action -eq 'Remove') { Remove-ComplianceCaseMember -Case $case.Identity -Member $member -Confirm:$false -ErrorAction Stop; $result = 'Removed' }
                else { Add-ComplianceCaseMember -Case $case.Identity -Member $member -Confirm:$false -ErrorAction Stop; $result = 'Added' }
            }
            else { $result = 'WhatIf' }
        }
        catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ("{0} failed for '{1}' on '{2}': {3}" -f $action, $member, $case.Name, $errorMessage) }
        $results.Add([PSCustomObject]@{ CaseName = [string]$case.Name; Member = $member; Action = $action; Result = $result; InRoleGroup = $inRole; Error = $errorMessage })
    }
    if ($action -ne 'Replace') { continue }

    # Update-ComplianceCaseMember replaces the whole list in one call, so it is confirmed once per case and reported per member.
    $result = 'WhatIf'; $errorMessage = $null
    if ($PSCmdlet.ShouldProcess($case.Name, ('Replace the member list with {0} member(s): {1}' -f $members.Count, ($members -join ', ')))) {
        try { Update-ComplianceCaseMember -Case $case.Identity -Members $members -Confirm:$false -ErrorAction Stop; $result = 'Replaced' }
        catch { $result = 'Failed'; $errorMessage = $_.Exception.Message; Write-Warning ("Replacing the members of '{0}' failed: {1}" -f $case.Name, $errorMessage) }
    }
    foreach ($member in $members) {
        $inRole = $null
        if ($roleCheck) { $inRole = $roleKeys.Contains($member) }
        $results.Add([PSCustomObject]@{ CaseName = [string]$case.Name; Member = $member; Action = $action; Result = $result; InRoleGroup = $inRole; Error = $errorMessage })
    }
}

Write-Host "`neDiscovery case membership summary" -ForegroundColor Cyan
foreach ($group in ($results | Group-Object -Property Result | Sort-Object -Property Name)) {
    $colour = @{ Failed = 'Red'; Added = 'Green'; Removed = 'Green'; Replaced = 'Green' }[$group.Name]; if (-not $colour) { $colour = 'Yellow' }
    Write-Host ('  {0,-10} {1,5}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
Write-Host ('  Not in eDiscovery Manager role group: {0}' -f @($results | Where-Object { $_.InRoleGroup -eq $false }).Count)
$results
#endregion Main
